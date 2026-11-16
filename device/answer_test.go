/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/quicinitial"
)

// siteAnswer is the start of a server's Initial: QUIC v1 long header,
// DCID = the client's 8 bytes, SCID = the 4 bytes the server chose.
func siteAnswer(scid []byte) []byte {
	b := []byte{0xc1, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, byte(len(scid))}
	b = append(b, scid...)
	return append(b, make([]byte, 1200-len(b))...)
}

// quicSite stands in for the HTTP/3 site behind the fallback: it answers
// every datagram with a server Initial after delay.
func quicSite(t *testing.T, delay time.Duration, scid []byte) netip.AddrPort {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			_, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			time.AfterFunc(delay, func() { c.WriteToUDP(siteAnswer(scid), from) })
		}
	}()
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

// handshakeAfterInitial returns how long after its QUIC Initial the client
// sent the handshake initiation (the first datagram that is neither an
// Initial nor shorter than S1 + 148).
func handshakeAfterInitial(t *testing.T, rec *wireBind) time.Duration {
	t.Helper()
	sent, at := rec.takeTimed()
	var initialAt time.Time
	for i, d := range sent {
		switch {
		case isQUICInitial(d):
			if initialAt.IsZero() {
				initialAt = at[i]
			}
		case !initialAt.IsZero() && len(d) >= 20+MessageInitiationSize:
			return at[i].Sub(initialAt)
		}
	}
	t.Fatalf("no Initial followed by a handshake initiation in %d datagrams", len(sent))
	return 0
}

// A server with a fallback answers the client's Initial with the site's
// Initial; the client holds its handshake until then, as a QUIC client
// waits for the server, learns the server's connection ID, and the tunnel
// works.
func TestHandshakeWaitsForTheAnswer(t *testing.T) {
	const delay = 150 * time.Millisecond
	site := quicSite(t, delay, []byte("SCID"))
	pair, rec := wirePair(t, [2][]string{{"i1", "<quic sni=vpn.example.com>", "jc", "0"}, {"fallback", site.String()}})
	pair.Send(t, Pong, nil) // the client starts the handshake
	pair.Send(t, Ping, nil)

	rec[0].mu.Lock()
	sent := append([][]byte(nil), rec[0].sent...)
	rec[0].mu.Unlock()
	wait := handshakeAfterInitial(t, rec[0])
	peer := pair[0].dev.LookupPeer(pair[1].dev.staticIdentity.publicKey)
	peer.flow.Lock()
	cid, noAnswer, gen := peer.flow.serverCID, peer.flow.noAnswer, peer.flow.gen
	peer.flow.Unlock()
	if wait < delay-20*time.Millisecond || wait >= answerWait {
		var kinds []string
		for _, d := range sent {
			kinds = append(kinds, fmt.Sprintf("%d:%v", len(d), isQUICInitial(d)))
		}
		t.Fatalf("handshake %v after the Initial, want after the site's answer (%v) and before %v; cid %q noAnswer %v attempts %d; sent %v",
			wait, delay, answerWait, cid, noAnswer, gen, kinds)
	}
	if !bytes.Equal(cid, []byte("SCID")) || noAnswer {
		t.Fatalf("server CID %q, noAnswer %v: the answer was not taken", cid, noAnswer)
	}
	if pair[0].dev.flowAwaiting.Load() != 0 {
		t.Fatal("still waiting after the answer")
	}

	// on the wire: the Initial flight; an Initial that ACKs the server's,
	// to its connection ID, sealed with the first DCID's keys; then the
	// handshake as one QUIC Handshake packet to the same connection ID
	firstDCID := sent[0][6 : 6+sent[0][5]]
	var ack, hs []byte
	for _, d := range sent[1:] {
		switch {
		case isQUICInitial(d) && d[5] == 4 && ack == nil:
			ack = d
		case !isQUICInitial(d) && len(d) >= 20+MessageInitiationSize && hs == nil:
			hs = d
		}
	}
	if ack == nil || hs == nil {
		t.Fatalf("no Initial ACK (%v) or handshake (%v) after the flight", ack != nil, hs != nil)
	}
	dcid, _, frames, err := quicinitial.OpenWithKeys(ack, firstDCID)
	if err != nil || !bytes.Equal(dcid, []byte("SCID")) || frames[0] != 0x02 {
		t.Fatalf("Initial ACK: dcid %q, first frame %#x, err %v", dcid, frames[0], err)
	}
	hl := quicHandshakeHeaderLen(cid)
	if hs[0]&0xf0 != 0xe0 || !bytes.Equal(hs[1:5], []byte{0, 0, 0, 1}) || hs[5] != 4 ||
		!bytes.Equal(hs[6:10], []byte("SCID")) || hs[10] != 0 ||
		int(binary.BigEndian.Uint16(hs[hl-2:hl])&0x3fff) != len(hs)-hl {
		t.Fatalf("handshake does not read as a QUIC Handshake packet to SCID: % x", hs[:hl])
	}

	// data: short header packets to the server's connection ID
	rec[0].take()
	for range 10 {
		pair.Send(t, Pong, nil)
		pair.Send(t, Ping, nil)
	}
	data := 0
	for _, d := range rec[0].take() {
		if !shaped(d) {
			t.Fatalf("client datagram of %d bytes not shaped: %#x", len(d), d[0])
		}
		if !bytes.Equal(d[1:5], []byte("SCID")) {
			t.Fatalf("data packet without the server's connection ID: % x", d[:8])
		}
		data++
	}
	if data < 10 {
		t.Fatalf("only %d data packets", data)
	}
}

// A Handshake header needs room in the S1 prefix: a short prefix keeps
// the short header shape.
func TestShapeQUICHandshake(t *testing.T) {
	prefix := make([]byte, 20)
	if !shapeQUICHandshake(prefix, []byte("SCID"), 300) {
		t.Fatal("20-byte prefix refused for a 4-byte DCID")
	}
	if prefix[0]&0xf0 != 0xe0 || binary.BigEndian.Uint16(prefix[11:13]) != uint16(300-13)|0x4000 {
		t.Fatalf("header % x", prefix[:13])
	}
	if shapeQUICHandshake(make([]byte, 13), []byte("SCID"), 300) {
		t.Fatal("a prefix with no room for a packet number byte accepted")
	}
}

// A server without a fallback never answers: the first attempt waits
// answerWait, later attempts do not wait at all, and the tunnel works.
func TestHandshakeWithoutAnswer(t *testing.T) {
	pair, rec := wirePair(t, [2][]string{{"i1", "<quic sni=vpn.example.com>", "jc", "0"}, nil})
	pair.Send(t, Pong, nil)
	pair.Send(t, Ping, nil)
	if wait := handshakeAfterInitial(t, rec[0]); wait < answerWait-50*time.Millisecond {
		t.Fatalf("handshake %v after the Initial, want the full wait of %v", wait, answerWait)
	}

	peer := pair[0].dev.LookupPeer(pair[1].dev.staticIdentity.publicKey)
	peer.flow.Lock()
	noAnswer := peer.flow.noAnswer
	peer.flow.key = flowKey{} // the next handshake starts a new flow
	peer.flow.Unlock()
	if !noAnswer {
		t.Fatal("a server that never answered is not remembered")
	}
	if plan := peer.planHandshake(); plan.await != nil || len(plan.ipackets) == 0 {
		t.Fatalf("new attempt on a silent server: await %v, %d I-packets", plan.await != nil, len(plan.ipackets))
	}
}

func TestQUICAnswer(t *testing.T) {
	ans := siteAnswer([]byte{9, 9, 9, 9})
	if scid, ok := quicAnswer(ans); !ok || !bytes.Equal(scid, []byte{9, 9, 9, 9}) {
		t.Fatalf("server Initial: %v %x", ok, scid)
	}
	hs := append([]byte(nil), ans...)
	hs[0] = 0xe1 // Handshake
	if _, ok := quicAnswer(hs); !ok {
		t.Fatal("server Handshake not taken")
	}
	for name, b := range map[string][]byte{
		"short header": {0x41, 0, 0, 0, 1, 8},
		"version 2":    append([]byte{0xc1, 0x6b, 0x33, 0x43, 0xcf}, ans[5:]...),
		"0-RTT":        append([]byte{0xd1}, ans[1:]...),
		"long DCID":    append([]byte{0xc1, 0, 0, 0, 1, 21}, ans[6:]...),
		"truncated":    ans[:10],
		"empty":        nil,
	} {
		if _, ok := quicAnswer(b); ok {
			t.Errorf("%s taken as an answer", name)
		}
	}
}
