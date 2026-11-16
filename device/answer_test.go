/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
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

	sent := rec[0].sent
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
