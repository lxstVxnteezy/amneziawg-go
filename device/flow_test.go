/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/quicinitial"
)

// flowPeer is the client's peer of an idle pair: nothing is sent until the
// test asks, so the flow state changes only through the test.
func flowPeer(t *testing.T, i1 string) (*Peer, testPair, [2]*wireBind) {
	t.Helper()
	var extra [2][]string
	if i1 != "" {
		extra[0] = []string{"i1", i1}
	}
	pair, rec := wirePair(t, extra)
	peer := pair[0].dev.LookupPeer(pair[1].dev.staticIdentity.publicKey)
	if peer == nil {
		t.Fatal("no peer")
	}
	return peer, pair, rec
}

// dcidOf parses the Initial flight of a plan.
func dcidOf(t *testing.T, plan handshakePlan) (dcid []byte, pn uint32) {
	t.Helper()
	if len(plan.ipackets) != 2 {
		t.Fatalf("plan has %d I-packet datagrams, want a 2-datagram Initial flight", len(plan.ipackets))
	}
	info, err := quicinitial.Parse(plan.ipackets)
	if err != nil {
		t.Fatalf("Initial flight: %v", err)
	}
	_, pn, _, err = quicinitial.Open(plan.ipackets[0])
	if err != nil {
		t.Fatal(err)
	}
	return info.DCID, pn
}

// An unanswered attempt is retransmitted twice with the same connection ID
// and growing packet numbers and intervals, then a new attempt starts.
func TestFlowRetransmitsAttempt(t *testing.T) {
	peer, _, _ := flowPeer(t, "<quic sni=vpn.example.com>")

	first := peer.planHandshake()
	if !first.junk || first.backoff != 0 {
		t.Fatalf("new attempt: junk %v backoff %d", first.junk, first.backoff)
	}
	dcid, pn := dcidOf(t, first)
	if pn != 0 {
		t.Fatalf("first Initial has packet number %d", pn)
	}

	for i := 1; i < maxFlightSends; i++ {
		p := peer.planHandshake()
		if p.junk || p.backoff != uint(i) {
			t.Fatalf("retransmission %d: junk %v backoff %d", i, p.junk, p.backoff)
		}
		d, pn := dcidOf(t, p)
		if !bytes.Equal(d, dcid) || pn != uint32(2*i) {
			t.Fatalf("retransmission %d: dcid %x pn %d, want dcid %x pn %d", i, d, pn, dcid, 2*i)
		}
	}

	next := peer.planHandshake()
	d, pn := dcidOf(t, next)
	if !next.junk || next.backoff != 0 || bytes.Equal(d, dcid) || pn != 0 {
		t.Fatalf("after %d sends: junk %v backoff %d dcid %x pn %d, want a new attempt", maxFlightSends, next.junk, next.backoff, d, pn)
	}
}

// An attempt abandoned long ago is not retransmitted: the next handshake
// starts a new one.
func TestFlowStaleAttempt(t *testing.T) {
	peer, pair, _ := flowPeer(t, "<quic sni=vpn.example.com>")
	dcid, _ := dcidOf(t, peer.planHandshake())
	peer.flow.Lock()
	peer.flow.lastSend = time.Now().Add(-pair[0].dev.maxRetransmitGap() - time.Second)
	peer.flow.Unlock()
	p := peer.planHandshake()
	d, pn := dcidOf(t, p)
	if bytes.Equal(d, dcid) || pn != 0 || !p.junk {
		t.Fatalf("a stale attempt was retransmitted: pn %d junk %v", pn, p.junk)
	}
}

// After a completed handshake, rekeys on the same flow go alone. When they
// stay unanswered, the flow is taken as lost and a new attempt starts.
func TestFlowRekeyWithoutIPackets(t *testing.T) {
	peer, _, _ := flowPeer(t, "<quic sni=vpn.example.com>")
	peer.planHandshake()
	peer.flowHandshakeComplete()

	for i := 0; i < maxFlightSends; i++ {
		p := peer.planHandshake()
		if len(p.ipackets) != 0 || p.junk || p.backoff != uint(i) {
			t.Fatalf("rekey %d: %d I-packets, junk %v, backoff %d", i, len(p.ipackets), p.junk, p.backoff)
		}
	}
	p := peer.planHandshake()
	if _, pn := dcidOf(t, p); !p.junk || pn != 0 {
		t.Fatalf("unanswered rekeys did not start a new attempt: junk %v pn %d", p.junk, pn)
	}
}

// A new socket, an old flow or a new configuration starts a new attempt.
func TestFlowNewAttempt(t *testing.T) {
	peer, pair, _ := flowPeer(t, "<quic sni=vpn.example.com>")
	dev := pair[0].dev

	established := func() {
		peer.planHandshake()
		peer.flowHandshakeComplete()
		if p := peer.planHandshake(); len(p.ipackets) != 0 {
			t.Fatal("rekey on an established flow carries I-packets")
		}
	}
	isNew := func(why string) {
		t.Helper()
		p := peer.planHandshake()
		if _, pn := dcidOf(t, p); !p.junk || pn != 0 {
			t.Fatalf("%s: not a new attempt (junk %v, pn %d)", why, p.junk, pn)
		}
	}

	established()
	dev.bindGen.Add(1)
	isNew("new socket")

	established()
	peer.flow.Lock()
	peer.flow.completed = time.Now().Add(-dev.keychainExpireTime() - time.Second)
	peer.flow.Unlock()
	isNew("flow silent for longer than keys live")

	// an unanswered attempt is not retransmitted after I1 changed
	peer.planHandshake()
	if err := dev.IpcSet(uapiCfg("i1", "<quic sni=other.example.com>")); err != nil {
		t.Fatal(err)
	}
	p := peer.planHandshake()
	info, err := quicinitial.Parse(p.ipackets)
	if err != nil || info.SNI != "other.example.com" || !p.junk {
		t.Fatalf("after reconfiguration: %v, SNI %q, junk %v", err, info.SNI, p.junk)
	}
}

// Without the QUIC shape every handshake carries I-packets and junk, as
// in AmneziaWG.
func TestFlowWithoutQUICShape(t *testing.T) {
	peer, pair, _ := flowPeer(t, "<r 100>")
	if pair[0].dev.quicShape.Load() {
		t.Fatal("QUIC shape is on")
	}
	peer.planHandshake()
	peer.flowHandshakeComplete()
	for i := 0; i < 2*maxFlightSends; i++ {
		p := peer.planHandshake()
		if len(p.ipackets) != 1 || !p.junk || p.backoff != 0 {
			t.Fatalf("handshake %d: %d I-packets, junk %v, backoff %d", i, len(p.ipackets), p.junk, p.backoff)
		}
	}
}

// On the wire: the flow begins with the Initial, and a rekey on it sends
// no Initial and no junk, only the handshake; the tunnel keeps working.
func TestFlowRekeyOnTheWire(t *testing.T) {
	peer, pair, rec := flowPeer(t, "<quic sni=vpn.example.com>")
	traffic(t, pair)
	sent := rec[0].take()
	if !isQUICInitial(sent[0]) {
		t.Fatal("the flow does not begin with the QUIC Initial")
	}

	// the responder rejects an initiation whose TAI64N timestamp is not
	// newer than the last one (rounded to ~16 ms) or that comes within
	// HandshakeInitationRate of it
	time.Sleep(50 * time.Millisecond)
	before := peer.lastHandshakeNano.Load()
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Time{}
	peer.handshake.mutex.Unlock()
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for peer.lastHandshakeNano.Load() == before {
		if time.Now().After(deadline) {
			t.Fatal("rekey did not complete")
		}
		time.Sleep(10 * time.Millisecond)
	}
	rekey := rec[0].take()
	if len(rekey) == 0 {
		t.Fatal("nothing sent")
	}
	init := 148 + 20 // MessageInitiationSize + S1
	for i, d := range rekey {
		if isQUICInitial(d) {
			t.Fatalf("datagram %d of the rekey is a QUIC Initial", i)
		}
		if !shaped(d) {
			t.Fatalf("datagram %d of the rekey is not shaped", i)
		}
	}
	if len(rekey[0]) < init {
		t.Fatalf("the rekey starts with a %d-byte datagram (junk?), want the %d+ byte initiation", len(rekey[0]), init)
	}
	traffic(t, pair)
}
