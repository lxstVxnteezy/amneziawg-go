/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"github.com/amnezia-vpn/amneziawg-go/v3/quicinitial"

	"testing"
	"time"
)

func countInitials(sent [][]byte) int {
	n := 0
	for _, d := range sent {
		if isQUICInitial(d) {
			n++
		}
	}
	return n
}

// handshakeNow sends a handshake initiation from pair[0] to pair[1] as a
// rekey would, waits for it to complete and returns what pair[0] sent.
func handshakeNow(t *testing.T, pair testPair, rec [2]*wireBind) [][]byte {
	t.Helper()
	peer := pair[0].dev.LookupPeer(pair[1].dev.staticIdentity.publicKey)
	// the initiation timestamp is coarse and the receiver rate-limits
	// initiations: back to back they are rejected as a replay or a flood
	time.Sleep(100 * time.Millisecond)
	before := peer.lastHandshakeNano.Load()
	rec[0].take()
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Time{}
	peer.handshake.mutex.Unlock()
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for peer.lastHandshakeNano.Load() == before {
		if time.Now().After(deadline) {
			t.Fatal("handshake did not complete")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return rec[0].take()
}

// A rekey inside a live flow carries no Initial and no junk; a handshake
// from a new port starts a new flow and carries both again.
func TestFlowStartOnlyOnNewFlow(t *testing.T) {
	pair, rec := wirePair(t, [2][]string{{"i1", "<quic sni=vpn.example.com>"}, nil})
	traffic(t, pair)
	if n := countInitials(rec[0].take()); n == 0 {
		t.Fatal("the first flow did not start with a QUIC Initial")
	}

	// The test binds may answer from another address than the configured
	// one; the peer roams to it, which is a new flow too. Settle on it.
	handshakeNow(t, pair, rec)

	// awgParams has jc=4: a disguised handshake is I-packets + 4 junk +
	// the initiation; a bare one is the initiation and the keepalive that
	// confirms the session.
	sent := handshakeNow(t, pair, rec)
	if n := countInitials(sent); n != 0 || len(sent) > 2 {
		t.Fatalf("rekey in a live flow sent %d datagrams, %d of them QUIC Initials", len(sent), n)
	}
	pair.Send(t, Ping, nil)

	pair[0].dev.rotatePort()
	deadline := time.Now().Add(5 * time.Second)
	var after [][]byte
	for countInitials(after) == 0 && time.Now().Before(deadline) {
		after = append(after, rec[0].take()...)
		time.Sleep(5 * time.Millisecond)
	}
	if countInitials(after) == 0 {
		t.Fatal("handshake from a new port did not start with a QUIC Initial")
	}
	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)
}

func TestStartsFlow(t *testing.T) {
	pair := genTestPair(t, true)
	pair.Send(t, Ping, nil)
	peer := pair[0].dev.LookupPeer(pair[1].dev.staticIdentity.publicKey)
	now := time.Now()

	// the flow started a second before its handshake completed and is
	// in use
	peer.startFlow(now) // records the current socket and address
	peer.flow.mu.Lock()
	peer.flow.started = peer.lastHandshakeNano.Load() - int64(time.Second)
	peer.flow.mu.Unlock()
	peer.flow.lastSent.Store(now.UnixNano())
	if m, _ := peer.startFlow(now); m != flowLive {
		t.Fatal("a live, answered flow is started again")
	}

	// unanswered since the last disguised handshake
	peer.flow.mu.Lock()
	peer.flow.started = now.UnixNano() + 1
	peer.flow.mu.Unlock()
	if m, _ := peer.startFlow(now); m != flowNew {
		t.Fatal("a flow the peer never answered is not restarted")
	}

	// silent for longer than flowIdleTimeout both ways
	peer.flow.mu.Lock()
	peer.flow.started = 1
	peer.flow.mu.Unlock()
	later := now.Add(flowIdleTimeout + time.Second)
	if m, _ := peer.startFlow(later); m != flowNew {
		t.Fatal("an idle flow is not restarted")
	}

	// a new socket
	peer.flow.mu.Lock()
	peer.flow.started = 1
	peer.flow.mu.Unlock()
	pair[0].dev.net.gen.Add(1)
	if m, _ := peer.startFlow(now); m != flowNew {
		t.Fatal("a handshake from a new socket does not start a flow")
	}
}

// With no answer, a QUIC attempt is retransmitted like a browser does:
// the same connection ID and ClientHello, packet numbers going on, no junk,
// after a probe timeout that doubles; after quicMaxRetransmits a new
// attempt starts with a new connection ID.
func TestFlowRetransmitsQUICAttempt(t *testing.T) {
	pair, rec := wirePair(t, [2][]string{{"i1", "<quic sni=vpn.example.com>"}, nil})
	traffic(t, pair)
	pair[1].dev.RemoveAllPeers() // the server stops answering
	rec[0].take()

	start := time.Now()
	pair[0].dev.rotatePort() // a new flow, which gets no answer
	// sends at 0, ~1, ~3 s; stop before the one at ~7 s
	time.Sleep(4 * time.Second)
	sent := rec[0].take()

	type flight struct {
		dcid string
		pns  []uint32
	}
	var flights []flight
	nonInitial := 0
	for _, d := range sent {
		if !isQUICInitial(d) {
			nonInitial++
			continue
		}
		dcid, pn, _, err := quicinitial.Open(d)
		if err != nil {
			t.Fatal(err)
		}
		if len(flights) == 0 || flights[len(flights)-1].dcid != string(dcid) || len(flights[len(flights)-1].pns) == 2 {
			flights = append(flights, flight{dcid: string(dcid)})
		}
		f := &flights[len(flights)-1]
		f.pns = append(f.pns, pn)
	}
	t.Logf("%v: %d Initials in %d flights, %d other datagrams", time.Since(start), len(sent)-nonInitial, len(flights), nonInitial)
	if len(flights) != 3 {
		t.Fatalf("got %d Initial flights in 4 s, want 3 (at 0, 1, 3 s)", len(flights))
	}
	next := uint32(0)
	for i, f := range flights {
		if f.dcid != flights[0].dcid {
			t.Fatalf("flight %d has a new connection ID: not a retransmission", i)
		}
		for _, pn := range f.pns {
			if pn != next {
				t.Fatalf("flight %d: packet number %d, want %d", i, pn, next)
			}
			next++
		}
	}
	// junk waits for an answer that never comes: each flight is the
	// Initials and the handshake initiation, nothing else
	if nonInitial != len(flights) {
		t.Fatalf("%d non-Initial datagrams, want %d (one initiation per flight, no junk)", nonInitial, len(flights))
	}

	// after quicMaxRetransmits the attempt is given up
	peer := pair[0].dev.LookupPeer(pair[1].dev.staticIdentity.publicKey)
	peer.flow.mu.Lock()
	peer.flow.retransmits = quicMaxRetransmits
	peer.flow.mu.Unlock()
	if m, _ := peer.startFlow(time.Now()); m != flowNew {
		t.Fatalf("after %d retransmissions: mode %d, want a new attempt", quicMaxRetransmits, m)
	}
}

// In a QUIC attempt the junk follows the server's answer: the initiation
// directly follows the Initials, the junk (jc=4) comes after the response.
func TestFlowJunkAfterAnswer(t *testing.T) {
	pair, rec := wirePair(t, [2][]string{{"i1", "<quic sni=vpn.example.com>"}, nil})
	traffic(t, pair)
	time.Sleep(100 * time.Millisecond) // see handshakeNow
	rec[0].take()
	peer := pair[0].dev.LookupPeer(pair[1].dev.staticIdentity.publicKey)
	before := peer.lastHandshakeNano.Load()
	pair[0].dev.rotatePort()
	deadline := time.Now().Add(5 * time.Second)
	for peer.lastHandshakeNano.Load() == before {
		if time.Now().After(deadline) {
			t.Fatal("handshake did not complete")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	sent := rec[0].take()
	initials := countInitials(sent)
	if initials == 0 || len(sent) < initials+1+4 {
		t.Fatalf("sent %d datagrams with %d Initials, want Initials, initiation and 4 junk", len(sent), initials)
	}
	if peer.flow.junkPending.Load() {
		t.Fatal("junk still pending after the answer")
	}
}
