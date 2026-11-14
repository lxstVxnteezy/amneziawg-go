/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
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
	peer.startsFlow(now) // records the current socket and address
	peer.flow.mu.Lock()
	peer.flow.started = peer.lastHandshakeNano.Load() - int64(time.Second)
	peer.flow.mu.Unlock()
	peer.flow.lastSent.Store(now.UnixNano())
	if peer.startsFlow(now) {
		t.Fatal("a live, answered flow is started again")
	}

	// unanswered since the last disguised handshake
	peer.flow.mu.Lock()
	peer.flow.started = now.UnixNano() + 1
	peer.flow.mu.Unlock()
	if !peer.startsFlow(now) {
		t.Fatal("a flow the peer never answered is not restarted")
	}

	// silent for longer than flowIdleTimeout both ways
	peer.flow.mu.Lock()
	peer.flow.started = 1
	peer.flow.mu.Unlock()
	later := now.Add(flowIdleTimeout + time.Second)
	if !peer.startsFlow(later) {
		t.Fatal("an idle flow is not restarted")
	}

	// a new socket
	peer.flow.mu.Lock()
	peer.flow.started = 1
	peer.flow.mu.Unlock()
	pair[0].dev.net.gen.Add(1)
	if !peer.startsFlow(now) {
		t.Fatal("a handshake from a new socket does not start a flow")
	}
}
