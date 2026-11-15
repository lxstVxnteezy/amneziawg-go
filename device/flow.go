/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/quicinitial"
)

// Handshakes on one flow, with the QUIC disguise.
//
// AmneziaWG sends the I-packets and junk before every handshake. On a
// flow disguised as QUIC that means a new QUIC Initial every couple of
// minutes (at every rekey) and at every retry, in the middle of a flow
// that is already carrying short-header traffic. A QUIC client never
// starts its connection over on the same flow: it sends its Initial once,
// repeats that same Initial while no answer comes, and then talks on.
//
// So with the QUIC shape on (quicshape.go) a peer keeps the state of its
// flow, the local socket and the peer's address:
//
//   - The first handshake of a flow is a new connection attempt: the
//     I-packets (a new <quic> Initial) and the junk go before it.
//   - While it is unanswered, the handshake is sent again with the same
//     attempt: a <quic> I-packet is retransmitted (same connection ID and
//     ClientHello, next packet numbers), without junk, and the interval
//     doubles, as QUIC's probe timeout does (RFC 9002). After
//     maxFlightSends unanswered sends the next one starts a new attempt.
//   - Once a handshake completes, later handshakes on the same flow
//     (rekeys) go alone, shaped like short-header packets, with no
//     I-packets or junk. If maxFlightSends of them go unanswered, the flow
//     is taken as lost and the next handshake is a new attempt again.
//   - A new flow starts with a new attempt: another local port (port
//     rotation, a rebind after a network change), another peer address, or
//     a flow that has been silent for longer than keys live
//     (RejectAfterTime): a middlebox has forgotten it by then.
//
// Without the QUIC shape every handshake carries the I-packets and junk,
// as in AmneziaWG. Only the sender changes; the receiver never needed the
// I-packets, so this works with any peer.

// maxFlightSends is how many times one attempt is sent before the next
// handshake starts a new one: the first send and two retransmissions, at
// intervals of one, two and four retransmit timeouts.
const maxFlightSends = 3

// numIPackets is I1-I5.
const numIPackets = 5

type flowKey struct {
	bind uint64 // device.bindGen: a new socket is a new flow
	dst  string // the peer's address
}

type peerFlow struct {
	sync.Mutex
	key         flowKey
	established bool      // a handshake completed on this flow
	completed   time.Time // when the last one did
	sends       int       // handshakes sent since then (or in this attempt)
	attempt     [numIPackets]ipacketAttempt
}

// ipacketAttempt is what one I-packet sends in the current attempt.
type ipacketAttempt struct {
	chain *obfChain            // the I-packet it was made from
	quic  *quicinitial.Attempt // a <quic> I-packet: retransmitted, not rebuilt
}

func (a *ipacketAttempt) datagrams() ([][]byte, error) {
	if a.quic != nil {
		return a.quic.Flight()
	}
	return a.chain.Datagrams()
}

func (peer *Peer) currentFlowKey() flowKey {
	key := flowKey{bind: peer.device.bindGen.Load()}
	peer.endpoint.Lock()
	if peer.endpoint.val != nil {
		key.dst = peer.endpoint.val.DstToString()
	}
	peer.endpoint.Unlock()
	return key
}

// handshakePlan is what goes out with one handshake initiation.
type handshakePlan struct {
	ipackets [][]byte
	junk     bool
	backoff  uint // the retransmit timeout is shifted left by this
}

// planHandshake decides what goes out before a handshake initiation.
func (peer *Peer) planHandshake() handshakePlan {
	device := peer.device
	if !device.quicShape.Load() {
		return handshakePlan{ipackets: peer.freshIPackets(nil), junk: true}
	}

	key := peer.currentFlowKey()
	f := &peer.flow
	f.Lock()
	defer f.Unlock()

	if f.key != key ||
		f.established && time.Since(f.completed) > device.keychainExpireTime() {
		f.key = key
		f.established = false
		f.sends = 0
		f.attempt = [numIPackets]ipacketAttempt{}
	}

	if f.established {
		if f.sends < maxFlightSends {
			// a rekey on a live flow: the handshake alone
			f.sends++
			return handshakePlan{backoff: uint(f.sends - 1)}
		}
		// rekeys go unanswered: the flow is lost, start over
		f.established = false
		f.sends = 0
	}

	if f.sends > 0 && f.sends < maxFlightSends && f.attemptCurrent(device) {
		f.sends++
		var out [][]byte
		for i := range f.attempt {
			a := &f.attempt[i]
			if a.chain == nil {
				continue
			}
			bufs, err := a.datagrams()
			if err != nil {
				device.log.Errorf("%v - Failed to build I%d: %v", peer, i+1, err)
				continue
			}
			out = append(out, bufs...)
		}
		return handshakePlan{ipackets: out, backoff: uint(f.sends - 1)}
	}

	// a new connection attempt
	f.sends = 1
	return handshakePlan{ipackets: peer.freshIPackets(&f.attempt), junk: true}
}

// attemptCurrent reports whether the attempt was made from the I-packets
// the device has now; after a configuration change it must not be resent.
func (f *peerFlow) attemptCurrent(device *Device) bool {
	for i := range f.attempt {
		if f.attempt[i].chain != device.ipackets[i].Load() {
			return false
		}
	}
	return true
}

// freshIPackets builds the I-packets of a new attempt and, when attempt is
// not nil, remembers it for retransmission.
func (peer *Peer) freshIPackets(attempt *[numIPackets]ipacketAttempt) [][]byte {
	var out [][]byte
	for i := range peer.device.ipackets {
		chain := peer.device.ipackets[i].Load()
		a := ipacketAttempt{chain: chain}
		if chain != nil && chain.quic != nil {
			q, err := chain.quic.newAttempt()
			if err != nil {
				// the handshake still goes out, without this disguise
				peer.device.log.Errorf("%v - Failed to build I%d: %v", peer, i+1, err)
				a.chain = nil
				chain = nil
			}
			a.quic = q
		}
		if attempt != nil {
			attempt[i] = a
		}
		if chain == nil {
			continue
		}
		bufs, err := a.datagrams()
		if err != nil {
			peer.device.log.Errorf("%v - Failed to build I%d: %v", peer, i+1, err)
			continue
		}
		out = append(out, bufs...)
	}
	return out
}

// flowHandshakeComplete marks the flow as carrying a session.
func (peer *Peer) flowHandshakeComplete() {
	key := peer.currentFlowKey()
	f := &peer.flow
	f.Lock()
	f.key = key
	f.established = true
	f.completed = time.Now()
	f.sends = 0
	f.attempt = [numIPackets]ipacketAttempt{}
	f.Unlock()
}
