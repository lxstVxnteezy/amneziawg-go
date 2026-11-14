/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/quicinitial"
)

// The I-packets (a QUIC Initial, say) and junk dress up the start of a UDP
// flow. A real QUIC client sends its Initial once, when the connection
// starts, and never again on the same 4-tuple. Sending a fresh Initial and
// junk with every handshake (every two minutes, and on every retry) in the
// middle of a running flow is a feature no browser shows.
//
// So they go out only with a handshake that starts a flow, that is when
//   - the local socket is new (bind update, port rotation) or the peer's
//     address changed: a middlebox sees a new 4-tuple;
//   - the peer has not answered since the last disguised handshake: the
//     flow never got going, keep trying to start it;
//   - nothing went either way for flowIdleTimeout: NATs and middleboxes may
//     have forgotten the flow, and a QUIC connection would have timed out.
//
// Otherwise the handshake is a rekey inside a live flow and goes out bare,
// like any other packet of it. Peers need nothing for this: receivers skip
// I-packets and junk, they never require them.
//
// With a QUIC disguise an unanswered flow is not restarted with a new
// Initial every RekeyTimeout either. A browser whose Initial got no answer
// retransmits it when the probe timeout fires: the same connection ID and
// ClientHello in packets with the next packet numbers, no junk, at 1, 2,
// 4, 8 s. Only after that does it give up on the attempt and open a new
// connection. Handshake retries follow the same schedule (see
// retransmitDelay).

// flowIdleTimeout is how long a flow may stay silent and still be treated as
// live. It is the QUIC idle timeout of Chrome and below the UDP mapping
// timeout of common NATs, so a flow kept up by a 25 s keepalive stays live.
const flowIdleTimeout = 30 * time.Second

const (
	// quicPTO is the first probe timeout of a client that has no RTT
	// sample yet (RFC 9002: 3 x 333 ms initial RTT); it doubles with each
	// retransmission.
	quicPTO = time.Second
	// quicMaxRetransmits retransmissions of one attempt, then a new one:
	// sends at 0, 1, 3, 7 s and a new connection at 15 s.
	quicMaxRetransmits = 3
)

type flowSend int

const (
	flowLive       flowSend = iota // rekey inside a live flow: bare
	flowNew                        // a new flow: fresh I-packets and junk
	flowRetransmit                 // unanswered QUIC attempt: same Initial again
)

type peerFlow struct {
	mu          sync.Mutex
	key         flowKey
	started     int64 // unix nanos of the last disguised handshake; 0: none yet
	retransmits int   // of the current attempt
	attempts    [5]flowAttempt

	// pto is the retransmission delay after the last handshake when it
	// was part of a QUIC attempt, 0 otherwise
	pto atomic.Int64

	lastSent atomic.Int64 // unix nanos of the last datagram sent to the peer

	// junkPending: the junk of a QUIC attempt waits for the server's
	// answer (see sendPendingJunk)
	junkPending atomic.Bool
}

// flowAttempt is the QUIC connection attempt an I-packet started, kept to
// retransmit it.
type flowAttempt struct {
	chain *obfChain
	quic  *quicinitial.Attempt
}

type flowKey struct {
	bindGen uint64
	dst     string
}

// startFlow decides what a handshake initiation sent now carries and builds
// the I-packet datagrams for it (none for flowLive).
func (peer *Peer) startFlow(now time.Time) (flowSend, [][]byte) {
	key := flowKey{bindGen: peer.device.net.gen.Load()}
	peer.endpoint.Lock()
	if peer.endpoint.val != nil {
		key.dst = peer.endpoint.val.DstToString()
	}
	peer.endpoint.Unlock()

	f := &peer.flow
	f.mu.Lock()
	defer f.mu.Unlock()

	mode := flowNew
	if f.started != 0 && f.key == key {
		heard := max(peer.diag.lastTransport.Load(), peer.lastHandshakeNano.Load())
		active := max(heard, f.lastSent.Load())
		switch {
		case heard > f.started:
			if now.UnixNano()-active < int64(flowIdleTimeout) {
				mode = flowLive
			}
		case peer.device.quicAttempts() && f.retransmits < quicMaxRetransmits &&
			now.UnixNano()-active < int64(quicPTO<<(quicMaxRetransmits+1)):
			mode = flowRetransmit
		}
	}

	var bufs [][]byte
	switch mode {
	case flowLive:
		f.pto.Store(0)
		return mode, nil
	case flowNew:
		f.key = key
		f.started = now.UnixNano()
		f.retransmits = 0
	case flowRetransmit:
		f.retransmits++
	}
	if peer.device.quicAttempts() {
		f.pto.Store(int64(quicPTO << f.retransmits))
	} else {
		f.pto.Store(0)
	}

	for i := range peer.device.ipackets {
		chain := peer.device.ipackets[i].Load()
		a := &f.attempts[i]
		if chain == nil {
			*a = flowAttempt{}
			continue
		}
		var (
			d   [][]byte
			err error
		)
		switch {
		case chain.quic == nil:
			// fixed bytes repeat anyway; random ones are new each time
			*a = flowAttempt{}
			d, err = chain.Datagrams()
		case mode == flowRetransmit && a.chain == chain && a.quic != nil:
			d, err = a.quic.Flight()
		default: // a new attempt, or I-packets changed since the last one
			*a = flowAttempt{chain: chain}
			if a.quic, err = chain.quic.attempt(); err == nil {
				d, err = a.quic.Flight()
			}
		}
		if err != nil {
			// the handshake still goes out, without this disguise
			peer.device.log.Errorf("%v - Failed to build I%d: %v", peer, i+1, err)
			continue
		}
		bufs = append(bufs, d...)
	}
	return mode, bufs
}

// quicAttempts: the handshakes of this device open QUIC connection
// attempts, that is the disguise is QUIC and there are I-packets to send.
func (device *Device) quicAttempts() bool {
	if !device.quicShape.Load() {
		return false
	}
	for i := range device.ipackets {
		if device.ipackets[i].Load() != nil {
			return true
		}
	}
	return false
}

// sendPendingJunk sends the junk of a QUIC attempt once the handshake
// response arrived. A browser is silent between its Initial and the
// server's answer, so junk right after the Initial is a tell; after the
// answer the client sends its Handshake and first 1-RTT packets, and the
// QUIC-shaped junk passes for those.
func (peer *Peer) sendPendingJunk() {
	if !peer.flow.junkPending.Swap(false) {
		return
	}
	if junk := peer.device.JunkPackets(); len(junk) > 0 {
		if err := peer.SendBuffers(junk); err != nil {
			peer.device.log.Verbosef("%v - Failed to send junk: %v", peer, err)
		}
	}
}

// retransmitDelay is how long to wait for the handshake response before
// trying again: WireGuard's RekeyTimeout with jitter, or the doubling probe
// timeout of a QUIC attempt.
func (peer *Peer) retransmitDelay() time.Duration {
	if pto := time.Duration(peer.flow.pto.Load()); pto != 0 {
		// a little spread, as RTT samples would give
		return pto + time.Millisecond*time.Duration(fastrandn(uint32(pto/time.Millisecond/16)+1))
	}
	return peer.retransmitHandshakeTimeout() + time.Millisecond*time.Duration(fastrandn(RekeyTimeoutJitterMaxMs))
}
