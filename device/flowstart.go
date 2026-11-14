/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"sync"
	"sync/atomic"
	"time"
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

// flowIdleTimeout is how long a flow may stay silent and still be treated as
// live. It is the QUIC idle timeout of Chrome and below the UDP mapping
// timeout of common NATs, so a flow kept up by a 25 s keepalive stays live.
const flowIdleTimeout = 30 * time.Second

type peerFlow struct {
	mu      sync.Mutex
	key     flowKey
	started int64 // unix nanos of the last disguised handshake; 0: none yet

	lastSent atomic.Int64 // unix nanos of the last datagram sent to the peer
}

type flowKey struct {
	bindGen uint64
	dst     string
}

// startsFlow reports whether a handshake initiation sent now must carry the
// I-packets and junk, and if so records that a new flow starts with it.
func (peer *Peer) startsFlow(now time.Time) bool {
	key := flowKey{bindGen: peer.device.net.gen.Load()}
	peer.endpoint.Lock()
	if peer.endpoint.val != nil {
		key.dst = peer.endpoint.val.DstToString()
	}
	peer.endpoint.Unlock()

	f := &peer.flow
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.started != 0 && f.key == key {
		heard := max(peer.diag.lastTransport.Load(), peer.lastHandshakeNano.Load())
		active := max(heard, f.lastSent.Load())
		if heard > f.started && now.UnixNano()-active < int64(flowIdleTimeout) {
			return false
		}
	}
	f.key = key
	f.started = now.UnixNano()
	return true
}
