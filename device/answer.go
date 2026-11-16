/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

// The server's answer to a QUIC Initial, client side.
//
// A QUIC client sends its Initial and waits: nothing else goes out until
// the server answers with its own Initial and Handshake packets. AmneziaWG
// sends the handshake initiation right behind the I-packets, a packet a
// QUIC client cannot send yet (the bench saw it in every flow).
//
// A server with a fallback (install.sh --domain) relays the client's
// Initial to a real HTTP/3 site and sends the site's answer back from the
// AWG port. So with the QUIC shape on, a new connection attempt sends its
// I-packets first and holds the handshake initiation until a QUIC long
// header packet comes back from the peer's address, at most answerWait.
// A server that never answers (no fallback) is remembered, and later
// attempts do not wait for it. Once the server has answered, retries of
// the attempt send the handshake alone, without the Initial again.
//
// Only the client changes; the server is any AWG server.

// maxDataCID is the longest server connection ID that transport packets
// carry. Their prefix is also the header protection nonce (12 bytes), and
// a constant CID in it leaves 6 bits of the first byte plus the bytes
// after the CID random: 4 bytes (quic-go, Caddy) leave 62 bits, an 8-byte
// CID would leave 30, too few for millions of packets.
const maxDataCID = 4

// answerWait is how long a new attempt holds its handshake initiation
// for the server's answer. It is paid once on a server without fallback.
const answerWait = time.Second

// newAttempt starts a new connection attempt on the flow (f locked):
// with waitForAnswer it returns the channel closed by the server's
// answer. The attempt number tells a late send that it is stale.
func (f *peerFlow) newAttempt(device *Device, waitForAnswer bool) (<-chan struct{}, uint64) {
	f.dropWait(device)
	f.gen++
	f.answered = false
	f.serverCID = nil
	f.initials = 0
	if !waitForAnswer || !device.quicShape.Load() || f.noAnswer {
		return nil, f.gen
	}
	f.answerCh = make(chan struct{})
	f.listening = true
	device.flowAwaiting.Add(1)
	return f.answerCh, f.gen
}

// dropWait stops waiting for an answer and noting its packets (f locked).
func (f *peerFlow) dropWait(device *Device) {
	f.answerCh = nil
	if f.listening {
		f.listening = false
		device.flowAwaiting.Add(-1)
	}
}

// flowAnswered records the server's answer to the current attempt.
func (peer *Peer) flowAnswered(scid []byte, initial bool) {
	f := &peer.flow
	f.Lock()
	defer f.Unlock()
	f.noAnswer = false
	if !f.listening {
		return
	}
	if initial {
		f.initials++
	}
	if f.answered {
		return
	}
	f.answered = true
	f.serverCID = append([]byte(nil), scid...)
	// the rest of the flight is still counted until the handshake goes
	close(f.answerCh)
	f.answerCh = nil
}

// answerSettle lets the rest of the server's first flight (its second
// Initial, the Handshake packets) arrive before the client answers it, as
// a client acknowledges the flight and not its first datagram.
const answerSettle = 3 * time.Millisecond

// afterAnswer is what a held handshake initiation needs once the wait is
// over: whether to go out at all (not when a newer attempt began), and,
// when the server answered, its connection ID and the client's Initial
// that acknowledges the server's Initials. A wait that timed out marks
// the server as one that does not answer.
func (peer *Peer) afterAnswer(gen uint64, answered bool) (ok bool, serverCID, ack []byte) {
	f := &peer.flow
	f.Lock()
	defer f.Unlock()
	if f.gen != gen {
		return false, nil, nil
	}
	f.dropWait(peer.device)
	if !answered && !f.answered {
		f.noAnswer = true
		return true, nil, nil
	}
	if f.serverCID == nil {
		return true, nil, nil
	}
	for i := range f.attempt {
		if q := f.attempt[i].quic; q != nil {
			a, err := q.Ack(f.serverCID, uint64(max(f.initials, 1)-1))
			if err != nil {
				peer.device.log.Errorf("%v - Failed to build the Initial ACK: %v", peer, err)
				break
			}
			ack = a
			break
		}
	}
	return true, f.serverCID, ack
}

// sendWhenAnswered sends a held handshake initiation once the server has
// answered the Initial (as a QUIC client goes on: an Initial with the ACK,
// then the handshake as a Handshake packet), or after answerWait.
func (peer *Peer) sendWhenAnswered(plan handshakePlan, msg *MessageInitiation) {
	t := time.NewTimer(answerWait)
	defer t.Stop()
	answered := true
	select {
	case <-plan.await:
		time.Sleep(answerSettle)
	case <-t.C:
		answered = false
	}
	ok, serverCID, ack := peer.afterAnswer(plan.gen, answered)
	if !ok || !peer.isRunning.Load() {
		return
	}
	buf, err := peer.initiationDatagram(msg, serverCID)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to build handshake initiation: %v", peer, err)
		return
	}
	bufs := [][]byte{buf}
	if serverCID != nil {
		// as Chrome: the Initial ACK, a Handshake ACK, then the Finished
		// (here the handshake initiation)
		bufs = [][]byte{handshakeAck(serverCID), buf}
		if ack != nil {
			bufs = append([][]byte{ack}, bufs...)
		}
	}
	if err := peer.SendBuffers(bufs); err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake initiation: %v", peer, err)
	}
}

// quicAnswer reports whether b starts like a server's answer to an
// Initial: a QUIC v1 long header packet of type Initial or Handshake. It
// returns the packet's SCID, the connection ID the server chose.
func quicAnswer(b []byte) (scid []byte, ok bool) {
	if len(b) < 7 || b[0]&0xc0 != 0xc0 || binary.BigEndian.Uint32(b[1:5]) != 1 {
		return nil, false
	}
	if typ := b[0] >> 4 & 3; typ != 0 && typ != 2 { // Initial, Handshake
		return nil, false
	}
	dcidLen := int(b[5])
	if dcidLen > 20 || 6+dcidLen >= len(b) {
		return nil, false
	}
	scidOff := 6 + dcidLen + 1
	scidLen := int(b[6+dcidLen])
	if scidLen > 20 || scidOff+scidLen > len(b) {
		return nil, false
	}
	return b[scidOff : scidOff+scidLen], true
}

// noteQUICAnswer passes a non-AWG datagram that looks like a server's
// QUIC answer to the waiting peer at its source address. When no peer has
// that address but exactly one is waiting (a client with one server whose
// answer comes from an address the endpoint does not spell the same way),
// that one takes it: at worst a forged answer makes it send its handshake
// sooner. head is the start of the datagram as it came off the wire.
func (device *Device) noteQUICAnswer(ep conn.Endpoint, head []byte) {
	scid, ok := quicAnswer(head)
	if !ok || ep == nil {
		return
	}
	src := ep.DstToString()
	var matched, waiting []*Peer
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.flow.Lock()
		w := peer.flow.listening
		peer.flow.Unlock()
		if !w {
			continue
		}
		waiting = append(waiting, peer)
		peer.endpoint.Lock()
		if peer.endpoint.val != nil && peer.endpoint.val.DstToString() == src {
			matched = append(matched, peer)
		}
		peer.endpoint.Unlock()
	}
	device.peers.RUnlock()
	if len(matched) == 0 && len(waiting) == 1 {
		matched = waiting
	}
	for _, peer := range matched {
		peer.flowAnswered(scid, head[0]&0x30 == 0)
	}
}
