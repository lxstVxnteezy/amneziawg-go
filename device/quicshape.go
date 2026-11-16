/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
)

// QUIC shape: when the device disguises its flow as QUIC, the first byte
// of everything it sends after the I-packets (junk, handshakes, cookies,
// transport) looks like a QUIC v1 short header: the top bit clear (short
// header) and the fixed bit set, 0b01xxxxxx.
//
// Without it the first byte is random: half of the packets of a flow that
// began with a genuine QUIC Initial would then read as long headers with a
// random version, which no QUIC endpoint sends. A DPI that follows the
// flow as QUIC drops the disguise at the first such packet.
//
// Only the random S1-S4 prefix and junk change, which the receiver never
// interprets: the change is invisible to any peer, fork or official. The
// prefix is also the header protection nonce; two of its 96 bits become
// fixed, which leaves 94 random bits.
//
// It is on when an I-packet is a QUIC Initial (the <quic> tag or a fixed
// <b 0x...> Initial), when non-AWG datagrams go to an HTTP/3 fallback, or
// when the device listens on UDP 443 (a server whose clients send QUIC
// Initials; whatever sits on 443/udp is expected to be QUIC).

// shapeQUIC turns the first byte of b into a QUIC short header byte.
func shapeQUIC(b []byte) {
	if len(b) > 0 {
		b[0] = b[0]&0x3f | 0x40
	}
}

// quicHandshakeHeaderLen is the long header of a client Handshake packet
// up to the packet number: first byte, version, DCID, an empty SCID (the
// client's, as Chrome's), a 2-byte Length.
func quicHandshakeHeaderLen(dcid []byte) int { return 1 + 4 + 1 + len(dcid) + 1 + 2 }

// shapeQUICHandshake writes the long header of a QUIC v1 Handshake packet
// to dcid (the server's connection ID) into the random prefix of a
// datagram of total bytes; the rest of the prefix stays random, as the
// protected packet number and payload do. The Length covers the datagram
// after it, so the datagram reads as one Handshake packet. It reports
// false, changing nothing, when the prefix is too short for the header
// and a packet number byte.
//
// The first 12 bytes of the prefix are also the header protection nonce:
// here they are mostly the fixed header of the connection, so only the
// handshake initiations that start a connection are shaped this way (a
// handful per connection, each with a fresh ephemeral key), never data.
func shapeQUICHandshake(prefix, dcid []byte, total int) bool {
	hl := quicHandshakeHeaderLen(dcid)
	if len(dcid) > 20 || len(prefix) < hl+1 || total-hl >= 1<<14 {
		return false
	}
	// long header, fixed bit, type Handshake; the low 4 bits (reserved
	// and packet number length) are header-protected in QUIC: random
	prefix[0] = 0xe0 | prefix[0]&0x0f
	binary.BigEndian.PutUint32(prefix[1:5], 1)
	prefix[5] = byte(len(dcid))
	copy(prefix[6:], dcid)
	prefix[6+len(dcid)] = 0 // SCID
	binary.BigEndian.PutUint16(prefix[hl-2:hl], uint16(total-hl)|0x4000)
	return true
}

// handshakeTrailerMax bounds the random trailer of a handshake initiation
// shaped as a Handshake packet: Chrome's Handshake Finished is ~140 bytes.
const handshakeTrailerMax = 16

// handshakeAck is the small Handshake packet a QUIC client sends before
// its Finished (35 bytes for Chrome with a 4-byte server connection ID: an
// ACK frame and the AEAD tag): a long header to dcid and random bytes, as
// a protected packet number and payload look. The server relays it to the
// site, which cannot decrypt it and drops it.
func handshakeAck(dcid []byte) []byte {
	b := make([]byte, quicHandshakeHeaderLen(dcid)+2+4+16)
	rand.Read(b)
	shapeQUICHandshake(b, dcid, len(b))
	return b
}

// isQUICInitial reports whether p starts like a QUIC v1 long header
// Initial packet.
func isQUICInitial(p []byte) bool {
	return len(p) >= 5 && p[0]&0xf0 == 0xc0 && binary.BigEndian.Uint32(p[1:5]) == 1
}

// wantQUICShape is the decision of updateQUICShape for the given state.
func wantQUICShape(ipackets []*obfChain, fallback bool, port uint16) bool {
	for _, c := range ipackets {
		if c == nil {
			continue
		}
		if c.quic != nil {
			return true
		}
		if d, err := c.Datagrams(); err == nil && len(d) > 0 && isQUICInitial(d[0]) {
			return true
		}
	}
	return fallback || port == 443
}

// updateQUICShape decides whether outgoing packets get the QUIC shape. It
// runs after a configuration change.
func (device *Device) updateQUICShape() {
	var chains []*obfChain
	for i := range device.ipackets {
		chains = append(chains, device.ipackets[i].Load())
	}
	_, fallback := device.fallbackTarget()
	device.net.RLock()
	port := device.net.port
	device.net.RUnlock()
	on := wantQUICShape(chains, fallback, port)
	if device.quicShape.Swap(on) != on {
		device.log.Verbosef("QUIC shape of outgoing packets: %v", on)
	}
}
