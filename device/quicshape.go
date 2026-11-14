/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import "encoding/binary"

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
