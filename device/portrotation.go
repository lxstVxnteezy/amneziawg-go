/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"time"
)

// minPortRotationSec keeps rotation from turning into a handshake flood:
// every rotation starts a new handshake.
const minPortRotationSec = 10

// RoutinePortRotation periodically rebinds the UDP socket to a new random
// local port and starts a handshake from it. To a middlebox every period
// then looks like a new, short flow that starts with the I-packets, instead
// of one long-lived high-volume flow. The server needs no support for it:
// it follows the client to the new port like any WireGuard roaming.
//
// Rotation is off unless port_rotation is set, and never runs when
// listen_port was set explicitly (a server must keep its port).
func (device *Device) RoutinePortRotation() {
	for {
		var wait <-chan time.Time
		if r := device.portRotation.Load(); !r.IsZero() {
			wait = time.After(time.Duration(r.PickOne()) * time.Second)
		}
		select {
		case <-device.closed:
			return
		case <-device.portRotationKick:
			// configuration changed, start a new period
		case <-wait:
			device.rotatePort()
		}
	}
}

func (device *Device) kickPortRotation() {
	select {
	case device.portRotationKick <- struct{}{}:
	default:
	}
}

func (device *Device) rotatePort() {
	// serialize with IpcSet/IpcGet and Close
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	if device.isClosed() || !device.isUp() {
		return
	}

	device.net.Lock()
	if device.net.portExplicit {
		device.net.Unlock()
		return
	}
	old := device.net.port
	device.net.port = 0 // let the OS pick a fresh port
	device.net.Unlock()

	if err := device.BindUpdate(); err != nil {
		device.log.Errorf("Port rotation failed: %v", err)
		return
	}
	device.net.RLock()
	device.log.Verbosef("Rotated local port %d -> %d", old, device.net.port)
	device.net.RUnlock()

	// Start the new flow with a handshake: it carries the I-packets and
	// junk, and tells the peer our new address right away.
	var peers []*Peer
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.endpoint.Lock()
		hasEndpoint := peer.endpoint.val != nil
		peer.endpoint.Unlock()
		if hasEndpoint && peer.isRunning.Load() {
			peers = append(peers, peer)
		}
	}
	device.peers.RUnlock()
	for _, peer := range peers {
		// The peer keeps sending to the old, now closed port until it hears
		// from the new one, so the handshake must go out now even if one was
		// sent (or answered) within RekeyTimeout. Rotation is at least
		// minPortRotationSec apart, so this cannot turn into a flood.
		peer.handshake.mutex.Lock()
		peer.handshake.lastSentHandshake = time.Time{}
		peer.handshake.mutex.Unlock()
		peer.SendHandshakeInitiation(false)
	}
}
