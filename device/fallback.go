/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

// Fallback relays datagrams that are not AmneziaWG to another UDP server
// on the same machine, typically a real HTTP/3 site, and sends its answers
// back from the AWG port. An active prober that sends a QUIC Initial to the
// port then talks to an ordinary website instead of meeting silence.
//
// It only matters on the server and needs nothing from clients. Valid AWG
// packets never reach the relay: only datagrams too short for AWG and ones
// whose type matches none of H1-H4 (at the expected S1-S4 size) do.
//
// Every remote address gets its own local socket, so the HTTP/3 server sees
// distinct clients and its answers can be matched back.

const (
	fallbackMaxRelays   = 1024             // remote addresses relayed at once
	fallbackIdleTimeout = 60 * time.Second // a relay closes after this much silence
)

type fallback struct {
	target atomic.Pointer[netip.AddrPort] // nil: off

	mu     sync.Mutex
	relays map[string]*fallbackRelay // by remote address
	closed bool
}

type fallbackRelay struct {
	conn     *net.UDPConn
	endpoint conn.Endpoint
	lastSeen atomic.Int64 // unix nanoseconds
}

// SetFallback enables relaying to target, or disables it for an invalid
// (zero) address. Existing relays are closed either way.
func (device *Device) SetFallback(target netip.AddrPort) {
	f := &device.fallback
	if target.IsValid() {
		t := target
		f.target.Store(&t)
	} else {
		f.target.Store(nil)
	}
	f.closeAll()
	device.updateQUICShape()
}

func (device *Device) fallbackTarget() (netip.AddrPort, bool) {
	t := device.fallback.target.Load()
	if t == nil {
		return netip.AddrPort{}, false
	}
	return *t, true
}

func (f *fallback) closeAll() {
	f.mu.Lock()
	relays := f.relays
	f.relays = nil
	f.mu.Unlock()
	for _, r := range relays {
		r.conn.Close()
	}
}

// close stops relaying for good (device shutdown).
func (f *fallback) close() {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	f.closeAll()
}

// forwardFallback hands a non-AWG datagram to the fallback server. It is
// called from the receive path and must not block on anything but a local
// UDP write.
func (device *Device) forwardFallback(ep conn.Endpoint, packet []byte) {
	target, ok := device.fallbackTarget()
	if !ok || ep == nil || len(packet) == 0 {
		return
	}
	r := device.fallbackRelay(ep, target)
	if r == nil {
		return
	}
	r.lastSeen.Store(time.Now().UnixNano())
	if _, err := r.conn.Write(packet); err != nil {
		device.log.Verbosef("Fallback: write to %v failed: %v", target, err)
	}
}

func (device *Device) fallbackRelay(ep conn.Endpoint, target netip.AddrPort) *fallbackRelay {
	f := &device.fallback
	key := ep.DstToString()

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	if r := f.relays[key]; r != nil {
		return r
	}
	if len(f.relays) >= fallbackMaxRelays {
		return nil // flood: drop rather than open more sockets
	}
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		device.log.Verbosef("Fallback: cannot reach %v: %v", target, err)
		return nil
	}
	r := &fallbackRelay{conn: c, endpoint: ep}
	r.lastSeen.Store(time.Now().UnixNano())
	if f.relays == nil {
		f.relays = make(map[string]*fallbackRelay)
	}
	f.relays[key] = r
	go device.runFallbackRelay(key, r)
	return r
}

// runFallbackRelay sends the fallback server's answers back to the remote
// from the AWG socket, until the relay goes idle or is closed.
func (device *Device) runFallbackRelay(key string, r *fallbackRelay) {
	f := &device.fallback
	defer func() {
		r.conn.Close()
		f.mu.Lock()
		if f.relays[key] == r {
			delete(f.relays, key)
		}
		f.mu.Unlock()
	}()

	buf := make([]byte, MaxMessageSize)
	for {
		deadline := time.Unix(0, r.lastSeen.Load()).Add(fallbackIdleTimeout)
		r.conn.SetReadDeadline(deadline)
		n, err := r.conn.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) &&
				time.Since(time.Unix(0, r.lastSeen.Load())) < fallbackIdleTimeout {
				continue // the remote spoke meanwhile
			}
			return
		}
		r.lastSeen.Store(time.Now().UnixNano())

		device.net.RLock()
		bind := device.net.bind
		var sendErr error
		if bind != nil {
			sendErr = bind.Send([][]byte{buf[:n]}, r.endpoint)
		}
		device.net.RUnlock()
		if sendErr != nil {
			device.log.Verbosef("Fallback: send to %v failed: %v", r.endpoint.DstToString(), sendErr)
		}
	}
}
