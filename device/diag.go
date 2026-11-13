/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"container/list"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

// Diagnostics: counters that tell at which stage a client's connection
// fails, seen from the server.
//
//   - per peer: handshake initiations received, responses sent, last
//     authenticated transport packet received;
//   - per source IP: datagrams that are not AWG for this server (junk,
//     I-packets, foreign traffic, or AWG with other parameters), handshakes
//     that do not verify (wrong keys, e.g. an outdated config) and data for
//     a session the server does not know (after a restart or a reissue).
//
// They are reported in the UAPI "get" output under diag_* keys, which
// amneziawg-tools ignores, so `awg show` keeps working.

const diagMaxSources = 1024

type peerDiag struct {
	initsReceived  atomic.Uint64
	lastInit       atomic.Int64 // unix nanoseconds
	responsesSent  atomic.Uint64
	lastTransport  atomic.Int64 // last authenticated transport packet (data or keepalive)
	transportStart atomic.Int64 // first transport packet after the latest handshake
}

type sourceStat struct {
	recent  *list.Element
	unknown uint64 // datagrams that are not AWG with this server's parameters
	invalid uint64 // handshakes that do not verify
	stale   uint64 // transport packets for an unknown or expired session
	bytes   uint64
	first   time.Time
	last    time.Time
}

type diagSources struct {
	mu     sync.Mutex
	m      map[netip.Addr]*sourceStat
	recent list.List // least recently seen at the back
}

type diagKind int

const (
	diagUnknown diagKind = iota
	diagInvalidHandshake
	diagStaleSession
)

func (device *Device) diagSource(ep conn.Endpoint, kind diagKind, size int) {
	if ep == nil {
		return
	}
	addr := ep.DstIP()
	if !addr.IsValid() {
		return
	}
	addr = addr.Unmap()
	now := time.Now()
	d := &device.diag
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.m == nil {
		d.m = make(map[netip.Addr]*sourceStat)
	}
	s := d.m[addr]
	if s == nil {
		if len(d.m) >= diagMaxSources {
			oldest := d.recent.Back()
			delete(d.m, oldest.Value.(netip.Addr))
			d.recent.Remove(oldest)
		}
		s = &sourceStat{first: now, recent: d.recent.PushFront(addr)}
		d.m[addr] = s
	} else {
		d.recent.MoveToFront(s.recent)
	}
	switch kind {
	case diagUnknown:
		s.unknown++
	case diagInvalidHandshake:
		s.invalid++
	case diagStaleSession:
		s.stale++
	}
	s.bytes += uint64(size)
	s.last = now
}

func (peer *Peer) diagInit() {
	peer.diag.initsReceived.Add(1)
	peer.diag.lastInit.Store(time.Now().UnixNano())
	// a new session starts: the next transport packet marks its start
	peer.diag.transportStart.Store(0)
}

func (peer *Peer) diagTransport() {
	now := time.Now().UnixNano()
	peer.diag.lastTransport.Store(now)
	peer.diag.transportStart.CompareAndSwap(0, now)
}

func unixSec(nano int64) int64 {
	if nano == 0 {
		return 0
	}
	return nano / int64(time.Second)
}

// diagSourceLines renders the source table for IpcGet, most recent first.
func (device *Device) diagSourceLines() []string {
	d := &device.diag
	d.mu.Lock()
	type row struct {
		addr netip.Addr
		s    sourceStat
	}
	rows := make([]row, 0, len(d.m))
	for a, s := range d.m {
		rows = append(rows, row{a, *s})
	}
	d.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].s.last.After(rows[j].s.last) })
	lines := make([]string, len(rows))
	for i, r := range rows {
		// ip,unknown,invalid,bytes,first_sec,last_sec,stale
		lines[i] = fmt.Sprintf("diag_source=%s,%d,%d,%d,%d,%d,%d", r.addr, r.s.unknown, r.s.invalid, r.s.bytes,
			r.s.first.Unix(), r.s.last.Unix(), r.s.stale)
	}
	return lines
}
