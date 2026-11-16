package splittun

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Tunnel-only mode: the listed sites go into the tunnel, everything else
// bypasses the VPN altogether.
//
// The operating system routes into the VPN only the DNS servers, FakeRange
// and the listed networks (on Android: VpnService routes instead of
// 0.0.0.0/0). A DNS query for a listed name goes into the tunnel, so the
// answer is not the one a Russian resolver would give, and each address in
// the answer is replaced with one from FakeRange. The app connects to that
// address; its packets reach this wrapper, which puts the real address in
// and sends them into the tunnel, and puts the fake one back into the
// answers. Any other query is answered through the direct resolver with
// real addresses, which are not routed into the VPN: that traffic never
// touches the tunnel, the wrapper or the userspace stack.
//
// Limits, as in the other mode: apps with their own DNS over HTTPS, and
// connections to an IP address without a lookup (only listed networks
// catch those).

// FakeRange holds the stand-in addresses of listed names (RFC 2544's
// benchmarking range: not used on the internet).
var FakeRange = netip.MustParsePrefix("198.18.0.0/15")

const (
	fakeKeep = 30 * time.Minute // a stand-in lives this long after its last answer or packet
)

type fakeEntry struct {
	fake, real netip.Addr
	until      time.Time
}

// fakeMap pairs stand-ins with real addresses one to one: two names on the
// same server share a stand-in, so the replies can be mapped back without
// tracking flows.
type fakeMap struct {
	mu     sync.Mutex
	base   uint32
	size   uint32
	next   uint32
	byFake map[netip.Addr]*fakeEntry
	byReal map[netip.Addr]*fakeEntry
}

func newFakeMap(p netip.Prefix) *fakeMap {
	b := p.Masked().Addr().As4()
	return &fakeMap{
		base:   binary.BigEndian.Uint32(b[:]),
		size:   1 << (32 - p.Bits()),
		next:   1, // not the network address
		byFake: map[netip.Addr]*fakeEntry{},
		byReal: map[netip.Addr]*fakeEntry{},
	}
}

func (m *fakeMap) addr(i uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], m.base+i)
	return netip.AddrFrom4(b)
}

// stand returns the stand-in of real, allocating one if needed; false
// when every stand-in is in use.
func (m *fakeMap) stand(real netip.Addr, keep time.Duration, now time.Time) (netip.Addr, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	until := now.Add(max(keep, fakeKeep))
	if e := m.byReal[real]; e != nil {
		e.until = later(e.until, until)
		return e.fake, true
	}
	for tries := uint32(0); tries < m.size; tries++ {
		i := m.next
		m.next++
		if m.next >= m.size-1 { // not the broadcast address
			m.next = 1
		}
		f := m.addr(i)
		if old := m.byFake[f]; old != nil {
			if now.Before(old.until) {
				continue
			}
			delete(m.byReal, old.real)
		}
		e := &fakeEntry{fake: f, real: real, until: until}
		m.byFake[f], m.byReal[real] = e, e
		return f, true
	}
	return netip.Addr{}, false
}

// realOf maps a stand-in to its address and keeps the pair alive.
func (m *fakeMap) realOf(fake netip.Addr, now time.Time) (netip.Addr, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.byFake[fake]
	if e == nil {
		return netip.Addr{}, false
	}
	e.until = later(e.until, now.Add(fakeKeep))
	return e.real, true
}

func (m *fakeMap) fakeOf(real netip.Addr) (netip.Addr, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.byReal[real]; e != nil {
		return e.fake, true
	}
	return netip.Addr{}, false
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// routeTunnelOnly decides a packet from the OS in tunnel-only mode. The
// OS sends here only DNS, stand-ins and listed networks.
func (d *Device) routeTunnelOnly(pkt []byte) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return true
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return true
	}
	proto := pkt[9]
	dst, _ := netip.AddrFromSlice(pkt[16:20])
	if FakeRange.Contains(dst) {
		real, ok := d.fakes.realOf(dst, time.Now())
		if !ok {
			return false // a stand-in nobody holds any more: the app looks the name up again
		}
		rewriteAddr(pkt, 16, real)
		d.Stats.TunnelPackets.Add(1)
		return true
	}
	if (proto != 6 && proto != 17) || len(pkt) < ihl+8 || binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
		return true
	}
	dport := binary.BigEndian.Uint16(pkt[ihl+2:])
	if (dport == 853 || dport == 443) && d.isResolver(dst) {
		if proto == 6 && len(pkt) >= ihl+14 && pkt[ihl+13]&0x12 == 0x02 {
			d.stack.inject(pkt) // a reset: fall back to plain DNS
		}
		return false
	}
	if proto != 17 || dport != 53 {
		return true // a listed network
	}
	q, ok := parseQuery(pkt[ihl+8:])
	if !ok {
		return true
	}
	if d.domains.match(q.name) {
		if q.qtype == dnsmessage.TypeAAAA {
			// stand-ins are IPv4: no IPv6 addresses, so the app uses them
			if a := emptyAnswer(pkt[ihl+8:]); a != nil {
				d.writeToOS(udpReply(pkt, a))
			}
			return false
		}
		return true // resolved through the tunnel; the answer is rewritten in Write
	}
	// everything else: the real answer from the direct resolver, and the
	// app's traffic to it never comes here
	d.Stats.DirectQueries.Add(1)
	select {
	case d.dnsSlots <- struct{}{}:
		cp := append([]byte(nil), pkt...)
		go func() {
			defer func() { <-d.dnsSlots }()
			ihl := int(cp[0]&0x0f) * 4
			answer, _, _ := d.exchange(cp[ihl+8:])
			if answer == nil {
				answer = servfail(cp[ihl+8:])
			}
			if answer != nil {
				d.writeToOS(udpReply(cp, answer))
			}
		}()
	default:
	}
	return false
}

func (d *Device) isResolver(a netip.Addr) bool {
	for _, r := range d.cfg.Resolvers {
		if r == a {
			return true
		}
	}
	return false
}

// fromTunnel rewrites a packet from the tunnel before the OS sees it:
// replies from real addresses come from their stand-ins, and DNS answers
// for listed names carry stand-ins. It works in place: the sizes do not
// change.
func (d *Device) fromTunnel(pkt []byte) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return
	}
	src, _ := netip.AddrFromSlice(pkt[12:16])
	if fake, ok := d.fakes.fakeOf(src); ok {
		rewriteAddr(pkt, 12, fake)
		return
	}
	if pkt[9] != 17 || len(pkt) < ihl+8 || binary.BigEndian.Uint16(pkt[ihl:]) != 53 ||
		binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 || pkt[6]&0x20 != 0 {
		return
	}
	if d.standInAnswers(pkt[ihl+8:]) {
		udpChecksum(pkt, ihl)
	}
}

// standInAnswers replaces, in place, every A record of an answer to a
// listed name with a stand-in. Records it cannot map are left as they
// are: that connection then bypasses the tunnel, which is better than no
// answer.
func (d *Device) standInAnswers(msg []byte) bool {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || !h.Response || h.OpCode != 0 {
		return false
	}
	q, err := p.Question()
	if err != nil || q.Class != dnsmessage.ClassINET || !d.domains.match(q.Name.String()) {
		return false
	}
	// walk the wire format to find each A record's data
	off := 12
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	for range qd {
		if off = skipName(msg, off); off < 0 || off+4 > len(msg) {
			return false
		}
		off += 4
	}
	changed := false
	now := time.Now()
	for range an {
		if off = skipName(msg, off); off < 0 || off+10 > len(msg) {
			return changed
		}
		typ := binary.BigEndian.Uint16(msg[off:])
		class := binary.BigEndian.Uint16(msg[off+2:])
		ttl := time.Duration(binary.BigEndian.Uint32(msg[off+4:])) * time.Second
		rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+rdlen > len(msg) {
			return changed
		}
		if typ == uint16(dnsmessage.TypeA) && class == uint16(dnsmessage.ClassINET) && rdlen == 4 {
			real := netip.AddrFrom4([4]byte(msg[off : off+4]))
			if fake, ok := d.fakes.stand(real, ttl, now); ok {
				b := fake.As4()
				copy(msg[off:], b[:])
				changed = true
			}
		}
		off += rdlen
	}
	return changed
}

// skipName returns the offset after a (possibly compressed) name.
func skipName(msg []byte, off int) int {
	for off < len(msg) {
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1
		case l&0xc0 == 0xc0:
			if off+2 > len(msg) {
				return -1
			}
			return off + 2
		case l&0xc0 != 0:
			return -1
		default:
			off += 1 + l
		}
	}
	return -1
}

// rewriteAddr replaces the IPv4 address at off (12: source, 16:
// destination) and updates the IP and TCP/UDP checksums (RFC 1624).
func rewriteAddr(pkt []byte, off int, to netip.Addr) {
	ihl := int(pkt[0]&0x0f) * 4
	old := [4]byte(pkt[off : off+4])
	n := to.As4()
	copy(pkt[off:], n[:])
	adjust := func(at int) {
		c := binary.BigEndian.Uint16(pkt[at:])
		binary.BigEndian.PutUint16(pkt[at:], csumReplace(c, old, n))
	}
	adjust(10)
	if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
		return // a later fragment: the transport header is in the first one
	}
	switch pkt[9] {
	case 6:
		if len(pkt) >= ihl+18 {
			adjust(ihl + 16)
		}
	case 17:
		if len(pkt) >= ihl+8 && binary.BigEndian.Uint16(pkt[ihl+6:]) != 0 {
			adjust(ihl + 6)
			if binary.BigEndian.Uint16(pkt[ihl+6:]) == 0 {
				binary.BigEndian.PutUint16(pkt[ihl+6:], 0xffff)
			}
		}
	}
}

func csumReplace(c uint16, old, n [4]byte) uint16 {
	sum := uint32(^c)
	for i := 0; i < 4; i += 2 {
		sum += uint32(^(uint16(old[i])<<8 | uint16(old[i+1])))
		sum += uint32(uint16(n[i])<<8 | uint16(n[i+1]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// udpChecksum recomputes the UDP checksum of an IPv4 packet.
func udpChecksum(pkt []byte, ihl int) {
	u := pkt[ihl:]
	binary.BigEndian.PutUint16(u[6:], 0)
	sum := sum32(pkt[12:20], 0)
	sum += 17 + uint32(len(u))
	c := ^checksum(u, sum)
	if c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:], c)
}
