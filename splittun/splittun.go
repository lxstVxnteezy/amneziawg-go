package splittun

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// Dialer opens the direct connections. It must not route into the tunnel.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// Logger is the device logger's shape.
type Logger func(format string, args ...any)

// Config of a split tunnel.
type Config struct {
	Rules Rules
	Dial  Dialer // nil: net.Dialer
	Log   Logger // nil: silent
}

const (
	minAddrTTL = 10 * time.Minute // how long a resolved address stays direct
	maxAddrs   = 100_000
	tcpIdle    = 30 * time.Minute
	udpIdle    = 3 * time.Minute
	queueLen   = 256
)

// Device wraps the operating system's TUN. The WireGuard device reads
// from it only what goes into the tunnel; the rest is handled here.
type Device struct {
	inner   tun.Device
	cfg     Config
	domains matcher
	stack   *direct

	tunnel chan []byte // packets for the WireGuard device
	pool   sync.Pool
	wmu    sync.Mutex // inner.Write from the device and from the stack

	amu   sync.Mutex
	addrs map[netip.Addr]time.Time // resolved direct addresses, until

	fmu   sync.Mutex
	flows map[flowKey]*flow

	readErr atomic.Value // error that stopped the reader
	closed  chan struct{}
	once    sync.Once

	// counters for the log and tests
	Stats struct {
		DirectFlows, DirectQueries, TunnelPackets atomic.Uint64
	}
}

type flowKey struct {
	proto    byte
	src, dst netip.AddrPort
}

type flow struct {
	direct bool
	seen   time.Time
}

// New wraps inner. With empty rules the result still works and sends
// everything into the tunnel.
func New(inner tun.Device, cfg Config) (*Device, error) {
	if cfg.Dial == nil {
		var d net.Dialer
		cfg.Dial = d.DialContext
	}
	if cfg.Log == nil {
		cfg.Log = func(string, ...any) {}
	}
	if !cfg.Rules.DNS.IsValid() {
		cfg.Rules.DNS = DefaultDNS
	}
	mtu, err := inner.MTU()
	if err != nil {
		return nil, err
	}
	d := &Device{
		inner:   inner,
		cfg:     cfg,
		domains: newMatcher(cfg.Rules.Domains),
		tunnel:  make(chan []byte, queueLen),
		addrs:   map[netip.Addr]time.Time{},
		flows:   map[flowKey]*flow{},
		closed:  make(chan struct{}),
	}
	d.pool.New = func() any { b := make([]byte, 65535); return &b }
	if d.stack, err = newDirect(mtu, cfg.Dial, d.writeToOS, cfg.Log); err != nil {
		return nil, err
	}
	go d.pump()
	go d.sweep()
	return d, nil
}

// pump reads the OS side and sorts packets.
func (d *Device) pump() {
	bs := d.inner.BatchSize()
	bufs := make([][]byte, bs)
	ptrs := make([]*[]byte, bs)
	sizes := make([]int, bs)
	for {
		for i := range bufs {
			if ptrs[i] == nil {
				ptrs[i] = d.pool.Get().(*[]byte)
				bufs[i] = *ptrs[i]
			}
		}
		n, err := d.inner.Read(bufs, sizes, 0)
		for i := 0; i < n; i++ {
			pkt := bufs[i][:sizes[i]]
			if d.route(pkt) {
				// handed to the tunnel queue: the buffer belongs to it now
				select {
				case d.tunnel <- pkt:
				case <-d.closed:
					return
				}
				ptrs[i] = nil
			}
		}
		if err != nil {
			if errors.Is(err, tun.ErrTooManySegments) {
				continue
			}
			d.readErr.Store(err)
			close(d.tunnel)
			return
		}
	}
}

// route decides one packet from the OS. true: into the tunnel; false:
// handled here (it must not be kept: the buffer is reused).
func (d *Device) route(pkt []byte) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return true // IPv6 and the rest: the tunnel decides
	}
	ihl := int(pkt[0]&0x0f) * 4
	proto := pkt[9]
	if ihl < 20 || len(pkt) < ihl+8 || (proto != 6 && proto != 17) {
		return true
	}
	if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
		return true // a later fragment has no ports
	}
	src, _ := netip.AddrFromSlice(pkt[12:16])
	dst, _ := netip.AddrFromSlice(pkt[16:20])
	sport := binary.BigEndian.Uint16(pkt[ihl:])
	dport := binary.BigEndian.Uint16(pkt[ihl+2:])

	if proto == 17 && dport == 53 && len(d.domains) > 0 {
		if q, ok := parseQuery(pkt[ihl+8:]); ok && d.domains.match(q.name) {
			d.Stats.DirectQueries.Add(1)
			cp := append([]byte(nil), pkt...)
			go d.resolveDirect(cp, q)
			return false
		}
	}

	key := flowKey{proto: proto, src: netip.AddrPortFrom(src, sport), dst: netip.AddrPortFrom(dst, dport)}
	now := time.Now()
	d.fmu.Lock()
	f := d.flows[key]
	if f == nil {
		// TCP is decided on its SYN; a packet of a flow seen before
		// this wrapper (or before the address became direct) stays in
		// the tunnel so that connections never switch paths midway.
		syn := proto == 6 && len(pkt) >= ihl+14 && pkt[ihl+13]&0x12 == 0x02
		if proto == 17 || syn {
			f = &flow{direct: d.isDirect(dst)}
			d.flows[key] = f
			if f.direct {
				d.Stats.DirectFlows.Add(1)
			}
		}
	}
	direct := f != nil && f.direct
	if f != nil {
		f.seen = now
	}
	d.fmu.Unlock()
	if direct {
		d.stack.inject(pkt)
		return false
	}
	d.Stats.TunnelPackets.Add(1)
	return true
}

func (d *Device) isDirect(a netip.Addr) bool {
	for _, p := range d.cfg.Rules.Networks {
		if p.Contains(a) {
			return true
		}
	}
	d.amu.Lock()
	until, ok := d.addrs[a]
	d.amu.Unlock()
	return ok && time.Now().Before(until)
}

func (d *Device) learn(addrs []netip.Addr, ttl time.Duration) {
	until := time.Now().Add(max(ttl, minAddrTTL))
	d.amu.Lock()
	defer d.amu.Unlock()
	for _, a := range addrs {
		if len(d.addrs) >= maxAddrs {
			return
		}
		if old, ok := d.addrs[a]; !ok || old.Before(until) {
			d.addrs[a] = until
		}
	}
}

// sweep forgets idle flows and expired addresses.
func (d *Device) sweep() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-d.closed:
			return
		case now := <-t.C:
			d.fmu.Lock()
			for k, f := range d.flows {
				idle := udpIdle
				if k.proto == 6 {
					idle = tcpIdle
				}
				if now.Sub(f.seen) > idle {
					delete(d.flows, k)
				}
			}
			d.fmu.Unlock()
			d.amu.Lock()
			for a, until := range d.addrs {
				if now.After(until) {
					delete(d.addrs, a)
				}
			}
			d.amu.Unlock()
		}
	}
}

func (d *Device) writeToOS(pkt []byte) {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	if _, err := d.inner.Write([][]byte{pkt}, 0); err != nil {
		d.cfg.Log("splittun: write to the OS: %v", err)
	}
}

// --- tun.Device ---

func (d *Device) File() *os.File { return d.inner.File() }

// Read gives the WireGuard device one packet bound for the tunnel.
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt, ok := <-d.tunnel
	if !ok {
		if err, _ := d.readErr.Load().(error); err != nil {
			return 0, err
		}
		return 0, os.ErrClosed
	}
	sizes[0] = copy(bufs[0][offset:], pkt)
	full := pkt[:cap(pkt)]
	d.pool.Put(&full)
	return 1, nil
}

func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	return d.inner.Write(bufs, offset)
}

func (d *Device) MTU() (int, error)        { return d.inner.MTU() }
func (d *Device) Name() (string, error)    { return d.inner.Name() }
func (d *Device) Events() <-chan tun.Event { return d.inner.Events() }
func (d *Device) BatchSize() int           { return 1 }

func (d *Device) Close() error {
	d.once.Do(func() {
		close(d.closed)
		d.stack.close()
	})
	return d.inner.Close()
}
