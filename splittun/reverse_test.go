package splittun

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// The internet behind the tunnel for tunnel-only tests: a stack that owns
// every address, with the tunnel's resolver at 10.0.0.53 (every name is
// 203.0.113.50) and a TCP echo server on port 443 of every address.
var blockedSite = netip.MustParseAddr("203.0.113.50")

type reverseRig struct {
	dev      *Device
	phone    *phone
	world    *world
	tunneled chan netip.Addr // destinations of packets sent into the tunnel
}

func newReverseRig(t *testing.T) *reverseRig {
	t.Helper()
	w := newWorld(t)
	p := newPhone(t)
	rules, err := ParseRules("youtube.com, preset:blocked", "", "")
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(p.ct.TUN(), Config{Rules: rules, Dial: w.dial, Log: t.Logf, TunnelOnly: true,
		Resolvers: []netip.Addr{netip.MustParseAddr("10.0.0.53")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	r := &reverseRig{dev: d, phone: p, world: w, tunneled: make(chan netip.Addr, 1024)}

	inet := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	ep := channel.New(512, 1280, "")
	if err := inet.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	inet.SetPromiscuousMode(1, true)
	inet.SetSpoofing(1, true)
	inet.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	ln, err := gonet.ListenTCP(inet, tcpip.FullAddress{NIC: 1, Port: 443}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	resolver := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice([]byte{10, 0, 0, 53}), Port: 53}
	inet.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: resolver.Addr.WithPrefix()}, stack.AddressProperties{})
	uc, err := gonet.DialUDP(inet, &resolver, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { uc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := uc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, _ := p.Question()
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true})
			b.EnableCompression()
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			cname := dnsmessage.MustNewName("edge." + q.Name.String())
			b.CNAMEResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.CNAMEResource{CNAME: cname})
			b.AResource(dnsmessage.ResourceHeader{Name: cname, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: blockedSite.As4()})
			out, _ := b.Finish()
			uc.WriteTo(out, a)
		}
	}()

	go func() { // wrapper -> tunnel -> internet
		bufs, sizes := [][]byte{make([]byte, 65535)}, []int{0}
		for {
			n, err := d.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			if n != 1 {
				continue
			}
			pkt := append([]byte(nil), bufs[0][:sizes[0]]...)
			if !header.IPv4(pkt).IsChecksumValid() {
				t.Errorf("a packet into the tunnel has a bad IP checksum")
			}
			dst, _ := netip.AddrFromSlice(pkt[16:20])
			select {
			case r.tunneled <- dst:
			default:
			}
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
			ep.InjectInbound(header.IPv4ProtocolNumber, pb)
			pb.DecRef()
		}
	}()
	go func() { // internet -> tunnel -> wrapper
		for {
			pkt := ep.ReadContext(ctx)
			if pkt.IsNil() {
				return
			}
			v := pkt.ToView()
			pkt.DecRef()
			d.Write([][]byte{v.AsSlice()}, 0)
		}
	}()
	return r
}

func (r *reverseRig) lookup(t *testing.T, name string, typ dnsmessage.Type) []netip.Addr {
	t.Helper()
	u := r.phone.dialUDP(t, "10.0.0.53:53")
	defer u.Close()
	u.Write(dnsQuery(t, name, typ))
	u.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	n, err := u.Read(buf)
	if err != nil {
		t.Fatalf("no answer for %s: %v", name, err)
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(buf[:n]); err != nil || msg.ID != 0x4242 {
		t.Fatalf("answer for %s: %v", name, err)
	}
	var out []netip.Addr
	for _, rr := range msg.Answers {
		if a, ok := rr.Body.(*dnsmessage.AResource); ok {
			out = append(out, netip.AddrFrom4(a.A))
		}
	}
	return out
}

// A listed name is resolved through the tunnel and answered with a
// stand-in; a connection to the stand-in reaches the real address through
// the tunnel, and the replies come back from the stand-in.
func TestTunnelOnlyListedSite(t *testing.T) {
	r := newReverseRig(t)
	addrs := r.lookup(t, "www.youtube.com.", dnsmessage.TypeA)
	if len(addrs) != 1 || !FakeRange.Contains(addrs[0]) {
		t.Fatalf("listed name answered with %v, want a stand-in from %v", addrs, FakeRange)
	}
	select {
	case q := <-r.world.queries:
		t.Fatalf("a listed name went to the direct resolver: %s", q)
	default:
	}
	// the same server under another listed name shares the stand-in
	if again := r.lookup(t, "instagram.com.", dnsmessage.TypeA); len(again) != 1 || again[0] != addrs[0] {
		t.Fatalf("second name: %v, want %v", again, addrs[0])
	}
	if aaaa := r.lookup(t, "youtube.com.", dnsmessage.TypeAAAA); len(aaaa) != 0 {
		t.Fatalf("AAAA: %v", aaaa)
	}

	c, err := r.phone.dialTCP(t, netip.AddrPortFrom(addrs[0], 443).String(), 5*time.Second)
	if err != nil {
		t.Fatalf("connect to the stand-in: %v", err)
	}
	echoTCP(t, c) // checksums wrong anywhere and the stacks drop the segments
	sawReal := false
	for len(r.tunneled) > 0 {
		dst := <-r.tunneled
		if FakeRange.Contains(dst) {
			t.Fatalf("a stand-in leaked into the tunnel: %v", dst)
		}
		sawReal = sawReal || dst == blockedSite
	}
	if !sawReal {
		t.Fatal("nothing went to the real address through the tunnel")
	}

	// a stand-in nobody holds is dropped, not sent anywhere
	if _, err := r.phone.dialTCP(t, "198.19.200.200:443", 500*time.Millisecond); err == nil {
		t.Fatal("an unknown stand-in connected")
	}
}

// Any other name is answered by the direct resolver with real addresses:
// that traffic is not routed into the VPN at all.
func TestTunnelOnlyOtherSitesBypass(t *testing.T) {
	r := newReverseRig(t)
	addrs := r.lookup(t, "gosuslugi.ru.", dnsmessage.TypeA)
	if len(addrs) == 0 || addrs[0] != netip.MustParseAddr("198.51.100.8") {
		t.Fatalf("unlisted name: %v", addrs)
	}
	if q := <-r.world.queries; q != "gosuslugi.ru." {
		t.Fatalf("direct resolver got %s", q)
	}
	for len(r.tunneled) > 0 {
		if dst := <-r.tunneled; dst == netip.MustParseAddr("10.0.0.53") {
			t.Fatal("an unlisted query went into the tunnel")
		}
	}
}

func TestFakeMap(t *testing.T) {
	m := newFakeMap(netip.MustParsePrefix("198.18.0.0/29")) // 6 usable
	now := time.Now()
	var got []netip.Addr
	for i := 0; i < 6; i++ {
		f, ok := m.stand(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 0, now)
		if !ok || f == netip.MustParseAddr("198.18.0.0") || f == netip.MustParseAddr("198.18.0.7") {
			t.Fatalf("stand-in %d: %v %v", i, f, ok)
		}
		got = append(got, f)
	}
	if _, ok := m.stand(netip.MustParseAddr("203.0.113.99"), 0, now); ok {
		t.Fatal("allocated past a full range")
	}
	// expired pairs are reused, live ones never
	later := now.Add(fakeKeep + time.Minute)
	m.realOf(got[2], later.Add(-2*time.Minute)) // still in use
	f, ok := m.stand(netip.MustParseAddr("203.0.113.99"), 0, later)
	if !ok || f == got[2] {
		t.Fatalf("reuse: %v %v", f, ok)
	}
	if r, _ := m.realOf(f, later); r != netip.MustParseAddr("203.0.113.99") {
		t.Fatal("reused stand-in maps to the old address")
	}
}

func TestCsumReplace(t *testing.T) {
	pkt := make([]byte, 20)
	pkt[0], pkt[8], pkt[9] = 0x45, 64, 6
	copy(pkt[12:], []byte{10, 66, 66, 2})
	copy(pkt[16:], []byte{198, 18, 0, 5})
	h := header.IPv4(pkt)
	h.SetTotalLength(20)
	h.SetChecksum(^h.CalculateChecksum())
	rewriteAddr(pkt, 16, netip.MustParseAddr("203.0.113.50"))
	if !h.IsChecksumValid() {
		t.Fatal("IP checksum broken by the rewrite")
	}
}
