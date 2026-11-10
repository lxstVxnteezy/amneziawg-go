package splittun

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
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

func TestRules(t *testing.T) {
	r, err := ParseRules("preset:ru, Gosuslugi.RU., рф, *.example.org", "198.51.100.0/24 203.0.113.7", "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	m := newMatcher(r.Domains)
	for name, want := range map[string]bool{
		"gosuslugi.ru.": true, "www.sberbank.ru": true, "m.vk.com.": true, "VK.COM": true,
		"xn--80aswg.xn--p1ai": true /* сайт.рф */, "a.example.org": true, "example.org": true,
		"google.com": false, "notvk.com": false, "ru.example.com": false,
	} {
		if m.match(name) != want {
			t.Errorf("match(%q) = %v", name, !want)
		}
	}
	if len(r.Networks) != 2 || r.Networks[1] != netip.MustParsePrefix("203.0.113.7/32") || r.DNS != netip.MustParseAddrPort("8.8.8.8:53") {
		t.Fatalf("networks %v dns %v", r.Networks, r.DNS)
	}
	if _, err := ParseRules("ok.ru", "2001:db8::/32 nonsense", "dns.example"); err == nil ||
		!strings.Contains(err.Error(), "only IPv4") || !strings.Contains(err.Error(), "nonsense") || !strings.Contains(err.Error(), "direct DNS") {
		t.Fatalf("bad input: %v", err)
	}
	if r, _ := ParseRules("", "", ""); !r.Empty() || r.DNS != DefaultDNS {
		t.Fatal("empty rules")
	}
}

// phone is a userspace stack standing for the apps on the device: what it
// sends reaches the wrapper as packets from the OS.
type phone struct {
	s  *stack.Stack
	ep *channel.Endpoint
	ct *tuntest.ChannelTUN
}

var phoneAddr = netip.MustParseAddr("10.66.66.2")

func newPhone(t *testing.T) *phone {
	t.Helper()
	p := &phone{
		s: stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}}),
		ep: channel.New(512, 1280, ""),
		ct: tuntest.NewChannelTUN(),
	}
	if err := p.s.CreateNIC(1, p.ep); err != nil {
		t.Fatal(err)
	}
	p.s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(phoneAddr.AsSlice()).WithPrefix()}, stack.AddressProperties{})
	p.s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { // apps -> OS -> wrapper
		for {
			pkt := p.ep.ReadContext(ctx)
			if pkt.IsNil() {
				return
			}
			v := pkt.ToView()
			pkt.DecRef()
			select {
			case p.ct.Outbound <- v.AsSlice():
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { // wrapper -> OS -> apps
		for msg := range p.ct.Inbound {
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(msg)})
			p.ep.InjectInbound(header.IPv4ProtocolNumber, pb)
			pb.DecRef()
		}
	}()
	return p
}

func fullAddr(ap netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ap.Addr().AsSlice()), Port: ap.Port()}
}

func (p *phone) dialTCP(t *testing.T, to string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return gonet.DialContextTCP(ctx, p.s, fullAddr(netip.MustParseAddrPort(to)), ipv4.ProtocolNumber)
}

func (p *phone) dialUDP(t *testing.T, to string) *gonet.UDPConn {
	t.Helper()
	ra := fullAddr(netip.MustParseAddrPort(to))
	c, err := gonet.DialUDP(p.s, nil, &ra, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// world: echo servers and a resolver on loopback, reached through the
// test dialer as if they were the real destinations.
type world struct {
	tcpEcho, udpEcho, dns string
	queries               chan string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{queries: make(chan string, 16)}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	w.tcpEcho = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	uc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { uc.Close() })
	w.udpEcho = uc.LocalAddr().String()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := uc.ReadFrom(buf)
			if err != nil {
				return
			}
			uc.WriteTo(buf[:n], a)
		}
	}()
	dc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dc.Close() })
	w.dns = dc.LocalAddr().String()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := dc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, _ := p.Question()
			w.queries <- q.Name.String()
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true})
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{198, 51, 100, 8}})
			out, _ := b.Finish()
			dc.WriteTo(out, a)
		}
	}()
	return w
}

// dial maps the "real" destinations of the test onto the loopback servers.
func (w *world) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	switch {
	case addr == "77.88.8.8:53":
		addr = w.dns
	case network == "tcp":
		addr = w.tcpEcho
	case network == "udp":
		addr = w.udpEcho
	}
	return d.DialContext(ctx, network, addr)
}

type rig struct {
	dev    *Device
	phone  *phone
	world  *world
	tunnel chan []byte
}

func newRig(t *testing.T) *rig {
	t.Helper()
	w := newWorld(t)
	p := newPhone(t)
	rules, err := ParseRules("preset:ru", "198.51.100.0/30", "")
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(p.ct.TUN(), Config{Rules: rules, Dial: w.dial, Log: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	r := &rig{dev: d, phone: p, world: w, tunnel: make(chan []byte, 64)}
	go func() { // the WireGuard device's reader
		bufs, sizes := [][]byte{make([]byte, 65535)}, []int{0}
		for {
			n, err := d.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			if n == 1 {
				r.tunnel <- append([]byte(nil), bufs[0][:sizes[0]]...)
			}
		}
	}()
	return r
}

// toTunnel waits for a packet to dst in the tunnel.
func (r *rig) toTunnel(t *testing.T, dst netip.AddrPort) []byte {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case pkt := <-r.tunnel:
			ihl := int(pkt[0]&0x0f) * 4
			a, _ := netip.AddrFromSlice(pkt[16:20])
			if a == dst.Addr() && binary.BigEndian.Uint16(pkt[ihl+2:]) == dst.Port() {
				return pkt
			}
		case <-deadline:
			t.Fatalf("nothing to %s in the tunnel", dst)
			return nil
		}
	}
}

func echoTCP(t *testing.T, c net.Conn) {
	t.Helper()
	defer c.Close()
	msg := bytes.Repeat([]byte("direct "), 20000) // more than a window
	go c.Write(msg)
	got := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo through the direct path: %v", err)
	}
}

func TestDirectNetworkTCPAndUDP(t *testing.T) {
	r := newRig(t)
	c, err := r.phone.dialTCP(t, "198.51.100.1:443", 5*time.Second)
	if err != nil {
		t.Fatalf("direct connect: %v", err)
	}
	echoTCP(t, c)

	u := r.phone.dialUDP(t, "198.51.100.2:3478")
	defer u.Close()
	u.Write([]byte("ping"))
	u.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	if n, err := u.Read(buf); err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("direct UDP: %q %v", buf[:n], err)
	}
	if r.dev.Stats.DirectFlows.Load() < 2 {
		t.Fatalf("direct flows: %d", r.dev.Stats.DirectFlows.Load())
	}
}

func TestEverythingElseGoesIntoTheTunnel(t *testing.T) {
	r := newRig(t)
	go r.phone.dialTCP(t, "203.0.113.9:443", 2*time.Second)
	if pkt := r.toTunnel(t, netip.MustParseAddrPort("203.0.113.9:443")); pkt[9] != 6 {
		t.Fatal("not TCP")
	}
	// a query for an unlisted name is not touched
	u := r.phone.dialUDP(t, "10.0.0.53:53")
	defer u.Close()
	u.Write(dnsQuery(t, "example.com.", dnsmessage.TypeA))
	r.toTunnel(t, netip.MustParseAddrPort("10.0.0.53:53"))
	select {
	case q := <-r.world.queries:
		t.Fatalf("%s went to the direct resolver", q)
	default:
	}
}

func dnsQuery(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x4242, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A listed name is resolved directly; connections to its address leave
// directly too, while the phone thinks it asked its usual resolver.
func TestDomainGoesDirect(t *testing.T) {
	r := newRig(t)
	u := r.phone.dialUDP(t, "10.0.0.53:53")
	defer u.Close()
	u.Write(dnsQuery(t, "www.gosuslugi.ru.", dnsmessage.TypeA))
	u.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	n, err := u.Read(buf)
	if err != nil {
		t.Fatalf("no DNS answer: %v", err)
	}
	var p dnsmessage.Parser
	h, err := p.Start(buf[:n])
	if err != nil || h.ID != 0x4242 || !h.Response {
		t.Fatalf("answer header: %+v %v", h, err)
	}
	p.SkipAllQuestions()
	a, err := p.AnswerHeader()
	if err != nil || a.Type != dnsmessage.TypeA {
		t.Fatalf("answer: %v", err)
	}
	if res, _ := p.AResource(); res.A != [4]byte{198, 51, 100, 8} {
		t.Fatalf("A %v", res.A)
	}
	if q := <-r.world.queries; q != "www.gosuslugi.ru." {
		t.Fatalf("resolver got %s", q)
	}
	c, err := r.phone.dialTCP(t, "198.51.100.8:443", 5*time.Second)
	if err != nil {
		t.Fatalf("connect to the resolved address: %v", err)
	}
	echoTCP(t, c)

	// AAAA for a direct name: answered empty, so apps use IPv4
	u.Write(dnsQuery(t, "gosuslugi.ru.", dnsmessage.TypeAAAA))
	n, err = u.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	h, _ = p.Start(buf[:n])
	p.SkipAllQuestions()
	if _, err := p.AnswerHeader(); err != dnsmessage.ErrSectionDone || h.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("AAAA answer: rcode %v, %v", h.RCode, err)
	}
}

// A connection that started in the tunnel stays there even if its
// address becomes direct later.
func TestFlowsDoNotSwitchPaths(t *testing.T) {
	d := &Device{domains: newMatcher(nil), addrs: map[netip.Addr]time.Time{}, flows: map[flowKey]*flow{}}
	pkt := func(flags byte) []byte {
		p := make([]byte, 40)
		p[0], p[9] = 0x45, 6
		copy(p[12:], phoneAddr.AsSlice())
		copy(p[16:], []byte{93, 184, 216, 34})
		binary.BigEndian.PutUint16(p[20:], 40000)
		binary.BigEndian.PutUint16(p[22:], 443)
		p[33] = flags
		return p
	}
	if !d.route(pkt(0x02)) { // SYN while the address is not direct
		t.Fatal("SYN not sent into the tunnel")
	}
	d.learn([]netip.Addr{netip.MustParseAddr("93.184.216.34")}, time.Minute)
	if !d.route(pkt(0x10)) { // ACK of the same flow
		t.Fatal("an established tunnel flow switched to the direct path")
	}
	// a packet of an unknown flow that is not a SYN also stays in the tunnel
	other := pkt(0x10)
	binary.BigEndian.PutUint16(other[20:], 40001)
	if !d.route(other) {
		t.Fatal("mid-flow packet of an unknown flow went directly")
	}
	if !d.isDirect(netip.MustParseAddr("93.184.216.34")) {
		t.Fatal("learned address not direct")
	}
}
