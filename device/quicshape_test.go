package device

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/v3/quicinitial"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// wireBind records every datagram a device puts on the wire.
type wireBind struct {
	conn.Bind
	mu   sync.Mutex
	sent [][]byte
}

func (b *wireBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	for _, buf := range bufs {
		b.sent = append(b.sent, append([]byte(nil), buf...))
	}
	b.mu.Unlock()
	return b.Bind.Send(bufs, ep)
}

func (b *wireBind) take() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sent
	b.sent = nil
	return s
}

// awgParams is a full AWG 3.x interface: junk, S1-S4 prefixes that hold the
// header protection nonce, H ranges, header protection.
var awgParams = []string{
	"jc", "4", "jmin", "40", "jmax", "200",
	"s1", "20", "s2", "30", "s3", "24", "s4", "16",
	"h1", "123456-123500", "h2", "67543-67550", "h3", "123123-123200", "h4", "32345-32350",
	"header_protection_key", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	"random_trailers", "true",
}

// wirePair is genTestPair with recording binds and an extra device
// section for each side.
func wirePair(t *testing.T, extra [2][]string) (testPair, [2]*wireBind) {
	t.Helper()
	cfg, endpointCfg := genConfigs(t, awgParams...)
	channel := bindtest.NewChannelBinds()
	var rec [2]*wireBind
	var pair testPair
	for i := range pair {
		p := &pair[i]
		rec[i] = &wireBind{Bind: channel[i]}
		p.tun = tuntest.NewChannelTUN()
		p.ip = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
		p.dev = NewDevice(p.tun.TUN(), rec[i], NewLogger(LogLevelError, fmt.Sprintf("dev%d: ", i)))
		t.Cleanup(p.dev.Close)
		if err := p.dev.IpcSet(cfg[i]); err != nil {
			t.Fatal(err)
		}
		if len(extra[i]) > 0 {
			if err := p.dev.IpcSet(uapiCfg(extra[i]...)); err != nil {
				t.Fatal(err)
			}
		}
		if err := p.dev.Up(); err != nil {
			t.Fatal(err)
		}
		endpointCfg[i^1] = fmt.Sprintf(endpointCfg[i^1], p.dev.net.port)
	}
	for i := range pair {
		if err := pair[i].dev.IpcSet(endpointCfg[i]); err != nil {
			t.Fatal(err)
		}
	}
	return pair, rec
}

// traffic runs pings both ways: handshake, data, keepalives. The first
// packet comes from pair[0] (Pong: pair[0]'s TUN sends), so the client
// initiates the handshake and sends its I-packets.
func traffic(t *testing.T, pair testPair) {
	t.Helper()
	for i := 0; i < 50; i++ {
		pair.Send(t, Pong, nil)
		pair.Send(t, Ping, nil)
	}
}

func shaped(b []byte) bool { return len(b) > 0 && b[0]&0xc0 == 0x40 }

// checkShaped: every datagram except QUIC Initials (the I-packets) starts
// like a QUIC short header.
func checkShaped(t *testing.T, who string, sent [][]byte) {
	t.Helper()
	initials, other := 0, 0
	for i, d := range sent {
		if isQUICInitial(d) {
			initials++
			continue
		}
		other++
		if !shaped(d) {
			t.Fatalf("%s: datagram %d of %d (%d bytes) starts with %#02x, not a QUIC short header", who, i, len(sent), len(d), d[0])
		}
	}
	if other < 40 {
		t.Fatalf("%s sent only %d datagrams besides I-packets", who, other)
	}
	t.Logf("%s: %d QUIC Initials, %d datagrams shaped", who, initials, other)
}

// checkRandom: the first bytes are left random. 40+ datagrams that all
// happen to be 0b01xxxxxx come with probability 4^-40.
func checkRandom(t *testing.T, who string, sent [][]byte) {
	t.Helper()
	if len(sent) < 40 {
		t.Fatalf("%s sent only %d datagrams", who, len(sent))
	}
	for _, d := range sent {
		if !shaped(d) {
			return
		}
	}
	t.Fatalf("%s: all %d datagrams are QUIC-shaped although nothing asked for it", who, len(sent))
}

// A client with <quic>: everything after the Initials looks like QUIC,
// and the tunnel works with a server that does not shape (any peer, fork
// or official, ignores the prefix).
func TestQUICShapeClientTag(t *testing.T) {
	pair, rec := wirePair(t, [2][]string{{"i1", "<quic sni=vpn.example.com>"}, nil})
	if !pair[0].dev.quicShape.Load() || pair[1].dev.quicShape.Load() {
		t.Fatalf("shape: client %v, server %v", pair[0].dev.quicShape.Load(), pair[1].dev.quicShape.Load())
	}
	traffic(t, pair)
	client := rec[0].take()
	checkShaped(t, "client", client)
	if !isQUICInitial(client[0]) {
		t.Fatal("the flow does not begin with the QUIC Initial")
	}
	if _, err := quicinitial.Parse(client[:2]); err != nil {
		t.Fatalf("the Initial flight is no longer valid QUIC: %v", err)
	}
	checkRandom(t, "server", rec[1].take())
}

// A fixed QUIC Initial (<b 0x...>, what the panel gives official apps)
// turns the shape on as well; another I-packet does not.
func TestQUICShapeFixedInitial(t *testing.T) {
	flight, err := quicinitial.Flight("vpn.example.com", quicinitial.Options{})
	if err != nil {
		t.Fatal(err)
	}
	pair, rec := wirePair(t, [2][]string{{"i1", "<b 0x" + hex.EncodeToString(flight[0]) + ">", "i2", "<b 0x" + hex.EncodeToString(flight[1]) + ">"}, nil})
	if !pair[0].dev.quicShape.Load() {
		t.Fatal("a fixed QUIC Initial did not turn the shape on")
	}
	traffic(t, pair)
	checkShaped(t, "client", rec[0].take())

	if err := pair[0].dev.IpcSet(uapiCfg("i1", "<r 100>", "i2", "")); err != nil {
		t.Fatal(err)
	}
	if pair[0].dev.quicShape.Load() {
		t.Fatal("random I-packets keep the QUIC shape on")
	}
	rec[0].take()
	traffic(t, pair)
	checkRandom(t, "client after the change", rec[0].take())
}

// The server shapes its packets when it relays to an HTTP/3 fallback, and
// stops when the fallback goes.
func TestQUICShapeServerFallback(t *testing.T) {
	pair, rec := wirePair(t, [2][]string{{"i1", "<quic>"}, {"fallback", "127.0.0.1:9"}})
	if !pair[1].dev.quicShape.Load() {
		t.Fatal("fallback did not turn the shape on")
	}
	traffic(t, pair)
	checkShaped(t, "client", rec[0].take())
	checkShaped(t, "server", rec[1].take())

	if err := pair[1].dev.IpcSet(uapiCfg("fallback", "off")); err != nil {
		t.Fatal(err)
	}
	if pair[1].dev.quicShape.Load() {
		t.Fatal("the shape stayed on after the fallback was turned off")
	}
}

// No disguise asked for: packets stay as random as before.
func TestQUICShapeOffByDefault(t *testing.T) {
	pair, rec := wirePair(t, [2][]string{nil, nil})
	if pair[0].dev.quicShape.Load() || pair[1].dev.quicShape.Load() {
		t.Fatal("shape on without a QUIC disguise")
	}
	traffic(t, pair)
	checkRandom(t, "client", rec[0].take())
	checkRandom(t, "server", rec[1].take())
}

// What turns the shape on, one thing at a time.
func TestWantQUICShape(t *testing.T) {
	chain := func(spec string) *obfChain {
		t.Helper()
		c, err := newObfChain(spec)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	flight, err := quicinitial.Flight("vpn.example.com", quicinitial.Options{})
	if err != nil {
		t.Fatal(err)
	}
	quicTag, fixed, random := chain("<quic>"), chain("<b 0x"+hex.EncodeToString(flight[0])+">"), chain("<r 100>")
	for _, tc := range []struct {
		name     string
		ipackets []*obfChain
		fallback bool
		port     uint16
		want     bool
	}{
		{"nothing", nil, false, 0, false},
		{"client port", nil, false, 51820, false},
		{"random I-packet", []*obfChain{random}, false, 0, false},
		{"<quic> tag", []*obfChain{nil, quicTag}, false, 0, true},
		{"fixed QUIC Initial", []*obfChain{random, fixed}, false, 0, true},
		{"fallback", nil, true, 51820, true},
		{"server on 443", nil, false, 443, true},
	} {
		if got := wantQUICShape(tc.ipackets, tc.fallback, tc.port); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestShapeQUICAndIsQUICInitial(t *testing.T) {
	for b := 0; b < 256; b++ {
		x := []byte{byte(b), 0xaa}
		shapeQUIC(x)
		if !shaped(x) || x[0]&0x3f != byte(b)&0x3f || x[1] != 0xaa {
			t.Fatalf("shapeQUIC(%#02x) = %#02x", b, x[0])
		}
	}
	shapeQUIC(nil) // no panic on an empty prefix

	flight, err := quicinitial.Flight("", quicinitial.Options{Classic: true})
	if err != nil {
		t.Fatal(err)
	}
	if !isQUICInitial(flight[0]) {
		t.Fatal("a QUIC Initial not recognised")
	}
	for _, p := range [][]byte{nil, {0xc0, 0, 0, 0}, {0xc0, 0, 0, 0, 2}, {0x40, 0, 0, 0, 1}, {0xe0, 0, 0, 0, 1}} {
		if isQUICInitial(p) {
			t.Fatalf("%x taken for a QUIC Initial", p)
		}
	}
}
