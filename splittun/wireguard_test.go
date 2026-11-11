package splittun

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"golang.org/x/crypto/curve25519"
)

func keyPair(t *testing.T) (priv, pub string) {
	t.Helper()
	k := make([]byte, 32)
	rand.Read(k)
	k[0] &= 248
	k[31] = k[31]&127 | 64
	p, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(k), hex.EncodeToString(p)
}

// The wrapper is the client device's TUN: tunnel traffic crosses a real
// WireGuard pair and reaches the server, direct traffic does not.
func TestWithWireGuardDevice(t *testing.T) {
	w := newWorld(t)
	p := newPhone(t)
	rules, _ := ParseRules("", "198.51.100.0/30", "")
	wrapped, err := New(p.ct.TUN(), Config{Rules: rules, Dial: w.dial, Log: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	binds := bindtest.NewChannelBinds()
	srvTun := tuntest.NewChannelTUN()
	logger := device.NewLogger(device.LogLevelError, "")
	srv := device.NewDevice(srvTun.TUN(), binds[0], logger)
	cli := device.NewDevice(wrapped, binds[1], logger)
	t.Cleanup(srv.Close)
	t.Cleanup(cli.Close)

	srvPriv, srvPub := keyPair(t)
	cliPriv, cliPub := keyPair(t)
	if err := srv.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=10.66.66.2/32\n", srvPriv, cliPub)); err != nil {
		t.Fatal(err)
	}
	srv.Up()
	get, _ := srv.IpcGet()
	var port string
	for _, l := range strings.Split(get, "\n") {
		if v, ok := strings.CutPrefix(l, "listen_port="); ok {
			port = v
		}
	}
	if err := cli.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=127.0.0.1:%s\nallowed_ip=0.0.0.0/0\n", cliPriv, srvPub, port)); err != nil {
		t.Fatal(err)
	}
	cli.Up()

	go p.dialTCP(t, "203.0.113.9:443", 5*time.Second)
	deadline := time.After(10 * time.Second)
	for got := false; !got; {
		select {
		case pkt := <-srvTun.Inbound:
			dst, _ := netip.AddrFromSlice(pkt[16:20])
			src, _ := netip.AddrFromSlice(pkt[12:16])
			ihl := int(pkt[0]&0x0f) * 4
			got = dst == netip.MustParseAddr("203.0.113.9") && src == phoneAddr && binary.BigEndian.Uint16(pkt[ihl+2:]) == 443
		case <-deadline:
			t.Fatal("the SYN did not come out of the server's end of the tunnel")
		}
	}

	c, err := p.dialTCP(t, "198.51.100.1:443", 5*time.Second)
	if err != nil {
		t.Fatalf("direct connect next to a live tunnel: %v", err)
	}
	echoTCP(t, c)
	select {
	case pkt := <-srvTun.Inbound:
		if dst, _ := netip.AddrFromSlice(pkt[16:20]); dst.String() == "198.51.100.1" {
			t.Fatal("direct traffic reached the server")
		}
	default:
	}
}
