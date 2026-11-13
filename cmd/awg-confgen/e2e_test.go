package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/quicinitial"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// toUAPI converts an awg-quick config into the UAPI text the device takes,
// like `awg setconf` does. wg-quick-only keys (Address, DNS, MTU, PostUp...)
// are skipped. endpoint overrides the peer Endpoint.
func toUAPI(t *testing.T, conf, endpoint string) string {
	t.Helper()
	b64hex := func(v string) string {
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(raw) != 32 {
			t.Fatalf("bad key %q: %v", v, err)
		}
		return hex.EncodeToString(raw)
	}
	device := map[string]string{
		"Jc": "jc", "Jmin": "jmin", "Jmax": "jmax",
		"S1": "s1", "S2": "s2", "S3": "s3", "S4": "s4",
		"H1": "h1", "H2": "h2", "H3": "h3", "H4": "h4",
		"I1": "i1", "I2": "i2", "I3": "i3", "I4": "i4", "I5": "i5",
		"ContentPaddingAddition": "content_padding_addition",
		"RekeyAfterTime":         "rekey_after_time",
		"RekeyTimeout":           "rekey_timeout",
		"RejectAfterTime":        "reject_after_time",
		"KeepaliveTimeout":       "keepalive_timeout",
		"MaxHandshakeAttempts":   "max_handshake_attempts",
	}
	var out strings.Builder
	out.WriteString("replace_peers=true\n")
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || line == "[Interface]" {
			continue
		}
		if line == "[Peer]" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("bad line %q", line)
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "PrivateKey":
			fmt.Fprintf(&out, "private_key=%s\n", b64hex(val))
		case "HeaderProtectionKey":
			fmt.Fprintf(&out, "header_protection_key=%s\n", b64hex(val))
		case "RandomTrailers", "DisableCookies":
			name := map[string]string{"RandomTrailers": "random_trailers", "DisableCookies": "disable_cookies"}[key]
			fmt.Fprintf(&out, "%s=%t\n", name, val == "on")
		case "PublicKey":
			fmt.Fprintf(&out, "public_key=%s\nprotocol_version=1\nreplace_allowed_ips=true\n", b64hex(val))
		case "PresharedKey":
			fmt.Fprintf(&out, "preshared_key=%s\n", b64hex(val))
		case "AllowedIPs":
			for _, ip := range strings.Split(val, ",") {
				fmt.Fprintf(&out, "allowed_ip=%s\n", strings.TrimSpace(ip))
			}
		case "Endpoint":
			fmt.Fprintf(&out, "endpoint=%s\n", endpoint)
		case "PersistentKeepalive":
			fmt.Fprintf(&out, "persistent_keepalive_interval=%s\n", val)
		case "Address", "DNS", "MTU", "PostUp", "PostDown", "ListenPort":
		default:
			uapi, ok := device[key]
			if !ok {
				t.Fatalf("unknown key %q", key)
			}
			fmt.Fprintf(&out, "%s=%s\n", uapi, val)
		}
	}
	return out.String()
}

// recordingBind keeps every datagram the device puts on the wire.
type recordingBind struct {
	conn.Bind
	mu   sync.Mutex
	sent [][]byte
}

func (b *recordingBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	for _, buf := range bufs {
		b.sent = append(b.sent, append([]byte(nil), buf...))
	}
	b.mu.Unlock()
	return b.Bind.Send(bufs, ep)
}

func listenPort(t *testing.T, d *device.Device) string {
	t.Helper()
	s, err := d.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			return v
		}
	}
	t.Fatal("no listen_port")
	return ""
}

func transit(t *testing.T, from, to *tuntest.ChannelTUN, src, dst netip.Addr) {
	t.Helper()
	msg := tuntest.Ping(dst, src)
	from.Outbound <- msg
	select {
	case got := <-to.Inbound:
		if !bytes.Equal(got, msg) {
			t.Fatal("packet corrupted in transit")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s -> %s did not transit", src, dst)
	}
}

func TestGeneratedConfigsWorkInCore(t *testing.T) {
	b, err := Generate(Options{
		Endpoint: "vpn.example.com",
		Port:     443,
		Clients:  2,
		Subnet:   netip.MustParsePrefix("10.66.66.0/24"),
		MTU:      1280,
		SNI:      "www.google.com",
		WAN:      "eth0",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range b.Clients {
		t.Run(c.Name, func(t *testing.T) {
			binds := bindtest.NewChannelBinds()
			rec := &recordingBind{Bind: binds[1]}
			level := device.LogLevelError
			if testing.Verbose() {
				level = device.LogLevelVerbose
			}
			srvTun, cliTun := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
			srv := device.NewDevice(srvTun.TUN(), binds[0], device.NewLogger(level, "server: "))
			cli := device.NewDevice(cliTun.TUN(), rec, device.NewLogger(level, c.Name+": "))
			t.Cleanup(srv.Close)
			t.Cleanup(cli.Close)

			if err := srv.IpcSet(toUAPI(t, b.ServerConfig(), "")); err != nil {
				t.Fatalf("server config rejected by core: %v", err)
			}
			if err := srv.Up(); err != nil {
				t.Fatal(err)
			}
			endpoint := "127.0.0.1:" + listenPort(t, srv)
			if err := cli.IpcSet(toUAPI(t, b.ClientConfig(c), endpoint)); err != nil {
				t.Fatalf("client config rejected by core: %v", err)
			}
			if err := cli.Up(); err != nil {
				t.Fatal(err)
			}

			transit(t, cliTun, srvTun, c.Address, b.Address)
			transit(t, srvTun, cliTun, b.Address, c.Address)

			// What went on the wire before the first handshake: I-packets, junk.
			rec.mu.Lock()
			sent := rec.sent
			rec.mu.Unlock()
			ni := len(c.IPackets)
			if len(sent) < ni+b.Obf.Jc+1 {
				t.Fatalf("only %d datagrams sent", len(sent))
			}
			for i, ip := range c.IPackets {
				want := mustHex(t, strings.TrimSuffix(strings.TrimPrefix(ip, "<b 0x"), ">"))
				if !bytes.Equal(sent[i], want) {
					t.Fatalf("datagram %d is not I%d", i, i+1)
				}
			}
			for _, j := range sent[ni : ni+b.Obf.Jc] {
				if len(j) < b.Obf.Jmin || len(j) >= b.Obf.Jmax {
					t.Fatalf("junk packet of %d bytes outside [%d,%d)", len(j), b.Obf.Jmin, b.Obf.Jmax)
				}
			}
			if init := sent[ni+b.Obf.Jc]; len(init) < 148+b.Obf.S1 {
				t.Fatalf("handshake initiation is %d bytes, expected >= %d", len(init), 148+b.Obf.S1)
			}
			// the plain WireGuard type (1, 0, 0, 0) must not be visible
			for _, p := range sent[ni:] {
				if bytes.HasPrefix(p, []byte{1, 0, 0, 0}) || bytes.HasPrefix(p, []byte{4, 0, 0, 0}) {
					t.Fatal("vanilla WireGuard header on the wire")
				}
			}
		})
	}
}

// With -fork the client builds its QUIC Initials itself: the flight on the
// wire is a valid Initial for the SNI, the tunnel works, and the next
// handshake sends a different connection attempt.
func TestForkClientsGenerateInitials(t *testing.T) {
	b, err := Generate(Options{Endpoint: "vpn.example.com", Port: 443, Clients: 1,
		Subnet: netip.MustParsePrefix("10.66.66.0/24"), MTU: 1280, WAN: "eth0", Fork: true})
	if err != nil {
		t.Fatal(err)
	}
	c := b.Clients[0]
	if len(c.IPackets) != 1 || c.IPackets[0] != "<quic sni=vpn.example.com>" {
		t.Fatalf("I-packets %q", c.IPackets)
	}
	binds := bindtest.NewChannelBinds()
	rec := &recordingBind{Bind: binds[1]}
	srvTun, cliTun := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	srv := device.NewDevice(srvTun.TUN(), binds[0], device.NewLogger(device.LogLevelError, "server: "))
	cli := device.NewDevice(cliTun.TUN(), rec, device.NewLogger(device.LogLevelError, "client: "))
	t.Cleanup(srv.Close)
	t.Cleanup(cli.Close)
	if err := srv.IpcSet(toUAPI(t, b.ServerConfig(), "")); err != nil {
		t.Fatal(err)
	}
	if err := srv.Up(); err != nil {
		t.Fatal(err)
	}
	if err := cli.IpcSet(toUAPI(t, b.ClientConfig(c), "127.0.0.1:"+listenPort(t, srv))); err != nil {
		t.Fatalf("client config rejected by core: %v", err)
	}
	if err := cli.Up(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ipcGet(t, cli), "i1=<quic sni=vpn.example.com>") {
		t.Fatal("the tag does not round-trip through UAPI")
	}

	flight := func() quicinitial.Info {
		t.Helper()
		rec.mu.Lock()
		sent := rec.sent
		rec.sent = nil
		rec.mu.Unlock()
		if len(sent) < 2+b.Obf.Jc+1 {
			t.Fatalf("only %d datagrams sent", len(sent))
		}
		info, err := quicinitial.Parse(sent[:2])
		if err != nil {
			t.Fatalf("first datagrams are not a QUIC Initial flight: %v", err)
		}
		if info.SNI != "vpn.example.com" || info.ALPN != "h3" {
			t.Fatalf("flight carries SNI %q ALPN %q", info.SNI, info.ALPN)
		}
		return info
	}

	transit(t, cliTun, srvTun, c.Address, b.Address)
	transit(t, srvTun, cliTun, b.Address, c.Address)
	first := flight()

	// a new session: Down drops the keys, the next packet needs a handshake
	if err := cli.Down(); err != nil {
		t.Fatal(err)
	}
	if err := cli.Up(); err != nil {
		t.Fatal(err)
	}
	transit(t, cliTun, srvTun, c.Address, b.Address)
	second := flight()
	if bytes.Equal(first.DCID, second.DCID) || bytes.Equal(first.ClientHello, second.ClientHello) {
		t.Fatal("the second handshake repeats the first connection attempt")
	}
}

func ipcGet(t *testing.T, d *device.Device) string {
	t.Helper()
	s, err := d.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestGenerateUniquePerClientSecrets(t *testing.T) {
	b, err := Generate(Options{Endpoint: "1.2.3.4", Port: 443, Clients: 50,
		Subnet: netip.MustParsePrefix("10.0.0.0/26"), MTU: 1280, WAN: "eth0"})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	ips := map[netip.Addr]bool{b.Address: true}
	for _, c := range b.Clients {
		for _, s := range append([]string{c.PSK, c.Keys.Private}, c.IPackets...) {
			if seen[s] {
				t.Fatal("secret reused between clients")
			}
			seen[s] = true
		}
		if ips[c.Address] || !b.Opts.Subnet.Contains(c.Address) {
			t.Fatalf("bad client address %s", c.Address)
		}
		ips[c.Address] = true
	}
	// 10.0.0.0/26 fits the server and 61 clients, not 62
	if _, err := Generate(Options{Endpoint: "1.2.3.4", Clients: 62, MTU: 1280,
		Subnet: netip.MustParsePrefix("10.0.0.0/26")}); err == nil {
		t.Fatal("subnet overflow not detected")
	}
}

func TestNormalizeSNI(t *testing.T) {
	for in, want := range map[string]string{
		"yandex.ru":                 "yandex.ru",
		"http://yandex.ru/":         "yandex.ru",
		"https://Yandex.RU:443/x?y": "yandex.ru",
		" yandex.ru/path ":          "yandex.ru",
		"yandex.ru:443":             "yandex.ru",
		"yandex.ru.":                "yandex.ru",
		"xn--d1acpjx3f.xn--p1ai":    "xn--d1acpjx3f.xn--p1ai",
	} {
		got, err := normalizeSNI(in)
		if err != nil || got != want {
			t.Errorf("normalizeSNI(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "localhost", "1.2.3.4", "http://[::1]/", "яндекс.рф", "-bad.ru", "a..ru", "ya ndex.ru"} {
		if got, err := normalizeSNI(bad); err == nil {
			t.Errorf("normalizeSNI(%q) = %q, want error", bad, got)
		}
	}
}

func TestSNIFromURLReachesI1(t *testing.T) {
	b, err := Generate(Options{Endpoint: "1.2.3.4", Port: 443, Clients: 1,
		Subnet: netip.MustParsePrefix("10.66.66.0/24"), MTU: 1280, WAN: "eth0", SNI: "http://yandex.ru/"})
	if err != nil {
		t.Fatal(err)
	}
	var pkts [][]byte
	for _, ip := range b.Clients[0].IPackets {
		pkts = append(pkts, mustHex(t, strings.TrimSuffix(strings.TrimPrefix(ip, "<b 0x"), ">")))
	}
	if info, err := quicinitial.Parse(pkts); err != nil || info.SNI != "yandex.ru" {
		t.Fatalf("I-packets carry SNI %q: %v", info.SNI, err)
	}
}

func TestServerConfig(t *testing.T) {
	b, err := Generate(Options{Endpoint: "1.2.3.4", Port: 443, Clients: 1,
		Subnet: netip.MustParsePrefix("10.66.66.0/24"), MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	srv := b.ServerConfig()
	for _, want := range []string{"MTU = 1280\n", "--ctstate RELATED,ESTABLISHED", "ip -4 route show default"} {
		if !strings.Contains(srv, want) {
			t.Errorf("server config lacks %q", want)
		}
	}
	for _, bad := range []string{"\nI1 =", "DisableCookies", "-m state"} {
		if strings.Contains(srv, bad) {
			t.Errorf("server config contains %q", bad)
		}
	}
	if !strings.Contains(b.ClientConfig(b.Clients[0]), "\nI2 = ") {
		t.Error("client config lacks I2")
	}

	b.Opts.DisableCookies = true
	if !strings.Contains(b.ServerConfig(), "DisableCookies = on") {
		t.Error("-disable-cookies is ignored")
	}

	if _, err := Generate(Options{Endpoint: "1.2.3.4", Clients: 1, MTU: 1280,
		Subnet: netip.MustParsePrefix("10.66.66.0/24"), WAN: "eth0; rm -rf /"}); err == nil {
		t.Error("shell metacharacters in -wan accepted")
	}
}

// An IP endpoint without -sni: the I-packets carry no SNI at all, not a
// popular site that does not resolve to the server.
func TestNoSNIForIPEndpoint(t *testing.T) {
	for _, fork := range []bool{false, true} {
		b, err := Generate(Options{Endpoint: "1.2.3.4", Port: 443, Clients: 1, Fork: fork,
			Subnet: netip.MustParsePrefix("10.66.66.0/24"), MTU: 1280, WAN: "eth0"})
		if err != nil {
			t.Fatal(err)
		}
		if b.Opts.SNI != "" || len(b.Warnings) == 0 {
			t.Fatalf("fork=%v: SNI %q, warnings %q", fork, b.Opts.SNI, b.Warnings)
		}
		ipk := b.Clients[0].IPackets
		if fork {
			if len(ipk) != 1 || ipk[0] != "<quic>" {
				t.Fatalf("fork: I-packets %q, want <quic>", ipk)
			}
			continue
		}
		var pkts [][]byte
		for _, ip := range ipk {
			pkts = append(pkts, mustHex(t, strings.TrimSuffix(strings.TrimPrefix(ip, "<b 0x"), ">")))
		}
		if info, err := quicinitial.Parse(pkts); err != nil || info.SNI != "" || info.ALPN != "h3" {
			t.Fatalf("I-packets carry SNI %q ALPN %q: %v", info.SNI, info.ALPN, err)
		}
	}
}

func TestDefaultSNIFollowsEndpoint(t *testing.T) {
	b, err := Generate(Options{Endpoint: "VPN.Example.com", Port: 443, Clients: 1,
		Subnet: netip.MustParsePrefix("10.66.66.0/24"), MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	if b.Opts.SNI != "vpn.example.com" || len(b.Warnings) != 0 {
		t.Fatalf("SNI %q, warnings %q", b.Opts.SNI, b.Warnings)
	}

	b, err = Generate(Options{Endpoint: "203.0.113.5", Port: 443, Clients: 1,
		Subnet: netip.MustParsePrefix("10.66.66.0/24"), MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Warnings) == 0 {
		t.Fatal("no warning for an IP endpoint without a domain")
	}

	b, err = Generate(Options{Endpoint: "203.0.113.5", Port: 443, Clients: 1, SNI: "my.domain.ru",
		Subnet: netip.MustParsePrefix("10.66.66.0/24"), MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	if b.Opts.SNI != "my.domain.ru" || len(b.Warnings) != 0 {
		t.Fatalf("explicit -sni: SNI %q, warnings %q", b.Opts.SNI, b.Warnings)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
