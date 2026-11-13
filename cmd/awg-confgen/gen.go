package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/quicinitial"
	"golang.org/x/crypto/curve25519"
)

type Options struct {
	Endpoint string // public host or IP of the server
	Port     int
	Clients  int
	Subnet   netip.Prefix // server gets .1, clients .2, .3, ...
	DNS      string
	MTU      int
	SNI      string // domain put into the QUIC ClientHello of the I-packets
	WAN      string // server uplink interface for NAT; "" detects it at PostUp time

	// DisableCookies turns off the cookie (load) mechanism. It removes one
	// more recognizable message type, but leaves the server without
	// handshake flood protection.
	DisableCookies bool

	// Fork writes I1 = <quic sni=...>: clients running this fork build a
	// fresh QUIC Initial flight before every handshake instead of resending
	// fixed bytes. Official AmneziaWG clients reject the tag.
	Fork bool
}

type keyPair struct {
	Private, Public string // base64, as awg-quick expects
}

type Obfuscation struct {
	Jc, Jmin, Jmax         int
	S1, S2, S3, S4         int
	H1, H2, H3, H4         string
	HeaderProtectionKey    string
	ContentPaddingAddition string
}

type Client struct {
	Name    string
	Keys    keyPair
	PSK     string
	Address netip.Addr
	// IPackets are I1..In: this client's own QUIC Initial datagrams. They
	// are fixed bytes resent before every handshake, so at least they must
	// not be shared: a common DCID would link all clients of the server.
	IPackets []string
}

type Bundle struct {
	Opts    Options
	Server  keyPair
	Address netip.Addr
	Obf     Obfuscation
	Clients []Client

	// Warnings are things the user should know about the generated
	// configs, e.g. an SNI that does not match the server's address.
	Warnings []string
}

// Timer ranges match the defaults AmneziaVPN ships for AWG 3.1.
const (
	rekeyAfterTime       = "100-120"
	rekeyTimeout         = "3-7"
	rejectAfterTime      = "150-180"
	keepaliveTimeout     = "5-15"
	maxHandshakeAttempts = "15-20"
	persistentKeepalive  = "20-30"
)

// normalizeSNI accepts a bare domain or a URL ("http://yandex.ru/") and
// returns the host name to put into the ClientHello.
func normalizeSNI(s string) (string, error) {
	host := strings.TrimSpace(s)
	if i := strings.Index(host, "://"); i >= 0 {
		u, err := url.Parse(host)
		if err != nil {
			return "", fmt.Errorf("bad SNI %q: %w", s, err)
		}
		host = u.Hostname()
	} else {
		host, _, _ = strings.Cut(host, "/")
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")

	if _, err := netip.ParseAddr(host); err == nil {
		return "", fmt.Errorf("SNI %q must be a domain name, not an IP address", s)
	}
	if len(host) == 0 || len(host) > 253 || !strings.Contains(host, ".") {
		return "", fmt.Errorf("SNI %q is not a valid domain name", s)
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("SNI %q is not a valid domain name", s)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("SNI %q contains %q; use the punycode (xn--) form for non-ASCII names", s, c)
			}
		}
	}
	return host, nil
}

func randInt(lo, hi int) int { // inclusive
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	if err != nil {
		panic(err)
	}
	return lo + int(n.Int64())
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func newKeyPair() keyPair {
	priv := randBytes(32)
	// clamp like `wg genkey`
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return keyPair{
		Private: base64.StdEncoding.EncodeToString(priv),
		Public:  base64.StdEncoding.EncodeToString(pub),
	}
}

// headerRanges returns four disjoint random H ranges that avoid the vanilla
// WireGuard message types 1-4.
func headerRanges() [4]string {
	type rng struct{ lo, hi uint64 }
	var picked []rng
	for len(picked) < 4 {
		width := uint64(randInt(100_000, 10_000_000))
		lo := uint64(randInt(1<<20, (1<<32)-1-10_000_000))
		r := rng{lo, lo + width}
		ok := true
		for _, p := range picked {
			if r.lo <= p.hi && p.lo <= r.hi {
				ok = false
				break
			}
		}
		if ok {
			picked = append(picked, r)
		}
	}
	var out [4]string
	for i, r := range picked {
		out[i] = fmt.Sprintf("%d-%d", r.lo, r.hi)
	}
	return out
}

func newObfuscation() Obfuscation {
	var o Obfuscation

	o.Jc = randInt(3, 6)
	o.Jmin = randInt(40, 100)
	o.Jmax = o.Jmin + randInt(100, 500)

	// All S values stay >= 12: the header protection nonce lives there.
	o.S1 = randInt(15, 150)
	for {
		// init (148+S1) and response (92+S2) must not have the same size
		o.S2 = randInt(15, 150)
		if 148+o.S1 != 92+o.S2 {
			break
		}
	}
	o.S3 = randInt(12, 64)
	o.S4 = randInt(12, 32) // paid on every data packet, keep it small

	h := headerRanges()
	o.H1, o.H2, o.H3, o.H4 = h[0], h[1], h[2], h[3]

	o.HeaderProtectionKey = base64.StdEncoding.EncodeToString(randBytes(32))
	o.ContentPaddingAddition = fmt.Sprintf("%d-%d", randInt(4, 12), randInt(40, 64))
	return o
}

func iPackets(sni string) ([]string, error) {
	initials, err := quicinitial.Flight(sni, quicinitial.Options{})
	if err != nil {
		return nil, err
	}
	out := make([]string, len(initials))
	for i, p := range initials {
		out[i] = "<b 0x" + hex.EncodeToString(p) + ">"
	}
	return out, nil
}

var wanName = regexp.MustCompile(`^[a-zA-Z0-9_.@-]{1,15}$`)

func Generate(opts Options) (*Bundle, error) {
	if opts.Endpoint == "" {
		return nil, errors.New("endpoint is required")
	}
	if opts.Clients < 1 {
		return nil, errors.New("need at least one client")
	}
	if strings.ContainsAny(opts.Endpoint, "\r\n") || strings.ContainsAny(opts.DNS, "\r\n") {
		return nil, errors.New("endpoint and DNS must fit on one configuration line")
	}
	if opts.Port < 1 || opts.Port > 65535 {
		return nil, errors.New("port must be between 1 and 65535")
	}
	if !opts.Subnet.Addr().Is4() {
		return nil, errors.New("subnet must be IPv4")
	}
	opts.Subnet = opts.Subnet.Masked()
	// network address, server, clients, broadcast
	if hostBits := 32 - opts.Subnet.Bits(); hostBits >= 31 || opts.Clients > (1<<hostBits)-3 {
		return nil, fmt.Errorf("subnet %s is too small for %d clients", opts.Subnet, opts.Clients)
	}
	var warnings []string
	if opts.SNI == "" {
		// A ClientHello for a domain that resolves to the server is
		// consistent: a DPI comparing SNI with the destination IP sees
		// nothing odd. Without a domain the Initials carry no SNI at all,
		// as a browser connecting to an IP address does: a popular site on
		// a VPS address (the old fallback) is what gets flagged.
		if host, err := normalizeSNI(opts.Endpoint); err == nil {
			opts.SNI = host
		} else {
			warnings = append(warnings, "-endpoint is not a domain name, so the I-packets carry no SNI, "+
				"like a browser connecting to an IP address. A domain of yours pointed at the server is better: "+
				"pass it as -endpoint or -sni.")
		}
	}
	if opts.SNI != "" {
		sni, err := normalizeSNI(opts.SNI)
		if err != nil {
			return nil, err
		}
		opts.SNI = sni
	}

	if opts.MTU < 1280 || opts.MTU > 1420 {
		return nil, fmt.Errorf("MTU %d is out of range 1280-1420", opts.MTU)
	}
	if opts.WAN != "" && !wanName.MatchString(opts.WAN) {
		return nil, fmt.Errorf("bad WAN interface name %q", opts.WAN)
	}

	b := &Bundle{
		Opts:     opts,
		Server:   newKeyPair(),
		Address:  opts.Subnet.Addr().Next(),
		Obf:      newObfuscation(),
		Warnings: warnings,
	}
	addr := b.Address
	for i := range opts.Clients {
		addr = addr.Next()
		ipk := []string{"<quic>"}
		if opts.SNI != "" {
			ipk = []string{"<quic sni=" + opts.SNI + ">"}
		}
		if !opts.Fork {
			var err error
			if ipk, err = iPackets(opts.SNI); err != nil {
				return nil, err
			}
		}
		b.Clients = append(b.Clients, Client{
			Name:     fmt.Sprintf("client%d", i+1),
			Keys:     newKeyPair(),
			PSK:      base64.StdEncoding.EncodeToString(randBytes(32)), // one per client
			Address:  addr,
			IPackets: ipk,
		})
	}
	return b, nil
}

// interfaceLines renders the obfuscation lines shared by server and clients.
// Only clients carry I-packets: they are client Initials, and a server
// sending them from port 443 would not look like QUIC. The receiving side
// ignores I-packets, so the server does not need them to accept a client.
func (o Obfuscation) interfaceLines(w *strings.Builder, ipackets []string, disableCookies bool) {
	fmt.Fprintf(w, "Jc = %d\nJmin = %d\nJmax = %d\n", o.Jc, o.Jmin, o.Jmax)
	fmt.Fprintf(w, "S1 = %d\nS2 = %d\nS3 = %d\nS4 = %d\n", o.S1, o.S2, o.S3, o.S4)
	fmt.Fprintf(w, "H1 = %s\nH2 = %s\nH3 = %s\nH4 = %s\n", o.H1, o.H2, o.H3, o.H4)
	for i, p := range ipackets {
		fmt.Fprintf(w, "I%d = %s\n", i+1, p)
	}
	fmt.Fprintf(w, "HeaderProtectionKey = %s\n", o.HeaderProtectionKey)
	fmt.Fprintf(w, "ContentPaddingAddition = %s\n", o.ContentPaddingAddition)
	fmt.Fprintf(w, "RekeyAfterTime = %s\nRekeyTimeout = %s\nRejectAfterTime = %s\n", rekeyAfterTime, rekeyTimeout, rejectAfterTime)
	fmt.Fprintf(w, "KeepaliveTimeout = %s\nMaxHandshakeAttempts = %s\n", keepaliveTimeout, maxHandshakeAttempts)
	w.WriteString("RandomTrailers = on\n")
	if disableCookies {
		w.WriteString("DisableCookies = on\n")
	}
}

func (b *Bundle) ServerConfig() string {
	var w strings.Builder
	w.WriteString("[Interface]\n")
	fmt.Fprintf(&w, "PrivateKey = %s\n", b.Server.Private)
	fmt.Fprintf(&w, "Address = %s/%d\n", b.Address, b.Opts.Subnet.Bits())
	fmt.Fprintf(&w, "ListenPort = %d\n", b.Opts.Port)
	// Same MTU as the clients: with awg-quick's default (1420) the server
	// would tunnel packets that, with S4, padding and trailers, no longer
	// fit a 1500-byte link and get fragmented.
	fmt.Fprintf(&w, "MTU = %d\n", b.Opts.MTU)
	b.Obf.interfaceLines(&w, nil, b.Opts.DisableCookies)
	wan := b.Opts.WAN
	if wan == "" {
		// awg-quick runs PostUp/PostDown through bash
		wan = "$(ip -4 route show default | awk '{print $5; exit}')"
	}
	// -I, not -A: with ufw/Docker the FORWARD policy is DROP and appended
	// rules may never be reached.
	// %i is expanded by awg-quick to the interface name
	nat := func(op string) string {
		return fmt.Sprintf("iptables %[1]s FORWARD -i %%i -j ACCEPT; "+
			"iptables %[1]s FORWARD -o %%i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; "+
			"iptables -t nat %[1]s POSTROUTING -s %[2]s -o %[3]s -j MASQUERADE",
			op, b.Opts.Subnet, wan)
	}
	fmt.Fprintf(&w, "PostUp = sysctl -w net.ipv4.ip_forward=1; %s\n", nat("-I"))
	fmt.Fprintf(&w, "PostDown = %s\n", nat("-D"))
	for _, c := range b.Clients {
		fmt.Fprintf(&w, "\n# %s\n[Peer]\n", c.Name)
		fmt.Fprintf(&w, "PublicKey = %s\n", c.Keys.Public)
		fmt.Fprintf(&w, "PresharedKey = %s\n", c.PSK)
		fmt.Fprintf(&w, "AllowedIPs = %s/32\n", c.Address)
	}
	return w.String()
}

func (b *Bundle) ClientConfig(c Client) string {
	var w strings.Builder
	w.WriteString("[Interface]\n")
	fmt.Fprintf(&w, "PrivateKey = %s\n", c.Keys.Private)
	fmt.Fprintf(&w, "Address = %s/32\n", c.Address)
	if b.Opts.DNS != "" {
		fmt.Fprintf(&w, "DNS = %s\n", b.Opts.DNS)
	}
	fmt.Fprintf(&w, "MTU = %d\n", b.Opts.MTU)
	b.Obf.interfaceLines(&w, c.IPackets, b.Opts.DisableCookies)
	w.WriteString("\n[Peer]\n")
	fmt.Fprintf(&w, "PublicKey = %s\n", b.Server.Public)
	fmt.Fprintf(&w, "PresharedKey = %s\n", c.PSK)
	// ::/0 without IPv6 on the server is deliberate: IPv6 is blackholed
	// instead of leaking past the tunnel.
	w.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	fmt.Fprintf(&w, "Endpoint = %s\n", hostPort(b.Opts.Endpoint, b.Opts.Port))
	fmt.Fprintf(&w, "PersistentKeepalive = %s\n", persistentKeepalive)
	return w.String()
}

func hostPort(host string, port int) string {
	if a, err := netip.ParseAddr(host); err == nil && a.Is6() {
		return fmt.Sprintf("[%s]:%d", a, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}
