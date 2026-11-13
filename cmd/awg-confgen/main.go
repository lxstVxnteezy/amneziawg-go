// Command awg-confgen generates a matching AmneziaWG 3.1 server config and
// client configs with every obfuscation feature enabled: random H/S/junk
// parameters, header protection, content padding, random trailers, a
// per-client preshared key and per-client QUIC Initial I-packets.
//
//	awg-confgen -endpoint vpn.example.com -clients 3
package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
)

func main() {
	var (
		opts   Options
		subnet string
		out    string
	)
	flag.StringVar(&opts.Endpoint, "endpoint", "", "public IP or hostname of the server (required)")
	flag.IntVar(&opts.Port, "port", 443, "server UDP port (443 matches the QUIC disguise)")
	flag.IntVar(&opts.Clients, "clients", 1, "number of client configs")
	flag.StringVar(&subnet, "subnet", "10.66.66.0/24", "tunnel subnet; server takes the first address")
	flag.StringVar(&opts.DNS, "dns", "1.1.1.1, 1.0.0.1", "DNS servers for clients")
	flag.IntVar(&opts.MTU, "mtu", 1280, "tunnel MTU for server and clients (1280 survives mobile and tunneled links)")
	flag.StringVar(&opts.SNI, "sni", "", "domain (or URL) put into the QUIC ClientHello of the I-packets (default: -endpoint if it is a domain, else no SNI, like a browser connecting to an IP)")
	flag.StringVar(&opts.WAN, "wan", "", "server uplink interface used for NAT (default: detected from the default route)")
	flag.BoolVar(&opts.DisableCookies, "disable-cookies", false, "turn off the cookie mechanism (no handshake flood protection)")
	flag.BoolVar(&opts.Fork, "fork", false, "clients run this fork: I1 = <quic sni=...>, a new QUIC Initial before every handshake (official clients reject it)")
	flag.StringVar(&out, "out", "awg-configs", "output directory")
	flag.Parse()

	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		fatal(fmt.Errorf("bad -subnet: %w", err))
	}
	opts.Subnet = prefix

	b, err := Generate(opts)
	if err != nil {
		fatal(err)
	}

	write := func(name, content string) {
		path := filepath.Join(out, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			fatal(err)
		}
		// configs contain private keys
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			fatal(err)
		}
		fmt.Println("wrote", path)
	}
	write(filepath.Join("server", "awg0.conf"), b.ServerConfig())
	for _, c := range b.Clients {
		write(filepath.Join("clients", c.Name+".conf"), b.ClientConfig(c))
	}
	if b.Opts.SNI != "" {
		fmt.Printf("QUIC disguise SNI: %s\n", b.Opts.SNI)
	} else {
		fmt.Println("QUIC disguise SNI: none (IP endpoint)")
	}
	for _, w := range b.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "awg-confgen:", err)
	os.Exit(1)
}
