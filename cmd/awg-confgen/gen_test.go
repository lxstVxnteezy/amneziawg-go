package main

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// H ranges are narrow (the type field is encrypted, and with
// RandomTrailers every value of width drops transport packets), stay
// within signed 32 bits and do not overlap; Jc is 0 because every flow
// starts with a QUIC Initial.
func TestObfuscationHeadersAndJunk(t *testing.T) {
	for range 500 {
		o := newObfuscation()
		if o.Jc != 0 {
			t.Fatalf("Jc = %d, want 0 after a QUIC Initial", o.Jc)
		}
		type rng struct{ lo, hi uint64 }
		var rs []rng
		var width uint64
		for _, h := range []string{o.H1, o.H2, o.H3, o.H4} {
			a, b, ok := strings.Cut(h, "-")
			lo, err1 := strconv.ParseUint(a, 10, 32)
			hi, err2 := strconv.ParseUint(b, 10, 32)
			if !ok || err1 != nil || err2 != nil || hi < lo {
				t.Fatalf("H %q is not a range", h)
			}
			if lo <= 4 || hi > maxHeader || hi-lo > maxHeaderWidth {
				t.Fatalf("H %q: want 5..%d and at most %d wide", h, maxHeader, maxHeaderWidth)
			}
			for _, r := range rs {
				if lo <= r.hi && r.lo <= hi {
					t.Fatalf("H ranges overlap: %+v", o)
				}
			}
			rs = append(rs, rng{lo, hi})
			width += hi - lo + 1
		}
		if loss := float64(width-(rs[3].hi-rs[3].lo+1)) / (1 << 32); loss > 0.00004 {
			t.Fatalf("H1-H3 drop %.5f %% of transport packets", loss*100)
		}
	}
}

// kernelChainBudget is what the Linux kernel module leaves for I1-I5 in
// its one netlink message, with a margin.
const kernelChainBudget = 3200

func netlinkBytes(ipackets []string) int {
	n := 0
	for _, p := range ipackets {
		n += 4 + (len(p)+1+3)/4*4
	}
	return n
}

// -kernel gives official clients one classic Initial that fits the
// module; the default Chrome-like flight does not.
func TestKernelIPacketsFitModule(t *testing.T) {
	sni := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + ".example"
	opts := Options{Endpoint: "vpn.example.com", Port: 443, Clients: 1, SNI: sni,
		Subnet: netip.MustParsePrefix("10.0.0.0/24"), MTU: 1280, WAN: "eth0"}
	full, err := Generate(opts)
	if err != nil {
		t.Fatal(err)
	}
	if n := netlinkBytes(full.Clients[0].IPackets); n <= kernelChainBudget {
		t.Errorf("full flight takes only %d bytes: is -kernel still needed?", n)
	}
	opts.Kernel = true
	short, err := Generate(opts)
	if err != nil {
		t.Fatal(err)
	}
	ipk := short.Clients[0].IPackets
	if len(ipk) != 1 {
		t.Fatalf("%d I-packets with -kernel, want 1", len(ipk))
	}
	if n := netlinkBytes(ipk); n > kernelChainBudget {
		t.Errorf("-kernel I-packets take %d netlink bytes, the module takes %d", n, kernelChainBudget)
	}
}
