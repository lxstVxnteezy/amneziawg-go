package splittun

import (
	"net/netip"
	"strings"
	"testing"
)

// geosite rules: domain (and subdomains), full (only the name), keyword,
// regexp.
func TestMatcherRules(t *testing.T) {
	var rules []string
	for _, r := range []string{"youtube.com", "domain:ggpht.com", "full:t.co", "keyword:googlevideo", `regexp:^r\d+---sn-.*\.example$`} {
		n, err := normalizeRule(r)
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, n)
	}
	m := newMatcher(rules)
	for name, want := range map[string]bool{
		"youtube.com": true, "www.youtube.com.": true, "yt3.ggpht.com": true,
		"t.co": true, "x.t.co": false,
		"rr1---sn-abc.googlevideo.com": true,
		"r12---sn-xyz.example":         true, "r12---sn-xyz.example.org": false,
		"example.org": false,
	} {
		if m.match(name) != want {
			t.Errorf("%s: want %v", name, want)
		}
	}
	for _, bad := range []string{"keyword:ab", "regexp:(", "full:"} {
		if _, err := normalizeRule(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if !newMatcher(nil).empty() || m.empty() {
		t.Fatal("empty() wrong")
	}
}

func TestNetSet(t *testing.T) {
	var ps []netip.Prefix
	for _, s := range []string{"5.255.255.0/24", "5.255.254.0/24", "10.0.0.0/8", "77.88.8.8/32", "2001:db8::/32"} {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	s := newNetSet(ps)
	if s.size() != 3 { // the two /24 merge, IPv6 is left out
		t.Fatalf("%d ranges, want 3", s.size())
	}
	for a, want := range map[string]bool{
		"5.255.254.1": true, "5.255.255.255": true, "5.255.253.255": false,
		"10.200.0.1": true, "77.88.8.8": true, "77.88.8.9": false, "1.1.1.1": false,
	} {
		if s.contains(netip.MustParseAddr(a)) != want {
			t.Errorf("%s: want %v", a, want)
		}
	}
	// geoip "ru" is ~25 000 networks: lookups stay cheap
	ps = ps[:0]
	for i := range 25000 {
		ps = append(ps, netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(i >> 8), byte(i), 0, 0}), 24))
	}
	big := newNetSet(ps)
	if !big.contains(netip.MustParseAddr("97.167.0.5")) || big.contains(netip.MustParseAddr("97.167.1.5")) {
		t.Fatal("lookup in a large set")
	}
}

// What the panel serves from geosite/geoip: rules and networks in one list.
func TestReadListRulesAndNetworks(t *testing.T) {
	names, nets, err := readList(strings.NewReader(`full:t.co
keyword:googlevideo
regexp:^cdn\d+\.example$
ru
5.255.255.0/24
77.88.8.8
1.0.0.0/4
2001:db8::/32
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names, " "); got != `full:t.co keyword:googlevideo regexp:^cdn\d+\.example$` {
		t.Fatalf("names %q", got)
	}
	if len(nets) != 2 || nets[0].String() != "5.255.255.0/24" || nets[1].String() != "77.88.8.8/32" {
		t.Fatalf("nets %v (a /4 and IPv6 must be skipped)", nets)
	}
}

// A network from a list goes directly in the direct mode.
func TestListNetworksAreDirect(t *testing.T) {
	d := &Device{}
	m := newMatcher(nil)
	d.domains.Store(&m)
	ns := newNetSet([]netip.Prefix{netip.MustParsePrefix("5.255.255.0/24")})
	d.nets.Store(&ns)
	if !d.isDirect(netip.MustParseAddr("5.255.255.77")) || d.isDirect(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("list networks not used for the direct decision")
	}
}
