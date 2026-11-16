package splittun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// Domain rules in the text form of v2ray/Xray domain lists, which is what
// geosite categories turn into: a plain name or "domain:" matches the name
// and its subdomains, "full:" only the name itself, "keyword:" any name
// containing the text, "regexp:" a regular expression (RE2, linear time).
// Rules are only checked on DNS queries, so keywords and expressions cost
// nothing per packet.

const (
	maxRegexps    = 2000
	maxRegexpLen  = 1000
	minKeywordLen = 3
)

// normalizeRule checks one domain rule and returns it in canonical form
// ("vk.com", "full:vk.com", "keyword:vk", "regexp:^vk\\.").
func normalizeRule(s string) (string, error) {
	kind, v, ok := strings.Cut(s, ":")
	if !ok {
		return normalizeDomain(s)
	}
	switch strings.ToLower(kind) {
	case "domain":
		return normalizeDomain(v)
	case "full":
		n, err := normalizeDomain(v)
		if err != nil {
			return "", err
		}
		return "full:" + n, nil
	case "keyword":
		v = strings.ToLower(strings.TrimSpace(v))
		if len(v) < minKeywordLen {
			return "", fmt.Errorf("keyword %q: at least %d characters", v, minKeywordLen)
		}
		return "keyword:" + v, nil
	case "regexp":
		if len(v) > maxRegexpLen {
			return "", fmt.Errorf("regexp longer than %d characters", maxRegexpLen)
		}
		if _, err := regexp.Compile(v); err != nil {
			return "", fmt.Errorf("regexp %q: %w", v, err)
		}
		return "regexp:" + v, nil
	}
	return normalizeDomain(s)
}

// matcher answers "is this name listed": a map lookup per label for
// domains, one for full names, then keywords and expressions.
type matcher struct {
	suffix   map[string]struct{}
	full     map[string]struct{}
	keywords []string
	regexps  []*regexp.Regexp
}

// newMatcher takes rules in canonical form (normalizeRule).
func newMatcher(rules []string) matcher {
	m := matcher{suffix: map[string]struct{}{}, full: map[string]struct{}{}}
	for _, r := range rules {
		switch {
		case strings.HasPrefix(r, "full:"):
			m.full[r[5:]] = struct{}{}
		case strings.HasPrefix(r, "keyword:"):
			m.keywords = append(m.keywords, r[8:])
		case strings.HasPrefix(r, "regexp:"):
			if len(m.regexps) >= maxRegexps {
				continue
			}
			if re, err := regexp.Compile(r[7:]); err == nil {
				m.regexps = append(m.regexps, re)
			}
		default:
			m.suffix[r] = struct{}{}
		}
	}
	return m
}

func (m matcher) empty() bool {
	return len(m.suffix) == 0 && len(m.full) == 0 && len(m.keywords) == 0 && len(m.regexps) == 0
}

func (m matcher) match(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if _, ok := m.full[name]; ok {
		return true
	}
	for n := name; ; {
		if _, ok := m.suffix[n]; ok {
			return true
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			break
		}
		n = n[i+1:]
	}
	for _, k := range m.keywords {
		if strings.Contains(name, k) {
			return true
		}
	}
	for _, re := range m.regexps {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// netSet is a set of IPv4 networks as sorted, merged ranges: a lookup is
// a binary search, so tens of thousands of networks (geoip "ru") cost a
// dozen comparisons per new flow.
type netSet struct{ lo, hi []uint32 }

func newNetSet(prefixes []netip.Prefix) netSet {
	type rng struct{ lo, hi uint32 }
	var rs []rng
	for _, p := range prefixes {
		if !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		a := p.Addr().As4()
		lo := binary.BigEndian.Uint32(a[:])
		hi := lo | uint32(uint64(1)<<(32-p.Bits())-1)
		rs = append(rs, rng{lo, hi})
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo < rs[j].lo })
	var s netSet
	for _, r := range rs {
		if n := len(s.hi); n > 0 && uint64(r.lo) <= uint64(s.hi[n-1])+1 {
			s.hi[n-1] = max(s.hi[n-1], r.hi)
			continue
		}
		s.lo = append(s.lo, r.lo)
		s.hi = append(s.hi, r.hi)
	}
	return s
}

func (s netSet) contains(a netip.Addr) bool {
	if !a.Is4() || len(s.lo) == 0 {
		return false
	}
	b := a.As4()
	v := binary.BigEndian.Uint32(b[:])
	i := sort.Search(len(s.lo), func(i int) bool { return s.lo[i] > v }) - 1
	return i >= 0 && v <= s.hi[i]
}

func (s netSet) size() int { return len(s.lo) }

var errNotNetwork = errors.New("not an IPv4 network")

// parseNetwork reads "1.2.3.0/24" or a single address.
func parseNetwork(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil {
			return netip.Prefix{}, err
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, errNotNetwork
	}
	return p.Masked(), nil
}
