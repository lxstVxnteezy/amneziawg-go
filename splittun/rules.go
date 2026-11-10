// Package splittun sends chosen sites past the tunnel, by domain name,
// the way Xray-based clients route "geosite" rules: a wrapper between the
// operating system's TUN and the WireGuard device.
//
// DNS queries for listed domains are answered through a direct resolver;
// the addresses in the answers are remembered, and connections to them
// (and to listed networks) leave through the device's own network instead
// of the tunnel, via a userspace TCP/IP stack. Everything else, other
// queries included, goes into the tunnel unchanged.
//
// The direct connections are made by this process: on Android the VPN
// must exclude the app itself (addDisallowedApplication), or they would
// loop back into the tunnel.
package splittun

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// Rules choose what bypasses the tunnel.
type Rules struct {
	// Domains match the name and its subdomains: "ru" covers every .ru
	// site, "vk.com" covers vk.com and m.vk.com. Stored in ASCII form.
	Domains []string
	// Networks are always direct.
	Networks []netip.Prefix
	// DNS resolves the listed domains outside the tunnel, so that the
	// answers point at servers near the user (Russian CDNs answer
	// differently abroad).
	DNS netip.AddrPort
}

// PresetRU is "Russian sites directly": the national zones and the big
// Russian services that live on other zones.
var PresetRU = []string{
	"ru", "su", "xn--p1ai" /* рф */, "xn--80adxhks", /* москва */
	// VK and its CDNs
	"vk.com", "vk.me", "vk.ru", "userapi.com", "vkuser.net", "vkuseraudio.net", "vkuservideo.net", "vk-cdn.net", "mycdn.me", "vkvideo.ru",
	// Yandex
	"yandex.net", "yandex.com", "yastatic.net", "yandexcloud.net", "yandex.cloud", "ya.ru",
	// marketplaces, maps, banks with non-.ru names
	"wbstatic.net", "wbbasket.ru", "avito.st", "2gis.com", "sberbank.com", "tochka.com", "ozone.ru",
}

// DefaultDNS is the direct resolver when none is given (Yandex DNS).
var DefaultDNS = netip.MustParseAddrPort("77.88.8.8:53")

// ParseRules reads the config form: comma or space separated domains
// ("ru, рф, vk.com"; "preset:ru" expands to PresetRU), networks
// ("5.255.255.0/24") and a resolver ("77.88.8.8" or "77.88.8.8:53").
func ParseRules(domains, networks, dns string) (Rules, error) {
	var r Rules
	var errs []error
	for _, d := range fields(domains) {
		if strings.EqualFold(d, "preset:ru") {
			r.Domains = append(r.Domains, PresetRU...)
			continue
		}
		n, err := normalizeDomain(d)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		r.Domains = append(r.Domains, n)
	}
	for _, n := range fields(networks) {
		p, err := netip.ParsePrefix(n)
		if err != nil {
			a, aerr := netip.ParseAddr(n)
			if aerr != nil {
				errs = append(errs, fmt.Errorf("network %q: %w", n, err))
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if !p.Addr().Is4() {
			errs = append(errs, fmt.Errorf("network %q: only IPv4 goes directly", n))
			continue
		}
		r.Networks = append(r.Networks, p.Masked())
	}
	r.DNS = DefaultDNS
	if dns = strings.TrimSpace(dns); dns != "" {
		if ap, err := netip.ParseAddrPort(dns); err == nil {
			r.DNS = ap
		} else if a, err := netip.ParseAddr(dns); err == nil {
			r.DNS = netip.AddrPortFrom(a, 53)
		} else {
			errs = append(errs, fmt.Errorf("direct DNS %q: want an IP address", dns))
		}
	}
	return r, errors.Join(errs...)
}

func fields(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
}

func normalizeDomain(d string) (string, error) {
	d = strings.Trim(strings.ToLower(strings.TrimSpace(d)), ".")
	d = strings.TrimPrefix(d, "*.")
	if d == "" {
		return "", errors.New("empty domain")
	}
	a, err := idna.Lookup.ToASCII(d)
	if err != nil {
		return "", fmt.Errorf("domain %q: %w", d, err)
	}
	return a, nil
}

// Empty reports whether nothing would go directly.
func (r Rules) Empty() bool { return len(r.Domains) == 0 && len(r.Networks) == 0 }

// matcher answers "is this name listed" with one map lookup per label.
type matcher map[string]struct{}

func newMatcher(domains []string) matcher {
	m := matcher{}
	for _, d := range domains {
		m[d] = struct{}{}
	}
	return m
}

func (m matcher) match(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for {
		if _, ok := m[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
}
