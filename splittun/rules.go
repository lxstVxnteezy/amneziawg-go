// Package splittun sends chosen sites past the tunnel (or, with
// Config.TunnelOnly, only chosen sites into it; see reverse.go), by domain name,
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
	// Lists are URLs of domain lists ("list:https://..."), fetched and
	// refreshed by the device (lists.go).
	Lists []string
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

// PresetBlocked is "into the tunnel only what is blocked": services that
// are blocked or slowed down in Russia, or that refuse Russian addresses
// themselves. Not complete: add your own names next to it.
var PresetBlocked = []string{
	// YouTube (slowed down since 2024) and its CDNs
	"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "ggpht.com", "youtube-nocookie.com", "youtubei.googleapis.com",
	// Meta (blocked since 2022)
	"instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net", "fb.com", "messenger.com", "threads.net",
	// X / Twitter, LinkedIn, Discord
	"x.com", "twitter.com", "twimg.com", "t.co", "linkedin.com", "licdn.com",
	"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media",
	// services that do not serve Russian addresses
	"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "anthropic.com", "claude.ai",
	"spotify.com", "scdn.co", "notion.so",
	// others blocked by Roskomnadzor
	"rutracker.org", "torproject.org", "proton.me", "signal.org",
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
		if strings.EqualFold(d, "preset:blocked") {
			r.Domains = append(r.Domains, PresetBlocked...)
			continue
		}
		if len(d) > 5 && strings.EqualFold(d[:5], "list:") {
			u, err := parseListURL(d[5:])
			if err != nil {
				errs = append(errs, err)
				continue
			}
			r.Lists = append(r.Lists, u)
			continue
		}
		n, err := normalizeRule(d)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		r.Domains = append(r.Domains, n)
	}
	for _, n := range fields(networks) {
		p, err := parseNetwork(n)
		if err == errNotNetwork {
			errs = append(errs, fmt.Errorf("network %q: only IPv4 goes directly", n))
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("network %q: %w", n, err))
			continue
		}
		r.Networks = append(r.Networks, p)
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
func (r Rules) Empty() bool { return len(r.Domains) == 0 && len(r.Networks) == 0 && len(r.Lists) == 0 }
