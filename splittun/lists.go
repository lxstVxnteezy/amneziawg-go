package splittun

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Lists of domains fetched from a URL ("list:https://..." among the
// domains), so a list of blocked sites keeps up without a new app: the
// panel serves one behind the client's subscription link and refreshes it
// from a public source. The device fetches each list directly (not
// through the tunnel), merges it with the domains of the config and
// fetches it again every listRefresh. Until the first fetch, and when one
// fails, the domains it already has stay in force: the built-in preset
// covers the start.
//
// A list is text, one rule per line; "#" starts a comment, and only the
// first field of a line counts, so hosts-style and "domain # note" lines
// work. A rule is a domain or a v2ray-style "full:", "keyword:",
// "regexp:" rule (match.go), which is what geosite categories become, or
// an IPv4 network ("5.255.255.0/24"), which is what geoip categories
// become: networks go directly in the direct mode. In the tunnel-only
// mode the system routes only the config's networks into the VPN, so
// networks from a list do nothing there.

const (
	listRefresh  = 12 * time.Hour
	listRetry    = 10 * time.Minute
	listTimeout  = 30 * time.Second
	listMaxBytes = 8 << 20 // 8 MB: geosite "ru-blocked" is ~75 000 names
	listMaxNames = 200000
)

// parseListURL checks a "list:" entry.
func parseListURL(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", fmt.Errorf("list %q: want an http(s) URL", s)
	}
	return u.String(), nil
}

// readList reads a list body: the domain rules and networks it holds,
// invalid lines skipped.
func readList(r io.Reader) ([]string, []netip.Prefix, error) {
	var out []string
	var nets []netip.Prefix
	sc := bufio.NewScanner(io.LimitReader(r, listMaxBytes+1))
	read := 0
	for sc.Scan() {
		read += len(sc.Bytes()) + 1
		if read > listMaxBytes {
			return nil, nil, fmt.Errorf("list larger than %d bytes", listMaxBytes)
		}
		line, _, _ := strings.Cut(sc.Text(), "#")
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		name := f[0]
		if len(f) > 1 && (name == "0.0.0.0" || name == "127.0.0.1") { // hosts file
			name = f[1]
		}
		if len(out)+len(nets) >= listMaxNames {
			return nil, nil, fmt.Errorf("list has more than %d rules", listMaxNames)
		}
		if strings.ContainsAny(name, "/") || strings.Count(name, ".") == 3 && strings.Trim(name, "0123456789.") == "" {
			if p, err := parseNetwork(name); err == nil && p.Bits() >= 8 {
				nets = append(nets, p) // shorter than /8 would take a huge part of the internet
			}
			continue
		}
		// a domain with at least two labels: a bare "com" in a downloaded
		// list would take half the internet with it
		n, err := normalizeRule(name)
		if err != nil {
			continue
		}
		if plain := strings.TrimPrefix(n, "full:"); !strings.Contains(n, ":") || plain != n {
			if !strings.Contains(plain, ".") {
				continue
			}
		}
		out = append(out, n)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	return out, nets, nil
}

// fetchList downloads one list through dial.
func fetchList(ctx context.Context, dial Dialer, u string) ([]string, []netip.Prefix, error) {
	client := &http.Client{
		Timeout: listTimeout,
		Transport: &http.Transport{
			DialContext:         func(ctx context.Context, network, addr string) (net.Conn, error) { return dial(ctx, network, addr) },
			TLSHandshakeTimeout: 10 * time.Second,
			Proxy:               nil, // straight to the panel, past any proxy setting
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	return readList(resp.Body)
}

// refreshLists keeps the fetched lists current until the device closes.
func (d *Device) refreshLists() {
	type list struct {
		names []string
		nets  []netip.Prefix
	}
	fetched := map[string]list{}
	for {
		var errs []error
		for _, u := range d.cfg.Rules.Lists {
			ctx, cancel := context.WithTimeout(context.Background(), listTimeout)
			names, nets, err := fetchList(ctx, d.cfg.Dial, u)
			cancel()
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", u, err))
				continue
			}
			fetched[u] = list{names, nets}
		}
		all := append([]string(nil), d.cfg.Rules.Domains...)
		allNets := append([]netip.Prefix(nil), d.cfg.Rules.Networks...)
		total, totalNets := 0, 0
		for _, l := range fetched {
			all = append(all, l.names...)
			allNets = append(allNets, l.nets...)
			total += len(l.names)
			totalNets += len(l.nets)
		}
		m := newMatcher(all)
		d.domains.Store(&m)
		ns := newNetSet(allNets)
		d.nets.Store(&ns)
		wait := listRefresh
		if err := errors.Join(errs...); err != nil {
			d.cfg.Log("Split tunneling lists: %v; keeping %d names and %d networks, again in %v", err, total, totalNets, listRetry)
			wait = listRetry
		} else {
			d.cfg.Log("Split tunneling lists: %d names and %d networks (%d ranges) from %d lists", total, totalNets, ns.size(), len(d.cfg.Rules.Lists))
		}
		select {
		case <-d.closed:
			return
		case <-time.After(wait):
		}
	}
}
