package splittun

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
// A list is text, one domain per line; "#" starts a comment, and only the
// first field of a line counts, so hosts-style and "domain # note" lines
// work.

const (
	listRefresh  = 12 * time.Hour
	listRetry    = 10 * time.Minute
	listTimeout  = 30 * time.Second
	listMaxBytes = 2 << 20 // 2 MB
	listMaxNames = 50000
)

// parseListURL checks a "list:" entry.
func parseListURL(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", fmt.Errorf("list %q: want an http(s) URL", s)
	}
	return u.String(), nil
}

// readList reads a list body: the domains it holds, invalid lines skipped.
func readList(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(io.LimitReader(r, listMaxBytes+1))
	read := 0
	for sc.Scan() {
		read += len(sc.Bytes()) + 1
		if read > listMaxBytes {
			return nil, fmt.Errorf("list larger than %d bytes", listMaxBytes)
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
		// a name with at least two labels: a bare "com" in a downloaded
		// list would take half the internet with it
		n, err := normalizeDomain(name)
		if err != nil || !strings.Contains(n, ".") {
			continue
		}
		out = append(out, n)
		if len(out) > listMaxNames {
			return nil, fmt.Errorf("list has more than %d names", listMaxNames)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// fetchList downloads one list through dial.
func fetchList(ctx context.Context, dial Dialer, u string) ([]string, error) {
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
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	return readList(resp.Body)
}

// refreshLists keeps the fetched lists current until the device closes.
func (d *Device) refreshLists() {
	fetched := map[string][]string{}
	for {
		var errs []error
		for _, u := range d.cfg.Rules.Lists {
			ctx, cancel := context.WithTimeout(context.Background(), listTimeout)
			names, err := fetchList(ctx, d.cfg.Dial, u)
			cancel()
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", u, err))
				continue
			}
			fetched[u] = names
		}
		all := append([]string(nil), d.cfg.Rules.Domains...)
		total := 0
		for _, names := range fetched {
			all = append(all, names...)
			total += len(names)
		}
		m := newMatcher(all)
		d.domains.Store(&m)
		wait := listRefresh
		if err := errors.Join(errs...); err != nil {
			d.cfg.Log("Split tunneling lists: %v; keeping %d names, again in %v", err, total, listRetry)
			wait = listRetry
		} else {
			d.cfg.Log("Split tunneling lists: %d names from %d lists", total, len(d.cfg.Rules.Lists))
		}
		select {
		case <-d.closed:
			return
		case <-time.After(wait):
		}
	}
}
