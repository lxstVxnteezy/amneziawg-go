package splittun

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseRulesLists(t *testing.T) {
	r, err := ParseRules("preset:blocked, list:https://vpn.example.com/c/tok/blocked.lst, example.org", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Lists) != 1 || r.Lists[0] != "https://vpn.example.com/c/tok/blocked.lst" {
		t.Fatalf("lists %v", r.Lists)
	}
	if r.Empty() {
		t.Fatal("rules with domains are empty")
	}
	only, _ := ParseRules("list:https://vpn.example.com/l", "", "")
	if only.Empty() {
		t.Fatal("rules with only a list are empty: the device would not start")
	}
	for _, bad := range []string{"list:ftp://x.example/l", "list:not a url", "list:https://"} {
		if _, err := ParseRules(bad, "", ""); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestReadList(t *testing.T) {
	names, _, err := readList(strings.NewReader(`# blocked sites
youtube.com
  .Instagram.COM  # with a note
0.0.0.0 tracker.example
*.discord.gg

not a domain!
пример.рф
`))
	if err != nil {
		t.Fatal(err)
	}
	want := "youtube.com instagram.com tracker.example discord.gg xn--e1afmkfd.xn--p1ai"
	if got := strings.Join(names, " "); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if _, _, err := readList(strings.NewReader(strings.Repeat("a.example\n", listMaxBytes/10+1))); err == nil {
		t.Fatal("a list over the size limit accepted")
	}
}

// The device fetches its lists directly, merges them with the config's
// domains, keeps what it has when a fetch fails, and stops on Close.
func TestRefreshLists(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("youtube.com\nrutracker.org\n"))
	}))
	defer srv.Close()
	var dialed atomic.Int32
	var dialer net.Dialer
	d := &Device{closed: make(chan struct{}), cfg: Config{
		Rules: Rules{Domains: []string{"example.org"}, Lists: []string{srv.URL + "/blocked.lst"}},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed.Add(1)
			return dialer.DialContext(ctx, network, addr)
		},
		Log: t.Logf,
	}}
	m := newMatcher(d.cfg.Rules.Domains)
	d.domains.Store(&m)
	done := make(chan struct{})
	go func() { d.refreshLists(); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for !d.names().match("www.rutracker.org") {
		if time.Now().After(deadline) {
			t.Fatal("the list never arrived")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !d.names().match("example.org") {
		t.Fatal("the config's own domains were lost")
	}
	if dialed.Load() == 0 {
		t.Fatal("the list was not fetched through the direct dialer")
	}
	close(d.closed)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("refreshLists did not stop on close")
	}
}
