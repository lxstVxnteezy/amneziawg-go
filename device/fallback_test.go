/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// echoServer stands in for the HTTP/3 site: it answers every datagram
// with "echo:" + datagram.
func echoServer(t *testing.T) (netip.AddrPort, func() int) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	got := make(chan struct{}, 100)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			got <- struct{}{}
			c.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	return c.LocalAddr().(*net.UDPAddr).AddrPort(), func() int { return len(got) }
}

// probe sends a datagram to the device port from a fresh socket and
// returns the answer, or nil after timeout.
func probe(t *testing.T, port uint16, payload []byte, timeout time.Duration) []byte {
	t.Helper()
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 65536)
	n, err := c.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

func TestFallbackAnswersProbes(t *testing.T) {
	// header protection on: the first bytes of a non-AWG datagram get
	// "decrypted" in place and must be restored before relaying
	pair := genTestPair(t, true,
		"h1", "1000-2000", "h2", "3000-4000", "h3", "5000-6000", "h4", "7000-8000",
		"s1", "20", "s2", "30", "s3", "20", "s4", "20",
		"header_protection_key", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	)
	dev := pair[0].dev
	target, count := echoServer(t)

	// off by default: probes meet silence, as in upstream
	if got := probe(t, dev.net.port, []byte("hello?"), 300*time.Millisecond); got != nil {
		t.Fatalf("answer without fallback: %q", got)
	}

	if err := dev.IpcSet(uapiCfg("fallback", target.String())); err != nil {
		t.Fatal(err)
	}
	if s, _ := dev.IpcGet(); !strings.Contains(s, "fallback="+target.String()+"\n") {
		t.Fatal("fallback missing from IpcGet")
	}

	short := []byte("hi") // shorter than any AWG message
	initial := make([]byte, 1200)
	rand.Read(initial)
	initial[0] = 0xc3 // looks like a QUIC long header
	for _, payload := range [][]byte{short, initial} {
		got := probe(t, dev.net.port, payload, 3*time.Second)
		if want := append([]byte("echo:"), payload...); !bytes.Equal(got, want) {
			t.Fatalf("probe of %d bytes: got %d bytes back, want the echo of the original datagram", len(payload), len(got))
		}
	}

	// the tunnel is not affected, and its packets never reach the site
	before := count()
	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)
	if count() != before {
		t.Fatalf("%d AWG packets leaked to the fallback server", count()-before)
	}

	// off again
	if err := dev.IpcSet(uapiCfg("fallback", "off")); err != nil {
		t.Fatal(err)
	}
	if got := probe(t, dev.net.port, []byte("hello?"), 300*time.Millisecond); got != nil {
		t.Fatalf("answer after fallback=off: %q", got)
	}
}

func TestFallbackRelayLimit(t *testing.T) {
	pair := genTestPair(t, true)
	dev := pair[0].dev
	target, _ := echoServer(t)
	dev.SetFallback(target)

	// fill the table with fake remotes; the next one must be refused
	// instead of opening yet another socket
	for i := 0; len(dev.fallback.relays) < fallbackMaxRelays; i++ {
		ep, err := dev.net.bind.ParseEndpoint(fmt.Sprintf("127.0.0.1:%d", 10000+i))
		if err != nil {
			t.Fatal(err)
		}
		if dev.fallbackRelay(ep, target) == nil {
			t.Fatalf("relay %d refused below the limit", i)
		}
	}
	ep, _ := dev.net.bind.ParseEndpoint("127.0.0.2:9")
	if dev.fallbackRelay(ep, target) != nil {
		t.Fatal("relay opened above the limit")
	}
	dev.SetFallback(netip.AddrPort{})
	if len(dev.fallback.relays) != 0 {
		t.Fatal("relays survived disabling the fallback")
	}
}

func TestFallbackRejectsBadTarget(t *testing.T) {
	pair := genTestPair(t, false)
	if err := pair[0].dev.IpcSet(uapiCfg("fallback", "not-an-address")); err == nil {
		t.Fatal("bad fallback accepted")
	}
}
