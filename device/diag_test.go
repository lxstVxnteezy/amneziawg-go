/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// ipcValues returns the values of key in the IpcGet output, in order.
func ipcValues(t *testing.T, d *Device, key string) []string {
	t.Helper()
	s, err := d.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			out = append(out, v)
		}
	}
	return out
}

func ipcInt(t *testing.T, d *Device, key string) int64 {
	t.Helper()
	v := ipcValues(t, d, key)
	if len(v) != 1 {
		t.Fatalf("%s: %v", key, v)
	}
	n, _ := strconv.ParseInt(v[0], 10, 64)
	return n
}

// source returns the diag_source counters for addr.
func source(t *testing.T, d *Device, addr string) (unknown, invalid int) {
	t.Helper()
	for _, v := range ipcValues(t, d, "diag_source") {
		f := strings.Split(v, ",")
		if len(f) != 7 {
			t.Fatalf("diag_source %q", v)
		}
		if f[0] == addr {
			u, _ := strconv.Atoi(f[1])
			i, _ := strconv.Atoi(f[2])
			return u, i
		}
	}
	return 0, 0
}

func TestDiagHealthyPeer(t *testing.T) {
	pair := genTestPair(t, true)
	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)

	// dev0 answers dev1's handshake or the other way round; the side that
	// received the initiation counts it
	inits := ipcInt(t, pair[0].dev, "diag_handshake_inits") + ipcInt(t, pair[1].dev, "diag_handshake_inits")
	resps := ipcInt(t, pair[0].dev, "diag_handshake_responses") + ipcInt(t, pair[1].dev, "diag_handshake_responses")
	if inits < 1 || resps < 1 {
		t.Fatalf("inits %d responses %d", inits, resps)
	}
	for i := range pair {
		if ipcInt(t, pair[i].dev, "diag_last_transport_sec") == 0 || ipcInt(t, pair[i].dev, "diag_session_start_sec") == 0 {
			t.Fatalf("dev%d: no transport recorded", i)
		}
	}
}

func TestDiagUnknownAndInvalidSources(t *testing.T) {
	pair := genTestPair(t, true)
	srv := pair[0].dev

	// junk from somewhere: not AWG for this server
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(srv.net.port)})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		c.Write([]byte("definitely not wireguard, just junk bytes"))
	}
	c.Close()

	// a client whose key the server does not know (an outdated config):
	// its handshake has the right shape and MAC1, but does not verify
	var stranger NoisePrivateKey
	rand.Read(stranger[:])
	srvPub := srv.staticIdentity.publicKey
	tun := tuntest.NewChannelTUN()
	dev := NewDevice(tun.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, "stranger: "))
	t.Cleanup(dev.Close)
	cfg := uapiCfg(
		"private_key", hex.EncodeToString(stranger[:]),
		"listen_port", "0",
		"public_key", hex.EncodeToString(srvPub[:]),
		"endpoint", fmt.Sprintf("127.0.0.1:%d", srv.net.port),
		"allowed_ip", "1.0.0.1/32",
	)
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	tun.Outbound <- tuntest.Ping(netip.MustParseAddr("1.0.0.1"), netip.MustParseAddr("1.0.0.9"))

	deadline := time.Now().Add(5 * time.Second)
	for {
		unknown, invalid := source(t, srv, "127.0.0.1")
		if unknown >= 3 && invalid >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("source 127.0.0.1: unknown %d, invalid %d", unknown, invalid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestDiagSourceTableIsBounded(t *testing.T) {
	pair := genTestPair(t, false)
	dev := pair[0].dev
	for i := 0; i < diagMaxSources+50; i++ {
		ep, err := conn.NewStdNetBind().ParseEndpoint(fmt.Sprintf("10.%d.%d.%d:1", i>>16&255, i>>8&255, i&255))
		if err != nil {
			t.Fatal(err)
		}
		dev.diagSource(ep, diagUnknown, 10)
	}
	if n := len(dev.diag.m); n != diagMaxSources {
		t.Fatalf("%d sources kept", n)
	}
}
