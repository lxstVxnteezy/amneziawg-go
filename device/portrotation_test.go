/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPortRotationKeepsTunnelUp(t *testing.T) {
	pair := genTestPair(t, true)
	pair.Send(t, Ping, nil)

	dev := pair[0].dev
	before := dev.net.port
	dev.rotatePort()
	if dev.net.port == before {
		t.Fatalf("local port is still %d after rotation", before)
	}

	// The handshake sent from the new port moves the peer over without
	// any traffic from us. Packets it sends before that are lost, like any
	// packet in flight to a roaming peer.
	peer := pair[1].dev.LookupPeer(dev.staticIdentity.publicKey)
	want := fmt.Sprintf(":%d", dev.net.port)
	deadline := time.Now().Add(5 * time.Second)
	for {
		peer.endpoint.Lock()
		dst := peer.endpoint.val.DstToString()
		peer.endpoint.Unlock()
		if strings.HasSuffix(dst, want) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer still sends to %s, want port %s", dst, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)
}

func TestPortRotationLeavesExplicitPortAlone(t *testing.T) {
	pair := genTestPair(t, true)
	dev := pair[0].dev
	port := dev.net.port
	if err := dev.IpcSet(uapiCfg("listen_port", fmt.Sprint(port))); err != nil {
		t.Fatal(err)
	}
	dev.rotatePort()
	if dev.net.port != port {
		t.Fatalf("explicit listen_port %d rotated to %d", port, dev.net.port)
	}
}

func TestPortRotationUAPI(t *testing.T) {
	pair := genTestPair(t, false)
	dev := pair[0].dev
	if err := dev.IpcSet(uapiCfg("port_rotation", "5")); err == nil {
		t.Fatal("port_rotation below the minimum accepted")
	}
	if err := dev.IpcSet(uapiCfg("port_rotation", "120-300")); err != nil {
		t.Fatal(err)
	}
	got, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "port_rotation=120-300\n") {
		t.Fatal("port_rotation missing from IpcGet")
	}
	if err := dev.IpcSet(uapiCfg("port_rotation", "0")); err != nil {
		t.Fatal(err)
	}
}
