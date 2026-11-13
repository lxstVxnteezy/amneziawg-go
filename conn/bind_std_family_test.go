package conn

import (
	"net"
	"syscall"
	"testing"
)

// withoutFamily makes Open see a host that lacks one address family.
func withoutFamily(t *testing.T, missing string) {
	t.Helper()
	orig := listenNetFn
	t.Cleanup(func() { listenNetFn = orig })
	listenNetFn = func(network string, port int) (*net.UDPConn, int, error) {
		if network == missing {
			return nil, 0, &net.OpError{Op: "listen", Net: network, Err: syscall.EAFNOSUPPORT}
		}
		// the other family is played by IPv4, which every test host has
		return orig("udp4", port)
	}
}

func localPort(t *testing.T, c *net.UDPConn) uint16 {
	t.Helper()
	if c == nil {
		t.Fatal("socket not opened")
	}
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

// On a host without IPv6 Open must report the port the IPv4 socket really
// has. It used to report 0: the device then showed no listen port and
// moved to a random one at the next rebind.
func TestOpenReportsThePortWithoutIPv6(t *testing.T) {
	withoutFamily(t, "udp6")

	b := NewStdNetBind().(*StdNetBind)
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if len(fns) != 1 || b.ipv6 != nil {
		t.Fatalf("%d receive functions, ipv6 %v", len(fns), b.ipv6)
	}
	if want := localPort(t, b.ipv4); port == 0 || port != want {
		t.Fatalf("Open(0) reported port %d, the socket listens on %d", port, want)
	}

	// an explicit port (a server's ListenPort) comes back as it is
	b.Close()
	b2 := NewStdNetBind().(*StdNetBind)
	_, got, err := b2.Open(port)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close()
	if got != port || localPort(t, b2.ipv4) != port {
		t.Fatalf("Open(%d) reported %d, socket on %d", port, got, localPort(t, b2.ipv4))
	}
}

// On a host without IPv4 the requested port must reach the IPv6 socket.
func TestOpenKeepsTheRequestedPortWithoutIPv4(t *testing.T) {
	// find a free port
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	want := uint16(probe.LocalAddr().(*net.UDPAddr).Port)
	probe.Close()

	withoutFamily(t, "udp4")
	b := NewStdNetBind().(*StdNetBind)
	fns, port, err := b.Open(want)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if len(fns) != 1 || b.ipv4 != nil {
		t.Fatalf("%d receive functions, ipv4 %v", len(fns), b.ipv4)
	}
	if port != want || localPort(t, b.ipv6) != want {
		t.Fatalf("Open(%d) reported %d, the socket listens on %d", want, port, localPort(t, b.ipv6))
	}
}

// No family at all is still an error.
func TestOpenWithoutAnyFamily(t *testing.T) {
	orig := listenNetFn
	t.Cleanup(func() { listenNetFn = orig })
	listenNetFn = func(network string, port int) (*net.UDPConn, int, error) {
		return nil, 0, &net.OpError{Op: "listen", Net: network, Err: syscall.EAFNOSUPPORT}
	}
	if _, _, err := NewStdNetBind().Open(0); err == nil {
		t.Fatal("Open succeeded without sockets")
	}
}
