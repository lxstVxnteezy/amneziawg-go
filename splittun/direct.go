package splittun

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// direct terminates the apps' direct TCP and UDP flows in a userspace
// stack and re-originates them from this process.
type direct struct {
	ep     *channel.Endpoint
	s      *stack.Stack
	dial   Dialer
	out    func([]byte)
	log    Logger
	refuse func(netip.AddrPort) bool // connections answered with a reset
	handle *channel.NotificationHandle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

const nicID = 1

func newDirect(mtu int, dial Dialer, out func([]byte), log Logger) (*direct, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	x := &direct{ep: channel.New(512, uint32(mtu), ""), s: s, dial: dial, out: out, log: log}
	x.ctx, x.cancel = context.WithCancel(context.Background())
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	if err := s.CreateNIC(nicID, x.ep); err != nil {
		return nil, fmt.Errorf("CreateNIC: %s", err)
	}
	// the stack answers for every address the apps connect to
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	tf := tcp.NewForwarder(s, 0, 2048, x.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)
	uf := udp.NewForwarder(s, x.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, uf.HandlePacket)
	x.handle = x.ep.AddNotify(x)
	return x, nil
}

// inject hands a packet from the OS to the stack (copied).
func (x *direct) inject(pkt []byte) {
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
	x.ep.InjectInbound(header.IPv4ProtocolNumber, pb)
	pb.DecRef()
}

// WriteNotify: the stack has a packet for the apps.
func (x *direct) WriteNotify() {
	for {
		pkt := x.ep.Read()
		if pkt.IsNil() {
			return
		}
		v := pkt.ToView()
		pkt.DecRef()
		x.out(v.AsSlice())
		v.Release()
	}
}

func addrPort(a tcpip.Address, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return netip.AddrPortFrom(ip, port)
}

func (x *direct) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst := addrPort(id.LocalAddress, id.LocalPort)
	if x.refuse != nil && x.refuse(dst) {
		r.Complete(true)
		return
	}
	x.wg.Add(1)
	go func() {
		defer x.wg.Done()
		ctx, cancel := context.WithTimeout(x.ctx, 15*time.Second)
		remote, err := x.dial(ctx, "tcp", dst.String())
		cancel()
		if err != nil {
			x.log("splittun: direct %s: %v", dst, err)
			r.Complete(true) // the app sees a reset, as with a refused connection
			return
		}
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			remote.Close()
			r.Complete(true)
			return
		}
		r.Complete(false)
		ep.SocketOptions().SetKeepAlive(true)
		local := gonet.NewTCPConn(&wq, ep)
		relay(local, remote)
	}()
}

// relay copies both ways until both sides are done.
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}

func (x *direct) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	dst := addrPort(id.LocalAddress, id.LocalPort)
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return
	}
	local := gonet.NewUDPConn(x.s, &wq, ep)
	x.wg.Add(1)
	go func() {
		defer x.wg.Done()
		defer local.Close()
		ctx, cancel := context.WithTimeout(x.ctx, 10*time.Second)
		remote, err := x.dial(ctx, "udp", dst.String())
		cancel()
		if err != nil {
			x.log("splittun: direct udp %s: %v", dst, err)
			return
		}
		defer remote.Close()
		var once sync.Once
		stop := func() { once.Do(func() { local.Close(); remote.Close() }) }
		go func() {
			defer stop()
			buf := make([]byte, 65535)
			for {
				remote.SetReadDeadline(time.Now().Add(udpIdle))
				n, err := remote.Read(buf)
				if err != nil {
					return
				}
				if _, err := local.Write(buf[:n]); err != nil {
					return
				}
			}
		}()
		buf := make([]byte, 65535)
		for {
			local.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := local.Read(buf)
			if err != nil {
				stop()
				return
			}
			if _, err := remote.Write(buf[:n]); err != nil {
				stop()
				return
			}
		}
	}()
}

func (x *direct) close() {
	x.cancel()
	x.ep.RemoveNotify(x.handle)
	x.s.Close()
	x.ep.Close()
}
