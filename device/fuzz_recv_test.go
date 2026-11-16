package device

import (
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// Whatever arrives on the socket goes through DeterminePacketTypeAndPadding
// first. On any input, with or without RandomTrailers, a recognised type
// must fit the datagram: the receive loop slices packet[padding:] and
// packet[:msgSize] right after.
func FuzzDeterminePacketType(f *testing.F) {
	dev := NewDevice(tuntest.NewChannelTUN().TUN(), bindtest.NewChannelBinds()[0], NewLogger(LogLevelError, ""))
	f.Cleanup(dev.Close)
	params := []string{"s1", "20", "s2", "30", "s3", "24", "s4", "16",
		"h1", "123456-123500", "h2", "67543-67550", "h3", "123123-123200", "h4", "32345-32350"}
	if err := dev.IpcSet(uapiCfg(params...)); err != nil {
		f.Fatal(err)
	}
	f.Add(make([]byte, 20+MessageInitiationSize), false, uint32(0))
	f.Add(make([]byte, 16+MessageTransportSize+40), true, uint32(0xdeadbeef))
	f.Add([]byte{1, 2, 3}, true, uint32(1))
	f.Fuzz(func(t *testing.T, packet []byte, trailers bool, hash uint32) {
		dev.randomTrailers.Store(trailers)
		typeHash := []byte{byte(hash), byte(hash >> 8), byte(hash >> 16), byte(hash >> 24)}
		msgSize, msgType, padding := dev.DeterminePacketTypeAndPadding(packet, typeHash)
		if msgType == MessageUnknownType {
			return
		}
		if int(padding)+msgSize > len(packet) {
			t.Fatalf("type %d: padding %d + size %d > datagram %d", msgType, padding, msgSize, len(packet))
		}
	})
}
