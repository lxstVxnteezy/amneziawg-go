package device

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"golang.org/x/net/ipv4"
)

var headerProtectionCfg = []string{
	"s1", "15",
	"s2", "18",
	"s3", "20",
	"s4", "25",
	"h1", "123456-123500",
	"h2", "67543-67550",
	"h3", "123123-123200",
	"h4", "32345-32350",
	"header_protection_key", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
}

func TestHeaderProtectionDevicePing(t *testing.T) {
	goroutineLeakCheck(t)

	pair := genTestPair(t, false, headerProtectionCfg...)
	if pair[0].dev.headerProtection.active.Load() == nil {
		t.Fatal("header protection key was not applied")
	}
	t.Run("ping 1.0.0.1", func(t *testing.T) {
		pair.Send(t, Ping, nil)
	})
	t.Run("ping 1.0.0.2", func(t *testing.T) {
		pair.Send(t, Pong, nil)
	})
}

// BenchmarkHeaderProtectionCipher measures the per-packet header cipher setup
// done by every encryption worker and by the receive loop.
func BenchmarkHeaderProtectionCipher(b *testing.B) {
	pair := genTestPair(b, false, headerProtectionCfg...)
	dev := pair[0].dev

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var salt [HeaderCipherNonceSize]byte
		var header [MessageTransportHeaderSize]byte
		for pb.Next() {
			cip, err := dev.HeaderProtectionCipher(salt[:])
			if err != nil || cip == nil {
				b.Fatal("no header cipher")
			}
			cip.XORKeyStream(header[:], header[:])
		}
	})
}

// bigPing returns an IPv4 packet of the given total size; only the IP
// header has to be valid for the device data path.
func bigPing(dst, src netip.Addr, size int) []byte {
	small := tuntest.Ping(dst, src)
	pkt := make([]byte, size)
	copy(pkt, small)
	binary.BigEndian.PutUint16(pkt[2:], uint16(size))
	pkt[10], pkt[11] = 0, 0
	var sum uint32
	for i := 0; i < ipv4.HeaderLen; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i:]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	binary.BigEndian.PutUint16(pkt[10:], ^uint16(sum))
	return pkt
}

func benchmarkThroughput(b *testing.B, size int, cfg ...string) {
	pair := genTestPair(b, false, cfg...)

	pair.Send(b, Ping, nil)
	pair.Send(b, Pong, nil)

	var recv atomic.Uint64
	var elapsed time.Duration
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var start time.Time
		for {
			<-pair[0].tun.Inbound
			new := recv.Add(1)
			if new == 1 {
				start = time.Now()
			}
			if new == uint64(b.N) {
				elapsed = time.Since(start)
				return
			}
		}
	}()

	ping := bigPing(pair[0].ip, pair[1].ip, size)
	pingc := pair[1].tun.Outbound
	var sent uint64
	for recv.Load() != uint64(b.N) {
		sent++
		pingc <- ping
	}
	wg.Wait()

	b.ReportMetric(float64(elapsed)/float64(b.N), "ns/op")
	b.ReportMetric(float64(size)*float64(b.N)/elapsed.Seconds()/1e6, "MB/s")
	b.ReportMetric(1-float64(b.N)/float64(sent), "packet-loss")
}

func BenchmarkThroughputHeaderProtection(b *testing.B) {
	b.Run("small", func(b *testing.B) { benchmarkThroughput(b, 32, headerProtectionCfg...) })
	b.Run("1400", func(b *testing.B) { benchmarkThroughput(b, 1400, headerProtectionCfg...) })
}

func BenchmarkThroughputPlain1400(b *testing.B) {
	benchmarkThroughput(b, 1400)
}

func BenchmarkLatencyHeaderProtection(b *testing.B) {
	pair := genTestPair(b, false, headerProtectionCfg...)

	pair.Send(b, Ping, nil)
	pair.Send(b, Pong, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pair.Send(b, Ping, nil)
		pair.Send(b, Pong, nil)
	}
}
