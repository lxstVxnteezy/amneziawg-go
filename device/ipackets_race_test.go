package device

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// I1-I5 are replaced by IpcSet while handshakes read them and IpcGet
// prints them. Run with -race: the plain array this used to be was written
// without any lock.
func TestIPacketsReconfiguredDuringHandshakes(t *testing.T) {
	pair := genTestPair(t, false)
	dev := pair[0].dev
	var peer *Peer
	dev.peers.RLock()
	for _, p := range dev.peers.keyMap {
		peer = p
	}
	dev.peers.RUnlock()
	if peer == nil {
		t.Fatal("no peer")
	}

	const rounds = 150
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { // the configuration changes
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			spec := fmt.Sprintf("<b 0x%02x%02x>", i%256, (i*7)%256)
			if i%5 == 4 {
				spec = "" // cleared
			}
			if err := dev.IpcSet(uapiCfg(fmt.Sprintf("i%d", i%5+1), spec)); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() { // handshakes go out
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			peer.handshake.mutex.Lock()
			peer.handshake.lastSentHandshake = peer.handshake.lastSentHandshake.Add(-RekeyTimeout * 10)
			peer.handshake.mutex.Unlock()
			peer.SendHandshakeInitiation(false)
		}
	}()
	go func() { // awg show
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if _, err := dev.IpcGet(); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	wg.Wait()

	// what was set last is what the device reports and sends
	if err := dev.IpcSet(uapiCfg("i1", "<b 0xcafe>", "i2", "", "i3", "<b 0x01>", "i4", "", "i5", "")); err != nil {
		t.Fatal(err)
	}
	got, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "i1=<b 0xcafe>\n") || !strings.Contains(got, "i3=<b 0x01>\n") ||
		strings.Contains(got, "i2=") || strings.Contains(got, "i4=") || strings.Contains(got, "i5=") {
		t.Fatalf("I-packets after reconfiguration:\n%s", got)
	}
}
