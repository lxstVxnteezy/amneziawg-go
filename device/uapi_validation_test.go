package device

import (
	"strings"
	"testing"
)

func TestUAPIRejectsJminGreaterThanJmax(t *testing.T) {
	pair := genTestPair(t, false)
	dev := pair[0].dev

	err := dev.IpcSet(uapiCfg("jc", "3", "jmin", "100", "jmax", "10"))
	if err == nil || !strings.Contains(err.Error(), "jmin") {
		t.Fatalf("expected jmin/jmax error, got %v", err)
	}
	if dev.junk.count.Load() != 0 {
		t.Fatal("rejected junk config was partially applied")
	}

	// order of lines must not matter for a valid config
	if err := dev.IpcSet(uapiCfg("jmin", "100", "jmax", "200", "jc", "3")); err != nil {
		t.Fatal(err)
	}
	if err := dev.IpcSet(uapiCfg("jmax", "500", "jmin", "300")); err != nil {
		t.Fatal(err)
	}
	for _, b := range dev.JunkPackets() {
		if len(b) < 300 || len(b) >= 500 {
			t.Fatalf("junk packet size %d out of [300,500)", len(b))
		}
	}
}

func TestUAPIRejectedConfigIsNotPartiallyApplied(t *testing.T) {
	pair := genTestPair(t, false)
	dev := pair[0].dev
	before := dev.headers.init.Load()

	// headers are valid, but S1 is too small for header protection
	err := dev.IpcSet(uapiCfg(
		"h1", "1000-2000", "h2", "3000-4000", "h3", "5000-6000", "h4", "7000-8000",
		"s1", "5", "s2", "20", "s3", "20", "s4", "20",
		"header_protection_key", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	))
	if err == nil || !strings.Contains(err.Error(), "S1 ") {
		t.Fatalf("expected S1 error, got %v", err)
	}
	if dev.headers.init.Load() != before {
		t.Fatal("headers were applied although the config was rejected")
	}
}
