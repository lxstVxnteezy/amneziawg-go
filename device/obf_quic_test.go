package device

import (
	"bytes"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/quicinitial"
)

func TestQuicTag(t *testing.T) {
	for spec, want := range map[string]int{
		"<quic sni=vk.com>":          2,
		"<quic vk.com>":              2,
		"<quic sni=VK.com. classic>": 1,
	} {
		c, err := newObfChain(spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		a, err := c.Datagrams()
		if err != nil || len(a) != want {
			t.Fatalf("%s: %d datagrams, %v", spec, len(a), err)
		}
		info, err := quicinitial.Parse(a)
		if err != nil || info.SNI != "vk.com" {
			t.Fatalf("%s: SNI %q, %v", spec, info.SNI, err)
		}
		b, _ := c.Datagrams()
		if bytes.Equal(a[0], b[0]) {
			t.Fatalf("%s: the same flight twice", spec)
		}
	}
	// no sni: a ClientHello without server_name, like a browser to an IP
	for spec, want := range map[string]int{"<quic>": 2, "<quic classic>": 1} {
		c, err := newObfChain(spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		a, err := c.Datagrams()
		if err != nil || len(a) != want {
			t.Fatalf("%s: %d datagrams, %v", spec, len(a), err)
		}
		if info, err := quicinitial.Parse(a); err != nil || info.SNI != "" || info.ALPN != "h3" {
			t.Fatalf("%s: SNI %q ALPN %q, %v", spec, info.SNI, info.ALPN, err)
		}
	}
	for _, bad := range []string{
		"<quic sni=>",
		"<quic sni=1.2.3.4>",
		"<quic sni=localhost>",
		"<quic sni=vk.com pq=off>",
		"<quic sni=vk.com><quic sni=ya.ru>",
		"<b 0x01><quic sni=vk.com>",
		"<quic sni=vk.com><r 10>",
		"<r -5>", "<rc -1>", "<rd -100>", "<dz -2>", "<r 65536>",
	} {
		if _, err := newObfChain(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// Fixed chains keep working through Datagrams.
func TestDatagramsOfFixedChain(t *testing.T) {
	c, err := newObfChain("<b 0xf6ab3267fa><r 10>")
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.Datagrams()
	if err != nil || len(d) != 1 || len(d[0]) != 15 || !bytes.HasPrefix(d[0], []byte{0xf6, 0xab, 0x32, 0x67, 0xfa}) {
		t.Fatalf("%x %v", d, err)
	}
}

func TestQuicTagViaUAPI(t *testing.T) {
	dev := genTestPair(t, false)[0].dev
	if err := dev.IpcSet(uapiCfg("i1", "<quic sni=vk.com>", "i2", "<r 20>")); err != nil {
		t.Fatal(err)
	}
	if err := dev.IpcSet(uapiCfg("i1", "<quic sni=bad_name.com>")); err == nil || !strings.Contains(err.Error(), "I1") {
		t.Fatalf("bad SNI: %v", err)
	}
	if got := dev.ipackets[0].Load().Spec; got != "<quic sni=vk.com>" {
		t.Fatalf("a rejected config replaced I1: %q", got)
	}
}

// I1-I5 come from configs people paste: the parser must never panic.
func FuzzObfChain(f *testing.F) {
	for _, s := range []string{"<quic sni=vk.com>", "<b 0xf6ab><r 10><t>", "<quic sni=vk.com classic>", "<rc 5><rd 3>", "<", "<>", "<quic"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		c, err := newObfChain(spec)
		if err != nil || c == nil {
			return
		}
		if c.ObfuscatedLen(0) > 1<<20 {
			return // many large tags: valid, but not worth the memory here
		}
		c.Datagrams()
	})
}
