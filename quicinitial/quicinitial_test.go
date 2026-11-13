package quicinitial

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readHex(t *testing.T, name string) []byte {
	t.Helper()
	s, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return mustHex(t, string(s))
}

var rfcDCID = "8394c8f03e515708"

// RFC 9001, Appendix A.1
func TestInitialKeysRFC9001(t *testing.T) {
	k := clientInitialKeys(mustHex(t, rfcDCID))
	for name, got := range map[string][]byte{
		"1f369613dd76d5467730efcbe3b1a22d": k.key,
		"fa044b2f42a3fd3b46fb255c":         k.iv,
		"9f50449e04a0e810283a1e9933adedd2": k.hp,
	} {
		if hex.EncodeToString(got) != name {
			t.Errorf("got %x, want %s", got, name)
		}
	}
}

// RFC 9001, Appendix A.2: the full protected client Initial, byte for byte.
func TestSealInitialRFC9001(t *testing.T) {
	frames := readHex(t, "rfc9001_a2_crypto.hex")
	frames = append(frames, make([]byte, 1162-len(frames))...)
	want := readHex(t, "rfc9001_a2_packet.hex")

	got, err := sealInitial(mustHex(t, rfcDCID), nil, 2, frames)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("protected packet differs from RFC 9001 A.2\n got %x\nwant %x", got[:48], want[:48])
	}
}

func openInitial(t *testing.T, p []byte) (dcid []byte, pn uint32, frames []byte) {
	t.Helper()
	dcid, pn, frames, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	return dcid, pn, frames
}

func sniFromClientHello(t *testing.T, m []byte) (sni, alpn string) {
	t.Helper()
	sni, alpn, err := ParseClientHello(m)
	if err != nil {
		t.Fatal(err)
	}
	return sni, alpn
}

func cryptoData(t *testing.T, frames []byte) map[int][]byte {
	t.Helper()
	d, err := CryptoData(frames)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func clientHelloFromInitials(t *testing.T, pkts [][]byte) []byte {
	t.Helper()
	info, err := Parse(pkts)
	if err != nil {
		t.Fatal(err)
	}
	return info.ClientHello
}

func TestQuicInitialsLookLikeHTTP3(t *testing.T) {
	pkts, err := Flight("vk.com", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pkts) != 2 {
		t.Fatalf("%d Initials, a post-quantum ClientHello takes 2", len(pkts))
	}
	hello := clientHelloFromInitials(t, pkts)
	sni, alpn := sniFromClientHello(t, hello)
	if sni != "vk.com" || alpn != "h3" {
		t.Errorf("sni=%q alpn=%q", sni, alpn)
	}

	// SNI must be readable from the first datagram alone
	_, _, frames := openInitial(t, pkts[0])
	if !bytes.Contains(cryptoData(t, frames)[0], []byte("vk.com")) {
		t.Error("SNI is not in the first Initial")
	}

	exts := extensionTypes(t, hello)
	for _, want := range []uint16{0x0033, 0x0039, 0x001b, 0x44cd} {
		if !slices.Contains(exts, want) {
			t.Errorf("extension %#04x missing", want)
		}
	}
	if !isGrease(exts[0]) || !isGrease(exts[len(exts)-1]) {
		t.Error("ClientHello is not wrapped in GREASE extensions like Chrome's")
	}
}

func TestClientHelloIsRandomized(t *testing.T) {
	a, _ := clientHello("vk.com", nil, false)
	b, _ := clientHello("vk.com", nil, false)
	if bytes.Equal(a, b) {
		t.Fatal("two ClientHellos are identical")
	}
}

func isGrease(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>12 == (v>>4)&0x0f }

// extensionTypes lists the extension types of a ClientHello in order.
func extensionTypes(t *testing.T, m []byte) []uint16 {
	t.Helper()
	b := m[4:]
	b = b[2+32:]
	b = b[1+int(b[0]):]
	b = b[2+int(binary.BigEndian.Uint16(b)):]
	b = b[1+int(b[0]):]
	exts := b[2 : 2+int(binary.BigEndian.Uint16(b))]
	var out []uint16
	for len(exts) > 0 {
		out = append(out, binary.BigEndian.Uint16(exts))
		exts = exts[4+int(binary.BigEndian.Uint16(exts[2:])):]
	}
	return out
}

func TestClassicFitsOneDatagram(t *testing.T) {
	pkts, err := Flight("vk.com", Options{Classic: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(pkts) != 1 || len(pkts[0]) != initialDatagram {
		t.Fatalf("%d Initials of %d bytes", len(pkts), len(pkts[0]))
	}
	hello := clientHelloFromInitials(t, pkts)
	if sni, _ := sniFromClientHello(t, hello); sni != "vk.com" {
		t.Errorf("sni=%q", sni)
	}
	if bytes.Contains(hello, []byte{0x11, 0xec}) && len(hello) > 1000 {
		t.Error("classic ClientHello carries the post-quantum key share")
	}
}

// No SNI: the ClientHello a browser sends to an IP address. Everything
// else, ALPN h3 and the GREASE wrapping included, stays Chrome's.
func TestFlightWithoutSNI(t *testing.T) {
	for _, classic := range []bool{false, true} {
		pkts, err := Flight("", Options{Classic: classic})
		if err != nil {
			t.Fatal(err)
		}
		if want := map[bool]int{false: 2, true: 1}[classic]; len(pkts) != want {
			t.Fatalf("classic=%v: %d Initials, want %d", classic, len(pkts), want)
		}
		hello := clientHelloFromInitials(t, pkts)
		if sni, alpn := sniFromClientHello(t, hello); sni != "" || alpn != "h3" {
			t.Errorf("classic=%v: sni=%q alpn=%q", classic, sni, alpn)
		}
		exts := extensionTypes(t, hello)
		if slices.Contains(exts, 0x0000) {
			t.Errorf("classic=%v: server_name extension present", classic)
		}
		for _, want := range []uint16{0x0033, 0x0039, 0x001b, 0x44cd} {
			if !slices.Contains(exts, want) {
				t.Errorf("classic=%v: extension %#04x missing", classic, want)
			}
		}
		if !isGrease(exts[0]) || !isGrease(exts[len(exts)-1]) {
			t.Errorf("classic=%v: not wrapped in GREASE extensions", classic)
		}
	}
}

// Every flight is a new connection attempt: nothing repeats.
func TestFlightsDiffer(t *testing.T) {
	a, err := Flight("vk.com", Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Flight("vk.com", Options{})
	dcidA, _, _ := openInitial(t, a[0])
	dcidB, _, _ := openInitial(t, b[0])
	if bytes.Equal(dcidA, dcidB) || bytes.Equal(a[0], b[0]) {
		t.Fatal("two flights share a connection ID or bytes")
	}
	dcidA2, pn, _ := openInitial(t, a[1])
	if !bytes.Equal(dcidA, dcidA2) || pn != 1 {
		t.Fatalf("second Initial: dcid %x pn %d", dcidA2, pn)
	}
}

func TestCheckSNI(t *testing.T) {
	for _, ok := range []string{"vk.com", "vpn.example.com", "xn--80ak6aa92e.com"} {
		if err := CheckSNI(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "localhost", "1.2.3.4", "a..b", "-a.com", "пример.рф", "a b.com", "x>y.com"} {
		if CheckSNI(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := Flight("1.2.3.4", Options{}); err == nil {
		t.Error("Flight accepted an IP address")
	}
}

// The parser takes datagrams from anyone: it must never panic.
func FuzzParse(f *testing.F) {
	pkts, _ := Flight("vk.com", Options{})
	f.Add(pkts[0], pkts[1])
	f.Add(pkts[0][:40], []byte{})
	f.Add([]byte{0xc3, 0, 0, 0, 1, 20}, []byte{0x01})
	f.Fuzz(func(t *testing.T, a, b []byte) {
		Open(a)
		Parse([][]byte{a, b})
		ParseClientHello(a)
		CryptoData(b)
	})
}
