package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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

// openInitial undoes header protection and decryption the way a middlebox
// would, independently of sealInitial.
func openInitial(t *testing.T, p []byte) (dcid []byte, pn uint32, frames []byte) {
	t.Helper()
	if p[0]&0xf0 != 0xc0 || binary.BigEndian.Uint32(p[1:5]) != 1 {
		t.Fatalf("not a QUIC v1 Initial: %x", p[:5])
	}
	off := 5
	dcid = p[off+1 : off+1+int(p[off])]
	off += 1 + len(dcid)
	off += 1 + int(p[off]) // scid
	if p[off] != 0 {
		t.Fatal("unexpected token")
	}
	off++
	length := int(binary.BigEndian.Uint16(p[off:]) & 0x3fff)
	off += 2
	if off+length != len(p) {
		t.Fatalf("length field %d does not match datagram", length)
	}

	k := clientInitialKeys(dcid)
	hp, _ := aes.NewCipher(k.hp)
	var mask [16]byte
	hp.Encrypt(mask[:], p[off+4:off+20])
	hdr := append([]byte(nil), p[:off+4]...)
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&0x03) + 1
	if pnLen != 4 {
		t.Fatalf("pn length %d", pnLen)
	}
	for i := range pnLen {
		hdr[off+i] ^= mask[1+i]
	}
	pn = binary.BigEndian.Uint32(hdr[off:])

	block, _ := aes.NewCipher(k.key)
	aead, _ := cipher.NewGCM(block)
	nonce := append([]byte(nil), k.iv...)
	for i := range 4 {
		nonce[8+i] ^= hdr[off+i]
	}
	frames, err := aead.Open(nil, nonce, p[off+4:], hdr)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return dcid, pn, frames
}

// sniFromClientHello walks a ClientHello and returns SNI and ALPN.
func sniFromClientHello(t *testing.T, m []byte) (sni, alpn string) {
	t.Helper()
	if m[0] != 0x01 {
		t.Fatalf("handshake type %d", m[0])
	}
	b := m[4:]
	b = b[2+32:]                                     // version, random
	b = b[1+int(b[0]):]                              // session id
	b = b[2+int(binary.BigEndian.Uint16(b)):]        // cipher suites
	b = b[1+int(b[0]):]                              // compression
	exts := b[2 : 2+int(binary.BigEndian.Uint16(b))] // extensions
	for len(exts) > 0 {
		typ := binary.BigEndian.Uint16(exts)
		l := int(binary.BigEndian.Uint16(exts[2:]))
		body := exts[4 : 4+l]
		switch typ {
		case 0x0000:
			n := int(binary.BigEndian.Uint16(body[3:]))
			sni = string(body[5 : 5+n])
		case 0x0010:
			alpn = string(body[3 : 3+int(body[2])])
		}
		exts = exts[4+l:]
	}
	return
}

// readVarint decodes a QUIC variable-length integer.
func readVarint(b []byte) (uint64, int) {
	n := 1 << (b[0] >> 6)
	v := uint64(b[0] & 0x3f)
	for _, c := range b[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, n
}

// cryptoData returns the CRYPTO frames of a decrypted Initial payload as
// offset -> data, and fails on anything but CRYPTO and PADDING.
func cryptoData(t *testing.T, frames []byte) map[int][]byte {
	t.Helper()
	out := map[int][]byte{}
	for len(frames) > 0 {
		switch frames[0] {
		case 0x00:
			frames = frames[1:]
		case 0x06:
			off, n1 := readVarint(frames[1:])
			l, n2 := readVarint(frames[1+n1:])
			start := 1 + n1 + n2
			out[int(off)] = frames[start : start+int(l)]
			frames = frames[start+int(l):]
		default:
			t.Fatalf("unexpected frame type %#x", frames[0])
		}
	}
	return out
}

// clientHelloFromInitials reassembles the CRYPTO stream of a connection
// attempt and checks the packets are consistent.
func clientHelloFromInitials(t *testing.T, pkts [][]byte) []byte {
	t.Helper()
	var firstDCID, stream []byte
	for i, p := range pkts {
		if len(p) < minInitialDatagram {
			t.Fatalf("datagram %d is %d bytes, QUIC requires >= %d", i, len(p), minInitialDatagram)
		}
		dcid, pn, frames := openInitial(t, p)
		if pn != uint32(i) {
			t.Errorf("packet %d has pn %d", i, pn)
		}
		if firstDCID == nil {
			firstDCID = dcid
		} else if !bytes.Equal(dcid, firstDCID) {
			t.Error("Initials of one connection use different DCIDs")
		}
		for off, data := range cryptoData(t, frames) {
			if off != len(stream) {
				t.Fatalf("CRYPTO offset %d, expected %d", off, len(stream))
			}
			stream = append(stream, data...)
		}
	}
	if len(stream) < 4 || int(stream[1])<<16|int(stream[2])<<8|int(stream[3]) != len(stream)-4 {
		t.Fatal("ClientHello is incomplete")
	}
	return stream
}

func TestQuicInitialsLookLikeHTTP3(t *testing.T) {
	pkts, err := quicInitials("vk.com")
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
	a, _ := clientHello("vk.com", nil)
	b, _ := clientHello("vk.com", nil)
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
