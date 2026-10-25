package main

// Builds a genuine QUIC v1 client Initial packet (RFC 9000/9001) carrying a
// TLS 1.3 ClientHello. It is used as an AmneziaWG I-packet: a DPI box that
// decrypts QUIC Initials (as SNI filters do) sees an ordinary HTTP/3
// connection attempt to the chosen domain instead of random bytes.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/curve25519"
)

var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// minInitialDatagram is the minimum size of a datagram carrying a client
// Initial (RFC 9000, Section 14.1).
const minInitialDatagram = 1200

type initialKeys struct {
	key, iv, hp []byte
}

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // empty context
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		panic(err)
	}
	return out
}

func clientInitialKeys(dcid []byte) initialKeys {
	initialSecret, err := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)
	if err != nil {
		panic(err)
	}
	clientSecret := hkdfExpandLabel(initialSecret, "client in", sha256.Size)
	return initialKeys{
		key: hkdfExpandLabel(clientSecret, "quic key", 16),
		iv:  hkdfExpandLabel(clientSecret, "quic iv", 12),
		hp:  hkdfExpandLabel(clientSecret, "quic hp", 16),
	}
}

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return binary.BigEndian.AppendUint16(b, uint16(v)|0x4000)
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(b, uint32(v)|0x80000000)
	default:
		return binary.BigEndian.AppendUint64(b, v|0xc000000000000000)
	}
}

// sealInitial protects an Initial packet whose frames are already padded.
// pn is encoded on 4 bytes.
func sealInitial(dcid, scid []byte, pn uint32, frames []byte) ([]byte, error) {
	if len(dcid) > 20 || len(scid) > 20 {
		return nil, errors.New("connection ID too long")
	}
	const pnLen = 4
	k := clientInitialKeys(dcid)

	hdr := []byte{0xc0 | (pnLen - 1)} // long header, Initial, 4-byte PN
	hdr = binary.BigEndian.AppendUint32(hdr, 1)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = appendVarint(hdr, 0) // token length
	// Length is always written as a 2-byte varint, like browsers do.
	length := pnLen + len(frames) + 16
	if length >= 1<<14 {
		return nil, errors.New("payload too large")
	}
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(length)|0x4000)
	pnOffset := len(hdr)
	hdr = binary.BigEndian.AppendUint32(hdr, pn)

	block, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	copy(nonce, k.iv)
	var pnBytes [8]byte
	binary.BigEndian.PutUint64(pnBytes[:], uint64(pn))
	for i := range 8 {
		nonce[4+i] ^= pnBytes[i]
	}
	packet := aead.Seal(hdr, nonce, frames, hdr)

	hpBlock, err := aes.NewCipher(k.hp)
	if err != nil {
		return nil, err
	}
	sample := packet[pnOffset+4 : pnOffset+4+16]
	var mask [16]byte
	hpBlock.Encrypt(mask[:], sample)
	packet[0] ^= mask[0] & 0x0f
	for i := range pnLen {
		packet[pnOffset+i] ^= mask[1+i]
	}
	return packet, nil
}

func appendU16Prefixed(b []byte, body []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(body)))
	return append(b, body...)
}

func extension(typ uint16, body []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, typ)
	return appendU16Prefixed(b, body)
}

func transportParam(id, value uint64) []byte {
	v := appendVarint(nil, value)
	b := appendVarint(nil, id)
	b = appendVarint(b, uint64(len(v)))
	return append(b, v...)
}

// clientHello returns a TLS 1.3 ClientHello handshake message for QUIC.
func clientHello(sni string, scid []byte) ([]byte, error) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, err
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	var exts []byte
	{
		name := []byte{0} // host_name
		name = appendU16Prefixed(name, []byte(sni))
		exts = append(exts, extension(0x0000, appendU16Prefixed(nil, name))...)
	}
	exts = append(exts, extension(0x000a, appendU16Prefixed(nil, []byte{0x00, 0x1d, 0x00, 0x17, 0x00, 0x18}))...)
	exts = append(exts, extension(0x000d, appendU16Prefixed(nil, []byte{
		0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01,
	}))...)
	exts = append(exts, extension(0x0010, appendU16Prefixed(nil, []byte{2, 'h', '3'}))...)
	exts = append(exts, extension(0x002b, []byte{2, 0x03, 0x04})...)
	exts = append(exts, extension(0x002d, []byte{1, 1})...)
	{
		share := binary.BigEndian.AppendUint16(nil, 0x001d)
		share = appendU16Prefixed(share, pub)
		exts = append(exts, extension(0x0033, appendU16Prefixed(nil, share))...)
	}
	{
		var tp []byte
		tp = append(tp, transportParam(0x01, 30000)...)    // max_idle_timeout
		tp = append(tp, transportParam(0x03, 1472)...)     // max_udp_payload_size
		tp = append(tp, transportParam(0x04, 15728640)...) // initial_max_data
		tp = append(tp, transportParam(0x05, 6291456)...)  // initial_max_stream_data_bidi_local
		tp = append(tp, transportParam(0x06, 6291456)...)  // initial_max_stream_data_bidi_remote
		tp = append(tp, transportParam(0x07, 6291456)...)  // initial_max_stream_data_uni
		tp = append(tp, transportParam(0x08, 100)...)      // initial_max_streams_bidi
		tp = append(tp, transportParam(0x09, 103)...)      // initial_max_streams_uni
		tp = appendVarint(tp, 0x0f)                        // initial_source_connection_id
		tp = appendVarint(tp, uint64(len(scid)))
		tp = append(tp, scid...)
		exts = append(exts, extension(0x0039, tp)...)
	}

	body := []byte{0x03, 0x03} // legacy_version
	body = append(body, random[:]...)
	body = append(body, 0)                                              // empty legacy_session_id (QUIC)
	body = append(body, 0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03) // cipher suites
	body = append(body, 0x01, 0x00)                                     // null compression
	body = appendU16Prefixed(body, exts)

	msg := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(msg, body...), nil
}

// cryptoFramePadded wraps data in a CRYPTO frame at offset 0 and pads it with
// PADDING frames so the whole datagram reaches minInitialDatagram bytes.
func cryptoFramePadded(data []byte, headerLen int) []byte {
	f := []byte{0x06, 0x00}
	f = appendVarint(f, uint64(len(data)))
	f = append(f, data...)
	if want := minInitialDatagram - headerLen - 16; len(f) < want {
		f = append(f, make([]byte, want-len(f))...)
	}
	return f
}

// quicInitials returns `count` client Initial datagrams for the same
// connection attempt: the first one and its retransmissions, as a browser
// sends them when the server does not answer.
func quicInitials(sni string, count int) ([][]byte, error) {
	dcid := make([]byte, 8)
	if _, err := rand.Read(dcid); err != nil {
		return nil, err
	}
	hello, err := clientHello(sni, nil)
	if err != nil {
		return nil, err
	}
	// header: 1 + 4 + 1+8 + 1+0 + 1 (token len) + 2 (length) + 4 (pn)
	headerLen := 1 + 4 + 1 + len(dcid) + 1 + 1 + 2 + 4
	frames := cryptoFramePadded(hello, headerLen)

	out := make([][]byte, 0, count)
	for pn := range count {
		p, err := sealInitial(dcid, nil, uint32(pn), frames)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
