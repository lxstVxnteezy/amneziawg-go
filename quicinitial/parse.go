package quicinitial

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

// Info is what a middlebox learns from a client's Initial flight.
type Info struct {
	DCID        []byte
	SNI         string
	ALPN        string
	ClientHello []byte
}

var errShort = errors.New("truncated")

// Open undoes header protection and decryption of a client Initial the way
// a middlebox would.
func Open(p []byte) (dcid []byte, pn uint32, frames []byte, err error) {
	if len(p) < 7 || p[0]&0xf0 != 0xc0 || binary.BigEndian.Uint32(p[1:5]) != 1 {
		return nil, 0, nil, errors.New("not a QUIC v1 Initial")
	}
	off := 5
	dl := int(p[off])
	if dl > 20 || off+1+dl >= len(p) {
		return nil, 0, nil, errShort
	}
	dcid = p[off+1 : off+1+dl]
	off += 1 + dl
	if off >= len(p) {
		return nil, 0, nil, errShort
	}
	off += 1 + int(p[off]) // scid
	if off >= len(p) {
		return nil, 0, nil, errShort
	}
	tokenLen, n := readVarint(p[off:])
	if n == 0 || tokenLen > uint64(len(p)) {
		return nil, 0, nil, errShort
	}
	off += n + int(tokenLen)
	if off >= len(p) {
		return nil, 0, nil, errShort
	}
	length, n := readVarint(p[off:])
	if n == 0 {
		return nil, 0, nil, errShort
	}
	off += n
	if length > uint64(len(p)) || off+int(length) != len(p) || length < 4+16+16 {
		return nil, 0, nil, fmt.Errorf("length field %d does not match the datagram", length)
	}

	k := clientInitialKeys(dcid)
	hp, _ := aes.NewCipher(k.hp)
	var mask [16]byte
	hp.Encrypt(mask[:], p[off+4:off+20])
	hdr := append([]byte(nil), p[:off+4]...)
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&0x03) + 1
	for i := range pnLen {
		hdr[off+i] ^= mask[1+i]
	}
	hdr = hdr[:off+pnLen]
	for _, b := range hdr[off:] {
		pn = pn<<8 | uint32(b)
	}

	block, _ := aes.NewCipher(k.key)
	aead, _ := cipher.NewGCM(block)
	nonce := append([]byte(nil), k.iv...)
	for i := range pnLen {
		nonce[12-pnLen+i] ^= hdr[off+i]
	}
	frames, err = aead.Open(nil, nonce, p[off+pnLen:], hdr)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("decrypt: %w", err)
	}
	return dcid, pn, frames, nil
}

// readVarint decodes a QUIC variable-length integer; n is 0 if b is short.
func readVarint(b []byte) (v uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v = uint64(b[0] & 0x3f)
	for _, c := range b[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, n
}

// CryptoData returns the CRYPTO frames of a decrypted Initial payload as
// offset -> data. Anything but CRYPTO, PADDING and PING is an error.
func CryptoData(frames []byte) (map[int][]byte, error) {
	out := map[int][]byte{}
	for len(frames) > 0 {
		switch frames[0] {
		case 0x00, 0x01:
			frames = frames[1:]
		case 0x06:
			off, n1 := readVarint(frames[1:])
			if n1 == 0 {
				return nil, errShort
			}
			l, n2 := readVarint(frames[1+n1:])
			if n2 == 0 {
				return nil, errShort
			}
			start := 1 + n1 + n2
			if l > uint64(len(frames)-start) || off > 1<<20 {
				return nil, errShort
			}
			out[int(off)] = frames[start : start+int(l)]
			frames = frames[start+int(l):]
		default:
			return nil, fmt.Errorf("unexpected frame type %#x", frames[0])
		}
	}
	return out, nil
}

// Parse decrypts the Initials of one connection attempt, reassembles the
// ClientHello and reads SNI and ALPN from it.
func Parse(pkts [][]byte) (Info, error) {
	var info Info
	var stream []byte
	var first uint32
	for i, p := range pkts {
		if len(p) < minInitialDatagram {
			return info, fmt.Errorf("datagram %d is %d bytes, QUIC requires >= %d", i, len(p), minInitialDatagram)
		}
		dcid, pn, frames, err := Open(p)
		if err != nil {
			return info, fmt.Errorf("datagram %d: %w", i, err)
		}
		// a first flight starts at 0; a retransmission continues the
		// numbering, packet after packet
		if i == 0 {
			first = pn
		} else if pn != first+uint32(i) {
			return info, fmt.Errorf("datagram %d has packet number %d", i, pn)
		}
		if info.DCID == nil {
			info.DCID = append([]byte(nil), dcid...)
		} else if !bytes.Equal(dcid, info.DCID) {
			return info, errors.New("Initials of one connection use different DCIDs")
		}
		data, err := CryptoData(frames)
		if err != nil {
			return info, fmt.Errorf("datagram %d: %w", i, err)
		}
		for len(data) > 0 {
			chunk, ok := data[len(stream)]
			if !ok {
				return info, errors.New("CRYPTO frames out of order")
			}
			delete(data, len(stream))
			stream = append(stream, chunk...)
		}
	}
	if len(stream) < 4 || int(stream[1])<<16|int(stream[2])<<8|int(stream[3]) != len(stream)-4 {
		return info, errors.New("ClientHello is incomplete")
	}
	info.ClientHello = stream
	var err error
	info.SNI, info.ALPN, err = ParseClientHello(stream)
	return info, err
}

// ParseClientHello walks a ClientHello handshake message and returns SNI
// and the first ALPN protocol.
func ParseClientHello(m []byte) (sni, alpn string, err error) {
	r := reader(m)
	typ, ok := r.u8()
	if !ok || typ != 0x01 {
		return "", "", errors.New("not a ClientHello")
	}
	if !r.skip(3 + 2 + 32) { // length, version, random
		return "", "", errShort
	}
	if !r.skip8() || !r.skip16() || !r.skip8() { // session id, cipher suites, compression
		return "", "", errShort
	}
	exts, ok := r.vec16()
	if !ok {
		return "", "", errShort
	}
	for len(exts) > 0 {
		typ, ok1 := exts.u16()
		body, ok2 := exts.vec16()
		if !ok1 || !ok2 {
			return "", "", errShort
		}
		switch typ {
		case 0x0000:
			list, _ := body.vec16()
			if kind, ok := list.u8(); ok && kind == 0 {
				name, _ := list.vec16()
				sni = string(name)
			}
		case 0x0010:
			list, _ := body.vec16()
			if proto, ok := list.vec8(); ok {
				alpn = string(proto)
			}
		}
	}
	return sni, alpn, nil
}

type reader []byte

func (r *reader) u8() (byte, bool) {
	if len(*r) < 1 {
		return 0, false
	}
	v := (*r)[0]
	*r = (*r)[1:]
	return v, true
}

func (r *reader) u16() (uint16, bool) {
	if len(*r) < 2 {
		return 0, false
	}
	v := binary.BigEndian.Uint16(*r)
	*r = (*r)[2:]
	return v, true
}

func (r *reader) skip(n int) bool {
	if len(*r) < n {
		return false
	}
	*r = (*r)[n:]
	return true
}

func (r *reader) vec8() (reader, bool) {
	n, ok := r.u8()
	if !ok || len(*r) < int(n) {
		return nil, false
	}
	v := (*r)[:n]
	*r = (*r)[n:]
	return v, true
}

func (r *reader) vec16() (reader, bool) {
	n, ok := r.u16()
	if !ok || len(*r) < int(n) {
		return nil, false
	}
	v := (*r)[:n]
	*r = (*r)[n:]
	return v, true
}

func (r *reader) skip8() bool  { _, ok := r.vec8(); return ok }
func (r *reader) skip16() bool { _, ok := r.vec16(); return ok }
