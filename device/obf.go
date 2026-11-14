package device

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type obfBuilder func(val string) (obf, error)

// maxObfLen bounds a generated field: nothing larger fits a UDP datagram.
const maxObfLen = 65535

// parseObfLen reads the length of <r N>, <rc N>, <rd N>. A negative one
// used to pass and crash the device at the first handshake.
func parseObfLen(val string) (int, error) {
	n, err := strconv.Atoi(val)
	if err != nil {
		return 0, err
	}
	if n < 0 || n > maxObfLen {
		return 0, fmt.Errorf("length %d out of range 0-%d", n, maxObfLen)
	}
	return n, nil
}

var obfBuilders = map[string]obfBuilder{
	"b":  newBytesObf,
	"t":  newTimestampObf,
	"r":  newRandObf,
	"rc": newRandCharObf,
	"rd": newRandDigitsObf,
	"d":  newDataObf,
	"ds": newDataStringObf,
	"dz": newDataSizeObf,
}

type obf interface {
	Obfuscate(dst, src []byte)
	Deobfuscate(dst, src []byte) bool
	ObfuscatedLen(srcLen int) int
	DeobfuscatedLen(srcLen int) int
}

type obfChain struct {
	Spec string
	obfs []obf
	quic *quicFlight // <quic ...>: a whole generated flight instead of obfs
}

func newObfChain(spec string) (*obfChain, error) {
	var (
		obfs []obf
		size int
		quic *quicFlight
		errs []error
	)

	remaining := spec[:]
	for {
		start := strings.IndexByte(remaining, '<')
		if start == -1 {
			break
		}

		end := strings.IndexByte(remaining[start:], '>')
		if end == -1 {
			return nil, errors.New("missing enclosing >")
		}
		end += start

		tag := remaining[start+1 : end]
		parts := strings.Fields(tag)
		if len(parts) == 0 {
			errs = append(errs, errors.New("empty tag"))
			remaining = remaining[end+1:]
			continue
		}

		key := parts[0]
		if key == "quic" {
			if quic != nil {
				errs = append(errs, errors.New("more than one <quic> tag"))
			} else if q, err := newQuicFlight(parts[1:]); err != nil {
				errs = append(errs, fmt.Errorf("failed to build <quic>: %w", err))
			} else {
				quic = q
			}
			remaining = remaining[end+1:]
			continue
		}
		builder, ok := obfBuilders[key]
		if !ok {
			errs = append(errs, fmt.Errorf("unknown tag <%s>", key))
			remaining = remaining[end+1:]
			continue
		}

		val := ""
		if len(parts) > 1 {
			val = parts[1]
		}

		o, err := builder(val)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to build <%s>: %w", key, err))
			remaining = remaining[end+1:]
			continue
		}

		n := o.ObfuscatedLen(0)
		if n > maxObfLen-size {
			return nil, fmt.Errorf("I-packet exceeds %d bytes", maxObfLen)
		}
		size += n
		obfs = append(obfs, o)
		remaining = remaining[end+1:]
	}

	if quic != nil && len(obfs) > 0 {
		errs = append(errs, errors.New("<quic> must be the only tag of its I-packet"))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if len(obfs) == 0 && quic == nil {
		return nil, nil
	}

	return &obfChain{
		Spec: spec,
		obfs: obfs,
		quic: quic,
	}, nil
}

// Datagrams returns what an I-packet puts on the wire before a handshake:
// one datagram, or a generated flight for <quic>.
func (c *obfChain) Datagrams() ([][]byte, error) {
	if c.quic != nil {
		return c.quic.datagrams()
	}
	buf := make([]byte, c.ObfuscatedLen(0))
	c.Obfuscate(buf, nil)
	return [][]byte{buf}, nil
}

func (c *obfChain) Obfuscate(dst, src []byte) {
	written := 0
	for _, o := range c.obfs {
		obfLen := o.ObfuscatedLen(len(src))
		o.Obfuscate(dst[written:written+obfLen], src)
		written += obfLen
	}
}

func (c *obfChain) Deobfuscate(dst, src []byte) bool {
	dynamicLen := len(src) - c.ObfuscatedLen(0)

	written, read := 0, 0

	for _, o := range c.obfs {
		deobfLen := o.DeobfuscatedLen(dynamicLen)
		obfLen := o.ObfuscatedLen(deobfLen)

		if !o.Deobfuscate(dst[written:written+deobfLen], src[read:read+obfLen]) {
			return false
		}

		written += deobfLen
		read += obfLen
	}

	return true
}

func (c *obfChain) ObfuscatedLen(n int) int {
	total := 0
	for _, o := range c.obfs {
		total += o.ObfuscatedLen(n)
	}
	return total
}

func (c *obfChain) DeobfuscatedLen(n int) int {
	dynamicLen := n - c.ObfuscatedLen(0)

	total := 0
	for _, o := range c.obfs {
		total += o.DeobfuscatedLen(dynamicLen)
	}
	return total
}
