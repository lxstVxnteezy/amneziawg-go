package device

import (
	"errors"
	"fmt"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/quicinitial"
)

// quicFlight is the <quic sni=example.com> I-packet tag (or <quic>, with
// no SNI, as a browser connecting to an IP address): before every
// handshake the device builds a new QUIC Initial flight (fresh connection
// ID, random and key shares) instead of sending the same bytes each time,
// which is what a fixed <b 0x...> Initial does. A post-quantum ClientHello
// takes two datagrams, like Chrome's; "classic" makes it one.
//
// The tag must be the only one of its I-packet. Only the sender needs to
// understand it: the receiver drops I-packets without parsing them.
type quicFlight struct {
	sni  string
	opts quicinitial.Options
}

func newQuicFlight(args []string) (*quicFlight, error) {
	q := &quicFlight{}
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "sni="):
			q.sni = strings.TrimPrefix(a, "sni=")
			if q.sni == "" {
				// a generator that lost its domain; no SNI is "<quic>"
				return nil, errors.New("empty sni= (leave it out for a ClientHello without SNI)")
			}
		case a == "classic":
			q.opts.Classic = true
		case !strings.Contains(a, "=") && q.sni == "":
			q.sni = a
		default:
			return nil, fmt.Errorf("unknown argument %q (want sni=<domain> or nothing for no SNI, and optionally classic)", a)
		}
	}
	// no sni: a ClientHello without server_name, as a browser sends to an
	// IP address; better than a domain that does not point at the server
	q.sni = strings.ToLower(strings.TrimSuffix(q.sni, "."))
	if q.sni != "" {
		if err := quicinitial.CheckSNI(q.sni); err != nil {
			return nil, err
		}
	}
	// build one now, so that a config that cannot work is rejected at
	// configuration time and not silently at every handshake
	if _, err := q.datagrams(); err != nil {
		return nil, err
	}
	return q, nil
}

func (q *quicFlight) datagrams() ([][]byte, error) {
	return quicinitial.Flight(q.sni, q.opts)
}

// attempt starts a connection attempt that can be retransmitted.
func (q *quicFlight) attempt() (*quicinitial.Attempt, error) {
	return quicinitial.NewAttempt(q.sni, q.opts)
}
