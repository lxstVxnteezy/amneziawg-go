package splittun

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type query struct {
	name  string
	qtype dnsmessage.Type
}

// parseQuery reads the question of a DNS query (UDP payload).
func parseQuery(b []byte) (query, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil || h.Response {
		return query{}, false
	}
	q, err := p.Question()
	if err != nil {
		return query{}, false
	}
	return query{name: q.Name.String(), qtype: q.Type}, true
}

// resolveDirect answers a query for a listed domain through the direct
// resolver and remembers the addresses. pkt is the whole IPv4/UDP packet
// from the OS (a copy).
func (d *Device) resolveDirect(pkt []byte, q query) {
	ihl := int(pkt[0]&0x0f) * 4
	payload := pkt[ihl+8:]
	var answer []byte
	if q.qtype == dnsmessage.TypeAAAA {
		// direct traffic is IPv4 only: no IPv6 addresses for these
		// names, so the app connects over IPv4 and can be sent directly
		answer = emptyAnswer(payload)
	} else {
		var ttl time.Duration
		var addrs []netip.Addr
		answer, addrs, ttl = d.exchange(payload)
		if answer == nil {
			answer = servfail(payload)
		}
		d.learn(addrs, ttl)
	}
	if answer == nil {
		return
	}
	d.writeToOS(udpReply(pkt, answer))
}

// exchange sends the query to the direct resolver.
func (d *Device) exchange(q []byte) (resp []byte, addrs []netip.Addr, ttl time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c, err := d.cfg.Dial(ctx, "udp", d.cfg.Rules.DNS.String())
	if err != nil {
		d.cfg.Log("splittun: direct DNS: %v", err)
		return nil, nil, 0
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := c.Write(q); err != nil {
		return nil, nil, 0
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			d.cfg.Log("splittun: direct DNS: %v", err)
			return nil, nil, 0
		}
		if n < 2 || buf[0] != q[0] || buf[1] != q[1] {
			continue // not the answer to this query
		}
		resp = buf[:n]
		break
	}
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		return resp, nil, 0
	}
	p.SkipAllQuestions()
	ttl = time.Hour
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		if h.Type == dnsmessage.TypeA {
			a, err := p.AResource()
			if err != nil {
				break
			}
			addrs = append(addrs, netip.AddrFrom4(a.A))
			ttl = min(ttl, time.Duration(h.TTL)*time.Second)
			continue
		}
		if err := p.SkipAnswer(); err != nil {
			break
		}
	}
	return resp, addrs, ttl
}

// emptyAnswer turns a query into a "no records" answer.
func emptyAnswer(q []byte) []byte {
	return replyHeader(q, dnsmessage.RCodeSuccess)
}

func servfail(q []byte) []byte {
	return replyHeader(q, dnsmessage.RCodeServerFailure)
}

func replyHeader(q []byte, rcode dnsmessage.RCode) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		return nil
	}
	question, err := p.Question()
	if err != nil {
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired,
		RecursionAvailable: true, RCode: rcode})
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(question) != nil {
		return nil
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// udpReply builds the IPv4/UDP packet answering req with payload: the
// addresses and ports swapped, so it looks like it came from the resolver
// the app asked.
func udpReply(req, payload []byte) []byte {
	ihl := int(req[0]&0x0f) * 4
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	binary.BigEndian.PutUint16(p[6:], 0x4000) // don't fragment
	p[8] = 64
	p[9] = 17
	copy(p[12:16], req[16:20])
	copy(p[16:20], req[12:16])
	binary.BigEndian.PutUint16(p[10:], ^checksum(p[:20], 0))
	u := p[20:]
	copy(u[0:2], req[ihl+2:ihl+4])
	copy(u[2:4], req[ihl:ihl+2])
	binary.BigEndian.PutUint16(u[4:], uint16(8+len(payload)))
	copy(u[8:], payload)
	// pseudo-header checksum
	var sum uint32
	sum = sum32(p[12:20], sum)
	sum += 17 + uint32(len(u))
	c := ^checksum(u, sum)
	if c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:], c)
	return p
}

func sum32(b []byte, sum uint32) uint32 {
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func checksum(b []byte, initial uint32) uint16 {
	sum := sum32(b, initial)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}
