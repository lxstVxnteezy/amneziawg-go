package splittun

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsAnswer builds a response for name with one A record (seed input).
func dnsAnswer(tb testing.TB, name string) []byte {
	tb.Helper()
	n := dnsmessage.MustNewName(name)
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, Response: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		tb.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		tb.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		tb.Fatal(err)
	}
	if err := b.AResource(dnsmessage.ResourceHeader{Name: n, Class: dnsmessage.ClassINET, TTL: 60},
		dnsmessage.AResource{A: [4]byte{203, 0, 113, 50}}); err != nil {
		tb.Fatal(err)
	}
	out, err := b.Finish()
	if err != nil {
		tb.Fatal(err)
	}
	return out
}

// DNS answers come from the network (the tunnel's resolver): rewriting
// their A records in place must not panic or change the message length
// on any input, and the query parsers must not panic either.
func FuzzDNSFromNetwork(f *testing.F) {
	f.Add(dnsAnswer(f, "www.youtube.com."))
	f.Add(dnsAnswer(f, "example.org."))
	f.Add([]byte{0, 7, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0xc0, 0x0c})
	f.Fuzz(func(t *testing.T, msg []byte) {
		d := &Device{domains: newMatcher([]string{"youtube.com"}), fakes: newFakeMap(FakeRange)}
		n := len(msg)
		d.standInAnswers(msg)
		if len(msg) != n {
			t.Fatalf("length changed from %d to %d", n, len(msg))
		}
		parseQuery(msg)
		emptyAnswer(msg)
		servfail(msg)
		skipName(msg, 12)
	})
}
