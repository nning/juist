package names

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// seedQuery is a query for name of qtype, with EDNS where edns.
func seedQuery(f *testing.F, name string, qtype dnsmessage.Type, edns bool) []byte {
	f.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x4a17, RecursionDesired: true})
	b.EnableCompression()
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: qtype, Class: dnsmessage.ClassINET})
	if edns {
		var rh dnsmessage.ResourceHeader
		rh.SetEDNS0(1232, dnsmessage.RCodeSuccess, false)
		b.StartAdditionals()
		b.OPTResource(rh, dnsmessage.OPTResource{})
	}
	q, err := b.Finish()
	if err != nil {
		f.Fatal(err)
	}
	return q
}

// Whatever a host's program sends the resolver, the zone answers it with a
// response to it that parses, or passes it on; it never panics.
func FuzzAnswer(f *testing.F) {
	for _, s := range []struct {
		name  string
		qtype dnsmessage.Type
		edns  bool
	}{
		{"anna.home.juist.", dnsmessage.TypeA, false},
		{"Anna.Home.Juist.", dnsmessage.TypeAAAA, true},
		{"home.juist.", dnsmessage.TypeSOA, true},
		{"nobody.home.juist.", dnsmessage.TypeA, false},
		{"www.example.org.", dnsmessage.TypeHTTPS, true},
		{"www.example.org.", dnsmessage.TypeTXT, false},
		{"mx.example.net.", dnsmessage.TypeMX, true},
		{"1.0.0.10.in-addr.arpa.", dnsmessage.TypePTR, false},
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.", dnsmessage.TypePTR, true},
	} {
		f.Add(seedQuery(f, s.name, s.qtype, s.edns))
	}
	f.Add([]byte{})
	f.Add(make([]byte, 12))
	z := &Zone{Domain: "home.juist", Public: "example.org",
		Members: map[string][]netip.Addr{"anna": {netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fd00::1")}},
		Overrides: map[string]Override{"www.example.org": {Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, Target: "anna"},
			"down.example.org": {Target: "bert"}},
		Up:      func(target string) bool { return target == "anna" },
		Reverse: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/22"), netip.MustParsePrefix("fd00::/48")}}
	f.Fuzz(func(t *testing.T, q []byte) {
		z.Overridden(q)
		Question(q)
		a := z.Answer(q)
		if a == nil {
			return
		}
		var p dnsmessage.Parser
		h, err := p.Start(a)
		if err != nil || !h.Response || len(q) < 2 || h.ID != binary.BigEndian.Uint16(q) {
			t.Fatalf("answered %x to %x: %+v, %v", a, q, h, err)
		}
	})
}
