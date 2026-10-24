package names

import (
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func query(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x6a75, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

type answer struct {
	rcode dnsmessage.RCode
	own   bool
	addrs []netip.Addr
	ttls  []uint32
	soa   int // SOAs answered
	auth  int // SOAs of the authority, with a minimum of TTL
}

func parse(t *testing.T, msg []byte) answer {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil {
		t.Fatal(err)
	}
	if m.ID != 0x6a75 || !m.Response || len(m.Questions) != 1 {
		t.Fatalf("no answer to the question: %+v", m.Header)
	}
	a := answer{rcode: m.RCode, own: m.Authoritative}
	for _, r := range m.Answers {
		a.ttls = append(a.ttls, r.Header.TTL)
		switch b := r.Body.(type) {
		case *dnsmessage.AResource:
			a.addrs = append(a.addrs, netip.AddrFrom4(b.A))
		case *dnsmessage.AAAAResource:
			a.addrs = append(a.addrs, netip.AddrFrom16(b.AAAA))
		case *dnsmessage.SOAResource:
			a.soa++
		}
	}
	for _, r := range m.Authorities {
		if soa, ok := r.Body.(*dnsmessage.SOAResource); ok && soa.MinTTL == TTL && r.Header.TTL == TTL &&
			r.Header.Name.String() == "home.juist." {
			a.auth++
		}
	}
	return a
}

var (
	mailer4 = netip.MustParseAddr("198.18.0.2")
	mailer6 = netip.MustParseAddr("fd12::2")
	zone    = &Zone{Domain: "home.juist",
		Members: map[string][]netip.Addr{"mailer": {mailer4, mailer6}, "zeus": {netip.MustParseAddr("fd12::3")}},
		Overrides: map[string]Override{"mx.example.net": {Addrs: []netip.Addr{mailer4, mailer6}, Target: "mailer"},
			"www.example.org": {Addrs: []netip.Addr{netip.MustParseAddr("fd12::3")}, Target: "zeus"}},
		Up: func(target string) bool { return target == "mailer" }}
)

// A member's name answers its addresses of the type asked, with the short TTL,
// in any case; a name the zone lacks does not exist, and a type a member has
// none of is empty.
func TestMembersAreAnswered(t *testing.T) {
	for _, tc := range []struct {
		name  string
		typ   dnsmessage.Type
		rcode dnsmessage.RCode
		addrs []netip.Addr
	}{
		{"mailer.home.juist.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []netip.Addr{mailer4}},
		{"MaIlEr.Home.Juist.", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, []netip.Addr{mailer6}},
		{"zeus.home.juist.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, nil},
		{"mailer.home.juist.", dnsmessage.TypeMX, dnsmessage.RCodeSuccess, nil},
		{"home.juist.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, nil},
		{"hades.home.juist.", dnsmessage.TypeA, dnsmessage.RCodeNameError, nil},
		{"a.mailer.home.juist.", dnsmessage.TypeA, dnsmessage.RCodeNameError, nil},
	} {
		msg := zone.Answer(query(t, tc.name, tc.typ))
		if msg == nil {
			t.Errorf("%s %v: not answered", tc.name, tc.typ)
			continue
		}
		a := parse(t, msg)
		if a.rcode != tc.rcode || !a.own || !slices.Equal(a.addrs, tc.addrs) {
			t.Errorf("%s %v: %v %v %v, want %v %v", tc.name, tc.typ, a.rcode, a.own, a.addrs, tc.rcode, tc.addrs)
		}
		for _, ttl := range a.ttls {
			if ttl != TTL {
				t.Errorf("%s: TTL %d", tc.name, ttl)
			}
		}
	}
}

// A public name pointed at a member answers its addresses and empty hints,
// and goes upstream for every other type, and while its member is not up; a
// name of neither goes upstream.
func TestOverridesAreAnswered(t *testing.T) {
	a := parse(t, zone.Answer(query(t, "MX.example.net.", dnsmessage.TypeA)))
	if a.rcode != dnsmessage.RCodeSuccess || a.own || !slices.Equal(a.addrs, []netip.Addr{mailer4}) {
		t.Errorf("A: %+v", a)
	}
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeHTTPS, dnsmessage.TypeSVCB} {
		if a := parse(t, zone.Answer(query(t, "mx.example.net.", typ))); a.rcode != dnsmessage.RCodeSuccess || len(a.addrs) != 0 {
			t.Errorf("%v: %+v", typ, a)
		}
	}
	for _, q := range [][]byte{
		query(t, "mx.example.net.", dnsmessage.TypeMX), query(t, "www.example.net.", dnsmessage.TypeA),
		query(t, "www.example.org.", dnsmessage.TypeA), query(t, "www.example.org.", dnsmessage.TypeHTTPS),
		query(t, "a.mx.example.net.", dnsmessage.TypeA), {1, 2, 3},
	} {
		if zone.Answer(q) != nil {
			t.Errorf("answered what goes upstream: %q", q)
		}
	}
	if (&Zone{}).Answer(query(t, "mailer.home.juist.", dnsmessage.TypeA)) != nil {
		t.Error("a zone of no domain answered for one")
	}
}

// The zone answers as its authority: its SOA for the domain, and beside an
// empty answer, so that it is cached for a TTL; an override has none.
func TestTheZoneIsItsAuthority(t *testing.T) {
	for _, tc := range []struct {
		name      string
		typ       dnsmessage.Type
		soa, auth int
	}{
		{"home.juist.", dnsmessage.TypeSOA, 1, 0},
		{"Home.Juist.", dnsmessage.TypeA, 0, 1},
		{"hades.home.juist.", dnsmessage.TypeA, 0, 1},
		{"hades.home.juist.", dnsmessage.TypeSOA, 0, 1},
		{"zeus.home.juist.", dnsmessage.TypeA, 0, 1},
		{"mailer.home.juist.", dnsmessage.TypeA, 0, 0},
		{"mx.example.net.", dnsmessage.TypeHTTPS, 0, 0},
	} {
		if a := parse(t, zone.Answer(query(t, tc.name, tc.typ))); a.soa != tc.soa || a.auth != tc.auth {
			t.Errorf("%s %v: %d SOAs answered, %d of the authority; want %d, %d", tc.name, tc.typ, a.soa, a.auth, tc.soa, tc.auth)
		}
	}
}

// An EDNS query is answered with EDNS, so that resolved keeps asking with it,
// and one without, without.
func TestEDNSIsAnsweredInKind(t *testing.T) {
	for _, edns := range []bool{true, false} {
		for _, name := range []string{"mailer.home.juist.", "hades.home.juist.", "mx.example.net."} {
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x6a75, RecursionDesired: true})
			b.StartQuestions()
			b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
			if edns {
				var rh dnsmessage.ResourceHeader
				rh.SetEDNS0(4096, dnsmessage.RCodeSuccess, true)
				b.StartAdditionals()
				b.OPTResource(rh, dnsmessage.OPTResource{})
			}
			q, err := b.Finish()
			if err != nil {
				t.Fatal(err)
			}
			var m dnsmessage.Message
			if err := m.Unpack(zone.Answer(q)); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			opts := 0
			for _, r := range m.Additionals {
				if r.Header.Type == dnsmessage.TypeOPT && r.Header.Class == ednsSize {
					opts++
				}
			}
			if want := map[bool]int{true: 1, false: 0}[edns]; opts != want {
				t.Errorf("%s, EDNS %v: %d OPTs, want %d", name, edns, opts, want)
			}
		}
	}
}

// A name overridden, or below one, is said to be, answered now or not.
func TestOverridden(t *testing.T) {
	for name, want := range map[string]bool{"mx.example.net.": true, "A.MX.example.net.": true,
		"www.example.org.": true, "example.net.": false, "xmx.example.net.": false, "mailer.home.juist.": false} {
		if got := zone.Overridden(query(t, name, dnsmessage.TypeA)); got != want {
			t.Errorf("%s: overridden %v, want %v", name, got, want)
		}
	}
	if zone.Overridden([]byte{1, 2}) {
		t.Error("a message that does not parse is overridden")
	}
}

// A query of the zone's own names it cannot answer is refused, never passed
// upstream, where it would tell the host's resolvers the network's names;
// one of another name goes on upstream.
func TestTheZonesNamesGoNowhereElse(t *testing.T) {
	build := func(name string, class dnsmessage.Class, op dnsmessage.OpCode, questions int) []byte {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x6a75, OpCode: op})
		b.StartQuestions()
		for range questions {
			b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: class})
		}
		q, err := b.Finish()
		if err != nil {
			t.Fatal(err)
		}
		return q
	}
	for _, tc := range []struct {
		why   string
		class dnsmessage.Class
		op    dnsmessage.OpCode
		n     int
		rcode dnsmessage.RCode
	}{
		{"two questions", dnsmessage.ClassINET, 0, 2, dnsmessage.RCodeFormatError},
		{"another class", dnsmessage.ClassCHAOS, 0, 1, dnsmessage.RCodeRefused},
		{"another opcode", dnsmessage.ClassINET, 2, 1, dnsmessage.RCodeNotImplemented},
	} {
		msg := zone.Answer(build("mailer.home.juist.", tc.class, tc.op, tc.n))
		var m dnsmessage.Message
		if msg == nil || m.Unpack(msg) != nil || m.RCode != tc.rcode || m.ID != 0x6a75 || len(m.Answers) != 0 {
			t.Errorf("%s: answered %+v, want %v", tc.why, m.Header, tc.rcode)
		}
		if zone.Answer(build("example.org.", tc.class, tc.op, tc.n)) != nil {
			t.Errorf("%s: answered another name", tc.why)
		}
	}
}

// Only a DNS label names a member.
func TestLabels(t *testing.T) {
	for in, want := range map[string]string{"Mailer": "mailer", "laptop-2": "laptop-2", "my laptop": "", "a_b": "",
		"-x": "", "müller": "", "": "", "a.b": ""} {
		if got := Label(in); got != want {
			t.Errorf("Label(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestAnUnreadableQueryIsAServerFailure: an answer by the header alone keeps
// the query's id, opcode and recursion bit and says it failed.
func TestAnUnreadableQueryIsAServerFailure(t *testing.T) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	query, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	h, err := p.Start(serverFailure(query))
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != 0x1234 || !h.Response || !h.RecursionDesired || h.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("answered %+v", h)
	}
	if serverFailure(query[:11]) != nil {
		t.Fatal("a query shorter than a header was answered")
	}
}

// A question's name is lowered as DNS compares names, A to Z alone, its
// other bytes kept, as resolved has them.
func TestAQuestionKeepsItsBytes(t *testing.T) {
	for in, want := range map[string]string{"\xc3\x89.Corp.": "\xc3\x89.corp", "\xff.Corp.": "\xff.corp"} {
		if got, _, _, ok := QuestionOf(query(t, in, dnsmessage.TypeA)); !ok || got != want {
			t.Errorf("%q is %q, want %q", in, got, want)
		}
	}
}

// A name is the zone's only as DNS compares names, A to Z alone folded: a
// Kelvin sign is no k.
func TestAZoneFoldsASCIIAlone(t *testing.T) {
	z := &Zone{Domain: "work.juist"}
	if msg := z.Answer(query(t, "x.WORK.juist.", dnsmessage.TypeA)); msg == nil {
		t.Error("x.WORK.juist is not answered")
	}
	if msg := z.Answer(query(t, "x.worK.juist.", dnsmessage.TypeA)); msg != nil {
		t.Errorf("x.worK.juist is answered: %v", parse(t, msg))
	}
}

// A reverse name of the network's own addresses is answered from the zone, a
// member's by its name, any other there as none, so that no resolver outside
// learns which of the network's addresses the host talks to; one outside
// them goes upstream.
func TestReverseNamesOfTheNetworkAreAnswered(t *testing.T) {
	z := *zone
	z.Reverse = []netip.Prefix{netip.MustParsePrefix("198.18.0.0/22"), netip.MustParsePrefix("fd12::/48")}
	v6 := "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.1.d.f.ip6.arpa."
	for _, tc := range []struct {
		name  string
		typ   dnsmessage.Type
		rcode dnsmessage.RCode
		ptr   string
	}{
		{"2.0.18.198.in-addr.arpa.", dnsmessage.TypePTR, dnsmessage.RCodeSuccess, "mailer.home.juist."},
		{"2.0.18.198.IN-ADDR.ARPA.", dnsmessage.TypePTR, dnsmessage.RCodeSuccess, "mailer.home.juist."},
		{v6, dnsmessage.TypePTR, dnsmessage.RCodeSuccess, "mailer.home.juist."},
		{"2.0.18.198.in-addr.arpa.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, ""},
		{"9.0.18.198.in-addr.arpa.", dnsmessage.TypePTR, dnsmessage.RCodeNameError, ""},
		{"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.1.d.f.ip6.arpa.", dnsmessage.TypePTR, dnsmessage.RCodeSuccess, "zeus.home.juist."},
	} {
		msg := z.Answer(query(t, tc.name, tc.typ))
		if msg == nil {
			t.Errorf("%s %v: not answered", tc.name, tc.typ)
			continue
		}
		var m dnsmessage.Message
		if err := m.Unpack(msg); err != nil {
			t.Fatal(err)
		}
		var ptr string
		for _, r := range m.Answers {
			if p, ok := r.Body.(*dnsmessage.PTRResource); ok {
				ptr = p.PTR.String()
			}
		}
		if m.RCode != tc.rcode || ptr != tc.ptr || !m.Authoritative {
			t.Errorf("%s %v: %v %q, want %v %q", tc.name, tc.typ, m.RCode, ptr, tc.rcode, tc.ptr)
		}
	}
	for _, name := range []string{"1.1.168.192.in-addr.arpa.", "18.198.in-addr.arpa.", "0.4.18.198.in-addr.arpa.", "x.0.18.198.in-addr.arpa."} {
		if msg := z.Answer(query(t, name, dnsmessage.TypePTR)); msg != nil {
			t.Errorf("%s answered, not passed on", name)
		}
	}
}
