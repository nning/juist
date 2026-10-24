// Package names answers the host's DNS for a network's members,
// DEVICE.NETWORK.juist, and for the public names pointed at them.
package names

import (
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nning/juist/internal/malformed"
)

// TTL is every answer's, in seconds: short, so that a name withdrawn or a
// member gone leaves caches soon.
const TTL = 30

// ednsSize is the UDP payload an answer to an EDNS query offers, which
// resolved otherwise takes for a server without EDNS, and so asks every name
// it forwards without.
const ednsSize = 1232

// A Zone is what a device answers: Domain, as home.juist, "" for none, with
// Members by their DNS label, and Overrides, public names pointed at
// members, by name, each lowercase without a final dot. Up says whether an
// override's target is answered for now; nil answers every one. Public is
// the network's public domain, which comes here whole, its names but the
// overrides going on upstream. Reverse are the network's own prefixes, whose
// reverse names it answers, a member's address by its name and any other as
// none, so that no resolver outside learns them.
type Zone struct {
	Domain    string
	Members   map[string][]netip.Addr
	Overrides map[string]Override
	Up        func(target string) bool
	Public    string
	Reverse   []netip.Prefix
}

// An Override points a public name at Target, a member, by its addresses.
type Override struct {
	Addrs  []netip.Addr
	Target string
}

// Label is name as a DNS label, lowercase, or "" where it is none: letters,
// digits and inner hyphens, 63 bytes at most.
func Label(name string) string {
	l := strings.ToLower(name)
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return ""
	}
	for i := 0; i < len(l); i++ {
		if c := l[i]; !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return ""
		}
	}
	return l
}

// Answer is z's response to query, or nil where z has no word on it and it
// goes on upstream: a name outside the zone and every override, a type of
// an override's other than its addresses and their hints, and an override
// whose target is not up, which then resolves as without it.
func (z *Zone) Answer(query []byte) (answer []byte) {
	defer malformed.RecoverWith(&answer, func() []byte { return serverFailure(query) })
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil || h.Response {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	name := asciiLower(strings.TrimSuffix(q.Name.String(), "."))
	rev, reverse := z.reverseOf(name)
	own := reverse || z.Domain != "" && (name == z.Domain || strings.HasSuffix(name, "."+z.Domain))
	_, more := p.Question()
	edns, ok := false, more == dnsmessage.ErrSectionDone
	if ok {
		edns, ok = hasOPT(&p)
	}
	var rcode dnsmessage.RCode
	switch {
	case h.OpCode != 0:
		rcode = dnsmessage.RCodeNotImplemented
	case !ok:
		rcode = dnsmessage.RCodeFormatError
	case q.Class != dnsmessage.ClassINET:
		rcode = dnsmessage.RCodeRefused
	}
	if rcode != dnsmessage.RCodeSuccess {
		// The zone's own names go nowhere else, asked as they may be.
		if own {
			return refuse(h, q, rcode)
		}
		return nil
	}
	if reverse {
		return z.replyReverse(h, q, edns, rev)
	}
	if own {
		label := strings.TrimSuffix(strings.TrimSuffix(name, z.Domain), ".")
		addrs, ok := z.Members[label]
		switch {
		case label == "":
			return z.reply(h, q, edns, true, dnsmessage.RCodeSuccess, nil)
		case !ok:
			return z.reply(h, q, edns, true, dnsmessage.RCodeNameError, nil)
		}
		return z.reply(h, q, edns, true, dnsmessage.RCodeSuccess, addrs)
	}
	o, ok := z.Overrides[name]
	switch {
	case !ok || z.Up != nil && !z.Up(o.Target):
		return nil
	case q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeAAAA:
		return z.reply(h, q, edns, false, dnsmessage.RCodeSuccess, o.Addrs)
	case q.Type == dnsmessage.TypeSVCB || q.Type == dnsmessage.TypeHTTPS:
		// Empty: their address hints would carry the public address.
		return z.reply(h, q, edns, false, dnsmessage.RCodeSuccess, nil)
	}
	return nil
}

// reply answers q with rcode and those of addrs its type asks for, with EDNS
// where edns; own, as z's authority, with its SOA, which answers for the
// domain and has an empty answer cached for a TTL.
func (z *Zone) reply(h dnsmessage.Header, q dnsmessage.Question, edns, own bool, rcode dnsmessage.RCode, addrs []netip.Addr) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: own,
		RecursionDesired: h.RecursionDesired, RecursionAvailable: true, RCode: rcode})
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(q) != nil || b.StartAnswers() != nil {
		return nil
	}
	rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: TTL}
	answered := false
	for _, a := range addrs {
		var err error
		switch {
		case q.Type == dnsmessage.TypeA && a.Is4():
			err = b.AResource(rh, dnsmessage.AResource{A: a.As4()})
		case q.Type == dnsmessage.TypeAAAA && a.Is6():
			err = b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: a.As16()})
		default:
			continue
		}
		if err != nil {
			return nil
		}
		answered = true
	}
	if own && !answered {
		apex, err := dnsmessage.NewName(z.Domain + ".")
		if err != nil {
			return nil
		}
		soa := dnsmessage.SOAResource{NS: apex, MBox: apex, Serial: 1, Refresh: TTL, Retry: TTL, Expire: TTL, MinTTL: TTL}
		atApex := rcode == dnsmessage.RCodeSuccess && q.Type == dnsmessage.TypeSOA && strings.EqualFold(q.Name.String(), apex.String())
		if !atApex && b.StartAuthorities() != nil {
			return nil
		}
		if b.SOAResource(dnsmessage.ResourceHeader{Name: apex, Class: dnsmessage.ClassINET, TTL: TTL}, soa) != nil {
			return nil
		}
	}
	if edns {
		var rh dnsmessage.ResourceHeader
		if rh.SetEDNS0(ednsSize, dnsmessage.RCodeSuccess, false) != nil || b.StartAdditionals() != nil ||
			b.OPTResource(rh, dnsmessage.OPTResource{}) != nil {
			return nil
		}
	}
	msg, err := b.Finish()
	if err != nil {
		return nil
	}
	return msg
}

// reverseOf is the address name is the reverse name of, where it is one of
// the network's own.
func (z *Zone) reverseOf(name string) (netip.Addr, bool) {
	var a netip.Addr
	if v4, ok := strings.CutSuffix(name, ".in-addr.arpa"); ok {
		o := strings.Split(v4, ".")
		if len(o) != 4 {
			return a, false
		}
		var err error
		if a, err = netip.ParseAddr(o[3] + "." + o[2] + "." + o[1] + "." + o[0]); err != nil {
			return a, false
		}
	} else if v6, ok := strings.CutSuffix(name, ".ip6.arpa"); ok {
		n := strings.Split(v6, ".")
		if len(n) != 32 {
			return a, false
		}
		var b [16]byte
		for i, l := range n {
			if len(l) != 1 || strings.IndexByte("0123456789abcdef", l[0]) < 0 {
				return a, false
			}
			nibble := byte(strings.IndexByte("0123456789abcdef", l[0]))
			b[15-i/2] |= nibble << (4 * (i % 2))
		}
		a = netip.AddrFrom16(b)
	} else {
		return a, false
	}
	for _, p := range z.Reverse {
		if p.Contains(a) {
			return a, true
		}
	}
	return a, false
}

// replyReverse answers q, the reverse name of a, with the name of the member
// holding a, empty for another type, and as none where no member holds it.
func (z *Zone) replyReverse(h dnsmessage.Header, q dnsmessage.Question, edns bool, a netip.Addr) []byte {
	var target string
	for label, addrs := range z.Members {
		if z.Domain != "" && slices.Contains(addrs, a) {
			target = label + "." + z.Domain + "."
		}
	}
	rcode := dnsmessage.RCodeSuccess
	if target == "" {
		rcode = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true,
		RecursionDesired: h.RecursionDesired, RecursionAvailable: true, RCode: rcode})
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(q) != nil || b.StartAnswers() != nil {
		return nil
	}
	if target != "" && q.Type == dnsmessage.TypePTR {
		n, err := dnsmessage.NewName(target)
		if err != nil || b.PTRResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: TTL},
			dnsmessage.PTRResource{PTR: n}) != nil {
			return nil
		}
	}
	if edns {
		var rh dnsmessage.ResourceHeader
		if rh.SetEDNS0(ednsSize, dnsmessage.RCodeSuccess, false) != nil || b.StartAdditionals() != nil ||
			b.OPTResource(rh, dnsmessage.OPTResource{}) != nil {
			return nil
		}
	}
	msg, err := b.Finish()
	if err != nil {
		return nil
	}
	return msg
}

// refuse answers q with rcode alone.
func refuse(h dnsmessage.Header, q dnsmessage.Question, rcode dnsmessage.RCode) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, OpCode: h.OpCode,
		RecursionDesired: h.RecursionDesired, RCode: rcode})
	if b.StartQuestions() != nil || b.Question(q) != nil {
		return nil
	}
	msg, err := b.Finish()
	if err != nil {
		return nil
	}
	return msg
}

// serverFailure answers query by its header alone, where it could not be
// read past that: refused here rather than asked of the resolver upstream,
// which might be told a name of the zone's.
func serverFailure(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	b := make([]byte, 12)
	copy(b, query[:2])
	b[2] = 0x80 | query[2]&0x79 // a response, the query's opcode and RD
	b[3] = byte(dnsmessage.RCodeServerFailure)
	return b
}

// hasOPT reports whether the rest of the query p parses carries an EDNS OPT
// record, and whether it parses.
func hasOPT(p *dnsmessage.Parser) (edns, ok bool) {
	if p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return false, false
	}
	for {
		h, err := p.AdditionalHeader()
		if err == dnsmessage.ErrSectionDone {
			return edns, true
		}
		if err != nil || p.SkipAdditional() != nil {
			return false, false
		}
		edns = edns || h.Type == dnsmessage.TypeOPT
	}
}

// Question is the name query asks for, lowercase without a final dot, and
// whether it asks for one.
func Question(query []byte) (name string, ok bool) {
	defer malformed.RecoverOK(&ok)
	name, _, _, ok = QuestionOf(query)
	return name, ok
}

// QuestionOf is [Question] and the type and class asked for.
func QuestionOf(query []byte) (_ string, qtype, qclass uint16, ok bool) {
	defer malformed.RecoverOK(&ok)
	var p dnsmessage.Parser
	if _, err := p.Start(query); err != nil {
		return "", 0, 0, false
	}
	q, err := p.Question()
	if err != nil {
		return "", 0, 0, false
	}
	return asciiLower(strings.TrimSuffix(q.Name.String(), ".")), uint16(q.Type), uint16(q.Class), true
}

// asciiLower is s with A to Z lowered alone, as DNS compares names.
func asciiLower(s string) string {
	b := []byte(s)
	for k, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[k] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// Overridden reports whether query asks for a name z overrides, or one below
// it, answered now or not.
func (z *Zone) Overridden(query []byte) bool {
	name, ok := Question(query)
	if !ok {
		return false
	}
	for {
		if _, ok := z.Overrides[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
}
