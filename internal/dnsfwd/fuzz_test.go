package dnsfwd

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// A query the host's programs send is answered a failure with its question,
// and an answer from upstream, whatever it holds, has every TTL capped where
// it parses and fits a datagram truncated; none of it panics.
func FuzzForwarded(f *testing.F) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, Response: true})
	b.EnableCompression()
	b.StartQuestions()
	name := dnsmessage.MustNewName("example.com.")
	b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	b.StartAnswers()
	b.AResource(dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 86400}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}})
	b.StartAdditionals()
	var opt dnsmessage.ResourceHeader
	opt.SetEDNS0(1232, dnsmessage.RCodeSuccess, true)
	b.OPTResource(opt, dnsmessage.OPTResource{})
	resp, err := b.Finish()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(query(1))
	f.Add(resp)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, msg []byte) {
		if isQuery(msg) {
			fail := failure(msg, RCodeServFail)
			if !answers(fail, msg) || fail[3]&0x0f != RCodeServFail {
				t.Fatalf("failed %x as %x", msg, fail)
			}
		}
		fit := (&Forwarder{opts: Options{MaxUDP: 512}}).fitUDP(msg)
		if len(msg) > 512 && len(fit) > 512 {
			t.Fatalf("%d bytes fit as %d", len(msg), len(fit))
		}
		capped := append([]byte(nil), msg...)
		capTTL(capped, 60)
		var p dnsmessage.Parser
		if _, err := p.Start(capped); err != nil {
			return
		}
		if p.SkipAllQuestions() != nil {
			return
		}
		for {
			h, err := p.AnswerHeader()
			if err != nil {
				break
			}
			if h.TTL > 60 {
				t.Fatalf("an answer's TTL %d passed the cap in %x", h.TTL, msg)
			}
			if p.SkipAnswer() != nil {
				return
			}
		}
	})
}
