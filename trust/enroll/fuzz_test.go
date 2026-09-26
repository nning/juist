package enroll

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"
)

// FuzzParseInvite covers the strings a person or a paste hands to "juist
// join": whatever parses must print back to something that parses the same.
func FuzzParseInvite(f *testing.F) {
	inv, err := NewInvite([]netip.AddrPort{netip.MustParseAddrPort("[2001:db8::1]:41642")})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(inv.Code().String())
	f.Add(inv.Link().String())
	f.Add(inv.Link().WithRelays([]netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:41645")}).String())
	f.Add("7 ACME Adviser aimless")
	f.Fuzz(func(t *testing.T, s string) {
		if IsLink(s) {
			l, err := ParseLink(s)
			if err != nil {
				return
			}
			again, err := ParseLink(l.String())
			if err != nil || again.secret != l.secret || !slices.Equal(again.Addrs, l.Addrs) ||
				!slices.Equal(again.Relays, l.Relays) {
				t.Fatalf("%q reprinted as %q, which parses as %v, %v", s, l.String(), again, err)
			}
			return
		}
		c, err := ParseCode(s)
		if err != nil {
			return
		}
		if again, err := ParseCode(c.String()); err != nil || again != c {
			t.Fatalf("%q reprinted as %q, which parses as %v, %v", s, c.String(), again, err)
		}
	})
}

// FuzzDecodeEnrollFrames covers both parsers a peer reaches before and after
// the key exchange, and asserts they only accept canonical encodings.
func FuzzDecodeEnrollFrames(f *testing.F) {
	hello, _ := encMode.Marshal(&hsFrame{Kind: hsHello, Version: 1, Mode: modeCode, Nameplate: 7,
		Element: spakeM.Bytes()})
	f.Add(hello)
	msg, _ := encMode.Marshal(&Message{Kind: KindWaiting, Waiting: &Waiting{Votes: 1, Quorum: 2}})
	f.Add(msg)
	f.Fuzz(func(t *testing.T, b []byte) {
		if fr, err := decodeHandshake(b); err == nil {
			if re, _ := encMode.Marshal(&fr); !bytes.Equal(re, b) {
				t.Fatal("a handshake frame decoded from a non-canonical encoding")
			}
		}
		if m, err := DecodeMessage(b); err == nil {
			if re, _ := encMode.Marshal(&m); !bytes.Equal(re, b) {
				t.Fatal("a message decoded from a non-canonical encoding")
			}
		}
	})
}
