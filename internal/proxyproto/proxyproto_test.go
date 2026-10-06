package proxyproto

import (
	"bufio"
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

// A header written reads back as the client it names, of either family, and
// leaves what follows it; bytes that are no header read as none.
func TestAHeaderReadsBack(t *testing.T) {
	for _, src := range []string{"203.0.113.7:51000", "[2001:db8::7]:51000"} {
		s := netip.MustParseAddrPort(src)
		h := Header(s, netip.MustParseAddrPort("198.18.0.2:443"))
		r := bufio.NewReader(bytes.NewReader(append(h, "\x16\x03rest"...)))
		got, ok, err := Read(r)
		if err != nil || !ok || got != s {
			t.Errorf("%s read back as %v, %v, %v", src, got, ok, err)
		}
		if rest, _ := r.ReadString('t'); rest != "\x16\x03rest" {
			t.Errorf("after the header: %q", rest)
		}
	}
	r := bufio.NewReader(strings.NewReader("\x16\x03\x01 a ClientHello"))
	if _, ok, err := Read(r); ok || err != nil {
		t.Errorf("a ClientHello read as a header: %v, %v", ok, err)
	}
	if b, _ := r.Peek(3); string(b) != "\x16\x03\x01" {
		t.Errorf("a ClientHello lost %q", b)
	}
}

// A header too long, of another version or of an unknown family is refused.
func TestABadHeaderIsRefused(t *testing.T) {
	good := Header(netip.MustParseAddrPort("203.0.113.7:1"), netip.MustParseAddrPort("198.18.0.2:443"))
	for name, mutate := range map[string]func([]byte){
		"version 1": func(b []byte) { b[12] = 0x11 },
		"too long":  func(b []byte) { b[14], b[15] = 0xff, 0xff },
		"unix":      func(b []byte) { b[13] = 0x31 },
	} {
		b := bytes.Clone(good)
		mutate(b)
		if _, ok, err := Read(bufio.NewReader(bytes.NewReader(b))); ok || err == nil {
			t.Errorf("%s: read as %v, %v", name, ok, err)
		}
	}
}

func FuzzRead(f *testing.F) {
	f.Add(Header(netip.MustParseAddrPort("203.0.113.7:1"), netip.MustParseAddrPort("198.18.0.2:443")))
	f.Add([]byte("\x16\x03\x01"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = Read(bufio.NewReader(bytes.NewReader(b)))
	})
}

// A header for UDP reads back from a datagram of its own, and is no header
// for TCP, nor one for TCP a header for UDP; a datagram carrying more than
// its header is refused.
func TestAHeaderForUDP(t *testing.T) {
	for _, src := range []string{"203.0.113.7:51000", "[2001:db8::7]:51000"} {
		s := netip.MustParseAddrPort(src)
		h := HeaderUDP(s, netip.MustParseAddrPort("198.18.0.2:443"))
		if !IsHeader(h) {
			t.Errorf("%s: no header", src)
		}
		if got, err := ReadUDP(h); err != nil || got != s {
			t.Errorf("%s read back as %v, %v", src, got, err)
		}
		if _, ok, err := Read(bufio.NewReader(bytes.NewReader(h))); ok || err == nil {
			t.Errorf("%s: a header for UDP read for TCP", src)
		}
		if _, err := ReadUDP(append(h, 0xc0)); err == nil {
			t.Errorf("%s: a datagram with more than its header taken", src)
		}
	}
	if _, err := ReadUDP(Header(netip.MustParseAddrPort("203.0.113.7:1"), netip.MustParseAddrPort("198.18.0.2:443"))); err == nil {
		t.Error("a header for TCP read for UDP")
	}
	if IsHeader([]byte{0xc0, 0, 0, 0, 1}) {
		t.Error("a QUIC packet read as a header")
	}
}

// A LOCAL header for UDP names its client to ReadLocalUDP alone, done or
// not, and no client to Read or ReadUDP.
func TestALocalHeaderForUDP(t *testing.T) {
	for _, src := range []string{"203.0.113.7:51000", "[2001:db8::7]:51000"} {
		s := netip.MustParseAddrPort(src)
		for _, done := range []bool{false, true} {
			l := LocalUDP(s, done)
			if got, d, ok := ReadLocalUDP(l); !ok || got != s || d != done {
				t.Errorf("%s, done %v: read back as %v, %v, %v", src, done, got, d, ok)
			}
			if !IsHeader(l) {
				t.Errorf("%s: no header", src)
			}
			if _, err := ReadUDP(l); err == nil {
				t.Errorf("%s: a LOCAL header named a client", src)
			}
			if got, ok, err := Read(bufio.NewReader(bytes.NewReader(l))); !ok || err != nil || got.IsValid() {
				t.Errorf("%s: read for TCP as %v, %v, %v", src, got, ok, err)
			}
			if _, _, ok := ReadLocalUDP(append(l, 0)); ok {
				t.Errorf("%s: a datagram with more than its header taken", src)
			}
		}
		if _, _, ok := ReadLocalUDP(HeaderUDP(s, netip.MustParseAddrPort("198.18.0.2:443"))); ok {
			t.Errorf("%s: a PROXY header taken for a LOCAL one", src)
		}
	}
}

func FuzzReadUDP(f *testing.F) {
	f.Add(HeaderUDP(netip.MustParseAddrPort("203.0.113.7:1"), netip.MustParseAddrPort("198.18.0.2:443")))
	f.Add(LocalUDP(netip.MustParseAddrPort("[2001:db8::7]:1"), true))
	f.Fuzz(func(t *testing.T, b []byte) {
		if src, err := ReadUDP(b); err == nil && !src.IsValid() {
			t.Fatal("a header naming nothing taken")
		}
		if src, _, ok := ReadLocalUDP(b); ok && !src.IsValid() {
			t.Fatal("a LOCAL header naming nothing taken")
		}
	})
}
