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
