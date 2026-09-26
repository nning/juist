package host

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func pipeFrom(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

// A full greeter admits a newcomer at once by closing the connection that
// has waited longest: the accept loop that calls enter must never stall.
func TestAFullGreeterEvictsWithoutBlocking(t *testing.T) {
	g := newGreeter(t.Context(), false)
	var oldest net.Conn
	for i := range maxGreeting {
		c, far := pipeFrom(t)
		if i == 0 {
			oldest = far
		}
		src := sourceOf(&net.TCPAddr{IP: net.IPv4(10, 0, byte(i/250), byte(i%250+1)), Port: 1})
		if _, ok := g.enter(c, src); !ok {
			t.Fatalf("connection %d refused below the bound", i)
		}
	}
	c, _ := pipeFrom(t)
	start := time.Now()
	_, ok := g.enter(c, sourceOf(&net.TCPAddr{IP: net.IPv4(10, 9, 9, 9), Port: 1}))
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("entering a full greeter took %v", d)
	}
	if !ok {
		t.Fatal("a newcomer was refused rather than displacing the longest-silent connection")
	}
	_ = oldest.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := oldest.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("the longest-silent connection is still open: %v", err)
	}
}

// One host's addresses share a budget: IPv4 by address, IPv6 by /64.
func TestOneSourcePerHost(t *testing.T) {
	g := newGreeter(t.Context(), false)
	for i := range maxGreetingPerSource {
		c, _ := pipeFrom(t)
		ip := netip.MustParseAddr("2001:db8:1:2::1").Next()
		for range i {
			ip = ip.Next()
		}
		if _, ok := g.enter(c, sourceOf(net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, 1)))); !ok {
			t.Fatalf("connection %d refused below the bound", i)
		}
	}
	c, _ := pipeFrom(t)
	src := sourceOf(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:ffff::1"), Port: 1})
	if _, ok := g.enter(c, src); ok {
		t.Fatal("a fifth connection from one /64 was admitted")
	}
	if got := src.String(); got != "2001:db8:1:2::/64" {
		t.Fatalf("a v6 source reads %q", got)
	}
	c, _ = pipeFrom(t)
	if _, ok := g.enter(c, sourceOf(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:3::1"), Port: 1})); !ok {
		t.Fatal("the neighbouring /64 was refused")
	}
	mapped := sourceOf(&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 1})
	if plain := sourceOf(&net.TCPAddr{IP: net.IPv4(192, 0, 2, 1).To4(), Port: 1}); mapped != plain {
		t.Fatalf("a v4-mapped address is its own source: %v and %v", mapped, plain)
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
