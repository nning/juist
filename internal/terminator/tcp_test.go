package terminator

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/internal/nettest"
	"github.com/nning/juist/internal/proxyproto"
	"github.com/nning/juist/ipc"
)

// speaker is a local service that speaks first, then echoes, and records
// what each connection carried first.
func speaker(t *testing.T) (string, chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan []byte, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = c.Write([]byte("hello\n"))
				buf := make([]byte, 4096)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				got <- slices.Clone(buf[:n])
				_, _ = c.Write(buf[:n])
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String(), got
}

// startTCP runs a terminator passing mc, published by TCP, to to on a free
// port of 127.0.0.1, which an ingress at 127.0.0.1 reaches.
func startTCP(t *testing.T, to string, proxy bool) (*source, ipc.PublishedTarget, string) {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(probe.Addr().(*net.TCPAddr).Port)
	probe.Close()
	mc := ipc.PublishedTarget{Name: "mc.pub.example.org", Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		Port: port, Proxy: proxy, To: to, Public: 25565}
	src := &source{asked: make(chan struct{}), p: &ipc.Published{TCP: []ipc.PublishedTarget{mc},
		Ingresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Serve(ctx, Options{Serving: src.serving, Poll: 10 * time.Millisecond, GetCertificate: selfSigned(t)})
	}()
	t.Cleanup(func() { cancel(); <-done })
	<-src.asked
	<-src.asked
	return src, mc, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String()
}

// member is the loopback address a member connects from, other than the
// ingress's.
func member(t *testing.T) string {
	t.Helper()
	if !nettest.HasLoopbackAddr(netip.MustParseAddr("127.0.0.2")) {
		nettest.SkipUnlessRequired(t, "this host carries no 127.0.0.2 for a member to connect from")
	}
	return "127.0.0.2"
}

// dialFrom connects to addr from from, sends header where set, and reads
// the service's first line.
func dialFrom(t *testing.T, addr, from string, header []byte) (net.Conn, *bufio.Reader) {
	t.Helper()
	d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(from)}}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if header != nil {
		if _, err := c.Write(header); err != nil {
			t.Fatal(err)
		}
	}
	r := bufio.NewReader(c)
	if line, err := r.ReadString('\n'); err != nil || line != "hello\n" {
		t.Fatalf("the client got %q first, %v", line, err)
	}
	return c, r
}

// A name published by TCP is passed to its service as it is, which speaks
// first, from an ingress and from a member alike; no TLS ends for it.
func TestANamePublishedByTCPIsPassedAsItIs(t *testing.T) {
	to, got := speaker(t)
	_, _, addr := startTCP(t, to, false)
	for _, from := range []string{"127.0.0.1", member(t)} {
		c, r := dialFrom(t, addr, from, nil)
		if _, err := c.Write([]byte("\x16\x03\x01ping\n")); err != nil {
			t.Fatal(err)
		}
		if b := <-got; string(b) != "\x16\x03\x01ping\n" {
			t.Errorf("from %s, the service got %q", from, b)
		}
		if line, err := r.ReadString('\n'); err != nil || line != "\x16\x03\x01ping\n" {
			t.Errorf("from %s, the client got %q back, %v", from, line, err)
		}
	}
}

// Where the name asks for it, the service learns the client an ingress's
// header names, and a member's own address, whose header is not believed.
func TestAPassedNameTellsTheServiceTheClient(t *testing.T) {
	other := member(t)
	to, got := speaker(t)
	_, _, addr := startTCP(t, to, true)
	client := netip.MustParseAddrPort("203.0.113.7:51000")
	header := proxyproto.Header(client, netip.MustParseAddrPort(addr))
	for _, c := range []struct {
		from   string
		header []byte
		want   netip.Addr
	}{
		{"127.0.0.1", header, client.Addr()},
		{other, nil, netip.MustParseAddr(other)},
	} {
		conn, _ := dialFrom(t, addr, c.from, c.header)
		if _, err := conn.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		b := <-got
		src, ok, err := proxyproto.Read(bufio.NewReader(strings.NewReader(string(b))))
		if err != nil || !ok || src.Addr() != c.want {
			t.Errorf("from %s, the service learned %v, %v, %v from %q", c.from, src, ok, err, b)
		}
	}
	// A member's header goes on to the service, after the one naming it.
	conn, _ := dialFrom(t, addr, other, nil)
	if _, err := conn.Write(header); err != nil {
		t.Fatal(err)
	}
	b := <-got
	if src, _, _ := proxyproto.Read(bufio.NewReader(strings.NewReader(string(b)))); src.Addr() != netip.MustParseAddr(other) {
		t.Errorf("a member's header was believed: %v", src)
	}
}

// A name published by TCP withdrawn, or sent elsewhere, ends its
// connections and is listened for no longer once withdrawn.
func TestAPassedNameWithdrawnEndsItsConnections(t *testing.T) {
	from := member(t)
	to, _ := speaker(t)
	other, _ := speaker(t)
	src, mc, addr := startTCP(t, to, false)
	c, _ := dialFrom(t, addr, from, nil)
	moved := mc
	moved.To = other
	src.set(&ipc.Published{TCP: []ipc.PublishedTarget{moved}}, false)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("the connection to where the name no longer goes: %v", err)
	}
	c, _ = dialFrom(t, addr, from, nil)
	src.set(&ipc.Published{}, false)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("the connection for a withdrawn name: %v", err)
	}
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.Close()
		t.Error("a withdrawn name is still listened for")
	}
}
