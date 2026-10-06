package ingress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/time/rate"

	"github.com/nning/juist/internal/proxyproto"
	"github.com/nning/juist/ipc"
)

// counted is a target's socket, which counts the datagrams it reads and
// keeps the PROXY headers among them out of QUIC's way.
type counted struct {
	net.PacketConn
	read     atomic.Int32
	mu       sync.Mutex
	headers  []netip.AddrPort
	byRemote map[string]netip.AddrPort
}

// clientOf is the client the last header from remote named.
func (c *counted) clientOf(remote net.Addr) (netip.AddrPort, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	client, ok := c.byRemote[remote.String()]
	return client, ok
}

func (c *counted) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, a, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, a, err
		}
		c.read.Add(1)
		if proxyproto.IsHeader(p[:n]) {
			src, err := proxyproto.ReadUDP(p[:n])
			if err == nil {
				c.mu.Lock()
				c.headers = append(c.headers, src)
				if c.byRemote == nil {
					c.byRemote = map[string]netip.AddrPort{}
				}
				c.byRemote[a.String()] = src
				c.mu.Unlock()
			}
			continue
		}
		return n, a, err
	}
}

func selfSigned(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), DNSNames: []string{name}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// quicTarget is a terminator's QUIC for name: it echoes every stream, and
// tells the ingress each client that completed its handshake, and each
// connection ended.
func quicTarget(t *testing.T, name string) (*counted, ipc.PublishedTarget) {
	return quicTargetTelling(t, name, true)
}

func quicTargetTelling(t *testing.T, name string, tell bool) (*counted, ipc.PublishedTarget) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &counted{PacketConn: pc}
	ln, err := quic.Listen(c, &tls.Config{Certificates: []tls.Certificate{selfSigned(t, name)}, NextProtos: []string{"echo"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); pc.Close() })
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			if client, ok := c.clientOf(conn.RemoteAddr()); ok && tell {
				_, _ = pc.WriteTo(proxyproto.LocalUDP(client, false), conn.RemoteAddr())
				context.AfterFunc(conn.Context(), func() {
					_, _ = pc.WriteTo(proxyproto.LocalUDP(client, true), conn.RemoteAddr())
				})
			}
			go func() {
				for {
					s, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func() {
						_, _ = io.Copy(s, s)
						s.Close()
					}()
				}
			}()
		}
	}()
	ap := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	return c, ipc.PublishedTarget{Name: name, Addrs: []netip.Addr{ap.Addr()}, Port: ap.Port()}
}

// startQUIC runs an ingress whose 443/udp is a socket on 127.0.0.1, and
// says where.
func startQUIC(t *testing.T, src *source, o Options) (*net.UDPConn, *ingress) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	o.ListenQUIC = func() (*net.UDPConn, error) { return pc, nil }
	var started atomic.Pointer[ingress]
	o.started = func(in *ingress) { started.Store(in) }
	startIngressWith(t, src, o)
	waitFor(t, "QUIC served", func() bool { return started.Load() != nil && started.Load().quic.Load() != nil })
	return pc, started.Load()
}

// echo opens QUIC to addr for name and has a stream echo a line.
func echo(ctx context.Context, addr net.Addr, name string) (string, error) {
	conn, err := quic.DialAddr(ctx, addr.String(), &tls.Config{ServerName: name, InsecureSkipVerify: true,
		NextProtos: []string{"echo"}}, nil)
	if err != nil {
		return "", err
	}
	defer conn.CloseWithError(0, "")
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return "", err
	}
	if _, err := s.Write([]byte("hello")); err != nil {
		return "", err
	}
	s.Close()
	b, err := io.ReadAll(s)
	return string(b), err
}

// QUIC for a published name reaches its target, a handshake and a stream
// both ways, by the name the client's Initials ask for; for another name
// not one datagram is passed on.
func TestQUICIsPassedByName(t *testing.T) {
	target, pt := quicTarget(t, "immich.pub.example.org")
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{pt}}}
	var l lines
	pc, _ := startQUIC(t, src, Options{Access: l.add})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if got, err := echo(ctx, pc.LocalAddr(), "immich.pub.example.org"); err != nil || got != "hello" {
		t.Fatalf("through the ingress: %q, %v", got, err)
	}
	target.mu.Lock()
	for _, h := range target.headers {
		if h.Addr() != netip.MustParseAddr("127.0.0.1") {
			t.Errorf("the target was told %v", h)
		}
	}
	target.mu.Unlock()

	// What the first connection sent last, its close, comes first.
	time.Sleep(300 * time.Millisecond)
	read := target.read.Load()
	short, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if _, err := echo(short, pc.LocalAddr(), "other.pub.example.org"); err == nil {
		t.Error("a name not published reached a target")
	}
	if n := target.read.Load() - read; n != 0 {
		t.Errorf("the target got %d datagrams for a name not published", n)
	}
	l.find(t, "access: quic 127.0.0.1:", `"other.pub.example.org" not served up=`)
}

// Where the name asks for it, the target is told the client in a PROXY v2
// header for UDP, a datagram of its own, until it answers.
func TestQUICTellsTheTargetTheClient(t *testing.T) {
	target, pt := quicTarget(t, "immich.pub.example.org")
	pt.Proxy = true
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{pt}}}
	pc, _ := startQUIC(t, src, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := quic.Dial(ctx, client, pc.LocalAddr(), &tls.Config{ServerName: "immich.pub.example.org",
		InsecureSkipVerify: true, NextProtos: []string{"echo"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.CloseWithError(0, "")
	target.mu.Lock()
	defer target.mu.Unlock()
	want := client.LocalAddr().(*net.UDPAddr).AddrPort()
	if len(target.headers) == 0 || target.headers[0] != want {
		t.Errorf("the target was told %v, want %v", target.headers, want)
	}
}

// A datagram that is no client's first Initial, or does not parse, keeps
// nothing at the ingress.
func TestWhatDoesNotParseKeepsNothing(t *testing.T) {
	_, pt := quicTarget(t, "immich.pub.example.org")
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{pt}}}
	pc, in := startQUIC(t, src, Options{})
	c, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	initialLike := make([]byte, 1200)
	initialLike[0], initialLike[4] = 0xc0, 1 // long header, version 1, and noise
	for _, d := range [][]byte{make([]byte, 1200), initialLike, {0x40, 1, 2, 3}, initialLike[:100]} {
		if _, err := c.Write(d); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	q := in.quic.Load()
	q.mu.Lock()
	n := len(q.flows)
	q.mu.Unlock()
	if n != 0 {
		t.Errorf("%d flows kept for what does not parse", n)
	}
}

// firstInitials are the datagrams a QUIC client sends for name before it
// hears back: its ClientHello, with a post-quantum key share, takes two.
func firstInitials(t *testing.T, name string) [][]byte {
	t.Helper()
	catch, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer catch.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		_, _ = quic.DialAddr(ctx, catch.LocalAddr().String(), &tls.Config{ServerName: name, NextProtos: []string{"echo"}}, nil)
	}()
	var out [][]byte
	for deadline := time.Now().Add(2 * time.Second); ; {
		buf := make([]byte, 2048)
		next := time.Now().Add(200 * time.Millisecond)
		if next.After(deadline) {
			next = deadline
		}
		_ = catch.SetReadDeadline(next)
		n, _, err := catch.ReadFromUDP(buf)
		if err != nil {
			break
		}
		out = append(out, buf[:n])
	}
	if len(out) == 0 {
		t.Fatal("the client sent nothing")
	}
	return out
}

// A target that answers more than it was sent reaches a client that has not
// shown its address is its own with three times what that client sent, no
// more (RFC 9000, 8.1), whatever the target sends.
func TestTheIngressAmplifiesThreeTimesAtMost(t *testing.T) {
	loud, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer loud.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			_, from, err := loud.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			for range 20 {
				_, _ = loud.WriteToUDPAddrPort(make([]byte, 1200), from)
			}
		}
	}()
	ap := loud.LocalAddr().(*net.UDPAddr).AddrPort()
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{{Name: "immich.pub.example.org",
		Addrs: []netip.Addr{ap.Addr()}, Port: ap.Port()}}}}
	pc, _ := startQUIC(t, src, Options{})
	c, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sent := 0
	for _, d := range firstInitials(t, "immich.pub.example.org") {
		if _, err := c.Write(d); err != nil {
			t.Fatal(err)
		}
		sent += len(d)
	}
	got := 0
	buf := make([]byte, 2048)
	for {
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.Read(buf)
		if err != nil {
			break
		}
		got += n
	}
	if got == 0 || got > 3*sent {
		t.Errorf("sent %d bytes, got %d back", sent, got)
	}
}

// A name withdrawn ends its QUIC flows: what the client sends then reaches
// the target no more.
func TestAWithdrawnNameEndsItsQUIC(t *testing.T) {
	target, pt := quicTarget(t, "immich.pub.example.org")
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{pt}}}
	pc, in := startQUIC(t, src, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, pc.LocalAddr().String(), &tls.Config{ServerName: "immich.pub.example.org",
		InsecureSkipVerify: true, NextProtos: []string{"echo"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	src.set(&ipc.Published{})
	waitFor(t, "the flow ended", func() bool {
		q := in.quic.Load()
		q.mu.Lock()
		defer q.mu.Unlock()
		return len(q.flows) == 0
	})
	read := target.read.Load()
	s, err := conn.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Write([]byte("hello"))
	time.Sleep(300 * time.Millisecond)
	if n := target.read.Load() - read; n != 0 {
		t.Errorf("the target got %d datagrams for a name withdrawn", n)
	}
}

// A proven flow quiet for flowIdle ends, and gives its slot back.
func TestAQuietQUICFlowEnds(t *testing.T) {
	_, pt := quicTarget(t, "immich.pub.example.org")
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{pt}}}
	pc, in := startQUIC(t, src, Options{flowIdle: 300 * time.Millisecond})
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: sock}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := tr.Dial(ctx, pc.LocalAddr(), &tls.Config{ServerName: "immich.pub.example.org",
		InsecureSkipVerify: true, NextProtos: []string{"echo"}}, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the client proven", func() bool { return len(in.conns) == 1 })
	sock.Close() // quiet, as a client gone
	waitFor(t, "the quiet flow ended", func() bool {
		q := in.quic.Load()
		q.mu.Lock()
		defer q.mu.Unlock()
		return len(q.flows) == 0 && len(in.conns) == 0
	})
}

// Flows whose client is unproven are bounded from one address, and hold
// no slot of the bounds TCP shares: what a spoofed address may start costs
// no more.
func TestUnprovenFlowsAreBoundedBySource(t *testing.T) {
	_, pt := quicTarget(t, "immich.pub.example.org")
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{pt}}}
	var l lines
	pc, in := startQUIC(t, src, Options{Access: l.add, MaxConns: 4})
	initials := firstInitials(t, "immich.pub.example.org")
	for range maxUnprovenPerSource + 1 {
		c, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		for _, d := range initials {
			if _, err := c.Write(d); err != nil {
				t.Fatal(err)
			}
		}
	}
	l.find(t, "access: quic 127.0.0.1:", "refused: too many unproven flows")
	q := in.quic.Load()
	q.mu.Lock()
	n, unproven := len(q.flows), (q.waiting.Len() + q.unproven.Len())
	q.mu.Unlock()
	if n != maxUnprovenPerSource || unproven != maxUnprovenPerSource {
		t.Errorf("%d flows, %d unproven", n, unproven)
	}
	if held := len(in.conns); held != 0 {
		t.Errorf("unproven flows hold %d slots TCP shares", held)
	}
}

// A client sending what any spoofed address could, a datagram with a short
// header to a connection ID it made up, is proven no more: three times what
// it sent is what comes back.
func TestAMadeUpPacketProvesNothing(t *testing.T) {
	loud, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer loud.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			_, from, err := loud.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			for range 20 {
				_, _ = loud.WriteToUDPAddrPort(make([]byte, 1200), from)
			}
		}
	}()
	ap := loud.LocalAddr().(*net.UDPAddr).AddrPort()
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{{Name: "immich.pub.example.org",
		Addrs: []netip.Addr{ap.Addr()}, Port: ap.Port()}}}}
	pc, _ := startQUIC(t, src, Options{})
	c, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sent := 0
	for _, d := range append(firstInitials(t, "immich.pub.example.org"), []byte{0x40, 1, 2, 3, 4, 5, 6, 7, 8, 9}) {
		if _, err := c.Write(d); err != nil {
			t.Fatal(err)
		}
		sent += len(d)
	}
	got := 0
	buf := make([]byte, 2048)
	for {
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.Read(buf)
		if err != nil {
			break
		}
		got += n
	}
	if got > 3*sent {
		t.Errorf("sent %d bytes, got %d back", sent, got)
	}
}

// A real client is proven once the target says so, and then holds a slot of
// the bounds TCP shares, which it gives back once the target says the
// connection ended.
func TestARealClientIsProven(t *testing.T) {
	_, pt := quicTarget(t, "immich.pub.example.org")
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{pt}}}
	pc, in := startQUIC(t, src, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, pc.LocalAddr().String(), &tls.Config{ServerName: "immich.pub.example.org",
		InsecureSkipVerify: true, NextProtos: []string{"echo"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the client proven", func() bool { return len(in.conns) == 1 })
	q := in.quic.Load()
	q.mu.Lock()
	unproven := (q.waiting.Len() + q.unproven.Len())
	q.mu.Unlock()
	if unproven != 0 {
		t.Errorf("%d unproven", unproven)
	}
	conn.CloseWithError(0, "")
	waitFor(t, "the slot given back", func() bool { return len(in.conns) == 0 })
}

// One socket of a client's connects to several names, as quic-go's does:
// a name going to the target of the flow from its address joins it, the
// first connection kept; a name going to another target is refused.
func TestConnectionsFromOneSocket(t *testing.T) {
	_, a := quicTarget(t, "a.pub.example.org")
	b := a
	b.Name = "b.pub.example.org"
	_, c := quicTarget(t, "c.pub.example.org")
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{a, b, c}}}
	var l lines
	pc, in := startQUIC(t, src, Options{Access: l.add})
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	tr := &quic.Transport{Conn: sock}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dial := func(ctx context.Context, name string) (*quic.Conn, error) {
		return tr.Dial(ctx, pc.LocalAddr(), &tls.Config{ServerName: name, InsecureSkipVerify: true,
			NextProtos: []string{"echo"}}, nil)
	}
	echoOn := func(conn *quic.Conn) error {
		s, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return err
		}
		if _, err := s.Write([]byte("hello")); err != nil {
			return err
		}
		s.Close()
		got, err := io.ReadAll(s)
		if err == nil && string(got) != "hello" {
			err = fmt.Errorf("echoed %q", got)
		}
		return err
	}
	first, err := dial(ctx, "a.pub.example.org")
	if err != nil {
		t.Fatal(err)
	}
	second, err := dial(ctx, "b.pub.example.org")
	if err != nil {
		t.Fatalf("a name of the same target: %v", err)
	}
	for i, conn := range []*quic.Conn{first, second} {
		if err := echoOn(conn); err != nil {
			t.Errorf("connection %d: %v", i, err)
		}
	}
	short, cancel2 := context.WithTimeout(ctx, 2*time.Second)
	defer cancel2()
	if _, err := dial(short, "c.pub.example.org"); err == nil {
		t.Error("a name of another target joined the flow")
	}
	if err := echoOn(first); err != nil {
		t.Errorf("the first connection, after another target's: %v", err)
	}
	l.find(t, "access: quic 127.0.0.1:", `"c.pub.example.org" refused: another name's flow from its address`)
	first.CloseWithError(0, "")
	time.Sleep(300 * time.Millisecond)
	if err := echoOn(second); err != nil {
		t.Errorf("the second connection, after the first ended: %v", err)
	}
	second.CloseWithError(0, "")
	waitFor(t, "the flow ended with its connections", func() bool {
		q := in.quic.Load()
		q.mu.Lock()
		defer q.mu.Unlock()
		return len(q.flows) == 0
	})
}

// Past the bound on unproven flows, the oldest gives way to a new one.
func TestTheOldestUnprovenFlowGivesWay(t *testing.T) {
	_, pt := quicTargetTelling(t, "immich.pub.example.org", false)
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{pt}}}
	var l lines
	pc, in := startQUIC(t, src, Options{Access: l.add, maxUnproven: 2})
	initials := firstInitials(t, "immich.pub.example.org")
	var socks []*net.UDPConn
	for range 3 {
		c, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		socks = append(socks, c)
		for _, d := range initials {
			if _, err := c.Write(d); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	q := in.quic.Load()
	waitFor(t, "two flows", func() bool {
		q.mu.Lock()
		defer q.mu.Unlock()
		return len(q.flows) == 2
	})
	q.mu.Lock()
	_, first := q.flows[socks[0].LocalAddr().(*net.UDPAddr).AddrPort()]
	q.mu.Unlock()
	if first {
		t.Error("the oldest unproven flow stayed")
	}
	l.find(t, "access: quic 127.0.0.1:", "ended for a newer unproven flow")
}

// loudTarget answers each datagram with twenty of 1200 bytes, and a PROXY
// header with what tell makes of the client it names, where set.
func loudTarget(t *testing.T, tell func(client netip.AddrPort) []byte) ipc.PublishedTarget {
	t.Helper()
	loud, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { loud.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := loud.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if proxyproto.IsHeader(buf[:n]) {
				if client, err := proxyproto.ReadUDP(buf[:n]); err == nil && tell != nil {
					_, _ = loud.WriteToUDPAddrPort(tell(client), from)
				}
				continue
			}
			for range 20 {
				_, _ = loud.WriteToUDPAddrPort(make([]byte, 1200), from)
			}
		}
	}()
	ap := loud.LocalAddr().(*net.UDPAddr).AddrPort()
	return ipc.PublishedTarget{Name: "immich.pub.example.org", Addrs: []netip.Addr{ap.Addr()}, Port: ap.Port()}
}

// sendInitials sends a client's first Initials for name through c, and
// reports what came back: in bytes, and whether a PROXY header did.
func sendInitials(t *testing.T, c *net.UDPConn, name string, more ...[]byte) (sent, got int, header bool) {
	t.Helper()
	for _, d := range append(firstInitials(t, name), more...) {
		if _, err := c.Write(d); err != nil {
			t.Fatal(err)
		}
		sent += len(d)
	}
	buf := make([]byte, 2048)
	for {
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.Read(buf)
		if err != nil {
			return sent, got, header
		}
		got += n
		header = header || proxyproto.IsHeader(buf[:n])
	}
}

// Once the target says by a LOCAL header naming the client that it proved
// its address, all it sends reaches the client, the header aside; one
// naming another client, as of a flow the socket was before, proves nothing.
func TestTheTargetProvesTheClient(t *testing.T) {
	other := loudTarget(t, func(netip.AddrPort) []byte {
		return proxyproto.LocalUDP(netip.MustParseAddrPort("203.0.113.7:1"), false)
	})
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{other}}}
	pc, in := startQUIC(t, src, Options{})
	c, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if sent, got, _ := sendInitials(t, c, "immich.pub.example.org"); got > 3*sent || len(in.conns) != 0 {
		t.Errorf("told of another client: sent %d bytes, got %d back, %d slots held", sent, got, len(in.conns))
	}

	src = &source{p: &ipc.Published{Names: []ipc.PublishedTarget{loudTarget(t, func(c netip.AddrPort) []byte {
		return proxyproto.LocalUDP(c, false)
	})}}}
	pc, in = startQUIC(t, src, Options{})
	c2, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	sent, got, header := sendInitials(t, c2, "immich.pub.example.org")
	if got <= 3*sent || header {
		t.Errorf("sent %d bytes, got %d back, a header among them: %v", sent, got, header)
	}
	if len(in.conns) != 1 {
		t.Errorf("a proven client holds %d slots TCP shares", len(in.conns))
	}
}

// A PROXY header from a client goes no further: it would name another
// client to the target.
func TestAClientsHeaderIsDropped(t *testing.T) {
	target, pt := quicTarget(t, "immich.pub.example.org")
	pt.Proxy = true
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{pt}}}
	pc, _ := startQUIC(t, src, Options{})
	c, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	lie := proxyproto.HeaderUDP(netip.MustParseAddrPort("6.6.6.6:1"), netip.MustParseAddrPort("0.0.0.0:443"))
	sendInitials(t, c, "immich.pub.example.org", lie)
	target.mu.Lock()
	defer target.mu.Unlock()
	want := c.LocalAddr().(*net.UDPAddr).AddrPort()
	for _, h := range target.headers {
		if h != want {
			t.Errorf("the target was told %v, want %v", h, want)
		}
	}
}

// A flow whose target does not say its client is proven ends after twice
// helloTimeout, holding no slot of the bounds TCP shares meanwhile.
func TestAnUnprovenFlowEnds(t *testing.T) {
	_, pt := quicTargetTelling(t, "immich.pub.example.org", false)
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{pt}}}
	var l lines
	pc, in := startQUIC(t, src, Options{Access: l.add, helloTimeout: 500 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if got, err := echo(ctx, pc.LocalAddr(), "immich.pub.example.org"); err != nil || got != "hello" {
		t.Fatalf("through the ingress: %q, %v", got, err)
	}
	if len(in.conns) != 0 {
		t.Errorf("an unproven flow holds %d slots TCP shares", len(in.conns))
	}
	l.find(t, "access: quic 127.0.0.1:", `"immich.pub.example.org" not proven up=`)
}

// 443/udp held by another program is said once and told juistd, and taken
// as soon as it is free.
func TestQUICIsTakenOnceFree(t *testing.T) {
	_, pt := quicTarget(t, "immich.pub.example.org")
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{pt}}}
	var held atomic.Bool
	held.Store(true)
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var logs lines
	startIngressWith(t, src, Options{Logf: logs.add, ListenQUIC: func() (*net.UDPConn, error) {
		if held.Load() {
			return nil, errors.New("address already in use")
		}
		return pc, nil
	}})
	waitFor(t, "juistd told", func() bool { return src.report().NoQUIC })
	time.Sleep(100 * time.Millisecond)
	logs.mu.Lock()
	n := strings.Count(strings.Join(logs.got, "\n"), "no QUIC on 443/udp")
	logs.mu.Unlock()
	if n != 1 {
		t.Errorf("said %d times", n)
	}
	held.Store(false)
	waitFor(t, "QUIC taken", func() bool { return !src.report().NoQUIC })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if got, err := echo(ctx, pc.LocalAddr(), "immich.pub.example.org"); err != nil || got != "hello" {
		t.Errorf("once free: %q, %v", got, err)
	}
}

// oneSocket is a client's socket, and an ingress whose names a and b go to
// one target.
func oneSocket(t *testing.T) (*quic.Transport, net.Addr, *ingress) {
	t.Helper()
	_, a := quicTarget(t, "a.pub.example.org")
	b := a
	b.Name = "b.pub.example.org"
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{a, b}}}
	pc, in := startQUIC(t, src, Options{})
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sock.Close() })
	tr := &quic.Transport{Conn: sock}
	t.Cleanup(func() { tr.Close() })
	return tr, pc.LocalAddr(), in
}

func dialOn(ctx context.Context, tr *quic.Transport, at net.Addr, name string) (*quic.Conn, error) {
	return tr.Dial(ctx, at, &tls.Config{ServerName: name, InsecureSkipVerify: true, NextProtos: []string{"echo"}}, nil)
}

func echoOn(ctx context.Context, conn *quic.Conn) error {
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	if _, err := s.Write([]byte("hello")); err != nil {
		return err
	}
	s.Close()
	_, err = io.ReadAll(s)
	return err
}

// Past the rate of new flows, a connection from a flow's socket is dropped,
// not passed uncounted: its end then would end the flow under the first.
func TestPastTheRateNoConnectionJoins(t *testing.T) {
	tr, at, in := oneSocket(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	first, err := dialOn(ctx, tr, at, "a.pub.example.org")
	if err != nil {
		t.Fatal(err)
	}
	defer first.CloseWithError(0, "")
	q := in.quic.Load()
	q.mu.Lock()
	q.inAll = rate.NewLimiter(0, 0) // as under a flood of spoofed Initials
	q.mu.Unlock()
	short, cancel2 := context.WithTimeout(ctx, 2*time.Second)
	defer cancel2()
	if second, err := dialOn(short, tr, at, "b.pub.example.org"); err == nil {
		second.CloseWithError(0, "")
		t.Error("a connection past the rate")
	}
	time.Sleep(300 * time.Millisecond)
	if err := echoOn(ctx, first); err != nil {
		t.Errorf("the first connection: %v", err)
	}
}

// The connections a flow carries are bounded while they live: one after
// another, more join than the bound.
func TestConnectionsJoinOneAfterAnother(t *testing.T) {
	tr, at, _ := oneSocket(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	first, err := dialOn(ctx, tr, at, "a.pub.example.org")
	if err != nil {
		t.Fatal(err)
	}
	defer first.CloseWithError(0, "")
	for i := range maxConnections + 2 {
		short, cancel2 := context.WithTimeout(ctx, 3*time.Second)
		conn, err := dialOn(short, tr, at, "b.pub.example.org")
		cancel2()
		if err != nil {
			t.Fatalf("connection %d after the first: %v", i+1, err)
		}
		if err := echoOn(ctx, conn); err != nil {
			t.Fatalf("connection %d after the first: %v", i+1, err)
		}
		conn.CloseWithError(0, "")
		time.Sleep(100 * time.Millisecond)
	}
	if err := echoOn(ctx, first); err != nil {
		t.Errorf("the first connection: %v", err)
	}
}
