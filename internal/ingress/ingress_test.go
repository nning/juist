package ingress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/ipc"
)

// target is a member's service: it records the first bytes of each
// connection and answers "ok".
type target struct {
	ln  net.Listener
	got chan []byte
}

func newTarget(t *testing.T) *target {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	tg := &target{ln: ln, got: make(chan []byte, 8)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				// What arrives until the client pauses.
				var got []byte
				buf := make([]byte, 4096)
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				for {
					n, err := c.Read(buf)
					got = append(got, buf[:n]...)
					if err != nil {
						break
					}
					_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				}
				tg.got <- got
				_, _ = c.Write([]byte("ok"))
			}()
		}
	}()
	return tg
}

func (tg *target) published(name string, proxy bool) ipc.PublishedTarget {
	ap := tg.ln.Addr().(*net.TCPAddr).AddrPort()
	return ipc.PublishedTarget{Name: name, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.9"), ap.Addr()},
		Port: ap.Port(), Proxy: proxy}
}

// source is juistd's answer, which a test may change or silence, and the
// last report it was told.
type source struct {
	mu     sync.Mutex
	p      *ipc.Published
	silent bool
	hangs  bool
	delay  time.Duration
	asked  atomic.Int32
	told   ipc.IngressReport
}

func (s *source) set(p *ipc.Published) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.p = p
}

func (s *source) report() ipc.IngressReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.told
}

func (s *source) ask(ctx context.Context, r *ipc.IngressReport) (*ipc.Published, error) {
	s.asked.Add(1)
	time.Sleep(s.delay)
	s.mu.Lock()
	defer s.mu.Unlock()
	if r != nil {
		s.told = *r
	}
	if s.hangs {
		s.mu.Unlock()
		<-ctx.Done()
		s.mu.Lock()
		return nil, ctx.Err()
	}
	if s.silent {
		return nil, errors.New("no juistd")
	}
	return s.p, nil
}

func startIngress(t *testing.T, src *source) (tlsAddr, httpAddr string) {
	t.Helper()
	return startIngressWith(t, src, Options{})
}

func startIngressWith(t *testing.T, src *source, o Options) (tlsAddr, httpAddr string) {
	t.Helper()
	tlsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	o.Published, o.Poll = src.ask, 20*time.Millisecond
	go func() { done <- Serve(ctx, tlsLn, httpLn, o) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	// asked counts on entry: the second ask means the first answer is stored.
	for src.asked.Load() < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	return tlsLn.Addr().String(), httpLn.Addr().String()
}

// hello sends a ClientHello for name and returns what came back, read by
// nothing else.
func hello(t *testing.T, addr, name string) []byte {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(clientHello(t, name)); err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(c)
	return b
}

// clientHello is the record a TLS client opens with, asking for name.
func clientHello(t *testing.T, name string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
		client.Close()
	}()
	head := make([]byte, 5)
	if _, err := io.ReadFull(server, head); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(head[3])<<8|int(head[4]))
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatal(err)
	}
	return append(head, body...)
}

// A connection for a published name reaches its target untouched, the
// ClientHello first, past an address that does not answer; for another name
// it reaches nothing.
func TestTheIngressSplicesByServerName(t *testing.T) {
	tg := newTarget(t)
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{tg.published("immich.pub.example.org", false)}}, delay: 50 * time.Millisecond}
	tlsAddr, _ := startIngress(t, src)

	if got := hello(t, tlsAddr, "Immich.Pub.Example.org"); !bytes.Equal(got, []byte("ok")) {
		t.Fatalf("the client got %q", got)
	}
	first := <-tg.got
	if len(first) < 6 || first[0] != 0x16 || first[5] != 0x01 {
		t.Fatalf("the target got %x, not the client's own ClientHello", first)
	}
	if got := hello(t, tlsAddr, "other.pub.example.org"); len(got) != 0 {
		t.Errorf("a name not published got %q", got)
	}
	select {
	case b := <-tg.got:
		t.Errorf("the target got %x for a name not published", b)
	case <-time.After(100 * time.Millisecond):
	}
}

// Where the name asks for it, the target learns the client's address from a
// PROXY protocol v2 header ahead of the ClientHello.
func TestTheIngressSaysWhoTheClientIs(t *testing.T) {
	tg := newTarget(t)
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{tg.published("immich.pub.example.org", true)}}}
	tlsAddr, _ := startIngress(t, src)
	hello(t, tlsAddr, "immich.pub.example.org")
	got := <-tg.got
	sig := []byte("\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c\x7f\x00\x00\x01")
	if !bytes.HasPrefix(got, sig) || got[28] != 0x16 {
		t.Fatalf("the target got %x", got)
	}
}

// Over HTTP an ingress redirects a served name to https, and reads nothing
// else of it.
func TestTheIngressRedirectsToHTTPS(t *testing.T) {
	tg := newTarget(t)
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{tg.published("immich.pub.example.org", false)}}}
	_, httpAddr := startIngress(t, src)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest("GET", "http://"+httpAddr+"/photos?a=1", nil)
	req.Host = "immich.pub.example.org"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != "https://immich.pub.example.org/photos?a=1" {
		t.Errorf("redirected %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	req.Host = "other.pub.example.org"
	if resp, err := client.Do(req); err != nil || resp.StatusCode != http.StatusNotFound {
		t.Errorf("a name not published: %v, %v", resp, err)
	}
}

// A juistd that stops answering takes the names down after two asks, and
// one that answers again brings them back.
func TestASilentJuistdPublishesNothing(t *testing.T) {
	tg := newTarget(t)
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{tg.published("immich.pub.example.org", false)}}}
	tlsAddr, _ := startIngress(t, src)
	src.mu.Lock()
	src.silent = true
	src.mu.Unlock()
	asked := src.asked.Load()
	for src.asked.Load() < asked+3 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := hello(t, tlsAddr, "immich.pub.example.org"); len(got) != 0 {
		t.Fatalf("with juistd silent, the client got %q", got)
	}
	src.mu.Lock()
	src.silent = false
	src.mu.Unlock()
	asked = src.asked.Load()
	for src.asked.Load() < asked+2 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := hello(t, tlsAddr, "immich.pub.example.org"); !bytes.Equal(got, []byte("ok")) {
		t.Errorf("with juistd back, the client got %q", got)
	}
}

// A connection that never says hello is let go.
func TestAClientThatSaysNothingIsLetGo(t *testing.T) {
	src := &source{p: &ipc.Published{}}
	tlsAddr, _ := startIngressWith(t, src, Options{helloTimeout: 200 * time.Millisecond})
	c, err := net.Dial("tcp", tlsAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("a silent client: %v", err)
	}
}

// holder is a service that takes connections and holds them, counting them.
type holder struct {
	ln       net.Listener
	accepted atomic.Int32
}

func newHolder(t *testing.T, closeAfterRead bool) *holder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	h := &holder{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			h.accepted.Add(1)
			go func() {
				defer c.Close()
				_, _ = c.Read(make([]byte, 4096))
				if !closeAfterRead {
					_, _ = io.Copy(io.Discard, c)
				}
			}()
		}
	}()
	return h
}

func (h *holder) published(name string) ipc.PublishedTarget {
	ap := h.ln.Addr().(*net.TCPAddr).AddrPort()
	return ipc.PublishedTarget{Name: name, Addrs: []netip.Addr{ap.Addr()}, Port: ap.Port()}
}

// helloAndHold sends a ClientHello for name and keeps the connection.
func helloAndHold(t *testing.T, addr, name string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() { _ = tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake() }()
	return c
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("not after 5s: %s", what)
		}
	}
}

// A client gone quiet once its target closed gives its slot back.
func TestAQuietClientGivesItsSlotBack(t *testing.T) {
	h := newHolder(t, true)
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{h.published("immich.pub.example.org")}}}
	tlsAddr, _ := startIngressWith(t, src, Options{MaxConns: 1, idle: 100 * time.Millisecond})
	helloAndHold(t, tlsAddr, "immich.pub.example.org")
	waitFor(t, "the first connection", func() bool { return h.accepted.Load() == 1 })
	waitFor(t, "a second connection, once the first idled", func() bool {
		c := helloAndHold(t, tlsAddr, "immich.pub.example.org")
		defer c.Close()
		time.Sleep(50 * time.Millisecond)
		return h.accepted.Load() == 2
	})
}

// One host holds a few connections at once, and no more.
func TestAHostHoldsAFewConnections(t *testing.T) {
	h := newHolder(t, false)
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{h.published("immich.pub.example.org")}}}
	tlsAddr, _ := startIngressWith(t, src, Options{MaxPerSource: 1})
	helloAndHold(t, tlsAddr, "immich.pub.example.org")
	waitFor(t, "the first connection", func() bool { return h.accepted.Load() == 1 })
	c := helloAndHold(t, tlsAddr, "immich.pub.example.org")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("a second connection from the host: %v", err)
	}
	if n := h.accepted.Load(); n != 1 {
		t.Errorf("the target took %d connections", n)
	}
}

// A name withdrawn ends the connections spliced for it.
func TestAWithdrawnNameEndsItsConnections(t *testing.T) {
	h := newHolder(t, false)
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{h.published("immich.pub.example.org")}}}
	tlsAddr, _ := startIngress(t, src)
	c := helloAndHold(t, tlsAddr, "immich.pub.example.org")
	waitFor(t, "the connection", func() bool { return h.accepted.Load() == 1 })
	src.mu.Lock()
	src.p = &ipc.Published{}
	src.mu.Unlock()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("the connection for a withdrawn name: %v", err)
	}
}

// A juistd that takes asks and answers none takes the names down within two
// polls, as a silent one does.
func TestAJuistdThatHangsPublishesNothing(t *testing.T) {
	h := newHolder(t, false)
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{h.published("immich.pub.example.org")}}}
	tlsAddr, _ := startIngress(t, src)
	src.mu.Lock()
	src.hangs = true
	src.mu.Unlock()
	asked := src.asked.Load()
	waitFor(t, "three asks", func() bool { return src.asked.Load() >= asked+3 })
	c := helloAndHold(t, tlsAddr, "immich.pub.example.org")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Read(make([]byte, 1))
	if n := h.accepted.Load(); n != 0 {
		t.Errorf("with juistd hanging, the target took %d connections", n)
	}
}

// The redirect lets a client that keeps its connection idle go.
func TestTheRedirectLetsAnIdleClientGo(t *testing.T) {
	src := &source{p: &ipc.Published{}}
	_, httpAddr := startIngressWith(t, src, Options{httpIdle: 100 * time.Millisecond})
	c, err := net.Dial("tcp", httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("an idle client: %v", err)
	}
}

// A client that says nothing once its target answered the ClientHello is let
// go at the answer's time, not the idle time; one that answers is kept.
func TestAClientThatStopsAfterItsHelloIsLetGo(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = c.Read(make([]byte, 4096))
				_, _ = c.Write([]byte("server hello"))
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	ap := ln.Addr().(*net.TCPAddr).AddrPort()
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{{Name: "immich.pub.example.org",
		Addrs: []netip.Addr{ap.Addr()}, Port: ap.Port()}}}}
	tlsAddr, _ := startIngressWith(t, src, Options{answer: 200 * time.Millisecond, idle: time.Minute})
	// A client picking a certificate takes longer than the hello may.
	patientAddr, _ := startIngressWith(t, src, Options{helloTimeout: 200 * time.Millisecond, idle: time.Minute})
	dial := func(tlsAddr string) net.Conn {
		c, err := net.Dial("tcp", tlsAddr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(clientHello(t, "immich.pub.example.org")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(c, make([]byte, len("server hello"))); err != nil {
			t.Fatalf("the target's answer: %v", err)
		}
		return c
	}
	silent := dial(tlsAddr)
	if _, err := silent.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("a client silent after its hello: %v", err)
	}
	picking := dial(patientAddr)
	_ = picking.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := picking.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("a client silent for longer than a hello takes was let go: %v", err)
	}
	answering := dial(tlsAddr)
	if _, err := answering.Write([]byte("finished")); err != nil {
		t.Fatal(err)
	}
	_ = answering.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := answering.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("a client that answered was let go: %v", err)
	}
}

// A redirect names the published host whatever the request's target says,
// and port 80 holds a few connections from one host, as 443 does.
func TestTheRedirectNamesItsHostAndBoundsASource(t *testing.T) {
	tg := newTarget(t)
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{tg.published("immich.pub.example.org", false)}}}
	_, httpAddr := startIngressWith(t, src, Options{MaxPerSource: 1})
	held, err := net.Dial("tcp", httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	_ = held.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := held.Write([]byte("GET http:@evil.example HTTP/1.1\r\nHost: immich.pub.example.org\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(held), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "https://immich.pub.example.org/" {
		t.Errorf("an opaque target is redirected to %q", loc)
	}
	second, err := net.Dial("tcp", httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = second.Write([]byte("GET / HTTP/1.1\r\nHost: immich.pub.example.org\r\n\r\n"))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Error("a second connection from the host was served while the first is open")
	}
}

// lines is what Access was told, safe to read while the ingress runs.
type lines struct {
	mu  sync.Mutex
	got []string
}

func (l *lines) add(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.got = append(l.got, fmt.Sprintf(format, args...))
}

func (l *lines) find(t *testing.T, parts ...string) string {
	t.Helper()
	var all []string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		l.mu.Lock()
		all = slices.Clone(l.got)
		l.mu.Unlock()
		for _, line := range all {
			if !slices.ContainsFunc(parts, func(p string) bool { return !strings.Contains(line, p) }) {
				return line
			}
		}
	}
	t.Errorf("no line holds %q among %q", parts, all)
	return ""
}

// Each connection on 443 is logged with its client, name, outcome, bytes and
// duration, and each request on 80 with its path and User-Agent too, what
// the client said quoted.
func TestTheIngressLogsEachConnection(t *testing.T) {
	tg := newTarget(t)
	src := &source{p: &ipc.Published{Names: []ipc.PublishedTarget{tg.published("immich.pub.example.org", false)}}}
	var l lines
	tlsAddr, httpAddr := startIngressWith(t, src, Options{Access: l.add})
	hello(t, tlsAddr, "immich.pub.example.org")
	if line := l.find(t, "access: tls 127.0.0.1:", `"immich.pub.example.org" spliced up=`, "down=2 "); line != "" &&
		strings.Contains(line, "up=0 ") {
		t.Errorf("no bytes up: %q", line)
	}
	hello(t, tlsAddr, "other.pub.example.org")
	l.find(t, `"other.pub.example.org" not served up=0 down=0`)
	c, err := net.Dial("tcp", tlsAddr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	c.Close()
	l.find(t, `"" no hello`)

	// Raw, a quote in what the client says.
	hc, err := net.Dial("tcp", httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = hc.Write([]byte("GET /robots.txt?x=1 HTTP/1.1\r\nHost: immich.pub.example.org\r\nUser-Agent: GPTBot/1.2 \"x\"\r\nConnection: close\r\n\r\n"))
	_, _ = io.ReadAll(hc)
	hc.Close()
	l.find(t, `access: http 127.0.0.1:`, `"immich.pub.example.org" GET "/robots.txt?x=1" 308 "GPTBot/1.2 \"x\""`)
}

// An IPv4 client on a dual-stack listener is logged as IPv4.
func TestAClientIsLoggedAsIPv4(t *testing.T) {
	a := &net.TCPAddr{IP: net.ParseIP("::ffff:203.0.113.7"), Port: 51000}
	if got := addrPort(a).String(); got != "203.0.113.7:51000" {
		t.Errorf("logged as %s", got)
	}
}

// A relay's name is handed on by TLS as a published name is, its client named
// in a PROXY header, and is no name to redirect plain HTTP for.
func TestTheIngressHandsARelaysNameOn(t *testing.T) {
	tg := newTarget(t)
	src := &source{p: &ipc.Published{Relays: []ipc.PublishedTarget{tg.published("relay.example.org", true)}}}
	tlsAddr, httpAddr := startIngress(t, src)
	hello(t, tlsAddr, "relay.example.org")
	if got := <-tg.got; !bytes.HasPrefix(got, []byte("\r\n\r\n\x00\r\nQUIT\n")) {
		t.Fatalf("the relay got %x", got)
	}
	req, _ := http.NewRequest("GET", "http://"+httpAddr+"/", nil)
	req.Host = "relay.example.org"
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if resp, err := client.Do(req); err != nil || resp.StatusCode != http.StatusNotFound {
		t.Errorf("plain HTTP for the relay's name: %v, %v", resp, err)
	}
	in := &ingress{}
	in.table.Store(&map[string]ipc.PublishedTarget{"relay.example.org": {}})
	in.relays.Store(&map[string]bool{"relay.example.org": true})
	if _, ok := in.lookupPublished("relay.example.org"); ok {
		t.Error("QUIC would take the relay's name")
	}
}

// A member's name the same as the relay's is not served: the relay's
// clients, and its certificate's challenges, stay the relay's.
func TestARelayKeepsItsNameFromAMembers(t *testing.T) {
	relayTarget, member := newTarget(t), newTarget(t)
	src := &source{p: &ipc.Published{
		Relays: []ipc.PublishedTarget{relayTarget.published("relay.example.org", true)},
		Names:  []ipc.PublishedTarget{member.published("relay.example.org", false)},
	}}
	tlsAddr, _ := startIngress(t, src)
	hello(t, tlsAddr, "relay.example.org")
	select {
	case got := <-relayTarget.got:
		if !bytes.HasPrefix(got, []byte("\r\n\r\n\x00\r\nQUIT\n")) {
			t.Errorf("the relay got %x", got)
		}
	case got := <-member.got:
		t.Fatalf("the member got the relay's client, %d bytes", len(got))
	case <-time.After(5 * time.Second):
		t.Fatal("nobody got the client")
	}
}
