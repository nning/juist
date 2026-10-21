package terminator

import (
	"bufio"
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
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/nning/juist/internal/proxyproto"
	"github.com/nning/juist/ipc"
)

func selfSigned(t *testing.T) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"immich.pub.example.org"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil }
}

// backend is the local service: it records what each connection carries
// first and answers "ok".
type backend struct {
	ln  net.Listener
	got chan []byte
}

func newBackend(t *testing.T) *backend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	b := &backend{ln: ln, got: make(chan []byte, 8)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var got []byte
				buf := make([]byte, 4096)
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				for {
					n, err := c.Read(buf)
					got = append(got, buf[:n]...)
					if err != nil || strings.HasSuffix(string(got), "\n") {
						break
					}
				}
				b.got <- got
				_, _ = c.Write([]byte("ok\n"))
			}()
		}
	}()
	return b
}

type source struct {
	mu      sync.Mutex
	p       *ipc.Published
	silent  bool
	asked   chan struct{}
	account *ipc.ACMEAccount // the last told
	report  *ipc.TerminatorReport
	hangs   bool
}

func (s *source) serving(ctx context.Context, r *ipc.TerminatorReport) (*ipc.Published, error) {
	var a *ipc.ACMEAccount
	if r != nil {
		a = r.Account
		s.mu.Lock()
		s.report = r
		s.mu.Unlock()
	}
	select {
	case s.asked <- struct{}{}:
	default:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hangs {
		s.mu.Unlock()
		<-ctx.Done()
		s.mu.Lock()
		return nil, ctx.Err()
	}
	if a != nil {
		s.account = a
	}
	if s.silent {
		return nil, errors.New("no juistd")
	}
	return s.p, nil
}

func (s *source) set(p *ipc.Published, silent bool) {
	s.mu.Lock()
	s.p, s.silent = p, silent
	s.mu.Unlock()
	<-s.asked
	<-s.asked
}

// start runs a terminator serving immich on a free port of 127.0.0.1.
func start(t *testing.T, b *backend, proxy bool, logf func(string, ...any)) (*source, string) {
	t.Helper()
	return startWith(t, b.ln.Addr().String(), proxy, logf, nil, nil)
}

// startWith runs a terminator sending immich to to, listening by listen,
// nil for the host's, with certificates from get, nil for a self-signed one.
func startWith(t *testing.T, to string, proxy bool, logf func(string, ...any),
	listen func(network, addr string) (net.Listener, error),
	get func(*tls.ClientHelloInfo) (*tls.Certificate, error)) (*source, string) {
	t.Helper()
	return startOpts(t, to, proxy, func(o *Options) { o.Logf, o.Listen, o.GetCertificate = logf, listen, get })
}

// freePort is a port of 127.0.0.1 free for TCP and UDP alike: one free for
// TCP may be held for UDP by another process, which then takes QUIC's
// packets while the terminator has no socket.
func freePort(t *testing.T) int {
	t.Helper()
	for range 100 {
		probe, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		pc, err := net.ListenPacket("udp", probe.Addr().String())
		probe.Close()
		if err == nil {
			pc.Close()
			return probe.Addr().(*net.TCPAddr).Port
		}
	}
	t.Fatal("no port of 127.0.0.1 free for TCP and UDP")
	return 0
}

// A port the tests serve on is free for QUIC too, where UDP sockets hold
// some of the ports TCP has free.
func TestFreePortIsFreeForUDP(t *testing.T) {
	for range 1000 {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
	}
	for range 200 {
		port := freePort(t)
		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			t.Fatalf("port %d: %v", port, err)
		}
		pc.Close()
	}
}

// startOpts is startWith with the options mutate makes.
func startOpts(t *testing.T, to string, proxy bool, mutate func(*Options)) (*source, string) {
	t.Helper()
	port := uint16(freePort(t))
	src := &source{asked: make(chan struct{}), p: &ipc.Published{
		Names: []ipc.PublishedTarget{{Name: "immich.pub.example.org", Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
			Port: port, Proxy: proxy, To: to}},
		Ingresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		o := Options{Serving: src.serving, Poll: 10 * time.Millisecond}
		mutate(&o)
		if o.GetCertificate == nil {
			o.GetCertificate = selfSigned(t)
		}
		_ = Serve(ctx, o)
	}()
	t.Cleanup(func() { cancel(); <-done })
	<-src.asked
	<-src.asked
	return src, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String()
}

// ask opens TLS to addr for name, from from where set, after header, and
// sends a line; it returns the answer.
func ask(t *testing.T, addr, name, from string, header []byte, protos ...string) (string, error) {
	t.Helper()
	d := net.Dialer{Timeout: 3 * time.Second}
	if from != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(from)}
	}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if header != nil {
		if _, err := c.Write(header); err != nil {
			return "", err
		}
	}
	tc := tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: true, NextProtos: protos})
	if _, err := tc.Write([]byte("GET /\n")); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(tc).ReadString('\n')
	return line, err
}

// TLS ends here, for a name served alone, and the plain connection reaches
// the local service; a browser's ALPN does not fail it.
func TestTheTerminatorEndsTLSForWhatItServes(t *testing.T) {
	b := newBackend(t)
	_, addr := start(t, b, false, nil)
	if got, err := ask(t, addr, "immich.pub.example.org", "", nil, "h2", "http/1.1"); err != nil || got != "ok\n" {
		t.Fatalf("the client got %q, %v", got, err)
	}
	if got := <-b.got; string(got) != "GET /\n" {
		t.Errorf("the service got %q", got)
	}
	if got, err := ask(t, addr, "other.pub.example.org", "", nil); err == nil {
		t.Errorf("a name not served got %q", got)
	}
	select {
	case got := <-b.got:
		t.Errorf("the service got %q for a name not served", got)
	case <-time.After(100 * time.Millisecond):
	}
}

// HTTP/2 is offered where the service takes it without TLS, and nowhere
// else: a service that takes HTTP/1.1 alone would get its preface.
func TestHTTP2IsOfferedWhereTheServiceTakesIt(t *testing.T) {
	negotiated := func(addr string, protos ...string) string {
		t.Helper()
		c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true,
			NextProtos: protos})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("PRI\n")); err != nil {
			t.Fatal(err)
		}
		if line, err := bufio.NewReader(c).ReadString('\n'); err != nil || line != "ok\n" {
			t.Fatalf("the client got %q, %v", line, err)
		}
		return c.ConnectionState().NegotiatedProtocol
	}
	b := newBackend(t)
	_, h2c := startWith(t, ipc.HTTP2To(b.ln.Addr().String()), false, nil, nil, nil)
	if p := negotiated(h2c, "h2", "http/1.1"); p != "h2" {
		t.Errorf("a browser got %q from a service taking h2c", p)
	}
	if p := negotiated(h2c, "http/1.1"); p == "h2" {
		t.Error("a client without h2 got it")
	}
	_, plain := start(t, b, false, nil)
	if p := negotiated(plain, "h2", "http/1.1"); p == "h2" {
		t.Error("a service taking HTTP/1.1 alone was offered h2")
	}
}

// The CA's TLS-ALPN-01 challenge is answered and goes no further.
func TestTheChallengeStopsHere(t *testing.T) {
	b := newBackend(t)
	_, addr := start(t, b, false, nil)
	c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true,
		NextProtos: []string{acme.ALPNProto}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if p := c.ConnectionState().NegotiatedProtocol; p != acme.ALPNProto {
		t.Fatalf("negotiated %q", p)
	}
	if _, err := io.ReadAll(c); err != nil && !errors.Is(err, io.EOF) {
		t.Logf("read: %v", err)
	}
	select {
	case got := <-b.got:
		t.Errorf("the service got %q from the CA", got)
	case <-time.After(100 * time.Millisecond):
	}
}

// The service learns the client an ingress's PROXY header names, where the
// name asks for it; a member's header is no header, and fails TLS.
func TestTheServiceLearnsTheClientFromAnIngress(t *testing.T) {
	b := newBackend(t)
	_, addr := start(t, b, true, nil)
	client := netip.MustParseAddrPort("203.0.113.7:51000")
	header := proxyproto.Header(client, netip.MustParseAddrPort(addr))
	if got, err := ask(t, addr, "immich.pub.example.org", "127.0.0.1", header); err != nil || got != "ok\n" {
		t.Fatalf("through the ingress, the client got %q, %v", got, err)
	}
	got := <-b.got
	src, ok, err := proxyproto.Read(bufio.NewReader(strings.NewReader(string(got))))
	if err != nil || !ok || src != client {
		t.Errorf("the service learned %v, %v, %v from %q", src, ok, err, got)
	}
	if got, err := ask(t, addr, "immich.pub.example.org", "127.0.0.2", header); err == nil {
		t.Errorf("a member's header was believed: %q", got)
	}
}

// What is served no longer, or while juistd is silent, is listened for no
// longer; a port another program holds is said.
func TestTheTerminatorListensWhereItServes(t *testing.T) {
	b := newBackend(t)
	var mu sync.Mutex
	var logged []string
	logf := func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, fmt.Sprintf(f, a...))
	}
	src, addr := start(t, b, false, logf)
	src.set(&ipc.Published{}, false)
	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Error("a name served no longer is still listened for")
	}
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	p := uint16(taken.Addr().(*net.TCPAddr).Port)
	src.set(&ipc.Published{Names: []ipc.PublishedTarget{{Name: "immich.pub.example.org",
		Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Port: p, To: b.ln.Addr().String()}}}, false)
	mu.Lock()
	said := strings.Join(logged, "\n")
	mu.Unlock()
	if !strings.Contains(said, "another program serves port") {
		t.Errorf("a port taken was not said: %q", said)
	}
	src.set(nil, true)
}

// holding is a local service that keeps each connection it takes.
func holding(t *testing.T) string {
	t.Helper()
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
			go func() { _, _ = io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

// connect opens TLS to addr for immich and keeps it.
func connect(t *testing.T, addr string) *tls.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	tc := tls.Client(c, &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true})
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := tc.Write([]byte("GET /\n")); err != nil {
		t.Fatal(err)
	}
	return tc
}

// A name no longer served ends the connections for it.
func TestANameNoLongerServedEndsItsConnections(t *testing.T) {
	src, addr := startWith(t, holding(t), false, nil, nil, nil)
	tc := connect(t, addr)
	time.Sleep(50 * time.Millisecond)
	src.set(&ipc.Published{}, false)
	if _, err := tc.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("the connection for a name no longer served: %v", err)
	}
}

// A connection piped to a name's service ends once the name goes elsewhere,
// as one to a port shared beside files does once that share stops, or once
// the name is proxied by path, as when a file is shared beside the port.
func TestANameGoneElsewhereEndsItsPipedConnections(t *testing.T) {
	service := holding(t)
	src, addr := startWith(t, service, false, nil, nil, nil)
	p := netip.MustParseAddrPort(addr).Port()
	for _, n := range []ipc.PublishedTarget{{To: holding(t)},
		{To: service, Paths: []ipc.PathTarget{{Prefix: "/tok/", To: holding(t)}}}} {
		src.set(&ipc.Published{Names: []ipc.PublishedTarget{{Name: "immich.pub.example.org",
			Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Port: p, To: service}}}, false)
		tc := connect(t, addr)
		time.Sleep(50 * time.Millisecond)
		n.Name, n.Addrs, n.Port = "immich.pub.example.org", []netip.Addr{netip.MustParseAddr("127.0.0.1")}, p
		src.set(&ipc.Published{Names: []ipc.PublishedTarget{n}}, false)
		if _, err := tc.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("the connection for a name now %+v: %v", n, err)
		}
	}
}

// A name with paths is proxied: a request under a path reaches that path's
// service, any other the name's; each request goes as the name does now, on
// a connection kept open across a change.
func TestANamesPathsReachTheirOwnServices(t *testing.T) {
	serve := func(says string) string {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, says+" "+r.URL.Path)
		})}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
		return ln.Addr().String()
	}
	app, a, b := serve("app"), serve("a"), serve("b")
	src, addr := startWith(t, app, false, nil, nil, nil)
	p := netip.MustParseAddrPort(addr).Port()
	withPaths := func(paths ...ipc.PathTarget) *ipc.Published {
		return &ipc.Published{Names: []ipc.PublishedTarget{{Name: "immich.pub.example.org",
			Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Port: p, To: app, Paths: paths}}}
	}
	src.set(withPaths(ipc.PathTarget{Prefix: "/tokA/", To: a}, ipc.PathTarget{Prefix: "/tokB/", To: b}), false)
	dials := 0
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dials++
			return tls.Dial("tcp", addr, &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true})
		}}}
	get := func(path string) string {
		t.Helper()
		resp, err := client.Get("https://immich.pub.example.org" + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}
	for path, want := range map[string]string{"/tokA/x.pdf": "a /tokA/x.pdf", "/tokB/": "b /tokB/", "/tokA": "app /tokA",
		"/": "app /", "/tokC/x": "app /tokC/x"} {
		if got := get(path); got != want {
			t.Errorf("%s reached %q, want %q", path, got, want)
		}
	}
	src.set(withPaths(ipc.PathTarget{Prefix: "/tokB/", To: b}), false)
	if got := get("/tokA/x.pdf"); got != "app /tokA/x.pdf" {
		t.Errorf("a path stopped reached %q", got)
	}
	if got := get("/tokB/y"); got != "b /tokB/y" {
		t.Errorf("a path kept reached %q", got)
	}
	if dials != 1 {
		t.Errorf("the client dialled %d times, so no connection was kept across the change", dials)
	}
}

// A juistd that takes asks and answers none ends serving within two polls.
func TestAJuistdThatHangsEndsServing(t *testing.T) {
	b := newBackend(t)
	src, addr := start(t, b, false, nil)
	src.mu.Lock()
	src.hangs = true
	src.mu.Unlock()
	for i := 0; i < 3; i++ {
		select {
		case <-src.asked:
		case <-time.After(5 * time.Second):
			t.Fatal("an ask juistd does not answer is never given up")
		}
	}
	if got, err := ask(t, addr, "immich.pub.example.org", "", nil); err == nil {
		t.Errorf("with juistd hanging, the client got %q", got)
	}
}

// failing is a listener whose Accept fails once failed is closed, as one of
// a network stack replaced does.
type failing struct {
	net.Listener
	failed chan struct{}
}

func (f failing) Accept() (net.Conn, error) {
	type result struct {
		c   net.Conn
		err error
	}
	got := make(chan result, 1)
	go func() {
		c, err := f.Listener.Accept()
		got <- result{c, err}
	}()
	select {
	case r := <-got:
		return r.c, r.err
	case <-f.failed:
		f.Listener.Close()
		// One taken as it closed is answered by nobody: closed, the client
		// tries again.
		go func() {
			if r := <-got; r.c != nil {
				r.c.Close()
			}
		}()
		return nil, errors.New("endpoint is in invalid state")
	}
}

// A listener that fails is listened for again, and serves.
func TestAFailedListenerIsListenedAgain(t *testing.T) {
	b := newBackend(t)
	failed := make(chan struct{})
	var mu sync.Mutex
	listens := 0
	_, addr := startWith(t, b.ln.Addr().String(), false, nil, func(network, addr string) (net.Listener, error) {
		ln, err := net.Listen(network, addr)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		defer mu.Unlock()
		if listens++; listens == 1 {
			return failing{ln, failed}, nil
		}
		return ln, nil
	}, nil)
	close(failed)
	var got string
	var err error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if got, err = ask(t, addr, "immich.pub.example.org", "", nil); err == nil {
			break
		}
	}
	if err != nil || got != "ok\n" {
		t.Errorf("after its listener failed, the client got %q, %v", got, err)
	}
}

// The terminator tells juistd where it listens, and where another program
// holds the port.
func TestTheTerminatorSaysWhereItListens(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	b := newBackend(t)
	src, addr := start(t, b, false, nil)
	taken := held.Addr().String()
	heldAP := held.Addr().(*net.TCPAddr).AddrPort()
	src.mu.Lock()
	src.p = &ipc.Published{Ingresses: src.p.Ingresses, Names: append(slices.Clone(src.p.Names), ipc.PublishedTarget{
		Name: "other.pub.example.org", Addrs: []netip.Addr{heldAP.Addr()}, Port: heldAP.Port(), To: b.ln.Addr().String()})}
	src.mu.Unlock()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		src.mu.Lock()
		r := src.report
		src.mu.Unlock()
		if r != nil && slices.Contains(r.Listening, addr) && slices.Contains(r.Unbound, taken) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the terminator said %+v", r)
		}
	}
}

// A name served that a client got no certificate for is reported, with why,
// until one is found; the CA's challenge and a name not served change nothing.
func TestTheTerminatorSaysWhichNamesHaveNoCertificate(t *testing.T) {
	b := newBackend(t)
	var mu sync.Mutex
	fail := true
	good := selfSigned(t)
	src, addr := startWith(t, b.ln.Addr().String(), false, nil, nil, func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail && !slices.Contains(h.SupportedProtos, acme.ALPNProto) {
			return nil, errors.New("acme/autocert: no viable challenge type found " + strings.Repeat("x", 300))
		}
		return good(h)
	})
	said := func(want func(*ipc.TerminatorReport) bool) *ipc.TerminatorReport {
		t.Helper()
		var r *ipc.TerminatorReport
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			src.mu.Lock()
			r = src.report
			src.mu.Unlock()
			if r != nil && want(r) {
				return r
			}
		}
		t.Fatalf("the terminator said %+v", r)
		return nil
	}
	_, _ = ask(t, addr, "other.pub.example.org", "", nil)
	_, _ = ask(t, addr, "Immich.pub.example.org.", "", nil)
	r := said(func(r *ipc.TerminatorReport) bool { return len(r.NoCert) > 0 })
	if len(r.NoCert) != 1 || r.NoCert[0].Name != "immich.pub.example.org" ||
		!strings.HasPrefix(r.NoCert[0].Why, "acme/autocert: no viable challenge type found") ||
		len(r.NoCert[0].Why) > ipc.MaxNoCertWhy {
		t.Fatalf("the terminator said %+v", r.NoCert)
	}
	_, _ = ask(t, addr, "immich.pub.example.org", "", nil, acme.ALPNProto)
	<-src.asked
	<-src.asked
	said(func(r *ipc.TerminatorReport) bool { return len(r.NoCert) == 1 })
	mu.Lock()
	fail = false
	mu.Unlock()
	if got, err := ask(t, addr, "immich.pub.example.org", "", nil); err != nil || got != "ok\n" {
		t.Fatalf("the client got %q, %v", got, err)
	}
	said(func(r *ipc.TerminatorReport) bool { return len(r.NoCert) == 0 })
}

// Told that nothing needs it, a terminator stops, and says so; told so while
// juistd still names what to serve, it serves on.
func TestAnIdleTerminatorStops(t *testing.T) {
	src := &source{asked: make(chan struct{}, 1), p: &ipc.Published{Idle: true, Names: []ipc.PublishedTarget{
		{Name: "immich.pub.example.org", Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Port: 1}}}}
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), Options{Serving: src.serving, Poll: 10 * time.Millisecond,
			GetCertificate: selfSigned(t), Listen: func(string, string) (net.Listener, error) {
				return nil, errors.New("not here")
			}})
	}()
	<-src.asked
	<-src.asked
	select {
	case err := <-done:
		t.Fatalf("stopped while it had a name to serve: %v", err)
	default:
	}
	src.mu.Lock()
	src.p = &ipc.Published{Idle: true}
	src.mu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an idle terminator serves on")
	}
	src.mu.Lock()
	defer src.mu.Unlock()
	if src.report == nil || !src.report.Stopping {
		t.Errorf("the terminator's last word was %+v", src.report)
	}
}

// A terminator that stops says so last.
func TestATerminatorSaysItStops(t *testing.T) {
	src := &source{asked: make(chan struct{}, 1), p: &ipc.Published{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Serve(ctx, Options{Serving: src.serving, Poll: 10 * time.Millisecond, GetCertificate: selfSigned(t)})
	}()
	<-src.asked
	cancel()
	<-done
	src.mu.Lock()
	defer src.mu.Unlock()
	if src.report == nil || !src.report.Stopping {
		t.Errorf("the terminator's last word was %+v", src.report)
	}
}

// A status page is served here, not sent on, and tells a member by its
// connection's address alone: an ingress's PROXY header naming a member
// brings the public still.
func TestTheStatusPageKnowsAMemberByItsAddress(t *testing.T) {
	for _, a := range []string{"127.0.0.2:0", "127.0.0.3:0"} {
		l, err := net.Listen("tcp", a)
		if err != nil {
			t.Skipf("a member and the public from addresses of their own need them on loopback: %v", err)
		}
		l.Close()
	}
	port := uint16(freePort(t))
	src := &source{asked: make(chan struct{}), p: &ipc.Published{
		Names: []ipc.PublishedTarget{{Name: "status.pub.example.org", Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
			Port: port, Proxy: true, To: ipc.StatusPageTo(ipc.ShowNone)}},
		Ingresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}
	page := &ipc.StatusPage{Members: []netip.Addr{netip.MustParseAddr("127.0.0.2")}}
	page.Status.InNetwork, page.Status.NetworkName = true, "home"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Serve(ctx, Options{Serving: src.serving, Poll: 10 * time.Millisecond, GetCertificate: selfSigned(t),
			StatusPage: func(context.Context) (*ipc.StatusPage, error) { return page, nil }})
	}()
	t.Cleanup(func() { cancel(); <-done })
	<-src.asked
	<-src.asked
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String()
	get := func(from string, header []byte) (int, string) {
		t.Helper()
		d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(from)}}
		c, err := d.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if header != nil {
			if _, err := c.Write(header); err != nil {
				t.Fatal(err)
			}
		}
		tc := tls.Client(c, &tls.Config{ServerName: "status.pub.example.org", InsecureSkipVerify: true})
		if _, err := tc.Write([]byte("GET / HTTP/1.1\r\nHost: status.pub.example.org\r\nConnection: close\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	if code, body := get("127.0.0.2", nil); code != 200 || !strings.Contains(body, "home") {
		t.Errorf("a member got %d", code)
	}
	if code, _ := get("127.0.0.3", nil); code != 404 {
		t.Errorf("the public got %d", code)
	}
	// A browser gets the page over HTTP/2.
	var h2 http.Protocols
	h2.SetHTTP2(true)
	member := &net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Protocols: &h2,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return member.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := c.Get("https://status.pub.example.org:" + strconv.Itoa(int(port)) + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != 200 || !strings.Contains(string(body), "home") {
		t.Errorf("over HTTP/2: HTTP/%d %d", resp.ProtoMajor, resp.StatusCode)
	}
	forged := proxyproto.Header(netip.MustParseAddrPort("127.0.0.2:4000"), netip.MustParseAddrPort(addr))
	if code, _ := get("127.0.0.1", forged); code != 404 {
		t.Errorf("an ingress naming a member got %d", code)
	}
}

// Plain HTTP to an address a name is served on is redirected to https, for
// a name served there alone; where another program holds the port, juistd
// is told.
func TestPlainHTTPIsRedirected(t *testing.T) {
	b := newBackend(t)
	httpPort := uint16(freePort(t))
	_, addr := startOpts(t, b.ln.Addr().String(), false, func(o *Options) { o.HTTPPort = httpPort })
	client := http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(host string) *http.Response {
		t.Helper()
		var resp *http.Response
		var err error
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/a%%2Fb?c=d", httpPort), nil)
			req.Host = host
			if resp, err = client.Do(req); err == nil {
				resp.Body.Close()
				return resp
			}
		}
		t.Fatalf("plain HTTP: %v", err)
		return nil
	}
	_, port, _ := net.SplitHostPort(addr)
	resp := get("immich.pub.example.org")
	if want := "https://immich.pub.example.org:" + port + "/a%2Fb?c=d"; resp.StatusCode != http.StatusPermanentRedirect ||
		resp.Header.Get("Location") != want {
		t.Errorf("redirected %d to %q, want %q", resp.StatusCode, resp.Header.Get("Location"), want)
	}
	if resp := get("other.pub.example.org"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("a name not served: %d", resp.StatusCode)
	}

	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	heldPort := uint16(held.Addr().(*net.TCPAddr).Port)
	src, _ := startOpts(t, b.ln.Addr().String(), false, func(o *Options) { o.HTTPPort = heldPort })
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		src.mu.Lock()
		r := src.report
		src.mu.Unlock()
		if r != nil && slices.Contains(r.Unbound, held.Addr().String()) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the terminator said %+v", r)
		}
	}
}
