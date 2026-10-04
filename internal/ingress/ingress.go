// Package ingress takes connections from the internet for the names members
// publish, reads the name a TLS client asks for, and splices the connection
// to the member through the overlay. It terminates nothing and holds no key:
// what it may serve it asks the juistd beside it, which says nothing while
// its view is stale.
package ingress

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/netutil"

	"github.com/nning/juist/internal/pipe"
	"github.com/nning/juist/internal/proxyproto"
	"github.com/nning/juist/ipc"
)

// Defaults for [Options].
const (
	DefaultPoll         = 5 * time.Second
	DefaultMaxConns     = 16384
	DefaultMaxPerSource = 256

	// idleTimeout ends a connection quiet for that long either way.
	idleTimeout = 5 * time.Minute

	// helloTimeout bounds the wait for a client's ClientHello, and
	// dialTimeout the dial of one of the target's addresses.
	helloTimeout = 10 * time.Second
	dialTimeout  = 3 * time.Second

	// answerTimeout bounds the wait for a client's answer to its target's
	// first flight: long enough to pick a client certificate or type a PIN.
	answerTimeout = time.Minute

	// missesAllowed is how many asks in a row may go unanswered before the
	// ingress publishes nothing.
	missesAllowed = 1
)

// Options configures an ingress.
type Options struct {
	// Published asks what to serve; [ipc.CallPublished] on juistd's socket.
	Published func(context.Context) (*ipc.Published, error)
	// Poll is how often it asks.
	Poll time.Duration
	// Dial reaches a target; a net.Dialer's by default.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// MaxConns bounds the connections spliced at once, and MaxPerSource
	// those from one client host.
	MaxConns     int
	MaxPerSource int
	Logf         func(format string, args ...any)
	// Access, where set, is told a line for each connection on 443 and each
	// request on 80: from where, for which name, and what came of it.
	Access func(format string, args ...any)

	helloTimeout, answer, idle, httpIdle time.Duration // for tests
}

// An ingress serves what juistd last said is published.
type ingress struct {
	o       Options
	table   atomic.Pointer[map[string]ipc.PublishedTarget]
	conns   chan struct{}
	sources pipe.Sources
	named   pipe.Named
}

// Serve runs the ingress on tlsLn, and on httpLn, where not nil, a redirect
// to https for the names it serves, until ctx ends.
func Serve(ctx context.Context, tlsLn, httpLn net.Listener, o Options) error {
	if o.Poll == 0 {
		o.Poll = DefaultPoll
	}
	if o.MaxConns == 0 {
		o.MaxConns = DefaultMaxConns
	}
	if o.MaxPerSource == 0 {
		o.MaxPerSource = DefaultMaxPerSource
	}
	if o.helloTimeout == 0 {
		o.helloTimeout = helloTimeout
	}
	if o.answer == 0 {
		o.answer = answerTimeout
	}
	if o.idle == 0 {
		o.idle = idleTimeout
	}
	if o.httpIdle == 0 {
		o.httpIdle = 30 * time.Second
	}
	if o.Dial == nil {
		var d net.Dialer
		o.Dial = d.DialContext
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Access == nil {
		o.Access = func(string, ...any) {}
	}
	in := &ingress{o: o, conns: make(chan struct{}, o.MaxConns), sources: pipe.Sources{Max: o.MaxPerSource}}
	in.table.Store(&map[string]ipc.PublishedTarget{})
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Go(func() { in.poll(ctx) })
	if httpLn != nil {
		srv := &http.Server{Handler: http.HandlerFunc(in.redirect), ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: o.httpIdle,
			ErrorLog: log.New(io.Discard, "", 0)}
		ln := perSource{Listener: httpLn, sources: &pipe.Sources{Max: o.MaxPerSource}}
		wg.Go(func() { _ = srv.Serve(netutil.LimitListener(ln, o.MaxConns)) })
		context.AfterFunc(ctx, func() { srv.Close() })
	}
	context.AfterFunc(ctx, func() { tlsLn.Close() })
	err := in.accept(ctx, tlsLn)
	cancel()
	wg.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// poll asks what to serve every Poll, and serves nothing once asks go
// unanswered: a juistd that stops answering takes the names down with it,
// and the connections for them.
func (in *ingress) poll(ctx context.Context) {
	misses := 0
	t := time.NewTicker(in.o.Poll)
	defer t.Stop()
	for {
		actx, cancel := context.WithTimeout(ctx, in.o.Poll)
		p, err := in.o.Published(actx)
		cancel()
		switch {
		case err == nil:
			if misses > missesAllowed {
				in.o.Logf("ingress: juistd answers again")
			}
			misses = 0
			in.serve(tableOf(p))
		case ctx.Err() != nil:
			return
		default:
			if misses++; misses == missesAllowed+1 {
				in.o.Logf("ingress: juistd does not answer (%v); serving nothing until it does", err)
				in.serve(&map[string]ipc.PublishedTarget{})
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// serve takes table as what is served, closing what no longer is.
func (in *ingress) serve(table *map[string]ipc.PublishedTarget) {
	in.table.Store(table)
	in.named.CloseUnless(func(name string) bool {
		_, ok := in.lookup(name)
		return ok
	})
}

func tableOf(p *ipc.Published) *map[string]ipc.PublishedTarget {
	m := make(map[string]ipc.PublishedTarget, len(p.Names))
	for _, t := range p.Names {
		m[t.Name] = t
	}
	return &m
}

// lookup is where name goes, if it is served.
func (in *ingress) lookup(name string) (ipc.PublishedTarget, bool) {
	t, ok := (*in.table.Load())[strings.TrimSuffix(strings.ToLower(name), ".")]
	return t, ok
}

func (in *ingress) accept(ctx context.Context, ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return err
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		client := addrPort(c.RemoteAddr())
		select {
		case in.conns <- struct{}{}:
		default:
			c.Close() // at the bound: the client tries again
			in.o.Access("access: tls %v refused: too many connections", client)
			continue
		}
		src := client.Addr()
		if !in.sources.Take(src) {
			<-in.conns
			c.Close()
			in.o.Access("access: tls %v refused: too many connections from it", client)
			continue
		}
		go func() {
			defer func() { <-in.conns }()
			defer in.sources.Done(src)
			in.splice(ctx, c)
		}()
	}
}

// splice passes c to the target its ClientHello names, the bytes read so far
// first, after a PROXY protocol header where the name asks for one, for as
// long as the name is served.
func (in *ingress) splice(ctx context.Context, c net.Conn) {
	defer c.Close()
	start, client := time.Now(), addrPort(c.RemoteAddr())
	var name, outcome string
	var up, down atomic.Int64
	defer func() {
		in.o.Access("access: tls %v %q %s up=%d down=%d %v", client, name, outcome, up.Load(), down.Load(),
			time.Since(start).Round(time.Millisecond))
	}()
	_ = c.SetDeadline(time.Now().Add(in.o.helloTimeout))
	name, hello, err := peekServerName(c)
	if err != nil {
		outcome = "no hello"
		return
	}
	t, ok := in.lookup(name)
	if !ok {
		outcome = "not served"
		return
	}
	target, err := in.dial(ctx, t)
	if err != nil {
		outcome = "target unreachable"
		return
	}
	defer target.Close()
	_ = c.SetDeadline(time.Time{})
	if t.Proxy {
		hello = append(proxyproto.Header(addrPort(c.RemoteAddr()), addrPort(c.LocalAddr())), hello...)
	}
	outcome = "spliced"
	if _, err := target.Write(hello); err != nil {
		return
	}
	up.Add(int64(len(hello)))
	in.named.Add(c, t.Name, func() { c.Close(); target.Close() })
	defer in.named.Remove(c)
	if _, ok := in.lookup(t.Name); !ok {
		return // withdrawn meanwhile
	}
	h := &handshake{c: c, wait: in.o.answer}
	pipe.Join(ctx, watched{c, func(n int) { up.Add(int64(n)); h.fromClient(n) }},
		watched{target, func(n int) { down.Add(int64(n)); h.fromTarget(n) }}, in.o.idle)
}

// handshake lets a client go that, once the target answered its ClientHello,
// says nothing within wait: a TLS client answers the server's first flight
// at once, so one that does not only holds a slot.
type handshake struct {
	c    net.Conn
	wait time.Duration

	mu              sync.Mutex
	armed, answered bool
}

func (h *handshake) fromTarget(n int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n > 0 && !h.armed && !h.answered {
		h.armed = true
		_ = h.c.SetReadDeadline(time.Now().Add(h.wait))
	}
}

func (h *handshake) fromClient(n int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n > 0 && !h.answered {
		h.answered = true
		if h.armed {
			_ = h.c.SetReadDeadline(time.Time{})
		}
	}
}

// watched tells saw how much each read took.
type watched struct {
	net.Conn
	saw func(n int)
}

func (w watched) Read(p []byte) (int, error) {
	n, err := w.Conn.Read(p)
	w.saw(n)
	return n, err
}

func (w watched) CloseWrite() error {
	if cw, ok := w.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return w.Conn.Close()
}

// dial reaches t on the first of its addresses that answers.
func (in *ingress) dial(ctx context.Context, t ipc.PublishedTarget) (net.Conn, error) {
	err := errors.New("ingress: the target has no address")
	for _, a := range t.Addrs {
		dctx, cancel := context.WithTimeout(ctx, dialTimeout)
		var c net.Conn
		c, err = in.o.Dial(dctx, "tcp", netip.AddrPortFrom(a, t.Port).String())
		cancel()
		if err == nil {
			return c, nil
		}
	}
	return nil, err
}

// redirect sends a client asking for a served name over HTTP to https; it
// reads nothing else.
func (in *ingress) redirect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if _, ok := in.lookup(host); !ok {
		in.o.Access("access: http %s %q %s %q %d %q", r.RemoteAddr, host, r.Method, r.URL.RequestURI(),
			http.StatusNotFound, r.UserAgent())
		http.NotFound(w, r)
		return
	}
	in.o.Access("access: http %s %q %s %q %d %q", r.RemoteAddr, host, r.Method, r.URL.RequestURI(),
		http.StatusPermanentRedirect, r.UserAgent())
	// From the path alone: an opaque target such as "http:@evil.com" would
	// otherwise name another host.
	to := url.URL{Scheme: "https", Host: strings.ToLower(host), Path: cmp.Or(r.URL.Path, "/"),
		RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	http.Redirect(w, r, to.String(), http.StatusPermanentRedirect)
}

// perSource is a listener taking no more connections from one source at once
// than sources bounds.
type perSource struct {
	net.Listener
	sources *pipe.Sources
}

func (l perSource) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		src := addrPort(c.RemoteAddr()).Addr()
		if !l.sources.Take(src) {
			c.Close()
			continue
		}
		return &givenBack{Conn: c, done: sync.OnceFunc(func() { l.sources.Done(src) })}, nil
	}
}

// givenBack gives its source's count back once closed.
type givenBack struct {
	net.Conn
	done func()
}

func (c *givenBack) Close() error {
	c.done()
	return c.Conn.Close()
}

// errPeeked ends a handshake once the ClientHello is read.
var errPeeked = errors.New("ingress: client hello read")

// peekServerName reads c's ClientHello with crypto/tls's own parser, and
// returns the name it asks for and every byte read, to replay to the target.
func peekServerName(c net.Conn) (string, []byte, error) {
	var buf bytes.Buffer
	var name string
	cfg := &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		name = h.ServerName
		return nil, errPeeked
	}}
	err := tls.Server(readOnlyConn{Conn: c, r: io.TeeReader(c, &buf)}, cfg).Handshake()
	if name == "" {
		return "", nil, fmt.Errorf("ingress: no server name: %w", err)
	}
	return name, buf.Bytes(), nil
}

// readOnlyConn reads through r and writes nothing, so that the handshake
// peekServerName starts answers the client nothing.
type readOnlyConn struct {
	net.Conn
	r io.Reader
}

func (c readOnlyConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c readOnlyConn) Write(p []byte) (int, error) { return 0, io.ErrClosedPipe }

func addrPort(a net.Addr) netip.AddrPort {
	if t, ok := a.(*net.TCPAddr); ok {
		ap := t.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
}
