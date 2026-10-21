// Package ingress takes connections from the internet for the names members
// publish, reads the name a TLS client asks for, or takes the port a name
// published by TCP has, and splices the connection to the member through the
// overlay. It terminates nothing and holds no key: what it may serve it asks
// the juistd beside it, which says nothing while its view is stale.
package ingress

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/netutil"

	"github.com/nning/juist/internal/admit"
	"github.com/nning/juist/internal/pipe"
	"github.com/nning/juist/internal/proxyproto"
	"github.com/nning/juist/internal/published"
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
)

// Options configures an ingress.
type Options struct {
	// Published asks what to serve, telling the ingress's report;
	// [ipc.CallPublished] on juistd's socket.
	Published func(context.Context, *ipc.IngressReport) (*ipc.Published, error)
	// Listen binds a public port for the names published by TCP; every
	// address's by default.
	Listen func(port uint16) (net.Listener, error)
	// ListenQUIC, where set, binds 443/udp, passed by the name a client's
	// Initial packets ask for, and is asked again with each poll until it
	// does; DialUDP opens a socket toward a target, a net.Dialer's by
	// default.
	ListenQUIC func() (*net.UDPConn, error)
	DialUDP    func(ctx context.Context, to netip.AddrPort) (net.Conn, error)
	// Poll is how often it asks.
	Poll time.Duration
	// Dial reaches a target; a net.Dialer's by default.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// MaxConns bounds the connections spliced at once, and MaxPerSource
	// those from one client host.
	MaxConns     int
	MaxPerSource int
	Logf         func(format string, args ...any)
	// Access, where set, is told a line for each connection on 443 or a
	// public port and each request on 80: from where, for which name, and
	// what came of it.
	Access func(format string, args ...any)

	helloTimeout, answer, idle, httpIdle, flowIdle time.Duration // for tests
	maxUnproven                                    int
	started                                        func(*ingress)
}

// An ingress serves what juistd last said is published.
type ingress struct {
	o       Options
	table   atomic.Pointer[map[string]ipc.PublishedTarget]
	tcp     atomic.Pointer[map[uint16]ipc.PublishedTarget] // by public port
	relays  atomic.Pointer[map[string]bool]                // in table, served by TLS alone
	members atomic.Pointer[map[string]ipc.PublishedTarget] // not in table: for members alone
	conns   chan struct{}
	sources *admit.Set[netip.Prefix]
	named   published.Named[spliceKey]
	passed  published.Named[passKey]

	mu        sync.Mutex
	listeners map[uint16]net.Listener
	failed    map[uint16]bool // said already, true where another program holds the port

	quic atomic.Pointer[quicFlows] // while QUIC is served

	// wg holds what Serve waits for; quicServing and quicSaid are poll's.
	wg                    sync.WaitGroup
	quicServing, quicSaid bool
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
	if o.maxUnproven == 0 {
		o.maxUnproven = maxUnproven
	}
	if o.flowIdle == 0 {
		o.flowIdle = flowIdle
	}
	if o.DialUDP == nil {
		o.DialUDP = func(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", to.String())
		}
	}
	if o.Listen == nil {
		o.Listen = func(port uint16) (net.Listener, error) { return net.Listen("tcp", fmt.Sprintf(":%d", port)) }
	}
	in := &ingress{o: o, conns: make(chan struct{}, o.MaxConns), sources: admit.HostsAndSites(o.MaxPerSource),
		listeners: map[uint16]net.Listener{}, failed: map[uint16]bool{}}
	in.table.Store(&map[string]ipc.PublishedTarget{})
	in.members.Store(&map[string]ipc.PublishedTarget{})
	in.tcp.Store(&map[uint16]ipc.PublishedTarget{})
	in.relays.Store(&map[string]bool{})
	if o.started != nil {
		o.started(in)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wg := &in.wg
	wg.Go(func() { in.poll(ctx) })
	if httpLn != nil {
		srv := &http.Server{Handler: http.HandlerFunc(in.redirect), ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: o.httpIdle,
			ErrorLog: log.New(io.Discard, "", 0)}
		ln := perSource{Listener: httpLn, sources: admit.HostsAndSites(o.MaxPerSource)}
		wg.Go(func() { _ = srv.Serve(netutil.LimitListener(ln, o.MaxConns)) })
		context.AfterFunc(ctx, func() { srv.Close() })
	}
	context.AfterFunc(ctx, func() { tlsLn.Close() })
	err := in.accept(ctx, tlsLn)
	cancel()
	wg.Wait()
	in.listen(ctx, nil)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// poll asks what to serve every Poll, and serves nothing once asks go
// unanswered: a juistd that stops answering takes the names down with it,
// and the connections for them.
func (in *ingress) poll(ctx context.Context) {
	var r *ipc.IngressReport
	published.Poll(ctx, in.o.Poll, func(actx context.Context) (*ipc.Published, error) {
		in.listenQUIC(ctx)
		r = in.report()
		return in.o.Published(actx, r)
	}, func(p *ipc.Published) (again, stop bool) {
		in.serve(ctx, p)
		// What it listens on changed: juistd hears of it at once.
		now := in.report()
		return !slices.Equal(now.Listening, r.Listening) || !slices.Equal(now.Unbound, r.Unbound) ||
			now.NoQUIC != r.NoQUIC, false
	}, func(err error) {
		in.o.Logf("ingress: juistd does not answer (%v); serving nothing until it does", err)
		in.serve(ctx, in.held())
	}, func() { in.o.Logf("ingress: juistd answers again") })
}

// serve takes p as what is served, closing what no longer is.
func (in *ingress) serve(ctx context.Context, p *ipc.Published) {
	table := make(map[string]ipc.PublishedTarget, len(p.Names)+len(p.Relays))
	relays := make(map[string]bool, len(p.Relays))
	for _, t := range p.Relays {
		table[t.Name], relays[t.Name] = t, true
	}
	for _, t := range p.Names {
		if !relays[t.Name] { // a relay keeps its name
			table[t.Name] = t
		}
	}
	members := make(map[string]ipc.PublishedTarget, len(p.Members))
	for _, t := range p.Members {
		if _, ok := table[t.Name]; !ok {
			members[t.Name] = t
		}
	}
	in.members.Store(&members)
	tcp := make(map[uint16]ipc.PublishedTarget, len(p.TCP))
	for _, t := range p.TCP {
		if t.Public != 0 {
			tcp[t.Public] = t
		}
	}
	in.relays.Store(&relays)
	in.table.Store(&table)
	in.tcp.Store(&tcp)
	in.named.CloseUnless(in.stillPassed)
	if q := in.quic.Load(); q != nil {
		q.closeUnless(func(name string) bool {
			_, ok := in.lookupPublished(name)
			return ok
		})
	}
	in.passed.CloseUnless(func(k passKey) bool {
		t, ok := tcp[k.port]
		return ok && passKeyOf(t) == k
	})
	in.listen(ctx, tcp)
}

// held is what is served while juistd does not answer: nothing, its public
// ports held still, so that no other program takes what the host's firewall
// lets in.
func (in *ingress) held() *ipc.Published {
	p := &ipc.Published{}
	for _, t := range *in.tcp.Load() {
		t.Addrs = nil
		p.TCP = append(p.TCP, t)
	}
	return p
}

// listen has a listener on each public port of tcp and on no other, saying
// once why one cannot be bound; a port it could not bind it tries again at
// the next answer.
func (in *ingress) listen(ctx context.Context, tcp map[uint16]ipc.PublishedTarget) {
	in.mu.Lock()
	defer in.mu.Unlock()
	for port, ln := range in.listeners {
		if _, ok := tcp[port]; !ok {
			ln.Close()
			delete(in.listeners, port)
		}
	}
	for port := range in.failed {
		if _, ok := tcp[port]; !ok {
			delete(in.failed, port)
		}
	}
	for port, t := range tcp {
		if in.listeners[port] != nil {
			continue
		}
		ln, err := in.o.Listen(port)
		if err != nil {
			if _, said := in.failed[port]; !said {
				in.o.Logf("ingress: listening on port %d for %s: %s", port, t.Name, strings.ReplaceAll(err.Error(), "\n", "; "))
			}
			in.failed[port] = errors.Is(err, syscall.EADDRINUSE)
			continue
		}
		delete(in.failed, port)
		in.listeners[port] = ln
		go in.acceptTCP(ctx, port, ln)
	}
}

// report is what the ingress tells juistd: the public ports it listens on,
// and those another program holds. poll alone asks it.
func (in *ingress) report() *ipc.IngressReport {
	in.mu.Lock()
	defer in.mu.Unlock()
	r := &ipc.IngressReport{}
	for port := range in.listeners {
		r.Listening = append(r.Listening, port)
	}
	for port, held := range in.failed {
		if held {
			r.Unbound = append(r.Unbound, port)
		}
	}
	slices.Sort(r.Listening)
	slices.Sort(r.Unbound)
	r.NoQUIC = in.o.ListenQUIC != nil && !in.quicServing
	return r
}

// listenQUIC serves QUIC on 443/udp where it is not yet, saying once why
// not: without it, browsers keep to TCP.
func (in *ingress) listenQUIC(ctx context.Context) {
	if in.o.ListenQUIC == nil || in.quicServing || ctx.Err() != nil {
		return
	}
	pc, err := in.o.ListenQUIC()
	if err != nil {
		if !in.quicSaid {
			in.o.Logf("ingress: no QUIC on 443/udp: %v", err)
			in.quicSaid = true
		}
		return
	}
	if in.quicSaid {
		in.o.Logf("ingress: QUIC on 443/udp")
	}
	in.quicServing = true
	in.wg.Go(func() { in.serveQUIC(ctx, pc) })
	context.AfterFunc(ctx, func() { pc.Close() })
}

// A passKey names the connections passed for a target: its port, its name
// and whether it is served, so that any of them changing closes them.
type passKey struct {
	port   uint16
	name   string
	served bool
}

func passKeyOf(t ipc.PublishedTarget) passKey { return passKey{t.Public, t.Name, len(t.Addrs) > 0} }

// A spliceKey names a connection spliced by name, or for the CA's
// validation of a name alone.
type spliceKey struct {
	name       string
	validation bool
}

// lookup is where name goes, if it is served.
func (in *ingress) lookup(name string) (ipc.PublishedTarget, bool) {
	t, ok := (*in.table.Load())[strings.TrimSuffix(strings.ToLower(name), ".")]
	return t, ok
}

// stillPassed reports whether a connection keyed so may go on: one passed
// by name while the name is served so, one for the CA's validation while
// the name is served at all.
func (in *ingress) stillPassed(k spliceKey) bool {
	_, served := in.lookup(k.name)
	if k.validation {
		_, members := in.lookupMembers(k.name)
		return served || members
	}
	return served
}

// acmeALPN is the protocol the CA asks for to validate a name by
// TLS-ALPN-01 (RFC 8737).
const acmeALPN = "acme-tls/1"

// lookupMembers is where name goes, if it is a name for members alone, for
// the CA's validation.
func (in *ingress) lookupMembers(name string) (ipc.PublishedTarget, bool) {
	t, ok := (*in.members.Load())[strings.TrimSuffix(strings.ToLower(name), ".")]
	return t, ok
}

// lookupPublished is [ingress.lookup] for a published name alone, not a
// relay's, which speaks neither QUIC nor plain HTTP.
func (in *ingress) lookupPublished(name string) (ipc.PublishedTarget, bool) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if (*in.relays.Load())[name] {
		return ipc.PublishedTarget{}, false
	}
	return in.lookup(name)
}

func (in *ingress) accept(ctx context.Context, ln net.Listener) error {
	return in.acceptEach(ctx, ln, "tls", "", in.splice)
}

// acceptTCP passes what ln takes on public port to the name published there,
// until ln is closed.
func (in *ingress) acceptTCP(ctx context.Context, port uint16, ln net.Listener) {
	_ = in.acceptEach(ctx, ln, "tcp", fmt.Sprintf(" %d", port), func(ctx context.Context, c net.Conn) {
		in.pass(ctx, port, c)
	})
}

// acceptEach serves what ln takes by serve, within the bounds on
// connections in all and from one source, until ln is closed; what and
// port, after the client, say which listener in the access log.
func (in *ingress) acceptEach(ctx context.Context, ln net.Listener, what, port string,
	serve func(context.Context, net.Conn)) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return err
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		client := published.AddrPort(c.RemoteAddr())
		select {
		case in.conns <- struct{}{}:
		default:
			c.Close() // at the bound: the client tries again
			in.o.Access("access: %s %v%s refused: too many connections", what, client, port)
			continue
		}
		slot, ok := in.sources.Admit(admit.Host(client.Addr()), nil)
		if !ok {
			<-in.conns
			c.Close()
			in.o.Access("access: %s %v%s refused: too many connections from it", what, client, port)
			continue
		}
		go func() {
			defer func() { <-in.conns }()
			defer slot.Release()
			serve(ctx, c)
		}()
	}
}

// pass splices c, taken on public port, to the name published there at
// once, after a PROXY protocol header where the name asks for one, for as
// long as the name is served there: a protocol may have the server speak
// first.
func (in *ingress) pass(ctx context.Context, port uint16, c net.Conn) {
	defer c.Close()
	start, client := time.Now(), published.AddrPort(c.RemoteAddr())
	var name, outcome string
	var up, down atomic.Int64
	defer func() {
		in.o.Access("access: tcp %v %d %q %s up=%d down=%d %v", client, port, name, outcome, up.Load(), down.Load(),
			time.Since(start).Round(time.Millisecond))
	}()
	t, ok := (*in.tcp.Load())[port]
	if ok {
		name = t.Name
	}
	if !ok || len(t.Addrs) == 0 {
		outcome = "not served"
		return
	}
	target, err := in.dial(ctx, t)
	if err != nil {
		outcome = "target unreachable"
		return
	}
	defer target.Close()
	if t.Proxy {
		if _, err := target.Write(proxyproto.Header(client, published.AddrPort(c.LocalAddr()))); err != nil {
			outcome = "target unreachable"
			return
		}
	}
	outcome = "spliced"
	key := passKeyOf(t)
	in.passed.Add(c, key, func() { c.Close(); target.Close() })
	defer in.passed.Remove(c)
	if now, ok := (*in.tcp.Load())[port]; !ok || passKeyOf(now) != key {
		return // withdrawn meanwhile
	}
	pipe.Join(ctx, watched{c, func(n int) { up.Add(int64(n)) }}, watched{target, func(n int) { down.Add(int64(n)) }}, in.o.idle)
}

// splice passes c to the target its ClientHello names, the bytes read so far
// first, after a PROXY protocol header where the name asks for one, for as
// long as the name is served.
func (in *ingress) splice(ctx context.Context, c net.Conn) {
	defer c.Close()
	start, client := time.Now(), published.AddrPort(c.RemoteAddr())
	var name, outcome string
	var up, down atomic.Int64
	defer func() {
		in.o.Access("access: tls %v %q %s up=%d down=%d %v", client, name, outcome, up.Load(), down.Load(),
			time.Since(start).Round(time.Millisecond))
	}()
	_ = c.SetDeadline(time.Now().Add(in.o.helloTimeout))
	name, protos, hello, err := peekServerName(c)
	if err != nil {
		outcome = "no hello"
		return
	}
	t, ok := in.lookup(name)
	key := spliceKey{name: t.Name}
	if !ok {
		mt, members := in.lookupMembers(name)
		switch {
		case !members:
			outcome = "not served"
			return
		case !slices.Equal(protos, []string{acmeALPN}):
			// The CA's validation alone, which asks acme-tls/1 and nothing
			// else, and gets nothing but its challenge's answer there.
			outcome = "members only"
			return
		}
		t, ok, key = mt, true, spliceKey{mt.Name, true}
	}
	target, err := in.dial(ctx, t)
	if err != nil {
		outcome = "target unreachable"
		return
	}
	defer target.Close()
	_ = c.SetDeadline(time.Time{})
	if t.Proxy {
		hello = append(proxyproto.Header(published.AddrPort(c.RemoteAddr()), published.AddrPort(c.LocalAddr())), hello...)
	}
	outcome = "spliced"
	if _, err := target.Write(hello); err != nil {
		return
	}
	up.Add(int64(len(hello)))
	in.named.Add(c, key, func() { c.Close(); target.Close() })
	defer in.named.Remove(c)
	if !in.stillPassed(key) {
		return // withdrawn, or made for members alone, meanwhile
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
	if t.Socket != "" {
		dctx, cancel := context.WithTimeout(ctx, dialTimeout)
		defer cancel()
		return in.o.Dial(dctx, "unix", t.Socket)
	}
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
	host := published.Host(r)
	if _, ok := in.lookupPublished(host); !ok {
		in.o.Access("access: http %s %q %s %q %d %q", r.RemoteAddr, host, r.Method, r.URL.RequestURI(),
			http.StatusNotFound, r.UserAgent())
		http.NotFound(w, r)
		return
	}
	in.o.Access("access: http %s %q %s %q %d %q", r.RemoteAddr, host, r.Method, r.URL.RequestURI(),
		http.StatusPermanentRedirect, r.UserAgent())
	published.RedirectHTTPS(w, r, strings.ToLower(host))
}

// perSource is a listener taking no more connections from one source at once
// than sources bounds.
type perSource struct {
	net.Listener
	sources *admit.Set[netip.Prefix]
}

func (l perSource) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		slot, ok := l.sources.Admit(admit.Host(published.AddrPort(c.RemoteAddr()).Addr()), nil)
		if !ok {
			c.Close()
			continue
		}
		return &givenBack{Conn: c, done: slot.Release}, nil
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
// returns the name and the protocols it asks for and every byte read, to
// replay to the target.
func peekServerName(c net.Conn) (string, []string, []byte, error) {
	var buf bytes.Buffer
	var name string
	var protos []string
	cfg := &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		name, protos = h.ServerName, slices.Clone(h.SupportedProtos)
		return nil, errPeeked
	}}
	err := tls.Server(readOnlyConn{Conn: c, r: io.TeeReader(c, &buf)}, cfg).Handshake()
	if name == "" {
		return "", nil, nil, fmt.Errorf("ingress: no server name: %w", err)
	}
	return name, protos, buf.Bytes(), nil
}

// readOnlyConn reads through r and writes nothing, so that the handshake
// peekServerName starts answers the client nothing.
type readOnlyConn struct {
	net.Conn
	r io.Reader
}

func (c readOnlyConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c readOnlyConn) Write(p []byte) (int, error) { return 0, io.ErrClosedPipe }
