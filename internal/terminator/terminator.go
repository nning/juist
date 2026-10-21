// Package terminator ends TLS for the names published on this device and
// sends the plain connection to the local service the operator named, or
// passes the bytes of a name published by TCP on as they are. It listens on
// the device's overlay addresses alone, where the ingress and the members
// reach it, takes its certificates from an ACME CA by TLS-ALPN-01, answered
// through the ingress, and holds no key of the network's.
package terminator

import (
	"bufio"
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/nning/juist/internal/lograte"
	"github.com/nning/juist/internal/pipe"
	"github.com/nning/juist/internal/proxyproto"
	"github.com/nning/juist/internal/published"
	"github.com/nning/juist/internal/statuspage"
	"github.com/nning/juist/ipc"
)

// Defaults for [Options].
const (
	DefaultPoll     = 5 * time.Second
	DefaultMaxConns = 8192

	helloTimeout = 10 * time.Second
	dialTimeout  = 5 * time.Second
	idleTimeout  = 5 * time.Minute
)

// Options configures a terminator.
type Options struct {
	// Serving asks what to serve, telling the terminator's report;
	// [ipc.CallServing] on juistd's socket.
	Serving func(context.Context, *ipc.TerminatorReport) (*ipc.Published, error)
	Poll    time.Duration

	// ACME is the CA's client and Cache where certificates and the account
	// key are kept; Email, where set, is given the CA.
	ACME  *acme.Client
	Cache autocert.Cache
	Email string

	// GetCertificate, where set, replaces ACME, for tests.
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	// HTTPPort, where not zero, is where the addresses a name is served on
	// redirect plain HTTP to it: members resolve such a name to this device,
	// whose port 80 they would otherwise reach.
	HTTPPort uint16

	// StatusPage asks what a status page served here shows,
	// [ipc.CallStatusPage]; nil serves none.
	StatusPage func(context.Context) (*ipc.StatusPage, error)

	Listen       func(network, addr string) (net.Listener, error)
	ListenPacket func(network, addr string) (net.PacketConn, error)
	Dial         func(ctx context.Context, network, addr string) (net.Conn, error)
	MaxConns     int
	Logf         func(format string, args ...any)
}

// what is one answer of juistd's, as the terminator uses it: tcp holds the
// names published by TCP by the port they take here.
type what struct {
	names     map[string]ipc.PublishedTarget
	tcp       map[uint16]ipc.PublishedTarget
	ingresses []netip.Addr
	// members are the names for members alone, each with the addresses it
	// is taken from.
	members map[string]map[netip.Addr]bool
}

type terminator struct {
	o     Options
	now   atomic.Pointer[what]
	conns chan struct{}
	tls   *tls.Config

	account atomic.Pointer[ipc.ACMEAccount]
	named   published.Named[nameKey]
	passed  published.Named[passKey]
	// byPeer are the connections by who opened them for which name, which end
	// once a name is for members alone their peer is not.
	byPeer  published.Named[memberKey]
	pages   *statuspage.Server
	quic    *quicServer
	quicTLS *tls.Config

	mu        sync.Mutex
	listeners map[netip.AddrPort]net.Listener
	services  map[string]*serviceConns // by address, each service's bound
	failed    map[netip.AddrPort]bool  // said already, true where the port is another's
	caaSaid   map[string]bool
	noCert    map[string]string // why a name served found no certificate, until one does
}

// Serve ends TLS for what juistd says this device serves until ctx ends, or
// juistd says nothing here needs it.
func Serve(ctx context.Context, o Options) error {
	if o.Poll == 0 {
		o.Poll = DefaultPoll
	}
	if o.MaxConns == 0 {
		o.MaxConns = DefaultMaxConns
	}
	if o.Listen == nil {
		o.Listen = net.Listen
	}
	if o.ListenPacket == nil {
		o.ListenPacket = net.ListenPacket
	}
	if o.Dial == nil {
		var d net.Dialer
		o.Dial = d.DialContext
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	t := &terminator{o: o, conns: make(chan struct{}, o.MaxConns),
		listeners: map[netip.AddrPort]net.Listener{}, failed: map[netip.AddrPort]bool{}, services: map[string]*serviceConns{},
		caaSaid: map[string]bool{}, noCert: map[string]string{}}
	t.now.Store(&what{names: map[string]ipc.PublishedTarget{}, tcp: map[uint16]ipc.PublishedTarget{}})
	if o.StatusPage != nil {
		t.pages = statuspage.New(o.StatusPage, nil)
	}
	getCert := o.GetCertificate
	if getCert == nil && o.ACME != nil {
		if err := orderUnder(ctx, o.ACME, o.Cache, func(name string) bool {
			_, ok := t.lookup(name)
			return ok
		}); err != nil {
			return err
		}
		go t.learnAccount(ctx)
	}
	if getCert == nil {
		m := &autocert.Manager{Prompt: autocert.AcceptTOS, Cache: o.Cache, Client: o.ACME, Email: o.Email,
			HostPolicy: func(_ context.Context, host string) error {
				if _, ok := t.lookup(host); !ok {
					return fmt.Errorf("terminator: %s is not served here", host)
				}
				return nil
			}}
		getCert = m.GetCertificate
	}
	getCert = t.logged(getCert)
	plain := &tls.Config{GetCertificate: getCert, MinVersion: tls.VersionTLS12}
	http2 := &tls.Config{GetCertificate: getCert, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	challenge := &tls.Config{GetCertificate: getCert, NextProtos: []string{acme.ALPNProto}}
	// ALPN only where the service's protocol is known: a server's list the
	// client's does not meet fails the handshake.
	t.tls = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		// A name for members alone is refused to whoever it is not for, and
		// from an ingress taken for the CA's validation alone, which asks
		// acme-tls/1 and nothing else. By the connection's own source,
		// never the PROXY header's.
		var peer netip.Addr
		if h.Conn != nil {
			peer = published.AddrPort(h.Conn.RemoteAddr()).Addr().Unmap()
		}
		if forMembers, ok := t.admits(h.ServerName, peer); forMembers && !ok {
			if !slices.Contains(t.now.Load().ingresses, peer) || !slices.Equal(h.SupportedProtos, []string{acme.ALPNProto}) {
				return nil, errForMembers
			}
		}
		if slices.Contains(h.SupportedProtos, acme.ALPNProto) {
			return challenge, nil
		}
		if n, ok := t.lookup(h.ServerName); ok && slices.Contains(h.SupportedProtos, "h2") {
			_, h2c := ipc.HTTP2Of(n.To)
			if h2c || HTTP3(n) {
				return http2, nil
			}
		}
		return plain, nil
	}}
	t.quic = newQUICServer(t)
	t.quicTLS = t.quic.tlsConfig(getCert)
	t.poll(ctx)
	t.mu.Lock()
	for ap, ln := range t.listeners {
		ln.Close()
		delete(t.listeners, ap)
	}
	t.mu.Unlock()
	t.quic.closeAll()
	// Said, so that the status does not count it running a while longer.
	sctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _ = t.o.Serving(sctx, &ipc.TerminatorReport{Stopping: true})
	return nil
}

// poll asks what to serve every Poll and listens where it says, until ctx
// ends or juistd says it is idle; once asks go unanswered it serves nothing.
// Where what it listens on changed, it asks again at once, so that juistd
// knows.
func (t *terminator) poll(ctx context.Context) {
	var r *ipc.TerminatorReport
	published.Poll(ctx, t.o.Poll, func(actx context.Context) (*ipc.Published, error) {
		r = t.report()
		return t.o.Serving(actx, r)
	}, func(p *ipc.Published) (again, stop bool) {
		if p.Idle && len(p.Names) == 0 {
			return false, true
		}
		t.set(ctx, p)
		now := t.report()
		return !slices.Equal(now.Listening, r.Listening) || !slices.Equal(now.Unbound, r.Unbound), false
	}, func(err error) {
		t.o.Logf("terminator: juistd does not answer (%v); serving nothing until it does", err)
		t.set(ctx, &ipc.Published{})
	}, nil)
}

// report is what the terminator tells juistd: its account, where it
// listens, and where another program holds the port.
func (t *terminator) report() *ipc.TerminatorReport {
	r := &ipc.TerminatorReport{Account: t.account.Load()}
	t.mu.Lock()
	defer t.mu.Unlock()
	for ap := range t.listeners {
		r.Listening = append(r.Listening, ap.String())
	}
	for ap, inUse := range t.failed {
		if inUse {
			r.Unbound = append(r.Unbound, ap.String())
		}
	}
	for name, why := range t.noCert {
		if _, served := t.lookup(name); served && len(r.NoCert) < maxNoCert {
			r.NoCert = append(r.NoCert, ipc.NoCert{Name: name, Why: why})
		}
	}
	slices.Sort(r.Listening)
	slices.Sort(r.Unbound)
	slices.SortFunc(r.NoCert, func(a, b ipc.NoCert) int { return strings.Compare(a.Name, b.Name) })
	return r
}

// maxNoCert caps the names a report says have no certificate.
const maxNoCert = 64

// set serves p: its names, on the addresses and ports it says, and ends the
// connections for names it no longer holds.
func (t *terminator) set(ctx context.Context, p *ipc.Published) {
	w := &what{names: map[string]ipc.PublishedTarget{}, tcp: map[uint16]ipc.PublishedTarget{}, ingresses: p.Ingresses,
		members: map[string]map[netip.Addr]bool{}}
	want := map[netip.AddrPort]bool{}
	redirect := map[netip.AddrPort]bool{}
	for _, n := range p.Members {
		from := map[netip.Addr]bool{}
		for _, a := range n.From {
			from[a.Unmap()] = true
		}
		w.members[n.Name] = from
	}
	names := slices.Concat(p.Names, p.Members)
	for _, n := range names {
		w.names[n.Name] = n
		for _, a := range n.Addrs {
			want[netip.AddrPortFrom(a, n.Port)] = true
			if t.o.HTTPPort != 0 {
				redirect[netip.AddrPortFrom(a, t.o.HTTPPort)] = true
			}
		}
	}
	for _, n := range p.TCP {
		w.tcp[n.Port] = n
		for _, a := range n.Addrs {
			want[netip.AddrPortFrom(a, n.Port)] = true
		}
	}
	quic := map[netip.AddrPort]bool{}
	for _, n := range names {
		for _, a := range n.Addrs {
			if HTTP3(n) {
				quic[netip.AddrPortFrom(a, n.Port)] = true
			}
		}
	}
	for ap := range redirect {
		if want[ap] {
			delete(redirect, ap) // a name served there
		} else {
			want[ap] = true
		}
	}
	t.now.Store(w)
	// A connection piped as it is ends once its name goes elsewhere, or is
	// proxied by path.
	t.named.CloseUnless(func(k nameKey) bool {
		n, ok := t.lookup(k.name)
		return ok && (!k.piped || n.To == k.to && len(n.Paths) == 0)
	})
	t.passed.CloseUnless(t.passing)
	t.byPeer.CloseUnless(func(k memberKey) bool {
		from, forMembers := w.members[k.name]
		return !forMembers || from[k.peer]
	})
	t.quic.set(quic, t.quicTLS)
	t.mu.Lock()
	defer t.mu.Unlock()
	// The record is said once, for whoever runs this without juist's CLI.
	if a := t.account.Load(); a != nil {
		for name := range w.names {
			for _, r := range a.CAA(name) {
				if !t.caaSaid[r] {
					t.caaSaid[r] = true
					t.o.Logf("terminator: CAA record: %s", r)
				}
			}
		}
	}
	for ap, ln := range t.listeners {
		if !want[ap] {
			ln.Close()
			delete(t.listeners, ap)
		}
	}
	for ap := range t.failed {
		if !want[ap] {
			delete(t.failed, ap)
		}
	}
	for name := range t.noCert {
		if _, ok := w.names[name]; !ok {
			delete(t.noCert, name)
		}
	}
	for ap := range want {
		if t.listeners[ap] != nil {
			continue
		}
		ln, err := t.o.Listen("tcp", ap.String())
		if err != nil {
			if _, said := t.failed[ap]; !said {
				t.failed[ap] = errors.Is(err, syscall.EADDRINUSE)
				switch {
				case errors.Is(err, syscall.EADDRINUSE) && redirect[ap]:
					err = fmt.Errorf("%w; another program serves port %d here, which http:// to a name served "+
						"here reaches instead of a redirect to https", err, ap.Port())
				case errors.Is(err, syscall.EADDRINUSE) && w.tcp[ap.Port()].Name != "":
					err = fmt.Errorf("%w; another program serves port %d here, where %s is passed by TCP", err,
						ap.Port(), w.tcp[ap.Port()].Name)
				case errors.Is(err, syscall.EADDRINUSE):
					err = fmt.Errorf("%w; another program serves port %d here, and a name published on another "+
						"port is served beside it", err, ap.Port())
				}
				t.o.Logf("terminator: %v", err)
			}
			continue
		}
		delete(t.failed, ap)
		t.listeners[ap] = ln
		if redirect[ap] {
			go t.redirect(ap, ln)
		} else {
			go t.accept(ctx, ap, ln)
		}
	}
}

// certLogEvery is how often one name's certificate failing is said.
const certLogEvery = time.Minute

// logged says why get finds no certificate for a name served, once a minute
// for each, and keeps it for the report until one is found: what the CA
// refused is the operator's to know, and a scanner's names are none.
func (t *terminator) logged(get func(*tls.ClientHelloInfo) (*tls.Certificate, error)) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	said := lograte.ByKey[string]{Interval: certLogEvery, Max: 4096}
	return func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, err := get(h)
		name := strings.TrimSuffix(strings.ToLower(h.ServerName), ".")
		// The CA's challenge is answered whatever becomes of the order.
		if _, served := t.lookup(name); !served || slices.Contains(h.SupportedProtos, acme.ALPNProto) {
			return c, err
		}
		t.mu.Lock()
		if err != nil {
			t.noCert[name] = truncate(err.Error(), ipc.MaxNoCertWhy)
		} else {
			delete(t.noCert, name)
		}
		t.mu.Unlock()
		if err != nil {
			if _, _, ok := said.Allow(name, time.Now()); ok {
				t.o.Logf("terminator: no certificate for %s: %v", h.ServerName, err)
			}
		}
		return c, err
	}
}

// truncate is s cut to at most n bytes, on a rune's boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func (t *terminator) lookup(name string) (ipc.PublishedTarget, bool) {
	n, ok := t.now.Load().names[canonicalName(name)]
	return n, ok
}

func canonicalName(name string) string { return strings.TrimSuffix(strings.ToLower(name), ".") }

// sameHost reports whether a request's Host names name.
func sameHost(host, name string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return canonicalName(host) == canonicalName(name)
}

// admits reports whether a connection from peer may have name: any where the
// name is not for members alone, and else one from a member it is for.
func (t *terminator) admits(name string, peer netip.Addr) (forMembers, ok bool) {
	from, forMembers := t.now.Load().members[canonicalName(name)]
	return forMembers, !forMembers || from[peer.Unmap()]
}

// A memberKey is a connection to a name, from peer.
type memberKey struct {
	name string
	peer netip.Addr
}

func memberKeyOf(name string, peer netip.Addr) memberKey {
	return memberKey{canonicalName(name), peer.Unmap()}
}

// A nameKey is a connection served by name, piped to a service where it is
// passed on whole.
type nameKey struct {
	name, to string
	piped    bool
}

// errForMembers refuses a name for members alone to whoever it is not for.
var errForMembers = errors.New("terminator: the name is for members alone")

// accept serves what ln takes until it fails, then lets the next answer
// listen at ap again: a network stack restarted leaves its listeners failing.
func (t *terminator) accept(ctx context.Context, ap netip.AddrPort, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			t.mu.Lock()
			if t.listeners[ap] == ln {
				delete(t.listeners, ap)
				ln.Close()
			}
			t.mu.Unlock()
			return
		}
		select {
		case t.conns <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-t.conns }()
			if n, ok := t.now.Load().tcp[ap.Port()]; ok {
				t.pass(ctx, c, n)
			} else {
				t.serve(ctx, c)
			}
		}()
	}
}

// A passKey names the connections passed for a name: its port, name and
// where it goes, so that any of them changing closes them.
type passKey struct {
	port     uint16
	name, to string
}

func passKeyOf(n ipc.PublishedTarget) passKey { return passKey{n.Port, n.Name, n.To} }

// passing reports whether the name published by TCP whose connections k
// names is served as it was.
func (t *terminator) passing(k passKey) bool {
	n, ok := t.now.Load().tcp[k.port]
	return ok && passKeyOf(n) == k
}

// pass sends what c carries for n, a name published by TCP, to its local
// service as it is, behind a PROXY protocol header naming the client where
// the name asks for one: the one an ingress's header names, from an ingress
// alone, and c's peer otherwise. An ingress sends a header for such a name
// alone, so that a service that speaks first is not kept waiting.
func (t *terminator) pass(ctx context.Context, c net.Conn, n ipc.PublishedTarget) {
	defer c.Close()
	client := published.AddrPort(c.RemoteAddr())
	if n.Proxy && slices.Contains(t.now.Load().ingresses, client.Addr().Unmap()) {
		_ = c.SetDeadline(time.Now().Add(helloTimeout))
		r := bufio.NewReader(c)
		src, ok, err := proxyproto.Read(r)
		if err != nil {
			return
		}
		if ok && src.IsValid() {
			client = src
		}
		_ = c.SetDeadline(time.Time{})
		c = published.BufferedConn{Conn: c, R: r}
	}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	backend, err := t.o.Dial(dctx, "tcp", n.To)
	cancel()
	if err != nil {
		return
	}
	defer backend.Close()
	if n.Proxy {
		if _, err := backend.Write(proxyproto.Header(client, published.AddrPort(c.LocalAddr()))); err != nil {
			return
		}
	}
	key := passKeyOf(n)
	t.passed.Add(c, key, func() { c.Close(); backend.Close() })
	defer t.passed.Remove(c)
	if !t.passing(key) {
		return // no longer served
	}
	pipe.Join(ctx, c, backend, idleTimeout)
}

// serve ends TLS on c and sends what it carries to the name's local service,
// behind a PROXY protocol header naming the client where the name asks for
// one. The client is the one an ingress's header names, from an ingress
// alone, and c's peer otherwise.
func (t *terminator) serve(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(helloTimeout))
	r := bufio.NewReader(c)
	client := published.AddrPort(c.RemoteAddr())
	if slices.Contains(t.now.Load().ingresses, client.Addr().Unmap()) {
		src, ok, err := proxyproto.Read(r)
		if err != nil {
			return
		}
		if ok && src.IsValid() {
			client = src
		}
	}
	peer := published.AddrPort(c.RemoteAddr()).Addr().Unmap()
	tc := tls.Server(published.BufferedConn{Conn: c, R: r}, t.tls)
	if err := tc.HandshakeContext(ctx); err != nil {
		return
	}
	st := tc.ConnectionState()
	if st.NegotiatedProtocol == acme.ALPNProto {
		return
	}
	n, ok := t.lookup(st.ServerName)
	if !ok {
		return
	}
	// Every connection, so that a name made for members alone ends those
	// of whoever it is not for, though opened while it was public.
	t.byPeer.Add(c, memberKeyOf(n.Name, peer), func() { c.Close() })
	defer t.byPeer.Remove(c)
	if _, ok := t.admits(n.Name, peer); !ok {
		return
	}
	if HTTP3(n) || len(n.Paths) > 0 {
		_, page := ipc.StatusPageOf(n.To)
		if page && t.pages == nil {
			return
		}
		_ = c.SetDeadline(time.Time{})
		t.named.Add(c, nameKey{name: n.Name}, func() { c.Close() })
		defer t.named.Remove(c)
		if _, ok := t.lookup(n.Name); !ok {
			return // no longer served
		}
		timeout, headerBytes := time.Duration(0), proxyHeaderBytes
		if page {
			timeout, headerBytes = pageTimeout, pageHeaderBytes
		}
		px := t.proxiesFor(client, published.AddrPort(c.LocalAddr()))
		defer px.close()
		var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			now, ok := t.lookup(n.Name)
			switch {
			case !ok:
				http.NotFound(w, r)
				return
			case !sameHost(r.Host, n.Name):
				// A service picking its site by Host would hand this one
				// another name's, perhaps one for members alone.
				http.Error(w, "", http.StatusMisdirectedRequest)
				return
			}
			t.serveName(w, r, now, px)
		})
		if HTTP3(n) {
			h = withAltSvc(h)
		}
		t.serveHTTP(ctx, tc, h, timeout, headerBytes)
		return
	}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	to, _ := ipc.HTTP2Of(n.To)
	backend, err := t.o.Dial(dctx, "tcp", to)
	cancel()
	if err != nil {
		return
	}
	defer backend.Close()
	_ = c.SetDeadline(time.Time{})
	if n.Proxy {
		if _, err := backend.Write(proxyproto.Header(client, published.AddrPort(c.LocalAddr()))); err != nil {
			return
		}
	}
	t.named.Add(c, nameKey{n.Name, n.To, true}, func() { c.Close(); backend.Close() })
	defer t.named.Remove(c)
	if now, ok := t.lookup(n.Name); !ok || now.To != n.To || len(now.Paths) > 0 {
		return // no longer served so
	}
	pipe.Join(ctx, tc, backend, idleTimeout)
}

// redirect sends plain HTTP for a name served here to https until ln
// fails, then lets the next answer listen at ap again.
func (t *terminator) redirect(ap netip.AddrPort, ln net.Listener) {
	srv := &http.Server{Handler: http.HandlerFunc(t.toHTTPS), ReadHeaderTimeout: helloTimeout,
		IdleTimeout: pageIdle, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	_ = srv.Serve(ln)
	t.mu.Lock()
	if t.listeners[ap] == ln {
		delete(t.listeners, ap)
		ln.Close()
	}
	t.mu.Unlock()
}

// toHTTPS redirects a request for a name served here to https, on the port
// it is served on; it reads nothing else.
func (t *terminator) toHTTPS(w http.ResponseWriter, r *http.Request) {
	n, ok := t.lookup(published.Host(r))
	if !ok {
		http.NotFound(w, r)
		return
	}
	host := n.Name
	if n.Port != 443 {
		host = net.JoinHostPort(n.Name, strconv.Itoa(int(n.Port)))
	}
	published.RedirectHTTPS(w, r, host)
}

// proxiesFor is a client connection's proxies, made as its requests need them.
func (t *terminator) proxiesFor(client, local netip.AddrPort) *connProxies {
	return &connProxies{t: t, client: client, local: local, by: map[proxyKey]*connProxy{}}
}

// proxyFor is a client connection's proxy to n's service.
func (t *terminator) proxyFor(n ipc.PublishedTarget, client, local netip.AddrPort) *connProxy {
	addr, _ := ipc.HTTP2Of(n.To)
	t.mu.Lock()
	s := t.services[addr]
	if s == nil {
		s = newServiceConns(maxServiceConns)
		t.services[addr] = s
	}
	t.mu.Unlock()
	return &connProxy{dial: t.o.Dial, service: s, n: n, client: client, local: local}
}

// serveName answers r for n, offered HTTP/3 or served by path: by the
// status page, or by the service, or the path's, through px. The page tells
// members from the public by the connection's peer, never by what an
// ingress says, which it could forge.
func (t *terminator) serveName(w http.ResponseWriter, r *http.Request, n ipc.PublishedTarget, px *connProxies) {
	if public, ok := ipc.StatusPageOf(n.To); ok {
		if t.pages == nil {
			http.NotFound(w, r)
			return
		}
		t.pages.Handler(n.Name, public).ServeHTTP(w, r)
		return
	}
	px.to(underPath(n, r.URL.Path)).ServeHTTP(w, r)
}

// underPath is where a request for path goes of n: under one of its paths,
// to that path's service.
func underPath(n ipc.PublishedTarget, path string) ipc.PublishedTarget {
	for _, p := range n.Paths {
		if strings.HasPrefix(path, p.Prefix) {
			return ipc.PublishedTarget{Name: n.Name, To: p.To}
		}
	}
	return n
}

// serveHTTP serves h on c, until its client is done with it and with what
// a request upgraded it to, each request within timeout where not zero: a
// service's downloads take what they take.
func (t *terminator) serveHTTP(ctx context.Context, c net.Conn, h http.Handler, timeout time.Duration, headerBytes int) {
	ln := &oneConn{c: c, closed: make(chan struct{})}
	var hs handlers
	srv := &http.Server{ReadHeaderTimeout: helloTimeout,
		ReadTimeout: timeout, WriteTimeout: timeout, IdleTimeout: pageIdle, MaxHeaderBytes: headerBytes,
		ErrorLog: log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hs.start() {
				defer hs.done()
				h.ServeHTTP(w, r)
			}
		}),
		ConnState: func(_ net.Conn, s http.ConnState) {
			if s == http.StateClosed || s == http.StateHijacked {
				ln.Close()
			}
		}}
	// A connection upgraded is the server's no more: it is closed here.
	stop := context.AfterFunc(ctx, func() { srv.Close(); c.Close() })
	defer stop()
	_ = srv.Serve(ln)
	hs.wait()
}

// handlers counts the requests being handled, until wait has them done.
type handlers struct {
	mu     sync.Mutex
	idle   *sync.Cond
	n      int
	closed bool
}

// start reports whether a request may be handled, and counts it.
func (hs *handlers) start() bool {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.closed {
		return false
	}
	hs.n++
	return true
}

func (hs *handlers) done() {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.n--; hs.n == 0 && hs.idle != nil {
		hs.idle.Broadcast()
	}
}

// wait refuses requests from now on, and returns once those started are
// done.
func (hs *handlers) wait() {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.closed = true
	hs.idle = sync.NewCond(&hs.mu)
	for hs.n > 0 {
		hs.idle.Wait()
	}
}

// Timeouts of a status page's connection.
const (
	pageTimeout     = 30 * time.Second
	pageIdle        = 2 * time.Minute
	pageHeaderBytes = 16 << 10
)

// oneConn is a listener of one connection, c, which it hands out once, as
// it is, so that a server sees the *tls.Conn and its ALPN; the server's
// ConnState closes it.
type oneConn struct {
	c      net.Conn
	once   sync.Once
	handed atomic.Bool
	closed chan struct{}
}

func (l *oneConn) Accept() (net.Conn, error) {
	if l.handed.CompareAndSwap(false, true) {
		return l.c, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *oneConn) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *oneConn) Addr() net.Addr { return l.c.LocalAddr() }
