package terminator

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"sync"
	"time"

	"github.com/nning/juist/internal/proxyproto"
	"github.com/nning/juist/ipc"
)

// altSvc tells a client of a name offered HTTP/3 that the name is reached
// so on 443, every ingress's QUIC port, for a day.
const altSvc = `h3=":443"; ma=86400`

// Bounds of the proxies to a service: connections for one client
// connection, kept idle for it, and for all.
const (
	maxBackendConns = 64
	maxBackendIdle  = 8
	maxServiceConns = 512

	// proxyHeaderBytes bounds a proxied request's header: an application's
	// cookies take more than the status page's bound.
	proxyHeaderBytes = 64 << 10
)

// connProxy is one client connection's reverse proxy to its name's service,
// made at its first request, so that each connection to the service is
// told its own client behind --proxy, and what it holds goes with it.
type connProxy struct {
	dial          func(ctx context.Context, network, addr string) (net.Conn, error)
	service       *serviceConns
	n             ipc.PublishedTarget
	client, local netip.AddrPort // as the client connection's ends see them

	once sync.Once
	h    http.Handler
	trs  []*http.Transport
}

func (c *connProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.once.Do(c.make)
	if c.h == nil {
		http.Error(w, "", http.StatusServiceUnavailable)
		return
	}
	c.h.ServeHTTP(w, r)
}

// close lets go of the service's connections the proxy keeps; once it has,
// it proxies nothing more.
func (c *connProxy) close() {
	c.once.Do(func() {})
	c.service.forget(c.trs...)
	for _, tr := range c.trs {
		tr.CloseIdleConnections()
	}
}

func (c *connProxy) make() {
	addr, h2c := ipc.HTTP2Of(c.n.To)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			b, err := c.service.dial(ctx, c.dial, addr)
			if err != nil || !c.n.Proxy {
				return b, err
			}
			if _, err := b.Write(proxyproto.Header(c.client, c.local)); err != nil {
				b.Close()
				return nil, err
			}
			return b, nil
		},
		MaxConnsPerHost:     maxBackendConns,
		MaxIdleConnsPerHost: maxBackendIdle,
		IdleConnTimeout:     pageIdle,
	}
	c.trs = []*http.Transport{tr}
	var rt http.RoundTripper = tr
	if h2c {
		tr.Protocols = new(http.Protocols)
		tr.Protocols.SetUnencryptedHTTP2(true)
		// An upgrade, as to a WebSocket, takes HTTP/1.1.
		up := tr.Clone()
		up.Protocols = new(http.Protocols)
		up.Protocols.SetHTTP1(true)
		c.trs = append(c.trs, up)
		rt = upgrades{tr, up}
	}
	c.service.keep(c.trs...)
	c.h = &httputil.ReverseProxy{
		// As TLS's bytes reached the service before: its own Host, and no
		// header of the proxy's nor a client's naming one.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = "http", addr
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Del("X-Real-Ip")
			pr.Out.Header.Del("True-Client-Ip")
		},
		Transport: rt,
		ErrorLog:  log.New(io.Discard, "", 0),
	}
}

// serviceConns bounds the connections all proxies open to one service:
// past the bound, the idle ones go, and a request waits dialTimeout at most.
type serviceConns struct {
	slots chan struct{}

	mu  sync.Mutex
	trs map[*http.Transport]bool
}

func newServiceConns(n int) *serviceConns {
	return &serviceConns{slots: make(chan struct{}, n), trs: map[*http.Transport]bool{}}
}

// keep has trs' idle connections let go of past the bound, until forget.
func (s *serviceConns) keep(trs ...*http.Transport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tr := range trs {
		s.trs[tr] = true
	}
}

func (s *serviceConns) forget(trs ...*http.Transport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tr := range trs {
		delete(s.trs, tr)
	}
}

func (s *serviceConns) dial(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error),
	addr string) (net.Conn, error) {
	select {
	case s.slots <- struct{}{}:
	default:
		s.mu.Lock()
		for tr := range s.trs {
			tr.CloseIdleConnections()
		}
		s.mu.Unlock()
		t := time.NewTimer(dialTimeout)
		defer t.Stop()
		select {
		case s.slots <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
			return nil, errors.New("terminator: too many connections to the service")
		}
	}
	c, err := dial(ctx, "tcp", addr)
	if err != nil {
		<-s.slots
		return nil, err
	}
	return &slotConn{Conn: c, release: func() { <-s.slots }}, nil
}

// slotConn gives its slot back once closed.
type slotConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *slotConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// upgrades sends a request to upgrade its connection by up, the rest by rt.
type upgrades struct{ rt, up http.RoundTripper }

func (u upgrades) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("Upgrade") != "" {
		return u.up.RoundTrip(r)
	}
	return u.rt.RoundTrip(r)
}

// withAltSvc adds the Alt-Svc header to h's answers.
func withAltSvc(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", altSvc)
		h.ServeHTTP(w, r)
	})
}
