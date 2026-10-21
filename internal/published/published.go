// Package published is what the ingress and the terminator share in serving
// what a network publishes: asking juistd what to serve, sending plain HTTP
// on to https, the connections open by what they were passed for, and
// reading their addresses.
package published

import (
	"bufio"
	"cmp"
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"
)

// MissesAllowed is how many asks in a row may go unanswered before nothing
// is served.
const MissesAllowed = 1

// Poll asks every every, by ask under a timeout of every, and hands each
// answer to take, until ctx ends or take says to stop; where take says what
// it changed is worth telling juistd at once, it asks again at once. Past
// [MissesAllowed] asks unanswered it calls lost once, and back, where not
// nil, once one is answered again.
func Poll[A any](ctx context.Context, every time.Duration, ask func(context.Context) (A, error),
	take func(A) (again, stop bool), lost func(error), back func()) {
	misses := 0
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		actx, cancel := context.WithTimeout(ctx, every)
		a, err := ask(actx)
		cancel()
		switch {
		case err == nil:
			if misses > MissesAllowed && back != nil {
				back()
			}
			misses = 0
			again, stop := take(a)
			if stop {
				return
			}
			if again {
				continue
			}
		case ctx.Err() != nil:
			return
		default:
			if misses++; misses == MissesAllowed+1 {
				lost(err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Host is the host r asks for, without a port.
func Host(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		return h
	}
	return r.Host
}

// RedirectHTTPS sends r on to https at host, which may carry a port.
func RedirectHTTPS(w http.ResponseWriter, r *http.Request, host string) {
	// From the path alone: an opaque target such as "http:@evil.com" would
	// otherwise name another host.
	to := url.URL{Scheme: "https", Host: host, Path: cmp.Or(r.URL.Path, "/"), RawPath: r.URL.RawPath,
		RawQuery: r.URL.RawQuery}
	http.Redirect(w, r, to.String(), http.StatusPermanentRedirect)
}

// AddrPort is a's address and port, unmapped; [::]:0 where it has none.
func AddrPort(a net.Addr) netip.AddrPort {
	var ap netip.AddrPort
	switch t := a.(type) {
	case *net.TCPAddr:
		ap = t.AddrPort()
	case *net.UDPAddr:
		ap = t.AddrPort()
	case nil:
	default:
		ap, _ = netip.ParseAddrPort(a.String())
	}
	if !ap.IsValid() {
		return netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// A BufferedConn reads through R, which may hold what was peeked of it.
type BufferedConn struct {
	net.Conn
	R *bufio.Reader
}

func (c BufferedConn) Read(p []byte) (int, error) { return c.R.Read(p) }

// CloseWrite passes the end of one way on, where c can.
func (c BufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// Named are the connections open for each key, to close those whose key is
// served no longer.
type Named[K comparable] struct {
	mu    sync.Mutex
	conns map[any]named[K]
}

type named[K comparable] struct {
	key   K
	close func()
}

// Add keeps c under key until Remove; close ends it.
func (n *Named[K]) Add(c any, key K, close func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conns == nil {
		n.conns = map[any]named[K]{}
	}
	n.conns[c] = named[K]{key, close}
}

// Remove forgets c.
func (n *Named[K]) Remove(c any) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.conns, c)
}

// CloseUnless ends every connection whose key served does not hold.
func (n *Named[K]) CloseUnless(served func(K) bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for c, e := range n.conns {
		if !served(e.key) {
			e.close()
			delete(n.conns, c)
		}
	}
}
