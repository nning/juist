package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/time/rate"

	"github.com/nning/juist/internal/proxyproto"
)

// tlsConfig shows a client asking for name, by SNI, the certificate named
// gives, and every other client the pinned one.
func tlsConfig(cert *selfSigned, name string, named func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	pinned := &tls.Config{Certificates: []tls.Certificate{cert.tls}, MinVersion: tls.VersionTLS12}
	if name == "" || named == nil {
		return pinned
	}
	// HTTP/1.1 alone: DERP takes the connection over, which HTTP/2 cannot.
	public := &tls.Config{GetCertificate: named, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	challenge := &tls.Config{GetCertificate: named, NextProtos: []string{acme.ALPNProto}}
	return &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		if !strings.EqualFold(strings.TrimSuffix(h.ServerName, "."), name) {
			return pinned, nil
		}
		if IsChallenge(h) {
			return challenge, nil
		}
		return public, nil
	}}
}

// IsChallenge reports whether h is an ACME CA's TLS-ALPN-01 challenge,
// offering its protocol alone, as autocert takes one.
func IsChallenge(h *tls.ClientHelloInfo) bool {
	return len(h.SupportedProtos) == 1 && h.SupportedProtos[0] == acme.ALPNProto
}

// ServeHTTPS serves the relay on ln as well, such as 443 for its public
// name, until the relay closes or ln does. The relay owns ln from here.
func (s *Server) ServeHTTPS(ln net.Listener) {
	go func() {
		err := s.http.ServeTLS(ln, "", "")
		select {
		case <-s.closed:
		default:
			if !errors.Is(err, net.ErrClosed) {
				s.logf("relay: serving on %v stopped: %v", ln.Addr(), err)
			}
		}
	}()
}

// handOffWait bounds how long a connection from loopback may take to say
// whose it is.
const (
	handOffWait    = 5 * time.Second
	maxHandingOver = 64
)

// handedOff reads the PROXY v2 header a connection from loopback may start
// with, as the ingress's do, while now says an ingress hands on, and reports
// the client it names as the remote address. Other connections pass as they
// are: a header from anywhere else would let any client say it is another.
func handedOff(ln net.Listener, now func() bool) net.Listener {
	h := &handOffListener{Listener: ln, now: now, conns: make(chan net.Conn), done: make(chan struct{}),
		slots: make(chan struct{}, maxHandingOver)}
	go h.run()
	return h
}

type handOffListener struct {
	net.Listener
	now   func() bool
	conns chan net.Conn
	done  chan struct{}
	err   error
	slots chan struct{}
}

func (h *handOffListener) run() {
	defer close(h.done)
	var pause time.Duration
	for {
		c, err := h.Listener.Accept()
		if t, ok := err.(interface{ Temporary() bool }); ok && t.Temporary() {
			// As out of descriptors: net/http's own wait, then again.
			pause = min(max(2*pause, 5*time.Millisecond), time.Second)
			time.Sleep(pause)
			continue
		}
		if err != nil {
			h.err = err
			return
		}
		pause = 0
		ta, _ := c.RemoteAddr().(*net.TCPAddr)
		if ta == nil || !ta.AddrPort().Addr().Unmap().IsLoopback() || !h.now() {
			if !h.give(c) {
				return
			}
			continue
		}
		select {
		case h.slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-h.slots }()
			_ = c.SetReadDeadline(time.Now().Add(handOffWait))
			br := bufio.NewReader(c)
			src, ok, err := proxyproto.Read(br)
			if err != nil {
				c.Close()
				return
			}
			_ = c.SetReadDeadline(time.Time{})
			out := &readerConn{Conn: c, r: br}
			if ok && src.IsValid() {
				out.remote = net.TCPAddrFromAddrPort(src)
			}
			h.give(out)
		}()
	}
}

func (h *handOffListener) give(c net.Conn) bool {
	select {
	case h.conns <- c:
		return true
	case <-h.done:
		c.Close()
		return false
	}
}

func (h *handOffListener) Accept() (net.Conn, error) {
	select {
	case c := <-h.conns:
		return c, nil
	case <-h.done:
		return nil, h.err
	}
}

func (h *handOffListener) Close() error { return h.Listener.Close() }

// readerConn reads through r, and names remote as its peer where set.
type readerConn struct {
	net.Conn
	r      *bufio.Reader
	remote net.Addr
}

func (c *readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *readerConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}

// RendezvousPath is where a relay answers for its network's announcements:
// GET and PUT of RendezvousPath followed by the hex of the key the member is
// published under in the DHT.
const RendezvousPath = "/juist/rendezvous/v1/"

// MaxRendezvousValue bounds a sealed announcement, as BEP 44 does an item.
const MaxRendezvousValue = 1000

// A Rendezvous answers for one network's members by the key each publishes
// its sealed announcement under in the DHT, which only a holder of the
// network's secret can derive. What it hands out is sealed under that secret,
// so a stranger who guessed a key would learn nothing from it.
type Rendezvous interface {
	// Knows reports whether key is one a member is published under, cheaply.
	Knows(key [32]byte) bool

	// Get is the sealed announcement held for key, false where key is none
	// of the network's or none is held.
	Get(key [32]byte) ([]byte, bool)

	// Put takes the sealed announcement for key, false where it is refused.
	Put(key [32]byte, sealed []byte) bool
}

// Bounds on what a relay's rendezvous answers, from one client and from all.
const (
	rendezvousPerSource   = 1 // a second, after a burst
	rendezvousSourceBurst = 16
	rendezvousTotal       = 64
	rendezvousTotalBurst  = 128
	maxRendezvousSources  = 4096
)

type rendezvousHandler struct {
	r     Rendezvous
	logf  func(string, ...any)
	total *rate.Limiter

	mu      sync.Mutex
	sources map[netip.Addr]*sourceLimit
}

type sourceLimit struct {
	*rate.Limiter
	seen time.Time
}

func newRendezvousHandler(r Rendezvous, logf func(string, ...any)) *rendezvousHandler {
	return &rendezvousHandler{r: r, logf: logf, total: rate.NewLimiter(rendezvousTotal, rendezvousTotalBurst),
		sources: map[netip.Addr]*sourceLimit{}}
}

// sourceOf is whose budget a request from a takes: an IPv6 client's whole
// /56, as one holds that many addresses.
func sourceOf(a netip.Addr) netip.Addr {
	if a.Is6() && !a.Is4In6() {
		p, _ := a.Prefix(56)
		return p.Addr()
	}
	return a.Unmap()
}

// allowSource takes one request's worth from the client's budget, making
// room for a client not seen yet by forgetting the one seen longest ago.
func (h *rendezvousHandler) allowSource(from netip.Addr, now time.Time) bool {
	from = sourceOf(from)
	h.mu.Lock()
	defer h.mu.Unlock()
	l := h.sources[from]
	if l == nil {
		if len(h.sources) >= maxRendezvousSources {
			var oldest netip.Addr
			var at time.Time
			for a, s := range h.sources {
				if !oldest.IsValid() || s.seen.Before(at) {
					oldest, at = a, s.seen
				}
			}
			delete(h.sources, oldest)
		}
		l = &sourceLimit{Limiter: rate.NewLimiter(rendezvousPerSource, rendezvousSourceBurst)}
		h.sources[from] = l
	}
	l.seen = now
	return l.AllowN(now, 1)
}

func (h *rendezvousHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, err := hex.DecodeString(strings.TrimPrefix(r.URL.Path, RendezvousPath))
	if err != nil || len(raw) != 32 {
		http.NotFound(w, r)
		return
	}
	key := [32]byte(raw)
	from, _ := netip.ParseAddrPort(r.RemoteAddr)
	now := time.Now()
	if !h.allowSource(from.Addr(), now) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	// A key of no member's costs the relay's budget nothing, so strangers
	// cannot spend it for the members.
	if !h.r.Knows(key) {
		http.NotFound(w, r)
		return
	}
	if !h.total.AllowN(now, 1) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	switch r.Method {
	case http.MethodGet:
		v, ok := h.r.Get(key)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(v)
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxRendezvousValue+1))
		if err != nil || len(body) == 0 || len(body) > MaxRendezvousValue {
			http.Error(w, "no announcement, or one too large", http.StatusBadRequest)
			return
		}
		if !h.r.Put(key, body) {
			// The same answer as a key nobody holds, so a stranger cannot
			// tell a key of the network's from any other.
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "GET or PUT", http.StatusMethodNotAllowed)
	}
}

// ErrNotHeld is a relay's answer that it holds no announcement for a key.
var ErrNotHeld = errors.New("relay: no announcement held for the key")

func rendezvousURL(name string, key [32]byte) string {
	return "https://" + name + RendezvousPath + hex.EncodeToString(key[:])
}

// GetAnnouncement asks the relay serving name on 443 for the sealed
// announcement it holds for key, through hc.
func GetAnnouncement(ctx context.Context, hc *http.Client, name string, key [32]byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rendezvousURL(name, key), nil)
	if err != nil {
		return nil, err
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrNotHeld
	default:
		return nil, fmt.Errorf("relay: %s answered %s", name, res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, MaxRendezvousValue+1))
	if err != nil {
		return nil, err
	}
	if len(body) == 0 || len(body) > MaxRendezvousValue {
		return nil, fmt.Errorf("relay: %s answered %d bytes", name, len(body))
	}
	return body, nil
}

// PutAnnouncement hands the relay serving name on 443 the sealed
// announcement for key, through hc.
func PutAnnouncement(ctx context.Context, hc *http.Client, name string, key [32]byte, sealed []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, rendezvousURL(name, key), bytes.NewReader(sealed))
	if err != nil {
		return err
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4<<10))
	if res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("relay: %s refused the announcement: %s", name, res.Status)
	}
	return nil
}
