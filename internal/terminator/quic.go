package terminator

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/nning/juist/internal/proxyproto"
	"github.com/nning/juist/internal/published"
	"github.com/nning/juist/ipc"
)

// QUIC bounds at the terminator.
const (
	// quicIdle ends a QUIC connection quiet for that long: shorter than an
	// ingress keeps its flow.
	quicIdle = time.Minute

	// quicPacket is what each packet fills at first: the tunnel's MTU of
	// 1280 carries 1232 bytes of UDP over IPv6, and path MTU discovery
	// finds more where there is.
	quicPacket = 1200

	// retryPast is the connections open past which a new client is to
	// prove its address by a Retry first (RFC 9000, 8.1.2).
	retryPast = 512

	// maxClients bounds the clients ingresses named that are kept.
	maxClients = 1 << 16
)

// HTTP3 says whether n is offered HTTP/3: a name whose service speaks HTTP,
// which the terminator then proxies, or the status page.
func HTTP3(n ipc.PublishedTarget) bool { return ipc.OffersHTTP3(n.To) }

// quicServer ends QUIC for the names offered HTTP/3, one socket for each of
// this device's addresses and port they are served on, and serves each
// request over HTTP/3 as it does over TCP.
type quicServer struct {
	t   *terminator
	srv *http3.Server

	setMu   sync.Mutex // serializes set and closeAll, which open sockets
	sockets map[netip.AddrPort]*quicSocket
	failed  map[netip.AddrPort]bool // said already
	conns   atomic.Pointer[[]*clientsConn]
}

type quicSocket struct {
	pc   *clientsConn
	tr   *quic.Transport
	ln   *quic.Listener
	conn net.PacketConn
}

// provenTold is when an ingress is told a client proved its address: at
// once and again, as a datagram may be lost.
var provenTold = []time.Duration{0, time.Second, 2 * time.Second}

// provingListener tells an ingress, by a LOCAL header to the flow it passes
// naming the client, that the client completed its handshake, which proves
// its address (RFC 9000, 8.1), and once done that the connection ended: the
// ingress can see neither itself.
type provingListener struct {
	*quic.Listener
	s *quicSocket
}

func (l provingListener) Accept(ctx context.Context) (*quic.Conn, error) {
	c, err := l.Listener.Accept(ctx)
	if err != nil {
		return c, err
	}
	remote := published.AddrPort(c.RemoteAddr())
	client, named := l.s.pc.client(remote)
	if !named || !containsAddr(l.s.pc.ingresses(), remote.Addr()) {
		return c, nil
	}
	go func() {
		defer func() { _, _ = l.s.tr.WriteTo(proxyproto.LocalUDP(client, true), c.RemoteAddr()) }()
		for _, d := range provenTold {
			select {
			case <-c.Context().Done():
				return
			case <-time.After(d):
			}
			_, _ = l.s.tr.WriteTo(proxyproto.LocalUDP(client, false), c.RemoteAddr())
		}
		<-c.Context().Done()
	}()
	return c, nil
}

func newQUICServer(t *terminator) *quicServer {
	// quic-go would say a small socket buffer on the standard logger, in
	// words of its own; the handbook says it instead.
	_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	q := &quicServer{t: t, sockets: map[netip.AddrPort]*quicSocket{}, failed: map[netip.AddrPort]bool{}}
	q.srv = &http3.Server{Handler: http.HandlerFunc(q.serveHTTP), MaxHeaderBytes: proxyHeaderBytes,
		IdleTimeout: pageIdle, ConnContext: q.opened, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return q
}

type connKey struct{}

// opened readies c, a client's connection for one name: its proxies to the
// name's services, and its end once the name is withdrawn.
func (q *quicServer) opened(ctx context.Context, c *quic.Conn) context.Context {
	n, ok := q.t.lookup(c.ConnectionState().TLS.ServerName)
	if !ok {
		_ = c.CloseWithError(0, "")
		return ctx
	}
	peer := published.AddrPort(c.RemoteAddr()).Addr()
	q.t.byPeer.Add(c, memberKeyOf(n.Name, peer), func() { _ = c.CloseWithError(0, "") })
	context.AfterFunc(c.Context(), func() { q.t.byPeer.Remove(c) })
	if _, ok := q.t.admits(n.Name, peer); !ok {
		_ = c.CloseWithError(0, "")
		return ctx
	}
	px := q.t.proxiesFor(q.clientOf(published.AddrPort(c.RemoteAddr())), published.AddrPort(c.LocalAddr()))
	q.t.named.Add(c, nameKey{name: n.Name}, func() { _ = c.CloseWithError(0, "") })
	context.AfterFunc(c.Context(), func() {
		q.t.named.Remove(c)
		px.close()
	})
	if _, ok := q.t.lookup(n.Name); !ok {
		_ = c.CloseWithError(0, "") // no longer served
	}
	return context.WithValue(ctx, connKey{}, px)
}

// tlsConfig is QUIC's TLS: for a name offered HTTP/3 alone, so that a
// client of another falls back to TCP at once.
func (q *quicServer) tlsConfig(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	cfg := &tls.Config{GetCertificate: getCert, MinVersion: tls.VersionTLS13}
	return http3.ConfigureTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			if n, ok := q.t.lookup(h.ServerName); !ok || !HTTP3(n) {
				return nil, fmt.Errorf("terminator: %s is offered no HTTP/3 here", h.ServerName)
			}
			var peer netip.Addr
			if h.Conn != nil {
				peer = published.AddrPort(h.Conn.RemoteAddr()).Addr()
			}
			if _, ok := q.t.admits(h.ServerName, peer); !ok {
				return nil, errForMembers
			}
			return cfg, nil
		}})
}

// set has a socket at each of want and none elsewhere, where QUIC is
// served for the names on them.
func (q *quicServer) set(want map[netip.AddrPort]bool, tlsConf *tls.Config) {
	q.setMu.Lock()
	defer q.setMu.Unlock()
	for ap, s := range q.sockets {
		if !want[ap] {
			s.close()
			delete(q.sockets, ap)
		}
	}
	for ap := range q.failed {
		if !want[ap] {
			delete(q.failed, ap)
		}
	}
	for ap := range want {
		if q.sockets[ap] != nil {
			continue
		}
		s, err := q.open(ap, tlsConf)
		if err != nil {
			if !q.failed[ap] {
				q.failed[ap] = true
				q.t.o.Logf("terminator: no QUIC at %v: %v", ap, err)
			}
			continue
		}
		delete(q.failed, ap)
		q.sockets[ap] = s
		go func() { _ = q.srv.ServeListener(provingListener{Listener: s.ln, s: s}) }()
	}
	q.noteConns()
}

// noteConns has clientOf see the sockets set holds. setMu is held.
func (q *quicServer) noteConns() {
	conns := make([]*clientsConn, 0, len(q.sockets))
	for _, s := range q.sockets {
		conns = append(conns, s.pc)
	}
	q.conns.Store(&conns)
}

// open listens for QUIC at ap. A new client is to prove its address by a
// Retry first while many connections are open, which keeps spoofed
// addresses from costing more; 0-RTT is off, which could be replayed.
func (q *quicServer) open(ap netip.AddrPort, tlsConf *tls.Config) (*quicSocket, error) {
	pc, err := q.t.o.ListenPacket("udp", ap.String())
	if err != nil {
		return nil, err
	}
	cc := &clientsConn{ingresses: func() []netip.Addr { return q.t.now.Load().ingresses }}
	var open atomic.Int64
	tr := &quic.Transport{Conn: pc,
		VerifySourceAddress: func(net.Addr) bool { return open.Load() > retryPast },
		ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
			select {
			case q.t.conns <- struct{}{}:
			default:
				return nil, errors.New("terminator: too many connections")
			}
			open.Add(1)
			context.AfterFunc(ctx, func() {
				open.Add(-1)
				<-q.t.conns
			})
			return ctx, nil
		}}
	cc.listen(tr)
	ln, err := tr.Listen(tlsConf, &quic.Config{MaxIdleTimeout: quicIdle, InitialPacketSize: quicPacket,
		HandshakeIdleTimeout: helloTimeout})
	if err != nil {
		pc.Close()
		return nil, err
	}
	go cc.read(tr)
	return &quicSocket{pc: cc, tr: tr, ln: ln, conn: pc}, nil
}

func (s *quicSocket) close() {
	s.ln.Close()
	s.tr.Close()
	s.conn.Close()
}

// closeAll closes every socket.
func (q *quicServer) closeAll() {
	q.setMu.Lock()
	defer q.setMu.Unlock()
	for ap, s := range q.sockets {
		s.close()
		delete(q.sockets, ap)
	}
	q.noteConns()
	_ = q.srv.Close()
}

// serveHTTP serves a request that came over HTTP/3, for the name its
// connection's TLS asked for alone.
func (q *quicServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	name := ""
	if r.TLS != nil {
		name = r.TLS.ServerName
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	n, ok := q.t.lookup(name)
	switch {
	case !ok || !HTTP3(n):
		http.Error(w, "", http.StatusNotFound)
		return
	case !strings.EqualFold(strings.TrimSuffix(host, "."), n.Name):
		http.Error(w, "", http.StatusMisdirectedRequest)
		return
	}
	px, _ := r.Context().Value(connKey{}).(*connProxies)
	if px == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}
	q.t.serveName(w, r, n, px)
}

// clientOf is the client an ingress named for remote, a flow of its, or
// remote itself.
func (q *quicServer) clientOf(remote netip.AddrPort) netip.AddrPort {
	if conns := q.conns.Load(); conns != nil {
		for _, cc := range *conns {
			if c, ok := cc.client(remote); ok {
				return c
			}
		}
	}
	return remote
}

// clientsConn keeps the clients ingresses name on a QUIC socket: a datagram
// from an ingress that is a PROXY v2 header, which QUIC takes for none of
// its own, names the client of the flow it came from.
type clientsConn struct {
	ingresses func() []netip.Addr

	mu      sync.Mutex
	clients map[netip.AddrPort]named
}

type named struct {
	client netip.AddrPort
	at     time.Time
}

// listen has tr keep what it takes for no QUIC packet, which it drops until
// first asked for it; it is called before any client can send.
func (c *clientsConn) listen(tr *quic.Transport) {
	done, cancel := context.WithCancel(context.Background())
	cancel()
	buf := make([]byte, 2048)
	if n, from, err := tr.ReadNonQUICPacket(done, buf); err == nil {
		c.take(buf[:n], from)
	}
}

// read reads what tr takes for no QUIC packet until tr is closed.
func (c *clientsConn) read(tr *quic.Transport) {
	buf := make([]byte, 2048)
	for {
		n, from, err := tr.ReadNonQUICPacket(context.Background(), buf)
		if err != nil {
			return
		}
		c.take(buf[:n], from)
	}
}

func (c *clientsConn) take(d []byte, from net.Addr) {
	remote := published.AddrPort(from)
	if !proxyproto.IsHeader(d) || !containsAddr(c.ingresses(), remote.Addr()) {
		return // a member's header names no one
	}
	if client, err := proxyproto.ReadUDP(d); err == nil {
		c.note(remote, client)
	}
}

// note has flow name client, in place of what it named before: an
// ingress's flow socket is taken again by another flow. Past maxClients
// those unused for 2*quicIdle go, or else the least lately used.
func (c *clientsConn) note(flow, client netip.AddrPort) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.clients == nil {
		c.clients = map[netip.AddrPort]named{}
	}
	if _, ok := c.clients[flow]; !ok && len(c.clients) >= maxClients {
		var oldest netip.AddrPort
		at := time.Now()
		for k, v := range c.clients {
			switch {
			case time.Since(v.at) > 2*quicIdle:
				delete(c.clients, k)
			case v.at.Before(at):
				oldest, at = k, v.at
			}
		}
		if len(c.clients) >= maxClients {
			delete(c.clients, oldest)
		}
	}
	c.clients[flow] = named{client: client, at: time.Now()}
}

func (c *clientsConn) client(flow netip.AddrPort) (netip.AddrPort, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.clients[flow]
	if ok {
		n.at = time.Now()
		c.clients[flow] = n
	}
	return n.client, ok
}

func containsAddr(as []netip.Addr, a netip.Addr) bool {
	for _, b := range as {
		if b == a.Unmap() {
			return true
		}
	}
	return false
}
