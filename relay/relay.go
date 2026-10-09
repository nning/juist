// Package relay runs a member's embedded DERP relay: the fallback path for
// pairs whose NATs cannot be punched, and the sideband over which off-LAN
// endpoints are exchanged.
//
// It is not trust-critical. A relay sees node keys and ciphertext and nothing
// else — WireGuard authenticates and encrypts end to end below it — so the
// worst a hostile relay can do is drop traffic and observe who talks to whom.
// What it must still enforce is that only members may use it, since it is a
// member's own bandwidth being volunteered.
package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"

	"github.com/nning/juist/relay/forward"
)

// Options configures a [Server].
type Options struct {
	// Admit reports whether a WireGuard public key belongs to a live member.
	// It is the whole of the relay's access control, consulted on every client
	// connection and on every [Server.Reauthorize]. A nil Admit is refused:
	// defaulting it to "yes" would turn a configuration slip into an open
	// relay.
	//
	// The key is the raw form the log records, so the caller answers from
	// membership state without naming the data plane's types.
	Admit func(wireGuard [32]byte) bool

	// Port is the TCP port DERP is served on and the UDP port STUN answers
	// on. Zero picks one, and both end up on the same number.
	Port uint16

	// Listener, when set, is used for DERP instead of binding Port. Tests
	// pass a loopback listener; STUN is then bound on its own port.
	Listener net.Listener

	// DisableSTUN turns the reflexive-address responder off, leaving the
	// relay as a pure DERP node.
	DisableSTUN bool

	// Certificate is the TLS identity to serve. Nil draws a fresh one.
	Certificate *Certificate

	// AdmitHost reports whether an identity key belongs to a live member,
	// which may then wait here for the guest of an invite (see forward.go).
	// Nil forwards no invites.
	AdmitHost func(identity [32]byte) bool

	// Logf receives diagnostics. Nil discards them.
	Logf logger.Logf
}

// A Server is one member's relay: a DERP server over TLS with a pinned
// self-signed certificate, and a STUN responder that tells a member its own
// reflexive address without asking a third party.
//
// The DERP identity key is drawn fresh each time a server starts, and so is
// the TLS certificate unless [Options.Certificate] passes one: both are
// connectivity material, and the certificate hash travels in the signed
// announcement that points members here, so a new one re-pins rather than
// breaking — once members hold the new announcement.
type Server struct {
	logf   logger.Logf
	derp   *derpserver.Server
	http   *http.Server
	ln     net.Listener
	stun   *stunResponder
	cert   *selfSigned
	admit  func([32]byte) bool
	fwd    *forwarder
	token  string
	closed chan struct{}

	// clients tracks live DERP connections by the node key that was admitted
	// on them, so that a member removed from the log loses the connection it
	// already holds and not merely the right to open another.
	mu      sync.Mutex
	clients map[*client]struct{}
}

// client is one live DERP connection and the key it was admitted under.
type client struct {
	nodeKey key.NodePublic
	conn    net.Conn
}

// New starts a relay. The caller owns it until [Server.Close].
func New(opts Options) (*Server, error) {
	if opts.Admit == nil {
		return nil, errors.New("relay: Admit is required")
	}
	logf := opts.Logf
	if logf == nil {
		logf = logger.Discard
	}

	ln := opts.Listener
	if ln == nil {
		var err error
		ln, err = net.Listen("tcp", fmt.Sprintf(":%d", opts.Port))
		if err != nil {
			return nil, fmt.Errorf("relay: listening for DERP: %w", err)
		}
	}
	port := uint16(0)
	if ta, ok := ln.Addr().(*net.TCPAddr); ok {
		port = uint16(ta.Port)
	}

	var cert *selfSigned
	if opts.Certificate != nil {
		cert = opts.Certificate.s
	} else {
		c, err := NewCertificate()
		if err != nil {
			ln.Close()
			return nil, err
		}
		cert = c.s
	}

	s := &Server{
		logf:    logf,
		ln:      ln,
		cert:    cert,
		admit:   opts.Admit,
		closed:  make(chan struct{}),
		clients: map[*client]struct{}{},
	}

	if !opts.DisableSTUN {
		// The same number as DERP where it is free, so that one port
		// travels in the announcement and an operator has one hole to
		// open. A port that is taken is not fatal: the relay still
		// relays, it just does not reflect.
		st, err := listenSTUN(port, logf)
		if err != nil {
			logf("relay: no STUN responder: %v", err)
		} else {
			s.stun = st
		}
	}

	// A key of its own rather than this member's WireGuard key: the same
	// static key would be used both to terminate DERP's client handshake and
	// as a WireGuard identity, and this node is a client of its own relay.
	s.derp = derpserver.New(key.NewNode(), logf)
	s.token = admissionToken()
	s.derp.SetVerifyClientURL(admissionURL(s.token))
	// Stated rather than left to the zero value: failing open here would
	// admit every non-member the moment the hook errored.
	s.derp.SetVerifyClientURLFailOpen(false)
	registerAdmission(s.token, s)

	mux := http.NewServeMux()
	h := s.track(http.HandlerFunc(s.serveDERP))
	// Both patterns: "/derp" is the connection endpoint and "/derp/..." the
	// latency probes a client's netcheck uses.
	mux.Handle("/derp", h)
	mux.Handle("/derp/", h)
	if opts.AdmitHost != nil {
		s.fwd = newForwarder(opts.AdmitHost, cert.sha256, logf)
		mux.HandleFunc(forward.HostPath, s.fwd.serveHost)
		mux.HandleFunc(forward.GuestPath, s.fwd.serveGuest)
	}
	s.http = &http.Server{
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert.tls}, MinVersion: tls.VersionTLS12},
		// The connection a request arrived on, so that a client admitted on
		// it can be dropped later. Nothing else can reach it: a DERP session
		// hijacks the connection and the server stops tracking it.
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey{}, c)
		},
		ErrorLog:          newServerErrorLog(logf, time.Now),
		ReadHeaderTimeout: 30 * time.Second,
		// A connection kept alive after one request, which anyone can open,
		// is not kept for ever. DERP sessions and forwarded invites are
		// taken over from the server and outlive this.
		IdleTimeout: 30 * time.Second,
	}

	go func() {
		err := s.http.ServeTLS(ln, "", "")
		select {
		case <-s.closed:
		default:
			logf("relay: DERP server stopped: %v", err)
		}
	}()
	return s, nil
}

// rawNodeKey is a client's WireGuard public key in the form the membership log
// records it. AppendTo is the serialization the DERP wire format itself uses,
// and unlike Raw32 it is not deprecated.
func rawNodeKey(k key.NodePublic) [32]byte {
	return [32]byte(k.AppendTo(make([]byte, 0, 32)))
}

// Context keys: the accepted connection, and the record the admission hook
// fills in for it.
type (
	connContextKey   struct{}
	clientContextKey struct{}
)

// track gives each request a record the admission hook can fill in, and drops
// it when the handler returns. For a DERP session the handler returns when the
// session ends, so that is the connection's lifetime — where the admission
// request's own context is not, since the hook cancels it as soon as it has an
// answer.
func (s *Server) track(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Context().Value(connContextKey{}).(net.Conn)
		rec := &client{conn: c}
		defer func() {
			s.mu.Lock()
			delete(s.clients, rec)
			s.mu.Unlock()
		}()
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientContextKey{}, rec)))
	})
}

// serveDERP is derpserver.Handler with the session kept on the request's
// goroutine and context, which carry the record the admission hook fills in.
// Upstream's detaches both, so its sessions are admitted with no record.
func (s *Server) serveDERP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/derp/probe", "/derp/latency-check":
		derpserver.ProbeHandler(w, r)
		return
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "derp") {
		http.Error(w, "DERP requires connection upgrade", http.StatusUpgradeRequired)
		return
	}
	nc, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "the connection cannot be taken over", http.StatusInternalServerError)
		return
	}
	if r.Header.Get(derp.FastStartHeader) != "1" {
		nc.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := fmt.Fprintf(nc, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: DERP\r\n"+
			"Connection: Upgrade\r\n"+
			"Derp-Version: %v\r\n"+
			"Derp-Public-Key: %s\r\n\r\n",
			derp.ProtocolVersion, s.derp.PublicKey().UntypedHexString()); err != nil {
			nc.Close()
			return
		}
	}
	s.derp.Accept(r.Context(), nc, brw, nc.RemoteAddr().String())
}

// Port reports the TCP port DERP is served on, which is what members put in
// their DERP map.
func (s *Server) Port() uint16 {
	if ta, ok := s.ln.Addr().(*net.TCPAddr); ok {
		return uint16(ta.Port)
	}
	return 0
}

// STUNPort reports the UDP port the reflexive-address responder answers on,
// or zero if there is none.
func (s *Server) STUNPort() uint16 {
	if s.stun == nil {
		return 0
	}
	return s.stun.port()
}

// CertHash returns the SHA-256 of the relay's TLS certificate. Members carry
// it in their announcement and pin it, which is what authenticates the relay
// without a certificate authority.
func (s *Server) CertHash() [32]byte { return s.cert.sha256 }

// HostName is the name the certificate is issued for, and the one a member
// must use as the TLS server name. It is derived from the certificate, never
// resolved: a member reaches a relay at the addresses its announcement
// carries.
func (s *Server) HostName() string { return s.cert.hostName }

// Connected reports whether a member with this WireGuard key holds a
// connection to the relay.
func (s *Server) Connected(wireGuard [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.clients {
		if rawNodeKey(c.nodeKey) == wireGuard {
			return true
		}
	}
	return false
}

// Reauthorize closes the connections of clients Admit no longer accepts. A
// removed member otherwise keeps the connection it already holds, since the
// admission check runs when a connection is opened and never again.
//
// Admit is asked without the relay's lock held: it may take a lock of its
// own under which the caller asks [Server.Connected].
func (s *Server) Reauthorize() {
	s.mu.Lock()
	held := make([]*client, 0, len(s.clients))
	for c := range s.clients {
		held = append(held, c)
	}
	s.mu.Unlock()
	var doomed []*client
	for _, c := range held {
		if !s.admit(rawNodeKey(c.nodeKey)) {
			doomed = append(doomed, c)
		}
	}
	for _, c := range doomed {
		s.logf("relay: dropping %v, which is no longer a member", c.nodeKey.ShortString())
		c.conn.Close()
	}
	if s.fwd != nil {
		s.fwd.reauthorize()
	}
}

// Clients reports how many DERP clients are connected. Diagnostics only.
func (s *Server) Clients() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients)
}

// Close shuts the relay down. It is idempotent.
func (s *Server) Close() error {
	select {
	case <-s.closed:
		return nil
	default:
	}
	close(s.closed)
	unregisterAdmission(s.token)
	err := s.http.Close()
	if s.fwd != nil {
		s.fwd.close()
	}
	s.derp.Close()
	if s.stun != nil {
		s.stun.close()
	}
	return err
}

// admitRequest answers one admission question, and records the connection it
// came in on so [Server.Reauthorize] can reach it later.
func (s *Server) admitRequest(ctx context.Context, nodeKey key.NodePublic) bool {
	if !s.admit(rawNodeKey(nodeKey)) {
		return false
	}
	c, _ := ctx.Value(clientContextKey{}).(*client)
	if c == nil || c.conn == nil {
		// Unreachable while this server owns its http.Server. Admitting
		// without a record would leave a client Reauthorize can never drop,
		// which is the half of the criterion admission alone does not reach.
		s.logf("relay: refusing %v: the connection carries no record, so it could never be dropped",
			nodeKey.ShortString())
		return false
	}
	c.nodeKey = nodeKey
	s.mu.Lock()
	s.clients[c] = struct{}{}
	s.mu.Unlock()
	return true
}

// localAddrs reports where the relay's own listener is bound. A member
// advertises the addresses of its endpoint announcement instead, so this
// exists for the tests, which bind loopback.
func (s *Server) localAddrs() []netip.AddrPort {
	ta, ok := s.ln.Addr().(*net.TCPAddr)
	if !ok {
		return nil
	}
	ap := ta.AddrPort()
	return []netip.AddrPort{netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}
}
