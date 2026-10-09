package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http/httpproxy"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/discovery/dht"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/aead"
	"github.com/nning/juist/internal/terminator"
	"github.com/nning/juist/internal/underlay"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/relay"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// Bounds on what an HTTPS-only device asks of the relays on 443.
const (
	maxRendezvousRelays = 4
	rendezvousTimeout   = 20 * time.Second
)

// proxyFor is the proxy an HTTPS-only connection to host goes through.
func (d *Daemon) proxyFor(host string) (*url.URL, error) {
	return proxyRoute(d.proxy, d.envProxy)(host)
}

// proxyRoute is the proxy a connection to a host goes through: the one set,
// or HTTPS_PROXY's of juistd's environment, NO_PROXY applied.
func proxyRoute(set string, env func(*url.URL) (*url.URL, error)) func(host string) (*url.URL, error) {
	return func(host string) (*url.URL, error) {
		if set != "" {
			return url.Parse(set)
		}
		return env(&url.URL{Scheme: "https", Host: host})
	}
}

// httpsClient is how an HTTPS-only device speaks to relays' names: TLS on
// 443, verified by WebPKI, through the proxy where there is one.
func (d *Daemon) httpsClient() *http.Client {
	dialer := underlay.Dialer(10 * time.Second)
	return &http.Client{Timeout: rendezvousTimeout, Transport: &http.Transport{
		Proxy:               func(r *http.Request) (*url.URL, error) { return d.proxyFor(r.URL.Hostname()) },
		DialContext:         dialer.DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     time.Minute,
	}}
}

// httpsRelayNames are the names of the relays on 443 this device holds, the
// home relay's first.
func (d *Daemon) httpsRelayNames() []string {
	home := d.manager.HomeRelay()
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for _, r := range d.namedRelays {
		if r.Region == home {
			out = append([]string{r.Name}, out...)
		} else {
			out = append(out, r.Name)
		}
	}
	return out
}

// relayItems keeps this device's announcement, and finds the members', at the
// relays on 443, for an HTTPS-only device, which reaches no DHT.
type relayItems struct {
	d  *Daemon
	hc *http.Client
}

func (r *relayItems) Put(ctx context.Context, seed [32]byte, value []byte) error {
	names := r.d.httpsRelayNames()
	if len(names) == 0 {
		return errors.New("daemon: no relay on 443 to leave this device's announcement at")
	}
	names = names[:min(len(names), maxRendezvousRelays)]
	key := dht.ItemKey(seed)
	errs := make([]error, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Go(func() { errs[i] = relay.PutAnnouncement(ctx, r.hc, name, key, value) })
	}
	wg.Wait()
	if slices.Contains(errs, nil) {
		return nil
	}
	return errors.Join(errs...)
}

func (r *relayItems) Get(ctx context.Context, seed [32]byte) ([]byte, error) {
	names := r.d.httpsRelayNames()
	err := errors.New("daemon: no relay on 443 to ask")
	key := dht.ItemKey(seed)
	for _, name := range names[:min(len(names), maxRendezvousRelays)] {
		var v []byte
		if v, err = relay.GetAnnouncement(ctx, r.hc, name, key); err == nil {
			return v, nil
		}
	}
	return nil, err
}

func (r *relayItems) Close() error {
	r.hc.CloseIdleConnections()
	return nil
}

// rendezvousWindows are the windows a relay answers for: the current one and
// those either side, for clocks a little apart.
func rendezvousWindows(now time.Time) [3]uint64 {
	w := dht.Window(now)
	return [3]uint64{w - 1, w, w + 1}
}

// A rendezvousEntry is whose announcement a key is, under which epoch.
type rendezvousEntry struct {
	id    types.Identity
	epoch uint64
}

// rendezvousKeys maps every key a live member is published under, in the
// windows a relay answers for and every epoch this device holds, to whom it
// is: what a member's relay answers for, and nothing else. Rebuilt where the
// head, the epochs or the window moved.
type rendezvousKeys struct {
	mu     sync.Mutex
	head   types.Hash
	epochs []uint64
	window uint64
	keys   map[[32]byte]rendezvousEntry
}

func (d *Daemon) rendezvousKey(key [32]byte) (rendezvousEntry, bool) {
	state, err := d.TrustedState()
	if err != nil {
		return rendezvousEntry{}, false
	}
	now := d.now()
	windows := rendezvousWindows(now)
	epochs := d.keyring.Epochs()
	k := &d.rvKeys
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.keys == nil || k.head != state.Head() || k.window != windows[1] || !slices.Equal(k.epochs, epochs) {
		k.keys = map[[32]byte]rendezvousEntry{}
		for _, epoch := range epochs {
			secret, ok := d.keyring.Secret(epoch)
			if !ok {
				continue
			}
			for _, n := range state.Nodes() {
				if n.Expired(now.Unix()) {
					continue
				}
				for _, w := range windows {
					k.keys[dht.ItemKey(secret.TopicSeed(epoch, w, n.Identity))] = rendezvousEntry{n.Identity, epoch}
				}
			}
		}
		k.head, k.window, k.epochs = state.Head(), windows[1], epochs
	}
	e, ok := k.keys[key]
	return e, ok
}

// relayRendezvous answers the relay's rendezvous from what this device holds.
type relayRendezvous Daemon

// Get is the newest announcement held for the member key names, sealed under
// the key's epoch, as the member would have published it: this device holds
// it from log sync, so it hands out nothing the member's peers do not hold.
// It answers under the newest epoch alone, as members publish: a device
// removed since holds the older ones.
func (r *relayRendezvous) Get(key [32]byte) ([]byte, bool) {
	d := (*Daemon)(r)
	e, ok := d.rendezvousKey(key)
	if latest, _, held := d.keyring.Latest(); !ok || !held || e.epoch != latest {
		return nil, false
	}
	var ep gossip.Endpoint
	if e.id == d.self {
		if ep, ok = d.publishedAnnouncement(); !ok {
			return nil, false
		}
	} else if ep, ok = d.endpoints.Get(e.id); !ok {
		if d.dht != nil && d.dht.Public() {
			d.dht.Kick()
		}
		return nil, false
	}
	secret, ok := d.keyring.Secret(e.epoch)
	if !ok {
		return nil, false
	}
	sealed, err := dht.SealAnnouncement(secret, e.epoch, ep)
	if err != nil {
		return nil, false
	}
	return sealed, true
}

// Knows reports whether a member is published under key.
func (r *relayRendezvous) Knows(key [32]byte) bool {
	_, ok := (*Daemon)(r).rendezvousKey(key)
	return ok
}

// Put takes a member's announcement as one found in the DHT: sealed under an
// epoch this device holds, signed by the member key names, which the log
// lists.
func (r *relayRendezvous) Put(key [32]byte, sealed []byte) bool {
	d := (*Daemon)(r)
	e, ok := d.rendezvousKey(key)
	if !ok || e.id == d.self {
		return false
	}
	if epoch, err := aead.Epoch(sealed); err != nil || epoch != e.epoch {
		return false
	}
	ep, err := dht.OpenAnnouncement(d.keyring, sealed)
	if err != nil || ep.Identity != e.id {
		return false
	}
	d.discovered(ep, "at this device's relay")
	return true
}

// relayCertHello is how the relay's certificate is asked for ahead of any
// client, as one that takes ECDSA, which every client of the relay's does:
// asked otherwise, autocert would order an RSA certificate as well.
var relayCertHello = tls.ClientHelloInfo{
	CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
	SupportedCurves:  []tls.CurveID{tls.CurveP256},
}

// A certSource gives the relay's certificate for its public name.
type certSource interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// noCA is the certificate source where no ACME CA is set.
type noCA struct{}

func (noCA) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, errors.New("no ACME CA is set")
}

// newRelayCertificates is where the relay's certificate for its public name
// comes from: the ACME CA at dir, by TLS-ALPN-01, kept in path; none where
// dir is empty.
func newRelayCertificates(name, dir, path string) (certSource, error) {
	if dir == "" {
		return noCA{}, nil
	}
	var cache autocert.Cache
	if path != "" {
		cache = autocert.DirCache(path)
	}
	return terminator.NewManager(context.Background(), &acme.Client{DirectoryURL: dir}, cache, name)
}

// namedCertificate is the relay's certificate for its public name, noting
// why there is none. Without one, a client's handshake orders none until
// the next order is due: each would be an order, and a CA limits them.
func (d *Daemon) namedCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if relay.IsChallenge(h) || !strings.EqualFold(strings.TrimSuffix(h.ServerName, "."), d.relayName) {
		return d.relayCerts.GetCertificate(h)
	}
	if !takesECDSA(h) {
		// Every client of a relay's does; another key would be another order.
		return nil, errors.New("the relay serves an ECDSA certificate alone")
	}
	d.mu.Lock()
	why, held, due := d.relayNoCert, d.relayHasCert, d.relayCertDue
	d.mu.Unlock()
	if why != "" && !held && d.now().Before(due) {
		return nil, errors.New(why)
	}
	return d.orderRelayCertificate(h)
}

// takesECDSA reports whether h accepts an ECDSA P-256 certificate, as
// autocert judges it, which orders an RSA one for a client that does not.
func takesECDSA(h *tls.ClientHelloInfo) bool {
	if h.SignatureSchemes != nil && !slices.ContainsFunc(h.SignatureSchemes, func(s tls.SignatureScheme) bool {
		return s == tls.ECDSAWithP256AndSHA256 || s == tls.ECDSAWithP384AndSHA384 || s == tls.ECDSAWithP521AndSHA512 ||
			s == tls.ECDSAWithSHA1
	}) {
		return false
	}
	if h.SupportedCurves != nil && !slices.Contains(h.SupportedCurves, tls.CurveP256) {
		return false
	}
	return slices.ContainsFunc(h.CipherSuites, func(c uint16) bool {
		switch c {
		case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
			return true
		}
		return false
	})
}

// orderRelayCertificate asks for the relay's certificate, ordering one where
// none is held, and notes when to order again after a failure.
func (d *Daemon) orderRelayCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c, err := d.relayCerts.GetCertificate(h)
	d.mu.Lock()
	defer d.mu.Unlock()
	if err == nil {
		d.relayNoCert, d.relayHasCert, d.relayCertGap = "", true, 0
		return c, nil
	}
	d.relayNoCert = err.Error()
	d.relayCertGap = min(max(2*d.relayCertGap, certFirstGap), certMostGap)
	d.relayCertDue = d.now().Add(d.relayCertGap)
	return nil, err
}

// Gaps between orders of the relay's certificate while there is none, and
// between asking for it once there is: autocert renews it by itself.
const (
	certFirstGap = time.Minute
	certMostGap  = time.Hour
	certHeldGap  = 12 * time.Hour
	certWaitGap  = 10 * time.Second
)

// keepRelayCertificate has the relay's certificate ordered ahead of any
// client, while the relay runs, so the first member on 443 does not wait for
// it, and the status says why there is none.
func (d *Daemon) keepRelayCertificate(ctx context.Context) {
	for {
		wait := certWaitGap
		d.mu.Lock()
		due := d.relayCertDue
		d.mu.Unlock()
		if now := d.now(); d.isRelaying() && !now.Before(due) {
			hello := relayCertHello
			hello.ServerName = d.relayName
			octx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			err := d.orderRelayCertificateCtx(octx, &hello)
			cancel()
			switch {
			case err == nil:
				wait = certHeldGap
			case ctx.Err() != nil:
				return
			default:
				d.logf("daemon: no certificate for %s yet: %v", d.relayName, err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-d.closed:
			return
		case <-time.After(wait):
		}
	}
}

// orderRelayCertificateCtx is orderRelayCertificate bounded by ctx.
func (d *Daemon) orderRelayCertificateCtx(ctx context.Context, h *tls.ClientHelloInfo) error {
	done := make(chan error, 1)
	go func() {
		_, err := d.orderRelayCertificate(h)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// schemaRefusesRelayName says why the relay's name is not in its
// announcement, "" where it is: a network below the schema that has it,
// whose older members would refuse the announcement.
func schemaRefusesRelayName(state *log.State) string {
	if state.Schema() < types.SchemaRelayName {
		return fmt.Sprintf("the network is at %v; members learn the name from %v on", state.Schema(), types.SchemaRelayName)
	}
	return ""
}

// syncHTTPS has the relay take 443 itself, at each address of this host's
// members may reach it at, unless this device is the ingress, which holds
// 443 and hands the name's connections on. Bound by address, not on the
// wildcard, so the terminator keeps 443 of the overlay addresses.
func (d *Daemon) syncHTTPS(state *log.State, srv *relay.Server) {
	want := map[netip.Addr]bool{}
	ingress := false
	if srv != nil && d.relayName != "" && state != nil {
		self, _ := state.Node(d.self)
		ingress = self.HasRole(types.RoleIngress)
		if !ingress {
			scanned, _ := d.underlayEndpoints()
			for _, ap := range scanned {
				want[ap.Addr()] = true
			}
		}
	}
	d.mu.Lock()
	d.httpsHanded = ingress && srv != nil && d.relayName != ""
	var gone []net.Listener
	for a, ln := range d.https443 {
		if !want[a] {
			gone = append(gone, ln)
			delete(d.https443, a)
		}
	}
	var missing []netip.Addr
	for a := range want {
		if d.https443[a] == nil {
			missing = append(missing, a)
		}
	}
	d.mu.Unlock()
	for _, ln := range gone {
		ln.Close()
	}
	var errs []string
	for _, a := range missing {
		ln, err := d.listenHTTPS(a)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		d.mu.Lock()
		if d.relay != srv || d.https443 == nil {
			d.mu.Unlock()
			ln.Close()
			continue
		}
		d.https443[a] = ln
		d.mu.Unlock()
		srv.ServeHTTPS(ln)
		d.logf("daemon: relaying as %s on %v", d.relayName, ln.Addr())
	}
	d.mu.Lock()
	d.httpsErr = strings.Join(errs, "; ")
	d.mu.Unlock()
}

// handingOn reports whether the ingress here hands the relay's name on, whose
// PROXY header alone the relay then reads from loopback.
func (d *Daemon) handingOn() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.httpsHanded
}

// closeHTTPS gives 443 back.
func (d *Daemon) closeHTTPS() {
	d.mu.Lock()
	held := d.https443
	d.https443 = map[netip.Addr]net.Listener{}
	d.httpsHanded, d.httpsErr = false, ""
	d.mu.Unlock()
	for _, ln := range held {
		ln.Close()
	}
}

// defaultListenHTTPS binds 443/tcp at a, which needs CAP_NET_BIND_SERVICE
// or root.
func defaultListenHTTPS(a netip.Addr) (net.Listener, error) {
	return net.Listen("tcp", netip.AddrPortFrom(a, conn.HTTPSPort).String())
}

// httpsNow is this device's use of 443 for the status; relays are those
// installed.
func (d *Daemon) httpsNow(relays []conn.Relay) *ipc.HTTPS {
	if !d.httpsOnly && d.relayName == "" {
		return nil
	}
	h := &ipc.HTTPS{Only: d.httpsOnly, Name: d.relayName}
	if d.httpsOnly {
		if d.proxy != "" {
			h.Proxy = ipc.RedactProxy(d.proxy)
		} else if u, err := d.envProxy(&url.URL{Scheme: "https", Host: "relay.invalid"}); err == nil && u != nil {
			h.Proxy = ipc.RedactProxy(u.String())
		}
	}
	for _, r := range relays {
		if r.Name != "" {
			h.Relays = append(h.Relays, r.Name)
		}
	}
	slices.Sort(h.Relays)
	if d.relayName == "" {
		return h
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	h.NotAnnounced = d.relayNameRefused
	if d.relay == nil {
		h.NotAnnounced = "this device does not relay"
	}
	if d.httpsHanded {
		h.Listening = []string{ipc.HandedOn}
	}
	for _, ln := range d.https443 {
		h.Listening = append(h.Listening, ln.Addr().String())
	}
	slices.Sort(h.Listening)
	h.ListenError = d.httpsErr
	switch {
	case d.relay == nil:
	case d.relayNoCert != "":
		h.NoCert = d.relayNoCert
	case !d.relayHasCert:
		h.NoCert = "not yet ordered"
	}
	return h
}

// envProxyFunc reads HTTPS_PROXY and NO_PROXY once.
func envProxyFunc() func(*url.URL) (*url.URL, error) { return httpproxy.FromEnvironment().ProxyFunc() }
