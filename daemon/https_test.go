package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/discovery/dht"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/relay"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

const testRelayName = "relay.example.org"

// bound records where a relay took 443, on loopback listeners in its place.
type bound struct {
	mu    sync.Mutex
	addrs []netip.Addr
}

func (b *bound) listen(a netip.Addr) (net.Listener, error) {
	b.mu.Lock()
	b.addrs = append(b.addrs, a)
	b.mu.Unlock()
	return net.Listen("tcp", "127.0.0.1:0")
}

func (b *bound) took() []netip.Addr {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.addrs)
}

// namedRelayFixture is a member granted the relay role whose operator named
// its relay, in a network founded at schema.
func namedRelayFixture(t *testing.T, schema types.SchemaVersion) (*reconcileFixture, *bound) {
	t.Helper()
	nw := newNetworkMutated(t, 3, func(nw *network) { nw.schema = schema })
	b := &bound{}
	f := newReconcileFixtureOn(t, nw, func(o *Options) {
		o.RelayName, o.ListenHTTPS = testRelayName, b.listen
		o.HandOffSocket, o.IngressUID = filepath.Join(t.TempDir(), "relay.sock"), uint32(os.Getuid())
	})
	nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)
	if !f.d.Status().Relaying {
		t.Fatal("the grant did not start the relay")
	}
	return f, b
}

// A relay's name enters its announcement once the network is at the schema
// every member then reads it at: before, an older member would refuse the
// whole announcement, and the relay with it.
func TestARelaysNameIsAnnouncedFromItsSchema(t *testing.T) {
	f, _ := namedRelayFixture(t, types.SchemaTCP)
	e, ok := f.d.Announcement()
	if !ok || e.Relay == nil || e.Relay.Name != "" {
		t.Fatalf("at %v the announcement's relay is %+v", types.SchemaTCP, e.Relay)
	}
	if h := f.d.Status().HTTPS; h == nil || !strings.Contains(h.NotAnnounced, "schema 11") {
		t.Errorf("the status does not say why the name is not announced: %+v", h)
	}
	up, err := f.auth.Builder().SchemaUpgrade(types.SchemaRelayName)
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{up}); err != nil {
		t.Fatal(err)
	}
	e, ok = f.d.Announcement()
	if !ok || e.Relay == nil || e.Relay.Name != testRelayName {
		t.Fatalf("at %v the announcement's relay is %+v", types.SchemaRelayName, e.Relay)
	}
	if err := e.Verify(); err != nil {
		t.Fatal(err)
	}
	if h := f.d.Status().HTTPS; h == nil || h.NotAnnounced != "" || h.Name != testRelayName {
		t.Errorf("the status says %+v", h)
	}
}

// The relay takes 443 at this host's own addresses, each by itself so the
// terminator keeps the overlay's; once the device is the ingress, which
// holds 443, it gives them back and the ingress hands the name on to it, at
// a socket only the ingress's user is answered at.
func TestTheRelayTakes443UnlessTheIngressDoes(t *testing.T) {
	f, b := namedRelayFixture(t, types.CurrentSchema)
	scanned, _ := f.d.underlayEndpoints()
	if len(scanned) == 0 {
		t.Skip("this host has no address a member could reach")
	}
	took := b.took()
	for _, ap := range scanned {
		if !slices.Contains(took, ap.Addr()) {
			t.Errorf("443 not taken at %v; took %v", ap.Addr(), took)
		}
	}
	for _, a := range took {
		if a.IsLoopback() || f.d.ula.Contains(a) || types.IsOverlayV4(a) {
			t.Errorf("443 taken at %v, which is no address of the host's to members", a)
		}
	}
	h := f.d.Status().HTTPS
	if h == nil || len(h.Listening) != len(scanned) || h.ListenError != "" {
		t.Fatalf("the status says %+v", h)
	}
	if p := f.d.Published(); len(p.Relays) != 0 {
		t.Errorf("a device that is no ingress hands its relay on: %+v", p.Relays)
	}

	if os.Getuid() == 0 {
		t.Skip("as root, there is no ingress user to tell apart")
	}
	f.nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable, types.RoleIngress)
	if h := f.d.Status().HTTPS; h == nil || !slices.Equal(h.Listening, []string{ipc.HandedOn}) {
		t.Fatalf("as the ingress, the status says %+v", h)
	}
	f.d.mu.Lock()
	held, socket := len(f.d.https443), f.d.handOffPath
	f.d.mu.Unlock()
	if held != 0 {
		t.Errorf("the relay holds %d sockets on 443 beside the ingress", held)
	}
	p := f.d.Published()
	if len(p.Relays) != 1 || p.Relays[0].Name != testRelayName || p.Relays[0].Socket != socket ||
		len(p.Relays[0].Addrs) != 0 || !p.Relays[0].Proxy {
		t.Errorf("the ingress is handed %+v, want %s at %s", p.Relays, testRelayName, socket)
	}
	if fi, err := os.Stat(socket); err != nil || fi.Mode().Type() != os.ModeSocket {
		t.Fatalf("no hand-off socket: %v", err)
	}
	// Not before the relay takes the ingress's connections there.
	f.d.mu.Lock()
	f.d.httpsHanded = false
	f.d.mu.Unlock()
	if p := f.d.Published(); len(p.Relays) != 0 {
		t.Errorf("handed on before the relay takes the ingress's connections: %+v", p.Relays)
	}
	f.d.mu.Lock()
	f.d.httpsHanded = true
	f.d.mu.Unlock()

	f.nw.setRoles(t, f, f.self.record.Identity)
	if h := f.d.Status().HTTPS; h == nil || len(h.Listening) != 0 {
		t.Errorf("no longer relaying, the status says %+v", h)
	}
	if _, err := os.Stat(socket); err == nil {
		t.Error("the hand-off socket outlived the relay")
	}
	if p := f.d.Published(); len(p.Relays) != 0 {
		t.Errorf("no longer relaying, the ingress is handed %+v", p.Relays)
	}
}

// rendezvousKeyOf is where member id is published under the newest epoch the
// relay holds, in the window of now.
func rendezvousKeyOf(t *testing.T, f *reconcileFixture, id types.Identity) (uint64, [32]byte) {
	t.Helper()
	epoch, secret, ok := f.d.keyring.Latest()
	if !ok {
		t.Fatal("the relay holds no epoch secret")
	}
	return epoch, dht.RendezvousKey(secret.TopicSeed(epoch, dht.Window(time.Now()), id))
}

// A relay answers for the members of its network alone, with what it holds
// of them sealed as they publish it, and takes a member's announcement as
// one found in the DHT, but no other member's under its key, nor one sealed
// under another epoch.
func TestTheRendezvousAnswersForMembersAlone(t *testing.T) {
	f, _ := namedRelayFixture(t, types.CurrentSchema)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	rv := (*relayRendezvous)(f.d)
	one, two := f.nw.devices[1], f.nw.devices[2]
	held := f.learn(t, one, 41641)
	epoch, keyOne := rendezvousKeyOf(t, f, one.record.Identity)
	sealed, ok := rv.Get(keyOne)
	if !ok {
		t.Fatal("the relay answers nothing for a member it holds")
	}
	got, err := dht.OpenAnnouncement(f.d.keyring, sealed)
	if err != nil || got.Identity != one.record.Identity || got.Seq != held.Seq {
		t.Fatalf("the relay answered %+v, %v", got, err)
	}
	if _, ok := rv.Get([32]byte{1, 2, 3}); ok {
		t.Error("the relay answers for a key no member is published under")
	}
	_, keyTwo := rendezvousKeyOf(t, f, two.record.Identity)
	if _, ok := rv.Get(keyTwo); ok {
		t.Error("the relay answers for a member it holds nothing of")
	}
	_, keySelf := rendezvousKeyOf(t, f, f.self.record.Identity)
	if sealed, ok := rv.Get(keySelf); !ok {
		t.Error("the relay does not answer for itself")
	} else if own, err := dht.OpenAnnouncement(f.d.keyring, sealed); err != nil || own.Identity != f.self.record.Identity {
		t.Errorf("for itself, the relay answered %+v, %v", own, err)
	}

	secret, _ := f.d.keyring.Secret(epoch)
	announce := func(dev *device, seq uint64) gossip.Endpoint {
		_, disco, err := conn.NewDiscoKey()
		if err != nil {
			t.Fatal(err)
		}
		e := gossip.Endpoint{Identity: dev.record.Identity, Disco: gossip.DiscoKey(disco), GossipPort: 41644, Seq: seq,
			HomeRelay: 7}
		if err := e.Sign(dev.identity); err != nil {
			t.Fatal(err)
		}
		return e
	}
	seal := func(e gossip.Endpoint) []byte {
		b, err := dht.SealAnnouncement(secret, epoch, e)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if rv.Put(keyOne, seal(announce(two, 5))) {
		t.Error("the relay took a member's announcement under another member's key")
	}
	if rv.Put([32]byte{1, 2, 3}, seal(announce(two, 5))) {
		t.Error("the relay took an announcement under a key no member is published under")
	}
	if other, err := dht.SealAnnouncement(secret, epoch+1, announce(two, 5)); err == nil && rv.Put(keyTwo, other) {
		t.Error("the relay took an announcement sealed under an epoch it does not hold")
	}
	if rv.Put(keySelf, seal(announce(f.self, 5))) {
		t.Error("the relay took its own announcement from a client")
	}
	if !rv.Put(keyTwo, seal(announce(two, 5))) {
		t.Fatal("the relay refused a member's announcement under its key")
	}
	if e, ok := f.d.endpoints.Get(two.record.Identity); !ok || e.Seq != 5 || e.HomeRelay != 7 {
		t.Errorf("the relay holds %+v for the member", e)
	}

	// A device removed since holds the older epochs, under which the relay
	// answers nothing, as members publish under the newest alone.
	f.d.keyring.Adopt(epoch+1, secrets.Secret{9})
	if _, ok := rv.Get(keyOne); ok {
		t.Error("the relay answers under an epoch older than its newest")
	}
	_, keyNewer := rendezvousKeyOf(t, f, one.record.Identity)
	if _, ok := rv.Get(keyNewer); !ok {
		t.Error("the relay answers nothing under its newest epoch")
	}
	if known, current := rv.Knows(keyOne); !known || current {
		t.Errorf("a key under an older epoch: known %v, current %v", known, current)
	}
	if known, current := rv.Knows(keyNewer); !known || !current {
		t.Errorf("a key under the newest epoch: known %v, current %v", known, current)
	}
}

// The key a relay answers under is none a DHT message carries: an item's
// public key is in every put and get of it, so a stranger watching the DHT
// would learn it and could ask the relay.
func TestTheRendezvousKeyIsNoneTheDHTShows(t *testing.T) {
	f, _ := namedRelayFixture(t, types.CurrentSchema)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	rv := (*relayRendezvous)(f.d)
	one := f.nw.devices[1]
	f.learn(t, one, 41641)
	epoch, secret, _ := f.d.keyring.Latest()
	seed := secret.TopicSeed(epoch, dht.Window(time.Now()), one.record.Identity)
	shown := [32]byte(ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey))
	if known, _ := rv.Knows(shown); known {
		t.Error("the relay knows the key the DHT shows")
	}
	if _, ok := rv.Get(shown); ok {
		t.Error("the relay answers under the key the DHT shows")
	}
	if _, ok := rv.Get(dht.RendezvousKey(seed)); !ok {
		t.Error("the relay answers nothing under the rendezvous key")
	}
}

// A device on HTTPS alone announces no address, which nothing reaches but
// through a relay, looks for members at the relays on 443 rather than in the
// DHT, and searches no LAN.
func TestHTTPSAloneAnnouncesNoAddressAndUsesTheRelays(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := newReconcileFixtureWith(t, 2, func(o *Options) {
		o.HTTPSOnly, o.TunName, o.GossipListener = true, "vpn0", ln
		o.DisableDiscovery, o.DisableDHT = false, false
		o.HostDNS = noHostDNS{}
		o.ServeDNS = func([]netip.Addr, func(netip.Addr) bool) (io.Closer, error) { return io.NopCloser(nil), nil }
		o.ServeNames = func(netip.AddrPort, func([]byte) []byte, func([]byte) []netip.AddrPort) (io.Closer, error) {
			return io.NopCloser(nil), nil
		}
	})
	e, ok := f.d.Announcement()
	if !ok || len(e.Addrs) != 0 {
		t.Fatalf("the announcement names %v", e.Addrs)
	}
	if f.d.beacon != nil {
		t.Error("a device on HTTPS alone searches the LAN")
	}
	if f.d.dht == nil || f.d.dht.Public() {
		t.Error("a device on HTTPS alone does not look for members at the relays")
	}
	if d, err := New(Options{Authority: f.auth, Storage: f.storage, Identity: f.self.identity,
		Recipient: f.self.recipient, WireGuard: f.self.wgPrivate, HTTPSOnly: true,
		Connect: func(conn.Options) (conn.Manager, error) { return &fakeManager{}, nil }}); err == nil {
		d.Close()
		t.Error("HTTPS alone started without a device, where log sync has no tunnel to run in")
	}
}

// noHostDNS routes nothing of the host's.
type noHostDNS struct{}

func (noHostDNS) Route(DNSRouting) error { return nil }
func (noHostDNS) Revert() error          { return nil }

// The device's settings of 443 are kept across a restart and shown, the
// proxy's password not; HTTPS alone is refused where log sync would have no
// tunnel to run in.
func TestSettingsOf443AreKeptAndShown(t *testing.T) {
	f := newServiceFixture(t, true)
	on := true
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdSettings, HTTPSOnly: &on}); err == nil ||
		!strings.Contains(err.Error(), `--tun ""`) {
		t.Errorf("HTTPS alone without a device: %v", err)
	}
	name, proxy := testRelayName, "http://user:secret@proxy.example:3128"
	resp, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdSettings, RelayName: &name, Proxy: &proxy})
	if err != nil {
		t.Fatal(err)
	}
	h := resp.Status.HTTPS
	if h == nil || h.Name != name {
		t.Fatalf("the status says %+v", h)
	}
	for _, file := range []string{statedir.ProxyFile, statedir.RelayNameFile} {
		fi, err := os.Stat(filepath.Join(f.home, file))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v, %v", file, fi, err)
		}
	}
	bad := "ftp://proxy.example"
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdSettings, Proxy: &bad}); err == nil {
		t.Error("a proxy that is no HTTP URL was taken")
	}
	f.s.Close()
	g := startServiceWith(t, f.nw, f.home, func(o *Options) { o.TunName = "vpn0" })
	resp, err = ipc.Call(g.sock, ipc.Request{Command: ipc.CmdStatus})
	if err != nil {
		t.Fatal(err)
	}
	if h := resp.Status.HTTPS; h == nil || h.Name != name {
		t.Fatalf("after a restart, the status says %+v", h)
	}
	g.s.mu.Lock()
	kept := g.s.proxy
	g.s.mu.Unlock()
	if kept != proxy {
		t.Errorf("the proxy kept is %q", kept)
	}
	if resp, err = ipc.Call(g.sock, ipc.Request{Command: ipc.CmdSettings, HTTPSOnly: &on}); err != nil {
		t.Fatal(err)
	}
	if h := resp.Status.HTTPS; h == nil || !h.Only || strings.Contains(h.Proxy, "secret") ||
		h.Proxy != "http://user:xxxxx@proxy.example:3128" {
		t.Errorf("HTTPS alone, the status says %+v", h)
	}
	none := ""
	if _, err := ipc.Call(g.sock, ipc.Request{Command: ipc.CmdSettings, RelayName: &none, Proxy: &none}); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{statedir.ProxyFile, statedir.RelayNameFile} {
		if _, err := os.Stat(filepath.Join(f.home, file)); !os.IsNotExist(err) {
			t.Errorf("%s stayed: %v", file, err)
		}
	}
}

// countingCA fails every order, counting them.
type countingCA struct {
	mu     sync.Mutex
	orders int
	issued int // orders that succeed first
}

func (c *countingCA) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.orders++
	if c.orders <= c.issued {
		return &tls.Certificate{}, nil
	}
	return nil, errors.New("the CA refused")
}

func (c *countingCA) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.orders
}

// A client's handshake for the relay's name orders no certificate, where
// none is held: the relay does, not again before the next order is due, the
// gap doubling. A CA limits orders, and a handshake would wait on one.
func TestARelayOrdersItsCertificateSparingly(t *testing.T) {
	f, _ := namedRelayFixture(t, types.CurrentSchema)
	now := time.Now()
	f.d.clock = func() time.Time { return now }
	ca := &countingCA{}
	f.d.relayCerts = ca
	hello := ecdsaHello()
	for range 5 {
		if _, err := f.d.namedCertificate(hello); err == nil {
			t.Fatal("a certificate came where none is held")
		}
	}
	if n := ca.count(); n != 0 {
		t.Fatalf("handshakes ordered %d certificates", n)
	}
	ctx := t.Context()
	f.d.orderIfDue(ctx)
	f.d.orderIfDue(ctx)
	if n := ca.count(); n != 1 {
		t.Fatalf("%d orders within the first gap", n)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if h := f.d.Status().HTTPS; h == nil || h.NoCert != "the CA refused" {
		t.Errorf("the status says %+v", h)
	}
	if _, err := f.d.namedCertificate(hello); err == nil || err.Error() != "the CA refused" {
		t.Errorf("a client is told %v", err)
	}
	now = now.Add(certFirstGap)
	f.d.orderIfDue(ctx)
	if n := ca.count(); n != 2 {
		t.Fatalf("%d orders after the first gap", n)
	}
	now = now.Add(certFirstGap)
	if f.d.orderIfDue(ctx); ca.count() != 2 {
		t.Error("the gap did not double")
	}
	challenge := &tls.ClientHelloInfo{ServerName: testRelayName, SupportedProtos: []string{acme.ALPNProto}}
	f.d.namedCertificate(challenge)
	if ca.count() != 3 {
		t.Error("a CA's challenge waited for the next order")
	}
	// Offering the challenge's protocol beside another is no challenge.
	posing := &tls.ClientHelloInfo{ServerName: testRelayName, SupportedProtos: []string{acme.ALPNProto, "http/1.1"}}
	f.d.namedCertificate(posing)
	if ca.count() != 3 {
		t.Error("a handshake posing as a challenge ordered")
	}
}

// Once a certificate is held, an order that fails for another client, as an
// RSA one autocert orders anew, locks out none: the held one is asked for.
func TestAFailedOrderLocksNoClientOutOfAHeldCertificate(t *testing.T) {
	f, _ := namedRelayFixture(t, types.CurrentSchema)
	ca := &countingCA{issued: 1}
	f.d.relayCerts = ca
	hello := ecdsaHello()
	f.d.orderIfDue(t.Context())
	f.d.namedCertificate(hello)
	f.d.namedCertificate(hello)
	if n := ca.count(); n != 3 {
		t.Errorf("%d asks, want each handshake to ask for the certificate held", n)
	}
}

// ecdsaHello is a client's hello for the relay's name, as Go's and browsers'.
func ecdsaHello() *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{ServerName: testRelayName, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}, SupportedCurves: []tls.CurveID{tls.X25519, tls.CurveP256}}
}

// A hello taking no ECDSA certificate orders nothing, though one is held:
// autocert would order an RSA certificate for it, and anyone can send one.
func TestAHelloWithoutECDSAOrdersNothing(t *testing.T) {
	f, _ := namedRelayFixture(t, types.CurrentSchema)
	ca := &countingCA{issued: 1}
	f.d.relayCerts = ca
	f.d.orderIfDue(t.Context())
	rsa := &tls.ClientHelloInfo{ServerName: testRelayName, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		SignatureSchemes: []tls.SignatureScheme{tls.PSSWithSHA256}}
	for range 3 {
		if _, err := f.d.namedCertificate(rsa); err == nil {
			t.Fatal("an RSA client was served")
		}
	}
	if n := ca.count(); n != 1 {
		t.Errorf("%d asks of the CA, want the relay's own order alone", n)
	}
}

// Below the schema that has it, an announcement naming a relay is refused,
// whoever signed it: relayed on, it would have older members refuse every
// frame that carries it.
func TestARelayNameIsRefusedBelowItsSchema(t *testing.T) {
	f, _ := namedRelayFixture(t, types.SchemaTCP)
	var other *device
	for _, d := range f.nw.devices {
		if d.record.Identity != f.self.record.Identity {
			other = d
			break
		}
	}
	named := func(seq uint64) gossip.Endpoint {
		e, err := endpointFor(other, 41642)
		if err != nil {
			t.Fatal(err)
		}
		e.Seq = seq
		e.Relay = &gossip.RelayInfo{Port: 4443, Cert: make([]byte, gossip.RelayCertSize),
			HostName: "abcdefgh.relay.juist.invalid", Name: "relay.example.org"}
		if err := e.Sign(other.identity); err != nil {
			t.Fatal(err)
		}
		return e
	}
	if f.d.endpoints.Add(named(2)) {
		t.Errorf("at %v an announcement naming a relay was taken", types.SchemaTCP)
	}
	up, err := f.auth.Builder().SchemaUpgrade(types.SchemaRelayName)
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{up}); err != nil {
		t.Fatal(err)
	}
	if !f.d.endpoints.Add(named(3)) {
		t.Errorf("at %v an announcement naming a relay was refused", types.SchemaRelayName)
	}
}

// A relay that answers with a redirect sends an HTTPS-only device nowhere:
// followed, it could have it speak plain HTTP to any host and port.
func TestARelaysRedirectIsNotFollowed(t *testing.T) {
	var elsewhere atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer plain.Close()
	redirecting := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()
	d := &Daemon{envProxy: func(*url.URL) (*url.URL, error) { return nil, nil }}
	hc := d.httpsClient()
	hc.Transport.(*http.Transport).TLSClientConfig.RootCAs = x509.NewCertPool()
	hc.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(redirecting.Certificate())
	name := strings.TrimPrefix(redirecting.URL, "https://")
	if _, err := relay.GetAnnouncement(t.Context(), hc, name, [32]byte{1}); err == nil {
		t.Error("a redirect was taken for an announcement")
	}
	if err := relay.PutAnnouncement(t.Context(), hc, name, [32]byte{1}, []byte("sealed")); err == nil {
		t.Error("a redirect was taken for a put")
	}
	if n := elsewhere.Load(); n != 0 {
		t.Errorf("the redirect was followed %d times", n)
	}
}

// An invite goes through the proxy on an HTTPS-only device alone: another
// reaches relays as it always did, and tells no proxy whom it invites.
func TestAnInviteTakesTheProxyOnHTTPSAloneOnly(t *testing.T) {
	d := &Daemon{proxy: "http://proxy.example:3128", envProxy: func(*url.URL) (*url.URL, error) { return nil, nil }}
	if d.inviteProxy() != nil {
		t.Error("an invite from a device reaching relays directly takes the proxy")
	}
	d.httpsOnly = true
	p := d.inviteProxy()
	if p == nil {
		t.Fatal("an HTTPS-only device's invite takes no proxy")
	}
	if u, err := p("relay.example.org"); err != nil || u == nil || u.Host != "proxy.example:3128" {
		t.Errorf("the proxy is %v, %v", u, err)
	}
}

// HTTPS_PROXY naming a proxy that speaks no HTTP is refused, not told the
// credentials in a CONNECT.
func TestAnEnvironmentsSOCKSProxyIsRefused(t *testing.T) {
	socks, _ := url.Parse("socks5://user:secret@proxy.example:1080")
	route := proxyRoute("", func(*url.URL) (*url.URL, error) { return socks, nil })
	if u, err := route("relay.example.org"); err == nil {
		t.Errorf("a SOCKS proxy was taken: %s", u.Redacted())
	}
	plain, _ := url.Parse("http://proxy.example:3128")
	route = proxyRoute("", func(*url.URL) (*url.URL, error) { return plain, nil })
	if u, err := route("relay.example.org"); err != nil || u != plain {
		t.Errorf("an http proxy is %v, %v", u, err)
	}
}

// The hand-off socket takes the ingress user's processes alone: any other
// user's could say, in a PROXY header, it is any client.
func TestTheHandOffTakesTheIngressAlone(t *testing.T) {
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "relay.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := net.Dial("unix", ln.Addr().String()); err == nil {
			defer c.Close()
			time.Sleep(time.Second)
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uid := uint32(os.Getuid())
	// Root is never the ingress's user.
	if uid != 0 && peerCredSupported && !(&Daemon{ingressUID: uid, logf: t.Logf}).fromIngress(c) {
		t.Error("the ingress user's process was refused")
	}
	if (&Daemon{ingressUID: uid + 1, logf: t.Logf}).fromIngress(c) {
		t.Error("another user's process was taken")
	}
	if (&Daemon{logf: t.Logf}).fromIngress(c) {
		t.Error("a process was taken where there is no ingress user")
	}
}

// A relay's name is taken as that relay's once the server at the name says
// it is: a member announcing another relay's name gets nothing by it, in the
// data plane or in an invite, and the relay keeps its own.
func TestARelaysNameIsTakenOnceItsServerSaysWhoseItIs(t *testing.T) {
	f, _ := namedRelayFixture(t, types.CurrentSchema)
	one, two := f.nw.devices[1], f.nw.devices[2]
	f.nw.setRoles(t, f, one.record.Identity, types.RoleRelayCapable)
	f.nw.setRoles(t, f, two.record.Identity, types.RoleRelayCapable)
	var asked atomic.Int32
	f.d.askWhoami = func(_ context.Context, name string) ([32]byte, error) {
		asked.Add(1)
		if name != "one.example.org" {
			return [32]byte{}, errors.New("no answer")
		}
		return one.record.Identity, nil
	}
	relayOf := func(b byte) *gossip.RelayInfo {
		r := testRelayInfo()
		r.Name, r.Cert = "one.example.org", bytes.Repeat([]byte{b}, gossip.RelayCertSize)
		return r
	}
	f.learnRelay(t, one, 41641, relayOf(1))
	f.learnRelay(t, two, 41642, relayOf(2))
	named := func() (out []byte) {
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		f.d.mu.Lock()
		defer f.d.mu.Unlock()
		for _, r := range f.d.namedRelays {
			if r.Name == "one.example.org" {
				out = append(out, r.CertHash[0])
			}
		}
		return out
	}
	if got := named(); len(got) != 0 {
		t.Errorf("the name was taken before its server was asked, for %v", got)
	}
	if !f.d.proveDue(t.Context()) || asked.Load() == 0 {
		t.Fatal("the name's server was not asked, or its answer changed nothing")
	}
	if got := named(); !slices.Equal(got, []byte{1}) {
		t.Errorf("the name is taken for the relays %v, want the one whose server it is", got)
	}
	state, err := f.d.TrustedState()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range f.d.inviteRelays(state) {
		if r.Name != "" && r.CertHash[0] != 1 {
			t.Errorf("an invite waits at %s by the relay %d", r.Name, r.CertHash[0])
		}
	}
}

// On the ingress, the relay orders its certificate once the ingress was told
// of the name: before, the CA's challenge finds nothing there, and a failed
// order costs the CA's limit.
func TestTheRelayOrdersOnceTheIngressHandsItsNameOn(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("as root, there is no ingress user to tell apart")
	}
	f, _ := namedRelayFixture(t, types.CurrentSchema)
	f.nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable, types.RoleIngress)
	ca := &countingCA{issued: 1}
	f.d.relayCerts = ca
	if f.d.orderIfDue(t.Context()); ca.count() != 0 {
		t.Fatal("ordered before the ingress was told of the name")
	}
	f.d.ingressTookRelay()
	if f.d.orderIfDue(t.Context()); ca.count() != 1 {
		t.Errorf("%d orders once the ingress was told of the name", ca.count())
	}
}

// A name one relay alone claims goes into an invite unasked, as the host may
// reach no name, but into the data plane once its server says whose it is.
func TestAnInviteNamesARelayItCouldNotAsk(t *testing.T) {
	f, _ := namedRelayFixture(t, types.CurrentSchema)
	one := f.nw.devices[1]
	f.nw.setRoles(t, f, one.record.Identity, types.RoleRelayCapable)
	f.d.askWhoami = func(context.Context, string) ([32]byte, error) { return [32]byte{}, errors.New("no answer") }
	r := testRelayInfo()
	r.Name = "solo.example.org"
	f.learnRelay(t, one, 41641, r)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.proveDue(t.Context())
	state, err := f.d.TrustedState()
	if err != nil {
		t.Fatal(err)
	}
	if relays := f.d.inviteRelays(state); len(relays) != 1 || relays[0].Name != "solo.example.org" {
		t.Errorf("the invite waits at %+v", relays)
	}
	f.d.mu.Lock()
	defer f.d.mu.Unlock()
	for _, r := range f.d.namedRelays {
		if r.Name == "solo.example.org" {
			t.Error("the data plane takes a name its server did not answer for")
		}
	}
}
