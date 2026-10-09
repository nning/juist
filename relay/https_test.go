package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go4.org/mem"
	"golang.org/x/crypto/acme"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus"

	"github.com/nning/juist/internal/proxyproto"
)

const testName = "relay.example.org"

// testPKI is a CA, which TestMain has the system trust through
// SSL_CERT_FILE, and a certificate it issued for testName, as a public CA
// would for a relay's name.
var testPKI struct {
	pool *x509.CertPool
	cert *tls.Certificate
	pem  []byte
}

func TestMain(m *testing.M) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: testName},
		DNSNames: []string{testName}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	testPKI.pool = x509.NewCertPool()
	testPKI.pool.AddCert(ca)
	testPKI.cert = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	dir, err := os.MkdirTemp("", "relay-test")
	if err != nil {
		panic(err)
	}
	file := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		panic(err)
	}
	// Read once, at the first verification against the system's roots.
	os.Setenv("SSL_CERT_FILE", file)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// namedRelay starts a relay that answers for testName too, and serves it on a
// second listener as on 443, and at a hand-off socket, admitting connections
// there while admitting says; hellos are the ClientHellos asking for the name.
type namedRelay struct {
	*Server
	admitting atomic.Bool
	handOff   string
	pool      *x509.CertPool
	https     netip.AddrPort
	mu        sync.Mutex
	hellos    []*tls.ClientHelloInfo
}

func startNamed(t *testing.T, members map[key.NodePublic]bool, rv Rendezvous, hosts ...[32]byte) *namedRelay {
	t.Helper()
	pool, cert := testPKI.pool, testPKI.cert
	n := &namedRelay{pool: pool, handOff: filepath.Join(t.TempDir(), "relay.sock")}
	n.admitting.Store(true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := Options{
		Admit:    func(k [32]byte) bool { return members[key.NodePublicFromRaw32(mem.B(k[:]))] },
		Listener: ln,
		Name:     testName,
		NamedCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			n.mu.Lock()
			n.hellos = append(n.hellos, h)
			n.mu.Unlock()
			return cert, nil
		},
		Rendezvous: rv,
		Logf:       t.Logf,
	}
	if len(hosts) > 0 {
		o.AdmitHost = func(id [32]byte) bool { return slices.Contains(hosts, id) }
	}
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	https, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.ServeHTTPS(https)
	handOff, err := net.Listen("unix", n.handOff)
	if err != nil {
		t.Fatal(err)
	}
	s.ServeHTTPS(HandedOn(handOff, func(net.Conn) bool { return n.admitting.Load() }))
	n.Server, n.https = s, https.Addr().(*net.TCPAddr).AddrPort()
	return n
}

// A client asking for the relay's public name is shown the certificate a CA
// issued for it, on the relay's own port and on its second listener alike;
// every other client the pinned one, whose hash members announce.
func TestANameIsServedUnderItsPublicCertificate(t *testing.T) {
	n := startNamed(t, nil, nil)
	own := n.localAddrs()[0]
	for _, at := range []netip.AddrPort{own, n.https} {
		c, err := tls.Dial("tcp", at.String(), &tls.Config{ServerName: testName, RootCAs: n.pool})
		if err != nil {
			t.Fatalf("at %v, the public name does not verify: %v", at, err)
		}
		c.Close()
		c, err = tls.Dial("tcp", at.String(), &tls.Config{ServerName: n.HostName(), InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(c.ConnectionState().PeerCertificates[0].Raw); sum != n.CertHash() {
			t.Errorf("at %v, the pinned name was shown another certificate", at)
		}
		c.Close()
	}
}

// A TLS-ALPN-01 challenge for the name reaches the certificate source with
// the protocol, so ACME's answer is given, and is negotiated.
func TestAChallengeForTheNameIsAnswered(t *testing.T) {
	n := startNamed(t, nil, nil)
	c, err := tls.Dial("tcp", n.https.String(), &tls.Config{ServerName: testName, RootCAs: n.pool,
		NextProtos: []string{acme.ALPNProto}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.ConnectionState().NegotiatedProtocol; got != acme.ALPNProto {
		t.Errorf("negotiated %q", got)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.hellos) == 0 || !slices.Contains(n.hellos[len(n.hellos)-1].SupportedProtos, acme.ALPNProto) {
		t.Error("the certificate source was not asked with the challenge's protocol")
	}
}

// Two members reach each other through the relay by its public name alone,
// verified by WebPKI as the data plane does with no pin: what a member on a
// network passing 443 alone does.
func TestMembersRelayThroughThePublicName(t *testing.T) {
	a, b := key.NewNode(), key.NewNode()
	n := startNamed(t, map[key.NodePublic]bool{a.Public(): true, b.Public(): true}, nil)
	reg := &tailcfg.DERPRegion{RegionID: 1, RegionCode: "j1", Nodes: []*tailcfg.DERPNode{{
		Name: "j1-https", RegionID: 1, HostName: testName, IPv4: "127.0.0.1", IPv6: "none",
		DERPPort: int(n.https.Port()), STUNPort: -1,
	}}}
	bus := eventbus.New()
	t.Cleanup(bus.Close)
	mon, err := netmon.New(bus, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mon.Close() })
	client := func(priv key.NodePrivate) *derphttp.Client {
		c := derphttp.NewRegionClient(priv, t.Logf, mon, func() *tailcfg.DERPRegion { return reg })
		c.TLSConfig = &tls.Config{RootCAs: n.pool}
		t.Cleanup(func() { c.Close() })
		return c
	}
	ca, cb := client(a), client(b)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, c := range []*derphttp.Client{ca, cb} {
		if err := c.Connect(ctx); err != nil {
			t.Fatalf("a member could not reach the relay by its name: %v", err)
		}
	}
	waitClients(t, n.Server, 2)
	got := make(chan struct{}, 1)
	go func() {
		for {
			m, err := cb.Recv()
			if err != nil {
				return
			}
			if _, ok := m.(derp.ReceivedPacket); ok {
				got <- struct{}{}
				return
			}
		}
	}()
	for deadline := time.Now().Add(20 * time.Second); ; {
		if err := ca.Send(b.Public(), []byte("by name")); err != nil {
			t.Fatal(err)
		}
		select {
		case <-got:
			return
		case <-time.After(200 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("nothing crossed the relay by its name")
		}
	}
}

type fakeRendezvous struct {
	mu   sync.Mutex
	held map[[32]byte][]byte
}

func (f *fakeRendezvous) Knows(k [32]byte) (known, current bool) {
	return k[0] == 1 || k[0] == 2, k[0] == 1
}

func (f *fakeRendezvous) Get(k [32]byte) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.held[k]
	return v, ok
}

func (f *fakeRendezvous) Put(k [32]byte, v []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if k[0] != 1 {
		return false
	}
	f.held[k] = v
	return true
}

// rendezvousClient asks the relay over TLS by its public name, from loopback,
// each request on a connection of its own that starts with a PROXY v2 header
// naming from, where valid.
func rendezvousClient(n *namedRelay, from netip.AddrPort) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if !from.IsValid() {
				c, err := (&net.Dialer{}).DialContext(ctx, "tcp", n.localAddrs()[0].String())
				if err != nil {
					return nil, err
				}
				tc := tls.Client(c, &tls.Config{ServerName: testName, RootCAs: n.pool})
				return tc, tc.HandshakeContext(ctx)
			}
			c, err := (&net.Dialer{}).DialContext(ctx, "unix", n.handOff)
			if err != nil {
				return nil, err
			}
			if _, err := c.Write(proxyproto.Header(from, n.https)); err != nil {
				return nil, err
			}
			tc := tls.Client(c, &tls.Config{ServerName: testName, RootCAs: n.pool})
			return tc, tc.HandshakeContext(ctx)
		},
		DisableKeepAlives: true,
	}}
}

func call(t *testing.T, c *http.Client, method string, k [32]byte, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, fmt.Sprintf("https://%s%s%x", testName, RendezvousPath, k), strings.NewReader(body))
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// The rendezvous takes what its owner takes and hands it back, and answers a
// key it refuses as it answers one nobody holds.
func TestTheRendezvousHoldsWhatItTakes(t *testing.T) {
	rv := &fakeRendezvous{held: map[[32]byte][]byte{}}
	n := startNamed(t, nil, rv)
	c := rendezvousClient(n, netip.AddrPort{})
	ours, theirs := [32]byte{1, 2}, [32]byte{2, 2}
	if code, _ := call(t, c, http.MethodGet, ours, ""); code != http.StatusNotFound {
		t.Errorf("an empty key answered %d", code)
	}
	if code, _ := call(t, c, http.MethodPut, ours, "sealed"); code != http.StatusNoContent {
		t.Errorf("a put answered %d", code)
	}
	if code, body := call(t, c, http.MethodGet, ours, ""); code != http.StatusOK || body != "sealed" {
		t.Errorf("a get answered %d %q", code, body)
	}
	if code, _ := call(t, c, http.MethodPut, theirs, "sealed"); code != http.StatusNotFound {
		t.Errorf("a refused put answered %d, which tells a key of the network's from another", code)
	}
	if code, _ := call(t, c, http.MethodPut, ours, strings.Repeat("x", MaxRendezvousValue+1)); code != http.StatusBadRequest {
		t.Errorf("an oversized put answered %d", code)
	}
	if code, _ := call(t, c, http.MethodDelete, ours, ""); code != http.StatusMethodNotAllowed {
		t.Errorf("a delete answered %d", code)
	}
}

// Each client has a budget of its own, the client a handing-off ingress
// names in its header from loopback; past it, it is turned away and another
// client is not.
func TestTheRendezvousLimitsEachClient(t *testing.T) {
	n := startNamed(t, nil, &fakeRendezvous{held: map[[32]byte][]byte{}})
	a := rendezvousClient(n, netip.MustParseAddrPort("192.0.2.1:5000"))
	limited := false
	for range rendezvousSourceBurst + 4 {
		if code, _ := call(t, a, http.MethodGet, [32]byte{1}, ""); code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("a client past its burst was not turned away")
	}
	b := rendezvousClient(n, netip.MustParseAddrPort("192.0.2.2:5000"))
	if code, _ := call(t, b, http.MethodGet, [32]byte{1}, ""); code == http.StatusTooManyRequests {
		t.Error("another client the ingress named was turned away for the first one's requests")
	}
}

// The relay's own port never reads a PROXY header, from loopback either: it
// is the start of the TLS handshake, which fails, so no local program can say
// it is another client.
func TestTheRelaysPortReadsNoHeader(t *testing.T) {
	n := startNamed(t, nil, nil)
	for _, at := range []netip.AddrPort{n.localAddrs()[0], n.https} {
		c, err := net.Dial("tcp", at.String())
		if err != nil {
			t.Fatal(err)
		}
		c.Write(proxyproto.Header(netip.MustParseAddrPort("192.0.2.1:5000"), at))
		tc := tls.Client(c, &tls.Config{ServerName: testName, RootCAs: n.pool})
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		if err := tc.Handshake(); err == nil {
			t.Errorf("at %v, a handshake after a PROXY header succeeded", at)
		}
		c.Close()
	}
}

// One IPv6 client holds a whole /56, so its addresses share one budget; a
// full table of clients makes room for the next by the one seen longest ago;
// and keys of no member's spend nothing of the relay's own budget.
func TestTheRendezvousBoundsClientsByNetwork(t *testing.T) {
	h := newRendezvousHandler(&fakeRendezvous{held: map[[32]byte][]byte{}}, t.Logf)
	now := time.Now()
	a, b := netip.MustParseAddr("2001:db8:0:1::1"), netip.MustParseAddr("2001:db8:0:2::9")
	for range rendezvousSourceBurst {
		h.allowSource(a, now)
	}
	if h.allowSource(b, now) {
		t.Error("another address in the client's /56 had a budget of its own")
	}
	if !h.allowSource(netip.MustParseAddr("2001:db8:1::1"), now) {
		t.Error("another /56 was turned away")
	}
	for i := range maxRendezvousSources + 10 {
		h.allowSource(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), now.Add(time.Duration(i)))
	}
	if len(h.sources) > maxRendezvousSources {
		t.Errorf("%d clients held", len(h.sources))
	}
	if !h.allowSource(netip.MustParseAddr("192.0.2.200"), now) {
		t.Error("a new client found no room")
	}

	h = newRendezvousHandler(&fakeRendezvous{held: map[[32]byte][]byte{}}, t.Logf)
	for i := range rendezvousTotalBurst + 10 {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("%s%064x", RendezvousPath, 2), nil)
		r.RemoteAddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), 1).String()
		h.ServeHTTP(w, r)
	}
	if got := h.total.Tokens(); got < rendezvousTotalBurst-1 {
		t.Errorf("keys of no member's spent the relay's budget down to %.0f", got)
	}
}

// A key under an older epoch, which a removed device may still derive, is
// only ever put, and spends a budget of its own: it cannot exhaust the one
// the network's members use.
func TestAnOlderEpochsKeysSpendABudgetOfTheirOwn(t *testing.T) {
	h := newRendezvousHandler(&fakeRendezvous{held: map[[32]byte][]byte{}}, t.Logf)
	serve := func(method string, key byte, from int) int {
		k := [32]byte{key}
		req := httptest.NewRequest(method, RendezvousPath+hex.EncodeToString(k[:]), strings.NewReader("sealed"))
		req.RemoteAddr = fmt.Sprintf("10.0.%d.%d:1000", from>>8, from&255)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := serve(http.MethodGet, 2, 0); code != http.StatusNotFound {
		t.Errorf("a get under an older epoch: %d", code)
	}
	limited := 0
	for i := 1; i <= 4*rendezvousOlderBurst; i++ {
		if serve(http.MethodPut, 2, i) == http.StatusTooManyRequests {
			limited = i
			break
		}
	}
	if limited == 0 || limited > rendezvousOlderBurst+2 {
		t.Errorf("puts under an older epoch were turned away at the %dth", limited)
	}
	if code := serve(http.MethodGet, 1, 1000); code == http.StatusTooManyRequests {
		t.Error("a member under the newest epoch was turned away for them")
	}
}

// A relay says whose it is to a client that asked for its public name, and
// to nobody else.
func TestARelaySaysWhoseItIsUnderItsName(t *testing.T) {
	pool, cert := testPKI.pool, testPKI.cert
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	id := [32]byte{7, 7, 7}
	s, err := New(Options{Admit: func([32]byte) bool { return false }, Listener: ln, Name: testName, Identity: id,
		NamedCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil }, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := ln.Addr().String()
	named := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", at)
		},
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	got, err := Whoami(t.Context(), named, testName)
	if err != nil || got != id {
		t.Fatalf("under its name, the relay says it is %x, %v", got, err)
	}
	pinned := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true,
		ServerName: s.HostName()}}}
	if _, err := Whoami(t.Context(), pinned, at); err == nil {
		t.Error("the relay says whose it is to a client that did not ask for its name")
	}
}
