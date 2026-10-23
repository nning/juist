package conn

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/tailcfg/nodecap"
)

func namedRelay() Relay {
	r := testRelay()
	r.Addrs = append(r.Addrs, netip.MustParseAddrPort("10.0.0.1:4443"))
	r.Name = "relay.example.org"
	return r
}

// A member whose network passes 443 alone reaches a relay by its name there,
// after every address on the relay's own port, the first three of which
// netcheck sends STUN to: resolved in DNS first, then at the relay's public
// addresses, which needs none.
func TestANamedRelayComesAfterItsPublicAddresses(t *testing.T) {
	dm, _ := derpMap([]Relay{namedRelay()}, nil, false, false, Networks{})
	nodes := dm.Regions[7].Nodes
	type want struct{ host, v4, v6 string }
	pinned, named := "abcdefgh.relay.juist.invalid", "relay.example.org"
	wants := []want{{pinned, "192.0.2.10", "none"}, {pinned, "none", "2001:db8::1"}, {pinned, "10.0.0.1", "none"},
		{named, "", ""}, {named, "192.0.2.10", "none"}, {named, "none", "2001:db8::1"}}
	if len(nodes) != len(wants) {
		t.Fatalf("%d nodes, want %d", len(nodes), len(wants))
	}
	for i, w := range wants {
		n := nodes[i]
		if n.HostName != w.host || n.IPv4 != w.v4 || n.IPv6 != w.v6 {
			t.Errorf("node %d is %+v, want %+v", i, n, w)
		}
		if w.host == named && (n.DERPPort != 443 || n.CertName != "" || n.STUNPort != -1) {
			t.Errorf("node %d of the name is %+v, want it on 443, verified by WebPKI, and no STUN", i, n)
		}
		if w.host == pinned && (n.DERPPort != 4443 || n.CertName == "") {
			t.Errorf("node %d at an address lost its port or its pin: %+v", i, n)
		}
	}
	seen := map[string]bool{}
	for _, n := range nodes {
		if seen[n.Name] {
			t.Errorf("two nodes are called %s", n.Name)
		}
		seen[n.Name] = true
	}
}

// Only TCP 443 keeps a relay's name and nothing else: no address on its own
// port, and no STUN server, which would be UDP.
func TestOnlyTCP443KeepsTheNamesAlone(t *testing.T) {
	plain := testRelay()
	plain.Region = 8
	dm, stunRegions := derpMap([]Relay{namedRelay(), plain}, []string{"stun.example:3478"}, true, false, Networks{})
	if len(dm.Regions) != 1 || len(stunRegions) != 0 {
		t.Fatalf("regions %v, STUN regions %v; want the named relay's alone", dm.RegionIDs(), stunRegions)
	}
	nodes := dm.Regions[7].Nodes
	if len(nodes) != 3 {
		t.Fatalf("%d nodes, want the name in DNS and at the two public addresses", len(nodes))
	}
	if nodes[0].IPv4 != "" || nodes[0].IPv6 != "" {
		t.Errorf("the first node is %+v, want the name resolved in DNS", nodes[0])
	}
	for _, n := range nodes {
		if n.HostName != "relay.example.org" || n.DERPPort != 443 || n.CertName != "" || n.STUNPort != -1 {
			t.Errorf("node %+v, want the name on 443 alone", n)
		}
	}
	if dm, _ := derpMap([]Relay{plain}, []string{"stun.example:3478"}, true, false, Networks{}); dm != nil {
		t.Errorf("a map without a named relay: %v", dm.RegionIDs())
	}
}

func TestARelayNameIsADNSName(t *testing.T) {
	for _, name := range []string{"relay", "relay.example.org:443", "relay.example.org\r\nX: y", ".example.org",
		"relay..example.org", "Relay.example.org", "relay.example.org."} {
		r := namedRelay()
		r.Name = name
		if err := validateRelays([]Relay{r}); err == nil {
			t.Errorf("%q was accepted", name)
		}
	}
	r := namedRelay()
	r.Addrs = nil
	if err := validateRelays([]Relay{r}); err != nil {
		t.Errorf("a relay known by its name alone was refused: %v", err)
	}
}

// What the engine sends towards a peer's address is UDP, and in HTTPS-only
// mode none of it may leave: the peer's announced address hears nothing,
// where an ordinary manager's handshake reaches it at once.
func TestHTTPSOnlySendsNoUDP(t *testing.T) {
	t.Parallel()
	for _, httpsOnly := range []bool{false, true} {
		pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: hostAddr(t).AsSlice()})
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		a := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) { o.HTTPSOnly = httpsOnly })
		b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
		peer := b.peer()
		peer.Endpoints = []netip.AddrPort{pc.LocalAddr().(*net.UDPAddr).AddrPort()}
		if err := a.mgr.SetPeers([]Peer{peer}); err != nil {
			t.Fatal(err)
		}
		got := make(chan struct{}, 1)
		go func() {
			buf := make([]byte, 2048)
			if _, _, err := pc.ReadFromUDP(buf); err == nil {
				got <- struct{}{}
			}
		}()
		deadline := time.After(5 * time.Second)
	wait:
		for {
			ping(t, a, b.pingAddr(), 200*time.Millisecond)
			select {
			case <-got:
				if httpsOnly {
					t.Fatal("an HTTPS-only manager sent a datagram to its peer's address")
				}
				break wait
			case <-deadline:
				if !httpsOnly {
					t.Fatal("an ordinary manager sent nothing, so the test sees nothing either")
				}
				break wait
			default:
			}
		}
		if m := a.mgr.(*tsManager); m.selfNV.HasCap(nodecap.OnlyTCP443) != httpsOnly {
			t.Errorf("HTTPS-only %v, but the self node's only-TCP-443 capability says otherwise", httpsOnly)
		}
	}
}

// The process-wide proxy hook answers for the relay names of an HTTPS-only
// manager alone; a relay's own port is never proxied.
func TestTheProxyIsForTheNamesOfHTTPSOnlyRelays(t *testing.T) {
	var at atomic.Pointer[url.URL]
	via, _ := url.Parse("http://user:secret@proxy.example:3128")
	at.Store(via)
	a := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) {
		o.HTTPSOnly = true
		o.Proxy = func(string) (*url.URL, error) { return at.Load(), nil }
	})
	if err := a.mgr.SetRelays([]Relay{namedRelay()}); err != nil {
		t.Fatal(err)
	}
	ask := func(host string) *url.URL {
		u, err := proxyFor(&http.Request{URL: &url.URL{Scheme: "https", Host: host, Path: "/"}})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	got := ask("relay.example.org")
	if got == nil || got.Host != via.Host || got.User != nil {
		t.Errorf("the relay's name goes through %v, want %s without its user, which the DERP client logs", got, via.Host)
	}
	if auth, _ := proxyAuth(got); auth != "Basic dXNlcjpzZWNyZXQ=" {
		t.Errorf("the proxy is told %q", auth)
	}
	for _, host := range []string{"abcdefgh.relay.juist.invalid", "other.example.org"} {
		if got := ask(host); got != nil {
			t.Errorf("%s goes through %v", host, got)
		}
	}
	if got := ProxyAuthorization(via); got != "Basic dXNlcjpzZWNyZXQ=" {
		t.Errorf("Proxy-Authorization %q", got)
	}
	// The same proxy without a user, as after the setting changed, is told
	// no credentials of before, once a netcheck dial under the old setting
	// is done.
	bare, _ := url.Parse("http://proxy.example:3128")
	at.Store(bare)
	for deadline := time.Now().Add(time.Second); ; time.Sleep(10 * time.Millisecond) {
		auth, _ := proxyAuth(ask("relay.example.org"))
		if auth == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("credentials taken back are still sent: %q", auth)
		}
	}
	a.mgr.Close()
	if got := ask("relay.example.org"); got != nil {
		t.Errorf("a closed manager's relay still goes through %v", got)
	}
}

// A public address of this host's counts a while after netcheck last
// reported it, which it does where two servers agree alone: an order of a
// relay's addresses coming and going with it would drop the home relay's
// connection each time.
func TestAPublicAddressOfThisHostsIsHeld(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	m := a.mgr.(*tsManager)
	public := netip.MustParseAddr("203.0.113.9")
	// Again where magicsock's own report came in between.
	for i := 0; !slices.Contains(m.local.Load().Public, public); i++ {
		if i == 50 {
			t.Fatal("a reported public address does not count")
		}
		m.epsMu.Lock()
		m.localEps = []netip.AddrPort{netip.AddrPortFrom(public, 41643)}
		m.epsMu.Unlock()
		m.followNetworks()
	}
	m.epsMu.Lock()
	m.localEps = nil
	m.epsMu.Unlock()
	m.followNetworks()
	if !slices.Contains(m.local.Load().Public, public) {
		t.Errorf("the public address went with one report: %v", m.local.Load().Public)
	}
	m.epsMu.Lock()
	m.publicSeen[public] = time.Now().Add(-publicHeld - time.Minute)
	m.epsMu.Unlock()
	m.followNetworks()
	if slices.Contains(m.local.Load().Public, public) {
		t.Error("a public address not reported for long still counts")
	}
}

// The proxy hook fails closed for an HTTPS-only manager's names: where the
// proxy cannot be told, or the name was dropped while a dial ran, the DERP
// client is given a proxy nothing reaches, not leave to dial direct.
func TestTheProxyFailsClosed(t *testing.T) {
	var fail atomic.Bool
	via, _ := url.Parse("http://proxy.example:3128")
	a := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", func(o *Options) {
		o.HTTPSOnly = true
		o.Proxy = func(string) (*url.URL, error) {
			if fail.Load() {
				return nil, errors.New("HTTPS_PROXY does not parse")
			}
			return via, nil
		}
	})
	if err := a.mgr.SetRelays([]Relay{namedRelay()}); err != nil {
		t.Fatal(err)
	}
	ask := func(host string) *url.URL {
		u, err := proxyFor(&http.Request{URL: &url.URL{Scheme: "https", Host: host, Path: "/"}})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	fail.Store(true)
	if got := ask("relay.example.org"); got == nil || got.Host != nowhere.Host {
		t.Errorf("with the proxy unknown, the relay's name goes through %v", got)
	}
	fail.Store(false)
	other := testRelay()
	other.Region = 2
	if err := a.mgr.SetRelays([]Relay{other}); err != nil {
		t.Fatal(err)
	}
	if got := ask("relay.example.org"); got == nil || got.Host != via.Host {
		t.Errorf("a name dropped goes through %v", got)
	}
}
