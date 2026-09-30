package conn

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"go4.org/netipx"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"
)

func setOf(t *testing.T, ps []netip.Prefix) *netipx.IPSet {
	t.Helper()
	var b netipx.IPSetBuilder
	for _, p := range ps {
		b.AddPrefix(p)
	}
	s, err := b.IPSet()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The internet an exit node carries is public space alone: never the
// overlay, a LAN, the host itself or what never leaves a link.
func TestInternetIsPublicSpaceAlone(t *testing.T) {
	overlay := []netip.Prefix{netip.MustParsePrefix("198.18.4.0/22"), netip.MustParsePrefix("fd12:3456:789a::/48"),
		netip.MustParsePrefix("8.8.4.0/24")}
	s := setOf(t, Internet(true, true, overlay))
	for _, a := range []string{"8.8.8.8", "1.1.1.1", "2606:4700::1111", "2a00:1450::1"} {
		if !s.Contains(netip.MustParseAddr(a)) {
			t.Errorf("the internet lacks %s", a)
		}
	}
	for _, a := range []string{"10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1", "198.18.4.5", "127.0.0.1",
		"169.254.1.1", "224.0.0.251", "255.255.255.255", "0.0.0.0", "192.0.2.1", "240.0.0.1",
		"fd12:3456:789a::1", "fc00::1", "fe80::1", "::1", "ff02::1", "2001:db8::1", "8.8.4.4"} {
		if s.Contains(netip.MustParseAddr(a)) {
			t.Errorf("the internet holds %s", a)
		}
	}
	if v4 := setOf(t, Internet(true, false, nil)); v4.Contains(netip.MustParseAddr("2606:4700::1111")) {
		t.Error("the IPv4 internet holds IPv6")
	}
	if v6 := setOf(t, Internet(false, true, nil)); v6.Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Error("the IPv6 internet holds IPv4")
	}
}

// A peer's routes send it what they hold and accept from it what they hold,
// and nothing beyond them goes to it.
func TestRoutesCarryTrafficToAndFromTheirPeer(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	c := newNode(t, 3, "100.64.0.3/32", "fd7a:115c:a1e0::3/128")
	exit := b.peer()
	exit.Routes = Internet(true, true, nil)
	if err := a.mgr.SetPeers([]Peer{exit, c.peer()}); err != nil {
		t.Fatal(err)
	}
	m := a.mgr.(*tsManager)
	bk := b.mgr.(*tsManager).self.NodeKey.Public()
	for _, dst := range []string{"8.8.8.8", "2606:4700::1111"} {
		if nk, ok := m.peerByIP(netip.MustParseAddr(dst)); !ok || nk != bk {
			t.Errorf("%s goes to %v, %v; want the exit node", dst, nk.ShortString(), ok)
		}
		if p, ok := m.peerForIP(netip.MustParseAddr(dst)); !ok || !p.Route.Contains(netip.MustParseAddr(dst)) {
			t.Errorf("%s has no route to the exit node: %+v", dst, p)
		}
	}
	if nk, ok := m.peerByIP(c.pingAddr()); !ok || nk == bk {
		t.Error("an overlay address went to the exit node")
	}
	for _, dst := range []string{"10.1.2.3", "192.168.1.1", "100.64.0.99", "fd7a:115c:a1e0::99"} {
		if _, ok := m.peerByIP(netip.MustParseAddr(dst)); ok {
			t.Errorf("%s goes to a peer", dst)
		}
	}
	allowed, _ := m.allowedIPs(bk)
	if s := setOf(t, allowed); !s.Contains(netip.MustParseAddr("8.8.8.8")) || !s.Contains(b.pingAddr()) {
		t.Errorf("the exit node may send from %v", allowed)
	}
	ck := c.mgr.(*tsManager).self.NodeKey.Public()
	if allowed, _ := m.allowedIPs(ck); setOf(t, allowed).Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Error("a member with no routes may send from the internet")
	}
}

// Routes that would give an address two peers, or take this node's or a
// peer's own, are refused whole.
func TestSetPeersRefusesRoutesThatClash(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	c := newNode(t, 3, "100.64.0.3/32", "fd7a:115c:a1e0::3/128")
	with := func(n *node, routes ...string) Peer {
		p := n.peer()
		for _, r := range routes {
			p.Routes = append(p.Routes, netip.MustParsePrefix(r))
		}
		return p
	}
	for _, tc := range []struct {
		name  string
		peers []Peer
		want  string
	}{
		{"a peer's address", []Peer{with(b, "100.64.0.0/24"), c.peer()}, "holds an overlay address"},
		{"this node's address", []Peer{with(b, "100.64.0.1/32")}, "holds an overlay address"},
		{"two peers", []Peer{with(b, "8.8.0.0/16"), with(c, "8.8.8.0/24")}, "carried twice"},
		{"host bits", []Peer{with(b, "8.8.8.1/24")}, "not a canonical prefix"},
	} {
		if err := a.mgr.SetPeers(tc.peers); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error naming %q", tc.name, err, tc.want)
		}
	}
}

// A node that serves accepts its members' traffic to what it serves, and
// nothing else outside its own addresses; one that does not serve accepts
// none of it.
func TestAServingNodeAcceptsWhatItServesAlone(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	if err := a.mgr.SetPeers([]Peer{b.peer()}); err != nil {
		t.Fatal(err)
	}
	m := a.mgr.(*tsManager)
	verdict := func(src, dst string) filter.Response {
		t.Helper()
		f, err := m.filter()
		if err != nil {
			t.Fatal(err)
		}
		var p packet.Parsed
		p.Decode(ipv4Packet(ipproto.UDP, netip.MustParseAddr(src), netip.MustParseAddr(dst)))
		return f.RunIn(&p, 0)
	}
	if got := verdict("100.64.0.2", "8.8.8.8"); got == filter.Accept {
		t.Fatal("a node that serves nothing forwards a member's traffic")
	}
	if err := m.SetServe(Serve{Routes: Internet(true, false, nil)}); err == nil {
		t.Fatal("serving without a device of its own was accepted")
	}
	m.serve = Serve{Routes: Internet(true, false, nil)}
	if got := verdict("100.64.0.2", "8.8.8.8"); got != filter.Accept {
		t.Errorf("a member's traffic to the internet: %v, want Accept", got)
	}
	for _, tc := range []struct{ src, dst string }{
		{"100.64.0.2", "192.168.1.1"}, // the exit node's own LAN
		{"100.64.0.99", "8.8.8.8"},    // no member
		{"8.8.4.4", "8.8.8.8"},        // not an overlay source
	} {
		if got := verdict(tc.src, tc.dst); got == filter.Accept {
			t.Errorf("%s to %s is accepted", tc.src, tc.dst)
		}
	}
}

// Egress and serving ask for a device of this node's own, and going direct
// asks for nothing.
func TestEgressNeedsADevice(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	for _, e := range []Egress{EgressTunnel, EgressRefused} {
		if err := a.mgr.SetEgress(e, false); err == nil {
			t.Errorf("%v without a device was accepted", e)
		}
	}
	if err := a.mgr.SetEgress(EgressDirect, false); err != nil {
		t.Fatal(err)
	}
	if err := a.mgr.SetServe(Serve{}); err != nil {
		t.Fatal(err)
	}
}

// The route lookup finds the one peer whose range holds an address, at the
// edges of each range too.
func TestByRouteAtTheEdges(t *testing.T) {
	k1, k2 := key.NewNode().Public(), key.NewNode().Public()
	st, _ := newPeerState(key.NodePublic{}, []Peer{
		{NodeKey: k1, Routes: []netip.Prefix{netip.MustParsePrefix("8.0.0.0/8"), netip.MustParsePrefix("2000::/3")}},
		{NodeKey: k2, Routes: []netip.Prefix{netip.MustParsePrefix("9.0.0.0/8")}},
	})
	for _, tc := range []struct {
		ip   string
		want key.NodePublic
		ok   bool
	}{
		{"8.0.0.0", k1, true}, {"8.255.255.255", k1, true}, {"9.0.0.0", k2, true}, {"9.255.255.255", k2, true},
		{"7.255.255.255", key.NodePublic{}, false}, {"10.0.0.0", key.NodePublic{}, false},
		{"2000::", k1, true}, {"3fff:ffff::1", k1, true}, {"4000::", key.NodePublic{}, false},
	} {
		nk, _, ok := st.byRoute(netip.MustParseAddr(tc.ip))
		if ok != tc.ok || nk != tc.want {
			t.Errorf("%s: %v %v, want %v %v", tc.ip, nk.ShortString(), ok, tc.want.ShortString(), tc.ok)
		}
	}
	if !slices.IsSortedFunc(st.routes, func(x, y routeEntry) int { return x.r.From().Compare(y.r.From()) }) {
		t.Error("the routes are not sorted")
	}
}

// An exit node serves none of the networks it is on, public or not, but its
// own addresses in them.
func TestAnExitNodeServesNotItsOwnNetworks(t *testing.T) {
	nets := []netip.Prefix{netip.MustParsePrefix("203.0.114.0/24"), netip.MustParsePrefix("2a02:810d::/64")}
	hosts := []netip.Addr{netip.MustParseAddr("203.0.114.5"), netip.MustParseAddr("2a02:810d::5")}
	s := setOf(t, served(Internet(true, true, nil), nets, hosts))
	for _, a := range []string{"8.8.8.8", "203.0.115.1", "2a02:810e::1", "203.0.114.5", "2a02:810d::5"} {
		if !s.Contains(netip.MustParseAddr(a)) {
			t.Errorf("it does not serve %s", a)
		}
	}
	for _, a := range []string{"203.0.114.9", "2a02:810d::10", "192.168.1.1"} {
		if s.Contains(netip.MustParseAddr(a)) {
			t.Errorf("it serves %s, on its own network", a)
		}
	}
	if served(nil, nets, hosts) != nil {
		t.Error("serving nothing serves its own addresses")
	}
}

// A peer's subnets are carried as its routes are, and routed into the tunnel
// by the host's own routes; its exit routes are not.
func TestSubnetsAreRoutedIntoTheTunnel(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	c := newNode(t, 3, "100.64.0.3/32", "fd7a:115c:a1e0::3/128")
	router := b.peer()
	router.Subnets = []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24"), netip.MustParsePrefix("fd00:50::/64")}
	exit := c.peer()
	exit.Routes = Internet(true, true, nil)
	if err := a.mgr.SetPeers([]Peer{router, exit}); err != nil {
		t.Fatal(err)
	}
	m := a.mgr.(*tsManager)
	routes := m.peerRoutes()
	for _, want := range router.Subnets {
		if !slices.Contains(routes, want) {
			t.Errorf("%v is not routed into the tunnel: %v", want, routes)
		}
	}
	if slices.ContainsFunc(routes, func(p netip.Prefix) bool { return p.Contains(netip.MustParseAddr("8.8.8.8")) }) {
		t.Error("the exit node's internet is routed by the host's routes")
	}
	bk := b.mgr.(*tsManager).self.NodeKey.Public()
	if nk, ok := m.peerByIP(netip.MustParseAddr("192.168.50.7")); !ok || nk != bk {
		t.Error("the subnet does not go to its router")
	}
	if allowed, _ := m.allowedIPs(bk); !setOf(t, allowed).Contains(netip.MustParseAddr("fd00:50::7")) {
		t.Error("the router may not answer from its subnet")
	}
	// The same addresses carried twice, by the exit node and the router, are
	// refused whole: the caller subtracts one from the other.
	public := b.peer()
	public.Subnets = []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}
	if err := a.mgr.SetPeers([]Peer{public, exit}); err == nil || !strings.Contains(err.Error(), "carried twice") {
		t.Errorf("a subnet inside the exit node's internet: %v", err)
	}
}

// A subnet router accepts its members' traffic to its subnets, which are its
// own networks, while the internet it serves leaves them out.
func TestARouterServesItsOwnNetworks(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	if err := a.mgr.SetPeers([]Peer{b.peer()}); err != nil {
		t.Fatal(err)
	}
	m := a.mgr.(*tsManager)
	nets, _ := attached("")
	var lan netip.Prefix
	for _, n := range nets {
		if n.Addr().Is4() {
			lan = n
		}
	}
	if !lan.IsValid() {
		t.Skip("the host is on no IPv4 network")
	}
	m.serve = Serve{Routes: Internet(true, false, nil), Subnets: []netip.Prefix{lan}}
	f, err := m.filter()
	if err != nil {
		t.Fatal(err)
	}
	var p packet.Parsed
	p.Decode(ipv4Packet(ipproto.UDP, netip.MustParseAddr("100.64.0.2"), lan.Addr().Next()))
	if got := f.RunIn(&p, 0); got != filter.Accept {
		t.Errorf("a member's traffic to the router's subnet %v: %v", lan, got)
	}
}

// recordingExits is an OS router's egress side that records what it is told,
// failing with err where set.
type recordingExits struct {
	told   []tunnelled
	served []Serve
	err    error
}

func (r *recordingExits) setEgress(_ Egress, t tunnelled) error {
	r.told = append(r.told, t)
	return r.err
}
func (r *recordingExits) setServe(s Serve) error {
	r.served = append(r.served, s)
	return nil
}
func (r *recordingExits) lans() ([]netip.Prefix, []netip.Addr) { return nil, nil }
func (r *recordingExits) answersThrough() string               { return "" }

// The router is told to redirect DNS as the node serves it, and again where
// only that changes.
func TestTheRouterServesDNSAsAsked(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	m := a.mgr.(*tsManager)
	rec := &recordingExits{}
	m.apply.Lock()
	m.exits = rec
	m.apply.Unlock()
	s := Serve{Routes: Internet(true, false, nil), Sources: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}}
	if err := m.SetServe(s); err != nil {
		t.Fatal(err)
	}
	s.DNS = 41646
	if err := m.SetServe(s); err != nil {
		t.Fatal(err)
	}
	var dns []uint16
	for _, s := range rec.served {
		dns = append(dns, s.DNS)
	}
	if len(dns) < 2 || dns[len(dns)-1] != 41646 {
		t.Errorf("the router was told to redirect DNS to %v", dns)
	}
}

// The router learns what the peers carry with the egress, and again whenever
// a new peer set changes it while an exit node is in use.
func TestTheRouterLearnsWhatThePeersCarry(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	c := newNode(t, 3, "100.64.0.3/32", "fd7a:115c:a1e0::3/128")
	m := a.mgr.(*tsManager)
	rec := &recordingExits{}
	m.apply.Lock()
	m.exits = rec
	m.apply.Unlock()
	exit := c.peer()
	exit.Routes = Internet(true, false, nil)
	if err := m.SetPeers([]Peer{exit}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetEgress(EgressTunnel, false); err != nil {
		t.Fatal(err)
	}
	exit.Routes = Internet(true, true, nil)
	if err := m.SetPeers([]Peer{exit}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetPeers([]Peer{exit}); err != nil {
		t.Fatal(err)
	}
	want := []tunnelled{{v4: true}, {v4: true, v6: true}}
	if len(rec.told) != len(want) || !rec.told[0].equal(want[0]) || !rec.told[1].equal(want[1]) {
		t.Errorf("the router was told %+v, want %+v", rec.told, want)
	}
	// The router failing to take it, as beside a lower network's egress,
	// does not make the peer set refused.
	rec.err = ErrEgressTaken
	exit.Routes = Internet(false, true, nil)
	if err := m.SetPeers([]Peer{exit}); err != nil {
		t.Errorf("the router failing, the peer set was refused: %v", err)
	}
}

// fixedRoutes is an OS router that reads routes.
type fixedRoutes []netip.Prefix

func (f fixedRoutes) hostRoutes() []netip.Prefix { return f }

// The manager says what its OS router reads of the host's routes, rather
// than the attached networks alone.
func TestTheManagerAsksItsRouterForTheHostsRoutes(t *testing.T) {
	want := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
	m := &tsManager{hostRouter: fixedRoutes(want)}
	if got := m.HostRoutes(); !slices.Equal(got, want) {
		t.Errorf("the host's routes are %v, want %v", got, want)
	}
}
