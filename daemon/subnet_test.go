package daemon

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

func prefixList(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range s {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

// subnetFixture is a network of three in which device router is granted
// routes, and device admin, where not -1, is a voucher; the daemon runs as
// device 0.
func subnetFixture(t *testing.T, router, admin int, routes []netip.Prefix, mutate func(*Options)) *reconcileFixture {
	t.Helper()
	return exitFixtureWith(t, func(nw *network) {
		nw.devices[router].record.Routes = routes
		if admin >= 0 {
			nw.devices[admin].record.Roles = append(nw.devices[admin].record.Roles, types.RoleAdmin)
			slices.Sort(nw.devices[admin].record.Roles)
		}
	}, mutate)
}

// learnRouter hands the daemon dev's announcement, saying it routes its
// subnets or not.
func (f *reconcileFixture) learnRouter(t *testing.T, dev *device, port uint16, routing bool) {
	t.Helper()
	e, err := endpointFor(dev, port)
	if err != nil {
		t.Fatal(err)
	}
	e.Subnets, e.Seq = routing, e.Seq+1
	if err := e.Sign(dev.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
}

func (f *reconcileFixture) peerSubnets(t *testing.T, dev *device) []netip.Prefix {
	t.Helper()
	f.mgr.mu.Lock()
	defer f.mgr.mu.Unlock()
	for _, p := range f.mgr.peers {
		if p.NodeKey == conn.NodePublicFromRaw32(dev.record.WireGuard) {
			return p.Subnets
		}
	}
	return nil
}

func (f *reconcileFixture) subnetRoute(t *testing.T, pfx string) ipc.SubnetRoute {
	t.Helper()
	st := f.d.Status().Subnets
	if st == nil {
		t.Fatal("the status says nothing of subnets")
	}
	for _, r := range st.Routes {
		if r.Prefix == netip.MustParsePrefix(pfx) {
			return r
		}
	}
	t.Fatalf("the status lists no %s: %+v", pfx, st.Routes)
	return ipc.SubnetRoute{}
}

// A client routes a router's granted subnets through it once its operator
// agreed, and says so.
func TestAClientRoutesAGrantedSubnet(t *testing.T) {
	f := subnetFixture(t, 1, -1, prefixList("192.168.50.0/24", "fd00:50::/64"), nil)
	router := f.nw.devices[1]
	f.learnRouter(t, router, 7001, true)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := f.peerSubnets(t, router); !slices.Equal(got, prefixList("192.168.50.0/24", "fd00:50::/64")) {
		t.Fatalf("the router carries %v", got)
	}
	if r := f.subnetRoute(t, "192.168.50.0/24"); !r.InUse || r.Why != "" || r.Name != router.record.Name {
		t.Errorf("the status says %+v", r)
	}
	if got := f.peerSubnets(t, f.nw.devices[2]); len(got) != 0 {
		t.Errorf("a member routing nothing carries %v", got)
	}
}

// Wherever a subnet cannot or must not go through its router, it is not
// routed into the tunnel, and the status says why; what the host reaches by
// routes of its own stays with them.
func TestASubnetIsLeftOutWhereItMustBe(t *testing.T) {
	for _, tc := range []struct {
		name    string
		admin   int
		routing bool
		mutate  func(*Options)
		host    []netip.Prefix
		want    []netip.Prefix
		why     string
	}{
		{"not agreed", -1, false, nil, nil, nil, "has not agreed"},
		{"stale", 2, true, nil, nil, nil, "view of the network is stale"},
		{"off", -1, true, func(o *Options) { o.SubnetsOff = true }, nil, nil, "subnets are off"},
		{"no IPv4", -1, true, func(o *Options) { o.NoV4 = true }, nil, nil, "no IPv4 in the network"},
		{"the host's own", -1, true, nil, prefixList("192.168.50.0/24"), nil, "by a route of its own"},
		{"a wider network of the host's", -1, true, nil, prefixList("192.168.0.0/16", "192.168.0.0/16"), prefixList("192.168.50.0/24"),
			"taken from this device's own route to 192.168.0.0/16"},
		{"partly the host's", -1, true, nil, prefixList("192.168.50.128/25"), prefixList("192.168.50.0/25"),
			"but for 192.168.50.128/25"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := subnetFixture(t, 1, tc.admin, prefixList("192.168.50.0/24"), tc.mutate)
			f.mgr.mu.Lock()
			f.mgr.hostRoutes = tc.host
			f.mgr.mu.Unlock()
			f.learnRouter(t, f.nw.devices[1], 7001, tc.routing)
			if err := f.d.Reconcile(); err != nil {
				t.Fatal(err)
			}
			if got := f.peerSubnets(t, f.nw.devices[1]); !slices.Equal(got, tc.want) {
				t.Errorf("the router carries %v, want %v", got, tc.want)
			}
			r := f.subnetRoute(t, "192.168.50.0/24")
			if !strings.Contains(r.Why, tc.why) || strings.HasPrefix(tc.why, "taken") && r.Why != tc.why || r.InUse != (tc.want != nil) {
				t.Errorf("the status says %+v, want %q", r, tc.why)
			}
		})
	}
}

// A router on a build before schema 14, in a network at it, routes nothing
// for this device and is given no preshared key: its tunnel carries juist's
// own traffic alone, which seals itself.
func TestARouterThatIsNotPostQuantumCarriesNothingElse(t *testing.T) {
	f := subnetFixture(t, 1, -1, prefixList("192.168.50.0/24"), nil)
	router := f.nw.devices[1]
	f.learnOld(t, router, 7001, true)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := f.peerSubnets(t, router); len(got) != 0 {
		t.Errorf("the router carries %v", got)
	}
	if r := f.subnetRoute(t, "192.168.50.0/24"); r.InUse || !strings.Contains(r.Why, "its router runs an older juist") {
		t.Errorf("the status says %+v", r)
	}
	p := f.peerOf(t, router)
	if p.PSK != ([32]byte{}) {
		t.Error("a peer naming no epoch is given a preshared key")
	}
	if a := p.Access; a == nil || !slices.Equal(a.Open, []conn.Ports{tcp(f.d.gossipPort)}) ||
		!slices.Equal(a.Sends, []conn.Ports{tcp(7001)}) || a.Through != nil {
		t.Errorf("it may open %+v", a)
	}
}

// A router routes its granted subnets while its operator agrees and its view
// is fresh, and says so in its announcement; without a grant, or stale, it
// routes none and says why.
func TestARouterRoutesWhatItIsGranted(t *testing.T) {
	f := subnetFixture(t, 0, -1, prefixList("192.168.50.0/24"), func(o *Options) { o.ServeSubnets = true })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	_, s := f.mgr.exitState()
	if !slices.Equal(s.Subnets, prefixList("192.168.50.0/24")) || len(s.Routes) > 0 || len(s.Sources) == 0 {
		t.Fatalf("it serves %+v", s)
	}
	if a, ok := f.d.Announcement(); !ok || !a.Subnets || a.Exit {
		t.Errorf("its announcement says subnets %v, exit %v", a.Subnets, a.Exit)
	}
	if st := f.d.Status().Subnets; st == nil || !slices.Equal(st.Serving, s.Subnets) {
		t.Errorf("the status says %+v", st)
	}

	for _, tc := range []struct {
		name   string
		routes []netip.Prefix
		admin  int
		why    string
	}{
		{"not granted", nil, -1, "routes no subnet through this device"},
		{"stale", prefixList("192.168.50.0/24"), 2, "stale"},
	} {
		f := subnetFixture(t, 0, tc.admin, tc.routes, func(o *Options) { o.ServeSubnets = true })
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		if _, s := f.mgr.exitState(); len(s.Subnets) > 0 {
			t.Errorf("%s: it serves %v", tc.name, s.Subnets)
		}
		if st := f.d.Status().Subnets; st == nil || !strings.Contains(st.NotServing, tc.why) {
			t.Errorf("%s: the status says %+v", tc.name, st)
		}
		if a, _ := f.d.Announcement(); a.Subnets {
			t.Errorf("%s: its announcement says it routes", tc.name)
		}
	}
}

// A public subnet goes through its router, and not through the exit node in
// use: the one carries what the other takes away.
func TestAnExitNodeCarriesNoRoutedSubnet(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.devices[1].record.Roles = []types.Role{types.RoleExit}
		nw.devices[1].record.Routes = defaultRoutes
		nw.devices[2].record.Routes = prefixList("8.8.8.0/24")
	}, nil)
	exit, router := f.nw.devices[1], f.nw.devices[2]
	f.learnExit(t, exit, 7001, true)
	f.learnRouter(t, router, 7002, true)
	f.d.SetExitChoice(ExitChoice{Chosen: true, Node: exit.record.Identity})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if e, _ := f.mgr.exitState(); e != conn.EgressTunnel {
		t.Fatalf("egress %v", e)
	}
	if contains(f.peerRoutes(t, exit), "8.8.8.8") || !contains(f.peerRoutes(t, exit), "8.8.4.4") {
		t.Error("the exit node carries the routed subnet, or not the rest")
	}
	if !contains(f.peerSubnets(t, router), "8.8.8.8") {
		t.Error("the router does not carry its subnet")
	}
}

// The operator's and the owner's word on subnets are kept, and a reset
// forgets both with the network.
func TestTheSubnetWordsAreKept(t *testing.T) {
	nw := newNetwork(t, 2)
	f := serviceWithChoice(t, nw, nw.devices[0], "")
	on, off := true, false
	for _, req := range []ipc.Request{{Command: ipc.CmdSubnet, ServeSubnets: &on}, {Command: ipc.CmdSubnet, AcceptSubnets: &off}} {
		if _, err := ipc.Call(f.sock, req); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{statedir.SubnetServeFile, statedir.SubnetsFile} {
		if _, err := os.Stat(filepath.Join(f.home, name)); err != nil {
			t.Errorf("%s is not kept: %v", name, err)
		}
	}
	st, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdStatus})
	if err != nil || st.Status.Subnets == nil || !st.Status.Subnets.Consent || !st.Status.Subnets.Off {
		t.Fatalf("the status says %+v, %v", st.Status.Subnets, err)
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdSubnet, AcceptSubnets: &on}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.home, statedir.SubnetsFile)); !os.IsNotExist(err) {
		t.Errorf("subnets on left %s: %v", statedir.SubnetsFile, err)
	}
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdReset, Force: true}); err != nil {
		t.Fatal(err)
	}
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	if f.s.serveSubnets || f.s.subnetsOff {
		t.Error("the service holds on to the words after a reset")
	}
}

// A router without overlay IPv4 routes none of its IPv4 subnets, which no
// peer's traffic reaches from a source it accepts.
func TestARouterWithoutIPv4RoutesNoIPv4(t *testing.T) {
	f := subnetFixture(t, 0, -1, prefixList("192.168.50.0/24", "fd00:50::/64"), func(o *Options) {
		o.ServeSubnets, o.NoV4 = true, true
	})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if _, s := f.mgr.exitState(); !slices.Equal(s.Subnets, prefixList("fd00:50::/64")) {
		t.Errorf("it serves %v", s.Subnets)
	}
	f = subnetFixture(t, 0, -1, prefixList("192.168.50.0/24"), func(o *Options) { o.ServeSubnets, o.NoV4 = true, true })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if st := f.d.Status().Subnets; st == nil || !strings.Contains(st.NotServing, "no IPv4") {
		t.Errorf("the status says %+v", st)
	}
}

// A device without overlay IPv4 says so only where the log routes through it,
// which its clients need to know; elsewhere it tells no one.
func TestOnlyARoutedDeviceSaysItHasNoIPv4(t *testing.T) {
	for _, tc := range []struct {
		routes []netip.Prefix
		want   bool
	}{
		{prefixList("192.168.50.0/24"), true},
		{prefixList("0.0.0.0/0", "::/0"), true},
		{nil, false},
	} {
		f := exitFixtureWith(t, func(nw *network) {
			nw.devices[0].record.Routes = tc.routes
			if slices.Contains(tc.routes, netip.MustParsePrefix("::/0")) {
				nw.devices[0].record.Roles = []types.Role{types.RoleExit}
			}
		}, func(o *Options) { o.NoV4 = true })
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		if a, ok := f.d.Announcement(); !ok || a.NoV4 != tc.want {
			t.Errorf("routing %v, it announces NoV4 %v", tc.routes, a.NoV4)
		}
	}
}

// A router, or an exit node, without overlay IPv4 is sent no IPv4, and its
// clients say why.
func TestAPeerWithoutIPv4IsSentNoIPv4(t *testing.T) {
	f := subnetFixture(t, 1, -1, prefixList("192.168.50.0/24", "fd00:50::/64"), nil)
	router := f.nw.devices[1]
	e, err := endpointFor(router, 7001)
	if err != nil {
		t.Fatal(err)
	}
	e.Subnets, e.NoV4, e.Seq = true, true, e.Seq+1
	if err := e.Sign(router.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := f.peerSubnets(t, router); !slices.Equal(got, prefixList("fd00:50::/64")) {
		t.Errorf("the router carries %v", got)
	}
	if r := f.subnetRoute(t, "192.168.50.0/24"); r.InUse || !strings.Contains(r.Why, "its router has no IPv4") {
		t.Errorf("the status says %+v", r)
	}
}
