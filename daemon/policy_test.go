package daemon

import (
	"errors"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/types/ipproto"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/addrkey"
	"github.com/nning/juist/internal/policy"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// setPolicy signs and applies the policy src names, devices by name.
func (nw *network) setPolicy(t *testing.T, f *reconcileFixture, src string) {
	t.Helper()
	p, err := policy.Parse(src, policy.Members(f.auth.State()))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := f.auth.Builder().SetPolicy(p)
	if err != nil {
		t.Fatalf("building the policy: %v", err)
	}
	if err := rec.Sign(nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{rec}); err != nil {
		t.Fatalf("applying the policy: %v", err)
	}
}

func tcp(port uint16) conn.Ports { return conn.Ports{Proto: ipproto.TCP, First: port, Last: port} }

// The policy decides who is a peer and what each may open: a member no rule
// joins to this device is none, a carrier is one for juist's own traffic,
// and log sync reaches peers alone.
func TestThePolicyDecidesThePeers(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.devices[2].record.Roles = []types.Role{types.RoleRelayCapable}
	}, nil)
	f.learnOthers(t)
	n1, n2 := f.nw.devices[1], f.nw.devices[2]
	f.nw.setPolicy(t, f, "pass from n0 to n1 proto tcp port 22\n")
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	gossip := f.d.gossipPort
	if a := f.peerOf(t, n1).Access; a == nil || !slices.Equal(a.Open, []conn.Ports{tcp(gossip)}) ||
		!slices.Equal(a.Sends, []conn.Ports{tcp(22), tcp(7001)}) || len(a.Through) > 0 {
		t.Errorf("n1, which n0 may open ssh on, has %+v", a)
	}
	if a := f.peerOf(t, n2).Access; a == nil || !slices.Equal(a.Open, []conn.Ports{tcp(gossip)}) ||
		!slices.Equal(a.Sends, []conn.Ports{tcp(7002)}) {
		t.Errorf("the relay n2, a carrier, has %+v", a)
	}
	if got := f.d.memberList(); len(got) != 2 {
		t.Errorf("log sync reaches %d members", len(got))
	}

	f.nw.setPolicy(t, f, "pass from n1 to n2\n")
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if f.mgr.has([32]byte(n1.record.WireGuard)) {
		t.Error("n1, which no rule joins to n0, is a peer")
	}
	if !f.mgr.has([32]byte(n2.record.WireGuard)) {
		t.Error("the carrier n2 is no peer")
	}
	if got := f.d.memberList(); !slices.Equal(got, []types.Identity{n2.record.Identity}) {
		t.Errorf("log sync reaches %v, want the carrier alone", got)
	}
	for _, dev := range f.d.Status().Devices {
		if dev.Identity == n1.record.Identity {
			t.Error("the status lists n1, which the policy keeps apart")
		}
	}
	state := f.auth.State()
	z, _, _ := f.d.namesZone(state, f.d.membersOf(state).view, log.Freshness{}, true, time.Now().Unix(),
		func(types.Identity) bool { return false })
	if _, ok := z.Members["n1"]; ok || z.Members["n2"] == nil || z.Members["n0"] == nil {
		t.Errorf("the names are %v, want n0 and n2", slices.Collect(maps.Keys(z.Members)))
	}

	// Without a carrier, every two members keep a tunnel for the log.
	f.nw.setRoles(t, f, n2.record.Identity)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if a := f.peerOf(t, n1).Access; a == nil || !slices.Equal(a.Open, []conn.Ports{tcp(gossip)}) ||
		!slices.Equal(a.Sends, []conn.Ports{tcp(7001)}) {
		t.Errorf("without a carrier, n1 has %+v", a)
	}
}

// A device uses an exit node the policy passes its traffic through, and no
// other; the exit node takes from each member what the policy passes it,
// and its DNS with it.
func TestThePolicyScopesExitNodes(t *testing.T) {
	f := exitFixture(t, 1, -1, nil)
	exit := f.nw.devices[1]
	f.learnExitDNS(t, exit, 7001, true, DefaultDNSPort)
	f.learn(t, f.nw.devices[2], 7002)
	f.nw.setPolicy(t, f, "pass from n2 to internet\n")
	f.d.SetExitChoice(ExitChoice{Chosen: true, Node: exit.record.Identity})
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if st := f.d.Status().Exit; st == nil || !strings.Contains(st.Refused, "access policy") {
		t.Errorf("an exit node the policy does not pass: %+v", st)
	}
	if got := f.peerRoutes(t, exit); len(got) > 0 {
		t.Errorf("routed through an exit node the policy does not pass: %v", got)
	}
	if e, _ := f.mgr.exitState(); e != conn.EgressRefused {
		t.Errorf("egress %v, want refused", e)
	}

	f.nw.setPolicy(t, f, "pass from n0 to internet via n1\n")
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if st := f.d.Status().Exit; st == nil || st.Refused != "" {
		t.Errorf("an exit node the policy passes: %+v", st)
	}
	if got := f.peerRoutes(t, exit); len(got) == 0 {
		t.Error("not routed through the exit node the policy passes")
	}
	// Its DNS, at the port it announces, which the policy names not.
	if a := f.peerOf(t, exit).Access; a == nil || !slices.Contains(a.Sends, conn.Ports{Proto: ipproto.UDP, First: DefaultDNSPort, Last: DefaultDNSPort}) {
		t.Errorf("this device may not ask the exit node's DNS: %+v", a)
	}
}

func TestAnExitNodeTakesWhatThePolicyPasses(t *testing.T) {
	f := exitFixture(t, 0, -1, func(o *Options) { o.ServeExit = true })
	f.learnOthers(t)
	f.nw.setPolicy(t, f, "pass from n1 to internet proto tcp port 443\npass from n2 to n0\n")
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	user := f.peerOf(t, f.nw.devices[1]).Access
	if user == nil || len(user.Through) == 0 {
		t.Fatalf("the member the policy passes may use n0 as %+v", user)
	}
	for _, th := range user.Through {
		if !slices.Equal(th.Ports, []conn.Ports{tcp(443)}) || th.Prefix.Contains(netip.MustParseAddr("198.18.0.2")) {
			t.Errorf("the member the policy passes may open %+v", th)
		}
	}
	for _, port := range []uint16{53, DefaultDNSPort} {
		if !slices.Contains(user.Open, conn.Ports{Proto: ipproto.UDP, First: port, Last: port}) {
			t.Errorf("the member using n0 may not ask its DNS on %d: %+v", port, user.Open)
		}
	}
	if other := f.peerOf(t, f.nw.devices[2]).Access; other == nil || len(other.Through) > 0 {
		t.Errorf("a member the policy passes no internet may use n0 as %+v", other)
	}
}

// A router's subnet is routed here as far as the policy passes it.
func TestThePolicyNarrowsSubnets(t *testing.T) {
	f := subnetFixture(t, 1, -1, prefixList("192.168.0.0/16"), nil)
	f.learnRouter(t, f.nw.devices[1], 7001, true)
	f.nw.setPolicy(t, f, "pass from n0 to { 192.168.10.0/24, 192.168.20.7 }\n")
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	want := prefixList("192.168.10.0/24", "192.168.20.7/32")
	if got := f.peerSubnets(t, f.nw.devices[1]); !slices.Equal(got, want) {
		t.Errorf("routed %v, want %v", got, want)
	}
	if r := f.subnetRoute(t, "192.168.0.0/16"); !r.InUse || !strings.Contains(r.Why, "passes 192.168.10.0/24, 192.168.20.7/32 alone") {
		t.Errorf("the status says %+v", r)
	}
	f.nw.setPolicy(t, f, "pass from n0 to n1 proto tcp port 22\n")
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := f.peerSubnets(t, f.nw.devices[1]); len(got) > 0 {
		t.Errorf("routed %v, which the policy passes none of", got)
	}
}

// A view stale past the TTL under a policy keeps its vouchers alone, and
// passes nothing with them but juist's own traffic, whatever the policy
// passed.
func TestAStaleViewFailsClosedUnderAPolicy(t *testing.T) {
	f := newFreshFixture(t, "")
	voucher, other := f.nw.devices[1], f.nw.devices[2]
	f.nw.setPolicy(t, f.reconcileFixture, "pass from any to any\n")
	f.d.offerLeases([][]byte{f.leaseFrom(t, 1, f.auth.Head(), f.start)})
	f.reconcileAt(t, f.start.Add(time.Minute))
	if a := f.peerOf(t, voucher).Access; a == nil || !slices.Equal(a.Open, []conn.Ports{{}, tcp(f.d.gossipPort)}) {
		t.Fatalf("fresh, the voucher has %+v", a)
	}
	f.reconcileAt(t, f.start.Add(testTTL))
	if !f.d.Status().Stale {
		t.Fatal("not stale at the TTL")
	}
	if f.mgr.has([32]byte(other.record.WireGuard)) {
		t.Error("a stale view keeps a member that is no voucher")
	}
	if a := f.peerOf(t, voucher).Access; a == nil || !slices.Equal(a.Open, []conn.Ports{tcp(f.d.gossipPort)}) ||
		!slices.Equal(a.Sends, []conn.Ports{tcp(7001)}) {
		t.Errorf("stale, the voucher has %+v", a)
	}
	if got := f.d.memberList(); !slices.Equal(got, []types.Identity{voucher.record.Identity}) {
		t.Errorf("stale, log sync reaches %v", got)
	}
}

// openAs is what dev opens of owner's sealed addresses with the key owner's
// record wraps for it; nil where none is wrapped for it.
func openAs(t *testing.T, network types.Hash, dev, owner *device, rec gossip.AddrKey, sealed []byte) []netip.AddrPort {
	t.Helper()
	scalar, _ := dev.recipient.Bytes()
	pair, err := addrkey.Pair(scalar, dev.record.Identity, owner.record.Identity, owner.record.X25519, network)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range rec.Wraps {
		if k, ok := addrkey.Unwrap(pair, owner.record.Identity, rec.ID, w); ok {
			addrs, err := addrkey.Open(k, sealed)
			if err != nil {
				t.Fatal(err)
			}
			return addrs
		}
	}
	return nil
}

// A device the policy keeps apart from a member seals its addresses, and
// only its peers open them: a member kept apart learns none. One every member
// peers announces them as before.
func TestAddressesAreForPeersAlone(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.devices[2].record.Roles = []types.Role{types.RoleRelayCapable}
	}, nil)
	f.learnOthers(t)
	n0, n1, n2 := f.nw.devices[0], f.nw.devices[1], f.nw.devices[2]
	f.mgr.mu.Lock()
	f.mgr.eps = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:41641")}
	f.mgr.mu.Unlock()
	f.nw.setPolicy(t, f, "pass from n0 to n2 proto tcp port 22\n")
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	e, ok := f.d.announcement()
	if !ok || len(e.Addrs) > 0 || e.Sealed == nil {
		t.Fatalf("kept apart from n1, n0 announces %+v", e)
	}
	rec, ok := f.d.ownAddrKey()
	if !ok || rec.Verify() != nil || len(rec.Wraps) != 1 {
		t.Fatalf("n0's address key is %+v", rec)
	}
	network := f.auth.State().GenesisHash()
	if got := openAs(t, network, n2, n0, rec, e.Sealed); !slices.Contains(got, netip.MustParseAddrPort("198.51.100.7:41641")) {
		t.Errorf("the peer n2 opens %v", got)
	}
	if got := openAs(t, network, n1, n0, rec, e.Sealed); got != nil {
		t.Errorf("n1, kept apart, opens %v", got)
	}

	f.nw.setPolicy(t, f, "pass from any to any\n")
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if e, _ := f.d.announcement(); len(e.Addrs) == 0 || e.Sealed != nil {
		t.Errorf("peering every member, n0 announces %+v", e)
	}
	if _, ok := f.d.ownAddrKey(); ok {
		t.Error("peering every member, n0 still hands an address key out")
	}
}

// A peer's sealed addresses are where it is reached once the key it wraps
// for this device arrives, and nowhere before.
func TestAPeersSealedAddressesOpenWithItsKey(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.devices[2].record.Roles = []types.Role{types.RoleRelayCapable}
	}, nil)
	n0, n1 := f.nw.devices[0], f.nw.devices[1]
	f.nw.setPolicy(t, f, "pass from n0 to n1\n")
	network := f.auth.State().GenesisHash()
	scalar, _ := n1.recipient.Bytes()
	k, err := addrkey.Derive(scalar, network, f.auth.State().Epoch(), []types.Identity{n0.record.Identity})
	if err != nil {
		t.Fatal(err)
	}
	addrs := []netip.AddrPort{netip.MustParseAddrPort("198.51.100.9:41641")}
	e, err := endpointFor(n1, 7001)
	if err != nil {
		t.Fatal(err)
	}
	e.Addrs, e.Sealed = nil, nil
	if e.Sealed, err = addrkey.Seal(k, addrs); err != nil {
		t.Fatal(err)
	}
	e.Seq++
	if err := e.SignPQ(n1.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := f.peerOf(t, n1).Endpoints; len(got) > 0 {
		t.Fatalf("before its key, n1 is reached at %v", got)
	}
	pair, err := addrkey.Pair(scalar, n1.record.Identity, n0.record.Identity, n0.record.X25519, network)
	if err != nil {
		t.Fatal(err)
	}
	rec := gossip.AddrKey{Owner: n1.record.Identity, ID: k.ID(), Seq: 1, Wraps: [][]byte{addrkey.Wrap(pair, n1.record.Identity, k)}}
	if err := rec.SignPQ(n1.identity); err != nil {
		t.Fatal(err)
	}
	if !f.d.endpoints.AddKey(rec) {
		t.Fatal("the key of a member was not taken")
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := f.peerOf(t, n1).Endpoints; !slices.Equal(got, addrs) {
		t.Errorf("with its key, n1 is reached at %v", got)
	}

	// After a restart, before any gossip, the key is read with the cache.
	path := filepath.Join(t.TempDir(), "endpoints")
	f.d.saveEndpointCache(path)
	f.d.endpoints.SetMembership(nil, nil)
	f.d.endpoints.Forget(n1.record.Identity)
	f.d.mu.Lock()
	f.d.opened = nil
	f.d.mu.Unlock()
	f.d.loadEndpointCache(path)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := f.peerOf(t, n1).Endpoints; !slices.Equal(got, addrs) {
		t.Errorf("restarted, n1 is reached at %v", got)
	}
}

// Beside a refused relay set, the ingresses are closed in the peer set last
// installed, not in one the data plane refused.
func TestIngressesCloseInThePeerSetInstalled(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[1].record.Roles = []types.Role{types.RoleIngress}
	}, nil)
	ingress := f.nw.devices[1]
	e, err := endpointFor(ingress, 7001)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	installed := len(f.mgr.snapshot())
	f.mgr.mu.Lock()
	f.mgr.err = errors.New("refused")
	f.mgr.mu.Unlock()
	f.learn(t, f.nw.devices[2], 7002)
	if err := f.d.Reconcile(); err == nil {
		t.Fatal("a refused peer set went unsaid")
	}
	f.mgr.mu.Lock()
	f.mgr.err, f.mgr.relayErr = nil, errors.New("refused")
	f.mgr.mu.Unlock()
	if err := f.d.Reconcile(); err == nil {
		t.Fatal("a refused relay set went unsaid")
	}
	if got := len(f.mgr.snapshot()); got != installed {
		t.Errorf("closing the ingresses installed %d peers, want the %d installed before", got, installed)
	}
	if a := f.peerOf(t, ingress).Access; a == nil || len(a.Open) != 1 {
		t.Errorf("the ingress may still open %+v", a)
	}
}

// A device decides to seal before anything can announce it, and before a
// reconcile can end early: a refused relay set does not send its addresses
// out in the clear.
func TestAddressesAreSealedFromTheStart(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.devices[2].record.Roles = []types.Role{types.RoleRelayCapable}
	}, nil)
	f.learnOthers(t)
	f.mgr.mu.Lock()
	f.mgr.eps = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:41641")}
	f.mgr.mu.Unlock()
	f.nw.setPolicy(t, f, "pass from n0 to n2\n")
	for _, restart := range []func(){
		func() { f.d.decideSealing() },
		func() {
			f.mgr.mu.Lock()
			f.mgr.relayErr = errors.New("refused")
			f.mgr.mu.Unlock()
			f.d.Reconcile()
		},
	} {
		f.d.mu.Lock()
		f.d.sealing, f.d.announced, f.d.signed = nil, nil, nil
		f.d.mu.Unlock()
		restart()
		if e, ok := f.d.announcement(); !ok || len(e.Addrs) > 0 || e.Sealed == nil {
			t.Errorf("kept apart from n1, n0 announces %+v", e)
		}
	}
}

// Where this device cannot make its address key, it announces no address
// rather than one every member reads.
func TestAddressesAreWithheldWithoutAKey(t *testing.T) {
	f := exitFixtureWith(t, func(nw *network) {
		nw.devices[2].record.Roles = []types.Role{types.RoleRelayCapable}
	}, nil)
	f.learnOthers(t)
	f.mgr.mu.Lock()
	f.mgr.eps = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:41641")}
	f.mgr.mu.Unlock()
	f.nw.setPolicy(t, f, "pass from n0 to n2\n")
	f.d.withholdAddrs()
	f.d.mu.Lock()
	f.d.announced, f.d.signed = nil, nil
	f.d.mu.Unlock()
	if e, ok := f.d.announcement(); !ok || len(e.Addrs) > 0 || e.Sealed != nil {
		t.Errorf("without a key, n0 announces %+v", e)
	}
	if _, ok := f.d.ownAddrKey(); ok {
		t.Error("without a key, n0 hands one out")
	}
}
