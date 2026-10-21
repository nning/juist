package daemon

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/internal/statedir"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/types"
)

// setRoles builds and signs a record granting a member a role set.
func (nw *network) setRoles(t *testing.T, f *reconcileFixture, id types.Identity, roles ...types.Role) {
	t.Helper()
	rec, err := f.auth.Builder().SetNodeRoutes(id, roles, nil)
	if err != nil {
		t.Fatalf("building the grant: %v", err)
	}
	if err := rec.Sign(nw.admin); err != nil {
		t.Fatalf("signing the grant: %v", err)
	}
	if err := f.d.Inform([]types.AUM{rec}); err != nil {
		t.Fatalf("applying the grant: %v", err)
	}
}

// A relay whose start a Close overtakes does not outlive the Close.
func TestARelayStartedAcrossCloseIsClosed(t *testing.T) {
	held, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	nw := newNetwork(t, 2)
	var d atomic.Pointer[Daemon]
	f := newReconcileFixtureOn(t, nw, func(o *Options) {
		o.RelayPort, o.PortFallback = uint16(held.Addr().(*net.TCPAddr).Port), true
		// The port taken is said between the relay's start and its keeping.
		o.Logf = func(format string, args ...any) {
			if strings.Contains(fmt.Sprintf(format, args...), "relay port") {
				d.Load().Close()
			}
		}
	})
	d.Store(f.d)
	nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)
	f.d.mu.Lock()
	srv := f.d.ownRelay.server
	f.d.mu.Unlock()
	if srv != nil {
		srv.Close()
		t.Fatal("the relay outlived Close")
	}
}

// learnRelay hands the daemon an announcement in which a peer says where its
// relay listens.
func (f *reconcileFixture) learnRelay(t *testing.T, dev *device, port uint16, info *gossip.RelayInfo) {
	t.Helper()
	_, discoPub, err := conn.NewDiscoKey()
	if err != nil {
		t.Fatal(err)
	}
	e := gossip.Endpoint{
		Identity:   dev.record.Identity,
		Disco:      gossip.DiscoKey(discoPub),
		Addrs:      []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), port)},
		GossipPort: port,
		Seq:        2,
		Relay:      info,
		Schema:     types.CurrentSchema,
	}
	if err := e.SignPQ(dev.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatalf("learning an announcement: %v", err)
	}
}

func testRelayInfo() *gossip.RelayInfo {
	return &gossip.RelayInfo{
		Port:     4443,
		STUNPort: 4443,
		Cert:     bytes.Repeat([]byte{7}, gossip.RelayCertSize),
		HostName: "abcdefgh.relay.juist.invalid",
	}
}

// TestRelayNeedsBothTheRoleAndTheAnnouncement: quorum says who may relay and
// the member says where. Either half alone must produce nothing — otherwise a
// member could volunteer itself as everyone's relay, or a grant would point
// the mesh at an address nobody stated.
func TestRelayNeedsBothTheRoleAndTheAnnouncement(t *testing.T) {
	f := newReconcileFixture(t, 3)
	other := f.nw.devices[1]

	// Announced but not granted.
	f.learnRelay(t, other, 41641, testRelayInfo())
	if err := f.d.Reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := f.mgr.relaySnapshot(); len(got) != 0 {
		t.Fatalf("installed %d relays for a member the log never granted the role", len(got))
	}

	// Granted and announced.
	f.nw.setRoles(t, f, other.record.Identity, types.RoleRelayCapable)
	relays := f.mgr.relaySnapshot()
	if len(relays) != 1 {
		t.Fatalf("installed %d relays, want 1", len(relays))
	}
	r := relays[0]
	if r.HostName != "abcdefgh.relay.juist.invalid" {
		t.Errorf("relay host name %q", r.HostName)
	}
	if r.STUNPort != 4443 {
		t.Errorf("relay STUN port %d, want 4443", r.STUNPort)
	}
	if want := netip.MustParseAddrPort("192.0.2.10:4443"); !slices.Contains(r.Addrs, want) {
		t.Errorf("relay addresses %v, want one at %v", r.Addrs, want)
	}
	if r.CertHash != [32]byte(bytes.Repeat([]byte{7}, 32)) {
		t.Error("the announced certificate hash did not reach the data plane")
	}
	if want := relayRegion(f.auth.State().GenesisHash(), other.record.Identity); r.Region != want {
		t.Errorf("relay region %d, want the derived %d", r.Region, want)
	}

	// Granted, then the grant withdrawn.
	f.nw.setRoles(t, f, other.record.Identity)
	if got := f.mgr.relaySnapshot(); len(got) != 0 {
		t.Errorf("a withdrawn grant left %d relays installed", len(got))
	}
}

// TestHomeRelayNamingNothingIsDropped: a peer names the region it can be
// reached through, and a region no relay-capable member serves is not a path.
// Installing it would make the data plane treat an address that reaches
// nothing as one that does.
func TestHomeRelayNamingNothingIsDropped(t *testing.T) {
	f := newReconcileFixture(t, 2)
	other := f.nw.devices[1]

	_, discoPub, err := conn.NewDiscoKey()
	if err != nil {
		t.Fatal(err)
	}
	e := gossip.Endpoint{
		Identity:   other.record.Identity,
		Disco:      gossip.DiscoKey(discoPub),
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:41641")},
		GossipPort: 41641,
		Seq:        3,
		HomeRelay:  4242,
		Schema:     types.CurrentSchema,
	}
	if err := e.SignPQ(other.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatalf("Learn: %v", err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	peers := f.mgr.snapshot()
	if len(peers) != 1 {
		t.Fatalf("installed %d peers, want 1", len(peers))
	}
	if peers[0].HomeRelay != 0 {
		t.Errorf("home relay %d survived with no relay serving it", peers[0].HomeRelay)
	}
}

// TestRelayRegionIsStableAndNetworkScoped: every member must derive the same
// number for a relay without agreeing on anything, and two networks must not
// derive the same one — a shared region would have members of one network
// sending to the other's relay.
func TestRelayRegionIsStableAndNetworkScoped(t *testing.T) {
	id, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	netA, netB := types.Hash{1}, types.Hash{2}
	a := relayRegion(netA, id.Public())
	if a != relayRegion(netA, id.Public()) {
		t.Error("the derivation is not a function of its inputs")
	}
	if a == relayRegion(netB, id.Public()) {
		t.Error("the same identity derives the same region in two networks")
	}
	if a < 1 || a > conn.MaxRegionID {
		t.Errorf("region %d is outside 1..%d, which the data plane truncates", a, conn.MaxRegionID)
	}
}

// TestCollidingRelayRegionsKeepOneDeterministically: the derivation is 16 bits
// wide because a peer's home region is, so two relay-capable members can
// collide. Both being installed would put two unmeshed relays in one region,
// where two clients can land on different servers and not reach each other.
func TestCollidingRelayRegionsKeepOneDeterministically(t *testing.T) {
	f := newReconcileFixture(t, 2)
	network := f.auth.State().GenesisHash()

	// Draw identities until two land in the same region: 16 bits, so a few
	// hundred draws is the expectation rather than the hope.
	seen := map[int]types.Identity{}
	var lo, hi types.Identity
	for range 200000 {
		id, err := types.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		r := relayRegion(network, id.Public())
		if other, dup := seen[r]; dup {
			lo, hi = other, id.Public()
			if hi.Compare(lo) < 0 {
				lo, hi = hi, lo
			}
			break
		}
		seen[r] = id.Public()
	}
	if lo.IsZero() {
		t.Skip("no region collision found; the derivation is wider than this test assumes")
	}

	held := map[types.Identity]gossip.Endpoint{
		lo: {Identity: lo, Addrs: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")},
			Relay: testRelayInfo()},
		hi: {Identity: hi, Addrs: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.2:41641")},
			Relay: testRelayInfo()},
	}
	nodes := []types.NodeRecord{
		{Identity: lo, Roles: []types.Role{types.RoleRelayCapable}},
		{Identity: hi, Roles: []types.Role{types.RoleRelayCapable}},
	}
	got := f.d.relaySet(network, nodes, held)
	if len(got) != 1 {
		t.Fatalf("two relays colliding on one region produced %d entries, want 1", len(got))
	}
	if want := relayRegion(network, lo); got[0].Region != want {
		t.Errorf("region %d survived, want %d", got[0].Region, want)
	}
	if got[0].Addrs[0].Addr() != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("the surviving relay is %v; the lower identity must keep the region", got[0].Addrs[0])
	}
}

// TestReflexiveAddressesJoinTheScanRatherThanReplacingIt: the interface scan is
// what makes a LAN with no internet work, and a reflexive address is what makes
// an off-LAN peer reachable. Neither is a superset of the other.
func TestReflexiveAddressesJoinTheScanRatherThanReplacingIt(t *testing.T) {
	scanned := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
	learned := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.7:33445"),
		netip.MustParseAddrPort("192.0.2.1:41641"), // the scan's own, reported back
	}
	got := mergeEndpoints(scanned, learned)
	for _, want := range []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.1:41641"),
		netip.MustParseAddrPort("198.51.100.7:33445"),
	} {
		if !slices.Contains(got, want) {
			t.Errorf("merged set %v is missing %v", got, want)
		}
	}
	if len(got) != 2 {
		t.Errorf("merged set %v holds a duplicate", got)
	}
	if len(mergeEndpoints(scanned, nil)) != 1 {
		t.Error("an empty learned set changed the scan")
	}

	// The bound is the announcement's, so a data plane reporting many
	// addresses cannot make one unencodable.
	many := make([]netip.AddrPort, 0, gossip.MaxEndpointAddrs*2)
	for i := range cap(many) {
		many = append(many, netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}), 1))
	}
	if n := len(mergeEndpoints(scanned, many)); n > gossip.MaxEndpointAddrs {
		t.Errorf("merged set holds %d addresses, over the %d announcement limit",
			n, gossip.MaxEndpointAddrs)
	}
}

// TestAFullScanDoesNotCrowdOutTheReflexiveAddress: a reflexive address is
// numerically higher than the private ranges a multi-homed host is full of, so
// truncating the sorted union would drop exactly the address the merge exists
// to carry — and the node would announce nothing but addresses no other member
// can reach.
func TestAFullScanDoesNotCrowdOutTheReflexiveAddress(t *testing.T) {
	scanned := make([]netip.AddrPort, 0, gossip.MaxEndpointAddrs)
	for i := range gossip.MaxEndpointAddrs {
		scanned = append(scanned,
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), 41641))
	}
	reflexive := netip.MustParseAddrPort("198.51.100.7:41641")

	got := mergeEndpoints(gossip.SortAddrs(scanned), []netip.AddrPort{reflexive})
	if len(got) != gossip.MaxEndpointAddrs {
		t.Fatalf("merged set holds %d addresses, want the %d limit",
			len(got), gossip.MaxEndpointAddrs)
	}
	if !slices.Contains(got, reflexive) {
		t.Errorf("the reflexive address was dropped for private ones: %v", got)
	}
}

// TestTheDataPlanesAddressesPassTheScansFilter: magicsock reads the host's
// interfaces too and leaves out only Tailscale's ranges, so without the scan's
// filter a device announces its own overlay addresses, and peers send its
// tunnel's traffic to the underlay at them.
func TestTheDataPlanesAddressesPassTheScansFilter(t *testing.T) {
	f := newReconcileFixture(t, 2)
	reflexive := netip.MustParseAddrPort("198.51.100.7:33445")
	var overlay []netip.AddrPort
	for _, p := range f.auth.State().Addrs(f.self.record.Identity, time.Now().Unix()) {
		overlay = append(overlay, netip.AddrPortFrom(p.Addr(), 41641))
	}
	if len(overlay) == 0 {
		t.Fatal("the device holds no overlay address")
	}
	f.mgr.mu.Lock()
	f.mgr.eps = append(slices.Clone(overlay), reflexive)
	f.mgr.mu.Unlock()

	e, ok := f.d.announcement()
	if !ok {
		t.Fatal("no announcement")
	}
	for _, ap := range overlay {
		if slices.Contains(e.Addrs, ap) {
			t.Errorf("the announcement carries the overlay address %v: %v", ap, e.Addrs)
		}
	}
	if !slices.Contains(e.Addrs, reflexive) {
		t.Errorf("the reflexive address was dropped: %v", e.Addrs)
	}

	bridge := netip.MustParseAddr("172.17.0.1")
	got := f.d.reachableLearned([]netip.AddrPort{netip.AddrPortFrom(bridge, 41641), reflexive}, []netip.Addr{bridge})
	if !slices.Equal(got, []netip.AddrPort{reflexive}) {
		t.Errorf("an address on an internal interface survived: %v", got)
	}
}

// TestThisDeviceRelaysOnlyWhereTheLogSaysSo: running a relay is a standing
// offer of this member's bandwidth, so it follows the grant rather than local
// configuration — and the announcement has to carry where it listens, or the
// grant points nowhere.
func TestThisDeviceRelaysOnlyWhereTheLogSaysSo(t *testing.T) {
	f := newReconcileFixture(t, 2)
	if err := f.d.Reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if f.d.Status().Relaying {
		t.Fatal("this device relays without the log granting it the role")
	}
	if e, ok := f.d.Announcement(); ok && e.Relay != nil {
		t.Fatal("the announcement names a relay this device is not running")
	}

	f.nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)
	if !f.d.Status().Relaying {
		t.Fatal("the grant did not start this device's relay")
	}
	e, ok := f.d.Announcement()
	if !ok || e.Relay == nil {
		t.Fatal("the announcement does not say where this device's relay listens")
	}
	if e.Relay.Port == 0 || e.Relay.HostName == "" || len(e.Relay.Cert) != gossip.RelayCertSize {
		t.Errorf("the relay announcement is incomplete: %+v", e.Relay)
	}
	if err := e.Verify(); err != nil {
		t.Errorf("the announcement carrying the relay does not verify: %v", err)
	}

	// The admission answer the relay serves from must be the log's, and it
	// must be current before the relay can accept anything.
	if !f.d.admitToRelay(f.nw.devices[1].record.WireGuard) {
		t.Error("a member would be refused by this device's relay")
	}
	var stranger types.WGKey
	stranger[0] = 9
	if f.d.admitToRelay(stranger) {
		t.Error("a key the log does not carry would be admitted to this device's relay")
	}

	f.nw.setRoles(t, f, f.self.record.Identity)
	if f.d.Status().Relaying {
		t.Error("withdrawing the grant did not stop this device's relay")
	}
	if e, ok := f.d.Announcement(); ok && e.Relay != nil {
		t.Error("the announcement still names a relay after the grant was withdrawn")
	}
}

// TestDisableRelayIsTheOperatorsVeto: the log decides who may relay, and the
// operator of the machine decides whether it will. Without that, a grant would
// commit someone else's uplink.
func TestDisableRelayIsTheOperatorsVeto(t *testing.T) {
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.DisableRelay = true })
	f.nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)
	if f.d.Status().Relaying {
		t.Error("a device with relaying disabled started one anyway")
	}
}

// TestOnlyUnheardMembersAreLookedUp: a rendezvous query is visible to whoever
// answers it, so asking after a member this node already holds an address for
// would spend privacy on nothing — and asking after every member at once is
// how a storage node would learn how many there are.
func TestOnlyUnheardMembersAreLookedUp(t *testing.T) {
	f := newReconcileFixture(t, 3)
	if err := f.d.Reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	want := []types.Identity{f.nw.devices[1].record.Identity, f.nw.devices[2].record.Identity}
	got := f.d.unheard()
	if len(got) != len(want) {
		t.Fatalf("unheard = %v, want the two members with no announcement", got)
	}
	for _, id := range want {
		if !slices.Contains(got, id) {
			t.Errorf("unheard omits %v", id.ShortString())
		}
	}
	if slices.Contains(got, f.self.record.Identity) {
		t.Error("this node is looking for itself")
	}

	// One announcement arrives; that member drops out of the set.
	f.learn(t, f.nw.devices[1], 41641)
	got = f.d.unheard()
	if len(got) != 1 || got[0] != f.nw.devices[2].record.Identity {
		t.Errorf("unheard = %v after one announcement, want only the remaining member", got)
	}
}

// TestAMemberWhoseTunnelIsDownIsLookedUpAgain: an announcement held can name
// a disco key its member replaced when it restarted, and then its pings are
// dropped unread on both sides. Holding it must not stop the lookup that
// would bring the current one; a member that answers is still not asked
// after.
func TestAMemberWhoseTunnelIsDownIsLookedUpAgain(t *testing.T) {
	f := newReconcileFixture(t, 4)
	for i, dev := range f.nw.devices[1:] {
		f.learn(t, dev, uint16(4001+i))
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	peer := func(i int) conn.Peer {
		want := conn.NodePublicFromRaw32([32]byte(f.nw.devices[i].record.WireGuard))
		for _, p := range f.mgr.snapshot() {
			if p.NodeKey == want {
				return p
			}
		}
		t.Fatalf("device %d is not installed", i)
		return conn.Peer{}
	}
	fresh, answering := peer(1), peer(2)
	f.mgr.mu.Lock()
	f.mgr.tunnels = map[uint64]conn.Tunnel{fresh.ID: {LastHandshake: time.Now()}}
	f.mgr.answers = map[netip.Addr]bool{answering.Addrs[0].Addr(): true}
	f.mgr.mu.Unlock()

	f.d.refreshReach(t.Context())
	got := f.d.wanted()
	if want := []types.Identity{f.nw.devices[3].record.Identity}; !slices.Equal(got, want) {
		t.Errorf("wanted = %v, want only the member whose tunnel does not answer", got)
	}
}

// TestAnAnnouncementFoundInTheDHTIsActedOn: where a record came from decides
// nothing but the log line — its authority is its signature — so the
// rendezvous path must reach the reconciler exactly as the LAN path does.
func TestAnAnnouncementFoundInTheDHTIsActedOn(t *testing.T) {
	f := newReconcileFixture(t, 2)
	if err := f.d.Reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	other := f.nw.devices[1]
	_, discoPub, err := conn.NewDiscoKey()
	if err != nil {
		t.Fatal(err)
	}
	e := gossip.Endpoint{
		Identity:   other.record.Identity,
		Disco:      gossip.DiscoKey(discoPub),
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("198.51.100.9:41641")},
		GossipPort: 41641,
		Seq:        7,
		Schema:     types.CurrentSchema,
	}
	if err := e.SignPQ(other.identity); err != nil {
		t.Fatal(err)
	}
	f.d.onFoundInDHT(e)
	if err := f.d.Reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	peers := f.mgr.snapshot()
	if len(peers) != 1 {
		t.Fatalf("installed %d peers after a DHT rendezvous, want 1", len(peers))
	}
	if len(peers[0].Endpoints) != 1 || peers[0].Endpoints[0] != e.Addrs[0] {
		t.Errorf("peer endpoints %v, want the address found through the DHT", peers[0].Endpoints)
	}
}

// TestTheEndpointCacheSurvivesARestart is what makes a cold start work where
// there is no LAN to be found on: a device that comes back knows where its
// peers were before it stopped, without a rendezvous round trip per peer.
func TestTheEndpointCacheSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	path := statedir.EndpointCachePath(dir)

	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.EndpointCachePath = path })
	other := f.nw.devices[1]
	want := f.learn(t, other, 41641)
	if err := f.d.Reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("nothing was written to %s: %v", path, err)
	}

	// A second daemon over the same network and the same cache file: what it
	// knows before hearing anything is what the first one wrote.
	auth, st := f.nw.authorityFor(t)
	mgr := &fakeManager{}
	restarted, err := New(Options{
		Authority:         auth,
		Storage:           st,
		Identity:          f.self.identity,
		Recipient:         f.self.recipient,
		WireGuard:         f.self.wgPrivate,
		Connect:           func(conn.Options) (conn.Manager, error) { return mgr, nil },
		DisableDiscovery:  true,
		DisableDHT:        true,
		EndpointCachePath: path,
		Logf:              safeLogf(t, "restarted: "),
	})
	if err != nil {
		t.Fatalf("restarting: %v", err)
	}
	defer restarted.Close()

	got, held := restarted.Endpoints().Get(other.record.Identity)
	if !held {
		t.Fatal("a restarted daemon knows nothing about its peer")
	}
	if got.Seq != want.Seq || len(got.Addrs) != 1 || got.Addrs[0] != want.Addrs[0] {
		t.Errorf("recovered %+v, want the announcement that was cached %+v", got, want)
	}
	if err := restarted.Reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n := len(mgr.snapshot()); n != 1 {
		t.Errorf("installed %d peers from the cache alone, want 1", n)
	}
}

// TestAnEditedEndpointCacheIsIgnored: the file is written by this node but is
// not trusted by it — anyone who can write the state directory could otherwise
// point every peer entry wherever they liked.
func TestAnEditedEndpointCacheIsIgnored(t *testing.T) {
	dir := t.TempDir()
	path := statedir.EndpointCachePath(dir)

	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.EndpointCachePath = path })
	other := f.nw.devices[1]
	f.learn(t, other, 41641)
	if err := f.d.Reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Flip a byte in the announced address. The signature covers it, so the
	// record must not survive the edit.
	var held []gossip.Endpoint
	if err := gossip.DecodeCachedEndpoints(raw, &held, nil); err != nil {
		t.Fatalf("decoding what was written: %v", err)
	}
	if len(held) != 1 {
		t.Fatalf("cached %d records, want 1", len(held))
	}
	held[0].Addrs = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:41641")}
	edited, err := gossip.EncodeCachedEndpoints(held, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}

	auth, st := f.nw.authorityFor(t)
	restarted, err := New(Options{
		Authority: auth, Storage: st,
		Identity: f.self.identity, Recipient: f.self.recipient, WireGuard: f.self.wgPrivate,
		Connect:           func(conn.Options) (conn.Manager, error) { return &fakeManager{}, nil },
		DisableDiscovery:  true,
		DisableDHT:        true,
		EndpointCachePath: path,
		Logf:              safeLogf(t, "restarted: "),
	})
	if err != nil {
		t.Fatalf("restarting: %v", err)
	}
	defer restarted.Close()
	if got, held := restarted.Endpoints().Get(other.record.Identity); held {
		t.Errorf("an edited announcement was adopted: %+v", got)
	}
}

// TestARelayStopsWhenMembershipCannotBeRead: who may use this member's relay
// is a membership question, and a node under a fork alarm cannot answer one.
// Leaving the relay up would keep admitting whoever the last state it managed
// to read said was a member — including someone a branch it cannot choose
// between has removed.
func TestARelayStopsWhenMembershipCannotBeRead(t *testing.T) {
	f := newReconcileFixture(t, 3)
	f.nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)
	if !f.d.Status().Relaying {
		t.Fatal("the grant did not start this device's relay")
	}
	member := f.nw.devices[1]
	if !f.d.admitToRelay(member.record.WireGuard) {
		t.Fatal("a member would be refused before the fork")
	}

	// A removal and a grant to the same member with the same parent, which
	// trust/log refuses to resolve.
	a, b := f.nw.devices[1], f.nw.devices[2]
	first, second := f.nw.conflictingFork(t, f.auth, a.record.Identity)
	_ = b
	if err := f.auth.Inform(first, second); err != nil {
		t.Fatalf("informing the fork: %v", err)
	}
	if f.auth.Alarm() == nil {
		t.Fatal("a conflicting fork did not raise an alarm")
	}
	if err := f.d.Reconcile(); err == nil {
		t.Fatal("reconcile succeeded under a fork alarm")
	}

	if f.d.Status().Relaying {
		t.Error("this device kept relaying under a fork alarm")
	}
	if f.d.admitToRelay(member.record.WireGuard) {
		t.Error("the relay would still admit a member it can no longer vouch for")
	}
}

// TestARemovedDeviceRelaysForNobody: the grant was in a state this device is
// no longer part of, so honouring it would be volunteering an uplink on behalf
// of a network that has removed you.
func TestARemovedDeviceRelaysForNobody(t *testing.T) {
	f := newReconcileFixture(t, 2)
	f.nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)
	if !f.d.Status().Relaying {
		t.Fatal("the grant did not start this device's relay")
	}

	rec := f.nw.removeNode(t, f.auth, f.self.record.Identity)
	if err := f.d.Inform([]types.AUM{rec}); err != nil {
		t.Fatalf("applying the removal: %v", err)
	}
	st := f.d.Status()
	if !st.NotMember {
		t.Fatal("the daemon does not know it was removed")
	}
	if st.Relaying {
		t.Error("a removed device kept relaying")
	}
}

// TestThisNodesOwnRelayIsInItsOwnMap: a member that is the network's only
// relay must still have a region to be reached through. Left out of its own
// map it would announce none, and every peer that cannot punch to it directly
// would have nowhere to fall back to.
func TestThisNodesOwnRelayIsInItsOwnMap(t *testing.T) {
	f := newReconcileFixture(t, 2)
	f.nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)

	relays := f.mgr.relaySnapshot()
	if len(relays) != 1 {
		t.Fatalf("installed %d relays, want this node's own", len(relays))
	}
	want := relayRegion(f.auth.State().GenesisHash(), f.self.record.Identity)
	if relays[0].Region != want {
		t.Errorf("relay region %d, want this node's own %d", relays[0].Region, want)
	}
	e, ok := f.d.Announcement()
	if !ok || e.Relay == nil {
		t.Fatal("this node announces no relay")
	}
	if relays[0].HostName != e.Relay.HostName {
		t.Errorf("the installed relay is %q, this node announces %q",
			relays[0].HostName, e.Relay.HostName)
	}
	if !relays[0].Own {
		t.Error("this node's own relay is installed as another's, to be dialled at its public address first")
	}

	// And it goes away with the grant, rather than lingering as a region
	// nothing serves.
	f.nw.setRoles(t, f, f.self.record.Identity)
	if got := f.mgr.relaySnapshot(); len(got) != 0 {
		t.Errorf("%d relays survived the grant being withdrawn", len(got))
	}
}

// TestTheRelayFloorIsReported is docs/04-architecture.md's floor: below two
// relay-capable members there is no fallback path left when one is offline.
// The count is of the *grant*, not of the relays installed, because a grant
// with no announcement behind it is a relay nobody can reach — and an operator
// needs to be able to tell those two situations apart.
func TestTheRelayFloorIsReported(t *testing.T) {
	f := newReconcileFixture(t, 3)
	if err := f.d.Reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := f.d.Status().RelayCapable; got != 0 {
		t.Fatalf("a network with no grants reports %d relay-capable members", got)
	}

	other := f.nw.devices[1]
	f.nw.setRoles(t, f, other.record.Identity, types.RoleRelayCapable)
	st := f.d.Status()
	if st.RelayCapable != 1 {
		t.Errorf("RelayCapable = %d after one grant, want 1", st.RelayCapable)
	}
	if st.Relays != 0 {
		t.Errorf("installed %d relays for a member that announced none", st.Relays)
	}

	f.learnRelay(t, other, 41641, testRelayInfo())
	if err := f.d.Reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if st := f.d.Status(); st.RelayCapable != 1 || st.Relays != 1 {
		t.Errorf("RelayCapable=%d Relays=%d after the announcement, want 1 and 1",
			st.RelayCapable, st.Relays)
	}
}

// An invite waits at the relays of other members the log makes
// relay-capable and whose announcement says where, with the certificate each
// announced; not at a member's that only announces, nor at its own.
func TestAnInviteWaitsAtTheMembersRelays(t *testing.T) {
	f := newReconcileFixture(t, 3)
	relayDev, plain := f.nw.devices[1], f.nw.devices[2]
	f.learnRelay(t, relayDev, 41641, testRelayInfo())
	f.learnRelay(t, plain, 41641, testRelayInfo())
	if got := f.d.inviteRelays(f.auth.State()); len(got) != 0 {
		t.Fatalf("an invite would wait at %d relays nobody granted", len(got))
	}
	f.nw.setRoles(t, f, relayDev.record.Identity, types.RoleRelayCapable)
	got := f.d.inviteRelays(f.auth.State())
	if len(got) != 1 {
		t.Fatalf("an invite would wait at %d relays, want 1", len(got))
	}
	if got[0].CertHash != [32]byte(bytes.Repeat([]byte{7}, 32)) || got[0].ServerName != "abcdefgh.relay.juist.invalid" ||
		!slices.Contains(got[0].Addrs, netip.MustParseAddrPort("192.0.2.10:4443")) {
		t.Fatalf("the relay to wait at is %+v", got[0])
	}
}

// A member nobody holds an announcement for, such as one just admitted, is
// looked up alongside members that are down, and one that stays down is
// looked up ever less often, but at least once an hour.
func TestLookupsPreferTheUnheardAndBackOffTheDown(t *testing.T) {
	c := &clock{now: time.Unix(1_700_000_000, 0)}
	f := newReconcileFixtureWith(t, 3, func(o *Options) { o.Clock = c.get })
	f.learn(t, f.nw.devices[2], 4002)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.refreshReach(t.Context()) // device 2 installed, answering nothing
	unheard, down := f.nw.devices[1].record.Identity, f.nw.devices[2].record.Identity
	if got := f.d.wanted(); !slices.Contains(got, unheard) || !slices.Contains(got, down) {
		t.Fatalf("wanted = %v, want the member not heard from and the one down", got)
	}
	start := c.get()
	var asked []time.Duration
	for s := time.Duration(0); s <= 3*time.Hour; s += 10 * time.Second {
		c.set(start.Add(s))
		if slices.Contains(f.d.wanted(), down) {
			asked = append(asked, s)
		}
	}
	for i := 2; i < len(asked); i++ {
		if gap, prev := asked[i]-asked[i-1], asked[i-1]-asked[i-2]; gap > time.Hour || gap < prev {
			t.Fatalf("lookups after %v: gaps must grow, up to the hour", asked)
		}
	}
	if len(asked) < 5 || asked[len(asked)-1] < 2*time.Hour {
		t.Fatalf("lookups after %v: a member down for hours is still looked up", asked)
	}
}

// A hint alone, as forged, adds no relay, and takes no relay's name from the
// member whose announcement claims it.
func TestAHintAloneAddsNoRelayAndTakesNoName(t *testing.T) {
	f := newReconcileFixture(t, 3)
	member, forged := f.nw.devices[1], f.nw.devices[2]
	named := testRelayInfo()
	named.Name = "relay.example.org"
	f.learnRelay(t, member, 41641, named)
	e, err := endpointFor(forged, 7002)
	if err != nil {
		t.Fatal(err)
	}
	f.learnHint(t, forged, e, func(h *gossip.Endpoint) {
		h.Seq, h.Relay = 2, &gossip.RelayInfo{Port: 4443, Cert: bytes.Repeat([]byte{9}, gossip.RelayCertSize),
			HostName: "forged.relay.juist.invalid", Name: named.Name}
	})
	f.nw.setRoles(t, f, member.record.Identity, types.RoleRelayCapable)
	f.nw.setRoles(t, f, forged.record.Identity, types.RoleRelayCapable)

	relays := f.mgr.relaySnapshot()
	if len(relays) != 1 || relays[0].Region != relayRegion(f.auth.State().GenesisHash(), member.record.Identity) {
		t.Fatalf("installed relays %+v, want the member's alone", relays)
	}
	invite := f.d.inviteRelays(f.auth.State())
	if len(invite) != 1 || invite[0].Name != named.Name {
		t.Fatalf("an invite would wait at %+v, want the member's relay under its name", invite)
	}
}
