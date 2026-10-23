package daemon

import (
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

// A peer announcing a home and no address reaches named relays alone, and
// this device keeps its connection to that home unless it rests; one with
// an address, open or sealed, is not walled.
func TestAPeerWalledIsKeptAtItsHome(t *testing.T) {
	for _, rests := range []bool{false, true} {
		f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Rests = rests })
		f.nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)
		region := uint16(relayRegion(f.auth.State().GenesisHash(), f.self.record.Identity))
		dev := f.nw.devices[1]
		at := time.Now()
		for _, c := range []struct {
			name   string
			change func(*gossip.Endpoint)
			walled bool
		}{
			{"an address", func(*gossip.Endpoint) {}, false},
			{"no address", func(e *gossip.Endpoint) { e.Addrs = nil }, true},
			{"no home", func(e *gossip.Endpoint) { e.Addrs, e.HomeRelay = nil, 0 }, false},
		} {
			at = at.Add(time.Second)
			e := f.signedBy(t, dev, at)
			e.HomeRelay = region
			c.change(&e)
			if err := e.SignPQ(dev.identity); err != nil {
				t.Fatal(err)
			}
			if err := f.d.Learn(e); err != nil {
				t.Fatal(err)
			}
			if err := f.d.Reconcile(); err != nil {
				t.Fatal(err)
			}
			if got, want := f.installed(t, 1).Walled, c.walled && !rests; got != want {
				t.Errorf("resting %v, a peer announcing %s is kept at its home: %v, want %v", rests, c.name, got, want)
			}
		}
	}
	if walled(gossip.Endpoint{HomeRelay: 7, Sealed: []byte{1}}) {
		t.Error("a peer whose addresses are sealed is taken for walled")
	}
}

// A walled device announces no address, which is what tells its peers.
func TestAWalledDeviceAnnouncesNoAddress(t *testing.T) {
	f := newReconcileFixture(t, 2)
	f.mgr.mu.Lock()
	f.mgr.home = 7
	f.mgr.mu.Unlock()
	if e, ok := f.d.announcement(); !ok || len(e.Addrs) == 0 {
		t.Fatalf("a device not walled announces %v", e.Addrs)
	}
	f.mgr.mu.Lock()
	f.mgr.walled = true
	f.mgr.mu.Unlock()
	if e, ok := f.d.announcement(); !ok || len(e.Addrs) != 0 || len(e.Sealed) != 0 || e.HomeRelay != 7 {
		t.Errorf("a walled device announces addresses %v, sealed %d bytes, home %d", e.Addrs, len(e.Sealed), e.HomeRelay)
	}
}

// A peer down that this device's relay said is not there, since it went
// down, is named in the status for juist health.
func TestAPeerNotAtTheRelayIsNamed(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 3, func(o *Options) { o.Clock = c.get })
	f.learnOthers(t)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.refreshReach(t.Context())
	gone, away := f.installed(t, 1), f.installed(t, 2)
	f.mgr.mu.Lock()
	f.mgr.notAt = map[uint64]time.Time{gone.ID: t0.Add(time.Second), away.ID: t0.Add(-time.Hour)}
	f.mgr.mu.Unlock()
	c.set(t0.Add(30 * time.Second))
	f.d.refreshReach(t.Context())
	st := f.d.Status()
	if len(st.TunnelsDown) != 2 {
		t.Fatalf("down: %v, want both peers", st.TunnelsDown)
	}
	name := f.nw.devices[1].record.Name
	if !slices.Equal(st.NotAtRelay, []string{name}) {
		t.Errorf("not at the relay: %v, want %s alone, which it said so of since it went down", st.NotAtRelay, name)
	}
}

// A peer the relay says is not there as the check that finds it down probes
// it is named.
func TestAPeerNotAtTheRelayAsItIsProbedIsNamed(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	f.learnOthers(t)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	gone := f.installed(t, 1)
	f.mgr.mu.Lock()
	f.mgr.onProbe = func() {
		f.mgr.mu.Lock()
		f.mgr.notAt = map[uint64]time.Time{gone.ID: c.get()}
		f.mgr.mu.Unlock()
		c.set(c.get().Add(2 * time.Second))
	}
	f.mgr.mu.Unlock()
	f.d.refreshReach(t.Context())
	st := f.d.Status()
	if name := f.nw.devices[1].record.Name; !slices.Equal(st.NotAtRelay, []string{name}) {
		t.Errorf("not at the relay: %v, want %s, which the relay said so of as it was probed", st.NotAtRelay, name)
	}
}

// The ingress that relays takes relay.DOMAIN, the one of the lowest identity
// where several do; without a domain, or an ingress that relays, none does.
func TestTheIngressRelayIsNamedUnderTheDomain(t *testing.T) {
	nw := newNetworkMutated(t, 4, func(nw *network) { nw.domain = "pub.example.org" })
	f := newReconcileFixtureOn(t, nw, nil)
	state := func() string {
		st, err := f.d.TrustedState()
		if err != nil {
			t.Fatal(err)
		}
		name, _ := IngressRelayName(st, time.Now().Unix())
		return name
	}
	a, b := nw.devices[1].record.Identity, nw.devices[2].record.Identity
	nw.setRoles(t, f, a, types.RoleIngress)
	if got := state(); got != "" {
		t.Errorf("an ingress that does not relay names %q", got)
	}
	nw.setRoles(t, f, a, types.RoleIngress, types.RoleRelayCapable)
	nw.setRoles(t, f, b, types.RoleIngress, types.RoleRelayCapable)
	st, _ := f.d.TrustedState()
	name, id := IngressRelayName(st, time.Now().Unix())
	first := a
	if b.Compare(a) < 0 {
		first = b
	}
	if name != "relay.pub.example.org" || id != first {
		t.Errorf("the relay named %q is %v's, want relay.pub.example.org of %v", name, id.ShortString(), first.ShortString())
	}
}

// The mesh of the ingress that relays runs its relay as relay.DOMAIN unless
// a name is set, and is restarted without it once the role goes.
func TestTheIngressMeshTakesTheRelaysName(t *testing.T) {
	nw := newNetworkMutated(t, 2, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RoleIngress, types.RoleRelayCapable}
	})
	home := socketDir(t)
	writeDevice(t, home, nw.devices[0])
	st, err := store.Open(filepath.Join(home, keys.LogDir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.FromRecords(st, []types.AUM{nw.genesis}); err != nil {
		t.Fatal(err)
	}
	f := startServiceWith(t, nw, home, func(o *Options) {
		inTunnel(o)
		o.DisableRelay, o.ACMEDirectory = true, "http://127.0.0.1:1/directory"
	})
	if m := f.s.Mesh(); m == nil || m.relayName != "relay.pub.example.org" {
		t.Fatalf("the ingress's mesh runs its relay as %q", m.relayName)
	}
	m := f.s.Mesh()
	f.s.followRelayName()
	if f.s.Mesh() != m {
		t.Fatal("the mesh restarted with its relay's name unmoved")
	}
	rec, err := m.authority.Builder().SetNodeRoutes(nw.devices[0].record.Identity, []types.Role{types.RoleRelayCapable}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := m.Inform([]types.AUM{rec}); err != nil {
		t.Fatal(err)
	}
	f.s.followRelayName()
	if m2 := f.s.Mesh(); m2 == m || m2 == nil || m2.relayName != "" {
		t.Errorf("without the ingress role, the mesh runs its relay as %q, restarted %v", m2.relayName, m2 != m)
	}
}

// A walled device names, for a peer it reaches through a relay, its own
// home where it does not reach the peer's, as that is where it sends.
func TestAWalledDeviceSaysWhereItMeetsAPeer(t *testing.T) {
	f := newReconcileFixture(t, 3)
	relayDev, dev := f.nw.devices[1], f.nw.devices[2]
	f.nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)
	f.nw.setRoles(t, f, relayDev.record.Identity, types.RoleRelayCapable)
	f.learnRelay(t, relayDev, 4001, testRelayInfo())
	own := relayRegion(f.auth.State().GenesisHash(), f.self.record.Identity)
	far := relayRegion(f.auth.State().GenesisHash(), relayDev.record.Identity)
	e := f.signedBy(t, dev, time.Now())
	e.HomeRelay = uint16(far)
	if err := e.SignPQ(dev.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	peer := f.installed(t, 2)
	if peer.HomeRelay != far {
		t.Fatalf("the peer is homed at %d, want %d", peer.HomeRelay, far)
	}
	f.mgr.mu.Lock()
	f.mgr.home, f.mgr.answers = own, map[netip.Addr]bool{peer.Addrs[0].Addr(): true}
	f.mgr.mu.Unlock()
	via := func() string {
		f.d.refreshReach(t.Context())
		for _, r := range f.d.Status().Reach {
			if r.Identity == dev.record.Identity {
				return r.Relay
			}
		}
		return ""
	}
	if got := via(); got != relayDev.record.Name {
		t.Errorf("a device not walled reaches the peer via %q, want its home's", got)
	}
	f.mgr.mu.Lock()
	f.mgr.walled = true
	f.mgr.mu.Unlock()
	if got := via(); got != f.self.record.Name {
		t.Errorf("a walled device reaches the peer via %q, want its own home's", got)
	}
}

// The relays asked for an announcement are the home's, then those named on
// 443, where a walled device leaves its own; a walled device asks those
// alone.
func TestNamedRelaysAreAskedFirst(t *testing.T) {
	f := newReconcileFixture(t, 2)
	relay := func(region int, name string) conn.Relay { return conn.Relay{Region: region, Name: name} }
	f.d.mu.Lock()
	f.d.relays = []conn.Relay{relay(1, ""), relay(2, ""), relay(3, "a.example.org"), relay(4, ""), relay(5, "b.example.org")}
	f.d.mu.Unlock()
	f.mgr.mu.Lock()
	f.mgr.home = 4
	f.mgr.mu.Unlock()
	regions := func() []int {
		var out []int
		for _, r := range f.d.askable() {
			out = append(out, r.Region)
		}
		return out
	}
	if got := regions(); !slices.Equal(got, []int{4, 3, 5, 1}) {
		t.Errorf("asked %v, want the home, the named, then the rest, four in all", got)
	}
	f.mgr.mu.Lock()
	f.mgr.walled = true
	f.mgr.mu.Unlock()
	if got := regions(); !slices.Equal(got, []int{4, 3, 5}) {
		t.Errorf("walled, asked %v, want the home and the named", got)
	}
}

// An ingress whose membership expired names no relay, and the next that
// relays takes the name.
func TestAnExpiredIngressNamesNoRelay(t *testing.T) {
	expired := uint64(time.Now().Add(-time.Minute).Unix())
	var gone types.Identity
	nw := newNetworkMutated(t, 4, func(nw *network) {
		nw.domain = "pub.example.org"
		low := 1
		if nw.devices[2].record.Identity.Compare(nw.devices[1].record.Identity) < 0 {
			low = 2
		}
		nw.devices[low].record.Expiry, gone = expired, nw.devices[low].record.Identity
	})
	f := newReconcileFixtureOn(t, nw, nil)
	a, b := nw.devices[1].record.Identity, nw.devices[2].record.Identity
	nw.setRoles(t, f, a, types.RoleIngress, types.RoleRelayCapable)
	nw.setRoles(t, f, b, types.RoleIngress, types.RoleRelayCapable)
	st, err := f.d.TrustedState()
	if err != nil {
		t.Fatal(err)
	}
	live := a
	if gone == a {
		live = b
	}
	if name, id := IngressRelayName(st, time.Now().Unix()); name != "relay.pub.example.org" || id != live {
		t.Errorf("the relay named %q is %v's, want the live ingress %v's", name, id.ShortString(), live.ShortString())
	}
}

// A relay name set, or one the role gave and still gives, is no move; one
// the role gives where none ran at the start is.
func TestTheRelayNameMovesByTheRoleAlone(t *testing.T) {
	nw := newNetworkMutated(t, 2, func(nw *network) {
		nw.domain = "pub.example.org"
		nw.devices[0].record.Roles = []types.Role{types.RoleIngress, types.RoleRelayCapable}
	})
	for _, c := range []struct {
		name, byRole string
		moved        bool
	}{
		{"relay.example.net", "", false},
		{"relay.pub.example.org", "relay.pub.example.org", false},
		{"", "", true},
	} {
		f := newReconcileFixtureOn(t, nw, func(o *Options) { o.RelayName, o.RelayNameByRole = c.name, c.byRole })
		st, err := f.d.TrustedState()
		if err != nil {
			t.Fatal(err)
		}
		if got := f.d.relayNameMoved(st); got != c.moved {
			t.Errorf("running as %q, %q by the role: moved %v, want %v", c.name, c.byRole, got, c.moved)
		}
	}
	f := newReconcileFixtureOn(t, newNetworkMutated(t, 2, func(nw *network) { nw.domain = "pub.example.org" }),
		func(o *Options) { o.RelayName = "relay.example.net" })
	st, err := f.d.TrustedState()
	if err != nil {
		t.Fatal(err)
	}
	if f.d.relayNameMoved(st) {
		t.Error("a relay name set, with no ingress role, moved")
	}
}
