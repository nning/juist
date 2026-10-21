package daemon

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// A network with a prefix of its own claims it, and while it moves the range
// it moves away from; one founded before prefixes were drawn claims only its
// members' addresses, or it would keep every host in a newer network from
// joining it too.
func TestHostClaims(t *testing.T) {
	p := netip.MustParsePrefix
	legacy := newNetwork(t, 2)
	auth, _ := legacy.authorityFor(t)
	v4, ula := hostClaims(auth.State(), 0)
	slices.SortFunc(v4, types.ComparePrefix)
	if want := []netip.Prefix{p("198.18.0.1/32"), p("198.18.0.2/32")}; !slices.Equal(v4, want) {
		t.Errorf("a network without a prefix of its own claims %v, want %v", v4, want)
	}
	if ula != auth.State().ULA() {
		t.Errorf("claims %v, not its ULA", ula)
	}
	own := newNetworkMutated(t, 2, func(nw *network) {
		prefix := p("198.18.0.0/24")
		nw.v4Prefix = &prefix
	})
	auth, _ = own.authorityFor(t)
	if v4, _ := hostClaims(auth.State(), 0); !slices.Equal(v4, []netip.Prefix{p("198.18.0.0/24")}) {
		t.Errorf("a network with a prefix of its own claims %v, not the prefix alone", v4)
	}
	var moves []types.MemberV4
	for i, d := range own.devices {
		moves = append(moves, types.MemberV4{Identity: d.record.Identity, V4: netip.AddrFrom4([4]byte{10, 7, 0, byte(i + 1)})})
	}
	renumber, err := auth.Builder().RenumberNetwork(p("10.7.0.0/24"), moves, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := renumber.Sign(own.admin); err != nil {
		t.Fatal(err)
	}
	if err := auth.Inform(renumber); err != nil {
		t.Fatal(err)
	}
	v4, _ = hostClaims(auth.State(), 999)
	slices.SortFunc(v4, types.ComparePrefix)
	if want := []netip.Prefix{p("10.7.0.0/24"), p("198.18.0.0/24")}; !slices.Equal(v4, want) {
		t.Errorf("moving, the network claims %v, want %v", v4, want)
	}
	if v4, _ := hostClaims(auth.State(), 1001); !slices.Equal(v4, []netip.Prefix{p("10.7.0.0/24")}) {
		t.Errorf("past the deadline the network claims %v, want its new prefix alone", v4)
	}
}

// Only a lower instance's holdings conflict: this one's table is consulted
// first, so a higher instance's routes are the ones that never win. The same
// network anywhere below comes before any IPv4, and one answering on its
// socket is taken at its claims.
func TestFindHostConflict(t *testing.T) {
	p := netip.MustParsePrefix
	nw := newNetwork(t, 2)
	auth, _ := nw.authorityFor(t)
	state := auth.State()
	ula := state.ULA()
	ownV6 := netip.PrefixFrom(state.Addr6(nw.devices[1].record.Identity), 128)
	kernel := func(n int, dev string, ps ...string) lowerInstance {
		h := conn.Holding{Instance: n, Device: dev}
		for _, s := range ps {
			h.Prefixes = append(h.Prefixes, p(s))
		}
		return lowerInstance{n: n, held: &h}
	}
	answering := func(n int, st ipc.Status) lowerInstance {
		st.Device = instance.Name(n)
		return lowerInstance{n: n, st: &st}
	}
	for _, tc := range []struct {
		name  string
		lower []lowerInstance
		want  *ipc.HostConflict
	}{
		{"nothing below", nil, nil},
		{"elsewhere", []lowerInstance{kernel(0, "juist0", "198.18.4.1/32")}, nil},
		{"a member's address", []lowerInstance{kernel(0, "juist0", "198.18.0.2/32")},
			&ipc.HostConflict{Instance: 0, Device: "juist0", Held: p("198.18.0.2/32"), Claim: p("198.18.0.2/32")}},
		{"a route over a member", []lowerInstance{kernel(1, "juist1", "198.18.0.0/30")},
			&ipc.HostConflict{Instance: 1, Device: "juist1", Held: p("198.18.0.0/30")}}, // either member's
		{"this network", []lowerInstance{kernel(0, "juist0", ownV6.String())},
			&ipc.HostConflict{Instance: 0, Device: "juist0", SameNetwork: true, Held: ownV6, Claim: ula}},
		{"a default route is no network", []lowerInstance{kernel(0, "juist0", "::/0")}, nil},
		{"this network, past an IPv4 conflict", []lowerInstance{kernel(0, "juist0", "198.18.0.1/32"),
			kernel(1, "juist1", ownV6.String())},
			&ipc.HostConflict{Instance: 1, Device: "juist1", SameNetwork: true, Held: ownV6, Claim: ula}},
		{"claims that overlap", []lowerInstance{answering(0, ipc.Status{InNetwork: true, Network: types.Hash{9},
			V4Claims: []netip.Prefix{p("198.18.0.0/16")}})},
			&ipc.HostConflict{Instance: 0, Device: "juist0", Held: p("198.18.0.0/16")}},
		{"claims elsewhere", []lowerInstance{answering(0, ipc.Status{InNetwork: true, Network: types.Hash{9},
			V4Claims: []netip.Prefix{p("198.18.4.0/22")}})}, nil},
		{"this network, answering", []lowerInstance{answering(0, ipc.Status{InNetwork: true, Network: state.GenesisHash()})},
			&ipc.HostConflict{Instance: 0, Device: "juist0", SameNetwork: true, Held: ula, Claim: ula}},
		{"removed from it", []lowerInstance{answering(0, ipc.Status{InNetwork: true, Network: state.GenesisHash(),
			Derived: ipc.Derived{NotMember: true}, V4Claims: []netip.Prefix{p("198.18.0.0/16")}})}, nil},
		{"itself without IPv4", []lowerInstance{answering(0, ipc.Status{InNetwork: true, Network: types.Hash{9},
			V4Claims: []netip.Prefix{p("198.18.0.0/16")}, HostConflict: &ipc.HostConflict{}})}, nil},
		{"its mesh not up", []lowerInstance{answering(0, ipc.Status{InNetwork: true, Network: types.Hash{9},
			V4Claims: []netip.Prefix{p("198.18.0.0/16")}, StartError: "no device"})}, nil},
		{"this network, its mesh not up", []lowerInstance{answering(0, ipc.Status{InNetwork: true,
			Network: state.GenesisHash(), StartError: "no device"})},
			&ipc.HostConflict{Instance: 0, Device: "juist0", SameNetwork: true, Held: ula, Claim: ula}},
		{"no device", []lowerInstance{{n: 0, st: &ipc.Status{InNetwork: true, Network: types.Hash{9},
			V4Claims: []netip.Prefix{p("198.18.0.0/16")}}}}, nil},
	} {
		got := findHostConflict(state, 0, tc.lower)
		if got != nil && tc.want != nil && !tc.want.Claim.IsValid() && got.Claim.Overlaps(got.Held) {
			tc.want.Claim = got.Claim
		}
		if (got == nil) != (tc.want == nil) || got != nil && *got != *tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// hostFixture is a service as instance 1, beside an instance 0 whose
// holdings the test sets, and a record of the addresses each mesh started on.
type hostFixture struct {
	*serviceFixture
	mu      sync.Mutex
	held    []conn.Holding
	heldErr error
	lower   *ipc.Status // what instance 0 answers, or nil for no answer
	// lowerHome is instance 0's state directory, empty for none.
	lowerHome string
	starts    [][]netip.Prefix
}

func newHostFixture(t *testing.T, held ...conn.Holding) *hostFixture {
	t.Helper()
	return newHostFixtureBeside(t, "", held...)
}

// newHostFixtureBeside is newHostFixture with instance 0's state directory
// at lowerHome from the start.
func newHostFixtureBeside(t *testing.T, lowerHome string, held ...conn.Holding) *hostFixture {
	t.Helper()
	h := &hostFixture{held: held, lowerHome: lowerHome}
	h.serviceFixture = newServiceFixtureWith(t, func(o *Options) {
		o.Instance = 1
		o.HostHoldings = func(self int, own string) ([]conn.Holding, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			if self != 1 {
				t.Errorf("asked for the holdings of all but instance %d", self)
			}
			return slices.Clone(h.held), h.heldErr
		}
		o.LowerHome = func(int) string { h.mu.Lock(); defer h.mu.Unlock(); return h.lowerHome }
		o.LowerStatus = func(_ context.Context, n int) (*ipc.Status, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			if n != 0 {
				t.Errorf("instance 1 asked instance %d", n)
			}
			if h.lower == nil {
				return nil, errors.New("no answer")
			}
			st := *h.lower
			return &st, nil
		}
		connect := o.Connect
		o.Connect = func(co conn.Options) (conn.Manager, error) {
			h.mu.Lock()
			h.starts = append(h.starts, slices.Clone(co.Self.Addrs))
			h.mu.Unlock()
			return connect(co)
		}
	})
	return h
}

func (h *hostFixture) setHeld(held ...conn.Holding) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.held = held
}

// lastStart is the addresses the newest mesh started on, and how many started.
func (h *hostFixture) lastStart() ([]netip.Prefix, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.starts) == 0 {
		return nil, 0
	}
	return h.starts[len(h.starts)-1], len(h.starts)
}

// holding is the addresses the data plane holds now, and how many meshes
// started.
func (h *hostFixture) holding() ([]netip.Prefix, int) {
	addrs, n := h.lastStart()
	if set := h.mgr.selfSet(); len(set) > 0 {
		addrs = set[len(set)-1].Addrs
	}
	return addrs, n
}

// learnPeer has the running mesh hear the other member's announcement.
func (h *hostFixture) learnPeer(t *testing.T) {
	t.Helper()
	e, err := endpointFor(h.nw.devices[1], 4001)
	if err != nil {
		t.Fatal(err)
	}
	m := h.s.Mesh()
	if err := m.Learn(e); err != nil {
		t.Fatal(err)
	}
	if err := m.Reconcile(); err != nil {
		t.Fatal(err)
	}
}

// installed is the peer set the data plane was last given.
func (h *hostFixture) installed() []conn.Peer {
	h.mgr.mu.Lock()
	defer h.mgr.mu.Unlock()
	return slices.Clone(h.mgr.peers)
}

func hasV4(addrs []netip.Prefix) bool {
	return slices.ContainsFunc(addrs, func(p netip.Prefix) bool { return p.Addr().Is4() })
}

// A lower instance holding a member's IPv4 address routes it into its own
// network, so this one runs on IPv6 alone and says why, keeping its log in
// step; it takes IPv4 back once the conflict is gone.
func TestAnInstanceRunsWithoutIPv4WhereALowerOneHoldsIt(t *testing.T) {
	p := netip.MustParsePrefix
	h := newHostFixture(t, conn.Holding{Instance: 0, Device: "juist0", Prefixes: []netip.Prefix{p("198.18.0.2/32")}})
	addrs, n := h.lastStart()
	if n != 1 || hasV4(addrs) || len(addrs) == 0 {
		t.Fatalf("the mesh started %d times, last on %v; want once, on IPv6 alone", n, addrs)
	}
	h.learnPeer(t)
	if peers := h.installed(); len(peers) != 1 || hasV4(peers[0].Addrs) || len(peers[0].Addrs) == 0 {
		t.Fatalf("installed peers %+v; want the other member, on IPv6 alone", peers)
	}
	for _, ap := range h.s.Mesh().overlayGossipAddrs(h.nw.devices[1].record.Identity) {
		if ap.Addr().Is4() {
			t.Errorf("log sync would dial the other member at %v", ap)
		}
	}

	// A host that cannot be read keeps what was found: no restart, no mode
	// change, the failure logged.
	h.mu.Lock()
	h.heldErr = errors.New("netlink says no")
	h.mu.Unlock()
	h.s.checkHost()
	if _, n := h.lastStart(); n != 1 || h.s.Status().HostConflict == nil {
		t.Fatalf("an unreadable host restarted the mesh or dropped the conflict (%d starts)", n)
	}
	h.mu.Lock()
	h.heldErr = nil
	h.mu.Unlock()
	st := h.s.Status()
	if st.HostConflict == nil || st.HostConflict.SameNetwork || st.StartError != "" || st.Instance != 1 {
		t.Fatalf("status: conflict %+v, start error %q, instance %d", st.HostConflict, st.StartError, st.Instance)
	}
	if hasV4(st.Addrs) {
		t.Errorf("the status lists IPv4 addresses the device does not have: %v", st.Addrs)
	}

	// The same conflict again is no restart.
	h.s.checkHost()
	if _, again := h.lastStart(); again != 1 || len(h.mgr.selfSet()) != 0 {
		t.Fatalf("an unchanged conflict restarted or moved the mesh")
	}
	// Gone once is not gone: a lower instance restarting holds nothing for
	// a moment. Seen gone a few checks in a row, it is.
	h.setHeld()
	for range conflictClearChecks - 1 {
		h.s.checkHost()
	}
	if addrs, n := h.holding(); n != 1 || hasV4(addrs) {
		t.Fatalf("IPv4 came back on the first check that found the conflict gone")
	}
	h.s.checkHost()
	addrs, n = h.holding()
	if n != 1 || !hasV4(addrs) {
		t.Fatalf("with the conflict gone the mesh started %d times and holds %v; want it running on, with IPv4", n, addrs)
	}
	h.learnPeer(t)
	if peers := h.installed(); len(peers) != 1 || !hasV4(peers[0].Addrs) {
		t.Fatalf("installed peers %+v; want the other member with its IPv4 address back", peers)
	}
	if st := h.s.Status(); st.HostConflict != nil {
		t.Errorf("the conflict outlived itself: %+v", st.HostConflict)
	}

	// A lower instance coming to hold it later takes IPv4 away again.
	h.setHeld(conn.Holding{Instance: 0, Device: "juist0", Prefixes: []netip.Prefix{p("198.18.0.0/16")}})
	h.s.checkHost()
	if addrs, n := h.holding(); n != 1 || hasV4(addrs) {
		t.Fatalf("a new conflict: the mesh started %d times and holds %v", n, addrs)
	}
	h.learnPeer(t)
	if peers := h.installed(); len(peers) != 1 || hasV4(peers[0].Addrs) {
		t.Fatalf("installed peers %+v; want the other member, on IPv6 alone", peers)
	}
}

// A lower instance that answers is taken at its claims, which move with its
// log and not with its peers: overlapping claims yield IPv4 whatever its
// device holds at the moment, and its very network, answered, is refused
// from the start.
func TestALowerInstanceIsAskedFirst(t *testing.T) {
	p := netip.MustParsePrefix
	h := newHostFixture(t)
	h.mu.Lock()
	h.lower = &ipc.Status{InNetwork: true, Network: types.Hash{9}, Device: "juist0",
		V4Claims: []netip.Prefix{p("198.18.0.0/16")}}
	h.mu.Unlock()
	h.s.checkHost()
	if addrs, n := h.holding(); n != 1 || hasV4(addrs) {
		t.Fatalf("claims that overlap: the mesh started %d times and holds %v", n, addrs)
	}
	if c := h.s.Status().HostConflict; c == nil || c.Held != p("198.18.0.0/16") || c.Device != "juist0" {
		t.Fatalf("conflict %+v", c)
	}

	auth, _ := h.nw.authorityFor(t)
	h.mu.Lock()
	h.lower = &ipc.Status{InNetwork: true, Network: auth.State().GenesisHash(), Device: "juist0"}
	h.mu.Unlock()
	h.s.checkHost()
	if h.s.Mesh() != nil || !strings.Contains(h.s.Status().StartError, "runs on this host already") {
		t.Fatalf("its own network answered below: mesh %v, %q", h.s.Mesh() != nil, h.s.Status().StartError)
	}
}

// The same network twice on one host is refused outright: the instance
// holding it already is the device's membership there.
func TestAnInstanceRefusesANetworkTheHostRunsAlready(t *testing.T) {
	h := newHostFixture(t)
	auth, _ := h.nw.authorityFor(t)
	other := netip.PrefixFrom(auth.State().Addr6(h.nw.devices[1].record.Identity), 128)
	h.setHeld(conn.Holding{Instance: 0, Device: "juist0", Prefixes: []netip.Prefix{other}})
	h.s.checkHost()
	if h.s.Mesh() != nil {
		t.Fatal("the mesh runs beside another instance of its own network")
	}
	st := h.s.Status()
	if st.HostConflict == nil || !st.HostConflict.SameNetwork || !strings.Contains(st.StartError, "already") {
		t.Fatalf("status: conflict %+v, start error %q", st.HostConflict, st.StartError)
	}
	// It starts once the other goes.
	h.setHeld()
	for range conflictClearChecks - 1 {
		h.s.retryMesh()
	}
	if h.s.Mesh() != nil {
		t.Fatal("the mesh started on the first check that found the other instance gone")
	}
	h.s.retryMesh()
	if h.s.Mesh() == nil {
		t.Fatalf("the mesh did not start once the other instance went: %q", h.s.Status().StartError)
	}
}

// The default instance never yields: its table is consulted first.
func TestTheLowerInstanceKeepsItsAddresses(t *testing.T) {
	p := netip.MustParsePrefix
	var starts [][]netip.Prefix
	f := newServiceFixtureWith(t, func(o *Options) {
		o.HostHoldings = func(int, string) ([]conn.Holding, error) {
			return []conn.Holding{{Instance: 4, Device: "juist4", Prefixes: []netip.Prefix{p("198.18.0.0/15")}}}, nil
		}
		connect := o.Connect
		o.Connect = func(co conn.Options) (conn.Manager, error) {
			starts = append(starts, co.Self.Addrs)
			return connect(co)
		}
	})
	if len(starts) != 1 || !hasV4(starts[0]) {
		t.Fatalf("the default instance started on %v", starts)
	}
	if st := f.s.Status(); st.HostConflict != nil {
		t.Fatalf("a higher instance's holdings conflict with the default's: %+v", st.HostConflict)
	}
}

// Started beside an instance that holds a network and does not answer yet,
// as when both start at boot, an instance waits for it before it takes
// IPv4: the kernel shows nothing of one that is not up.
func TestAnInstanceWaitsForOneBelowThatIsNotUpYet(t *testing.T) {
	below := t.TempDir()
	if err := os.MkdirAll(filepath.Join(below, keys.LogDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(below, keys.LogDir, "anchor"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHostFixtureBeside(t, below)
	if addrs, n := h.lastStart(); n != 1 || hasV4(addrs) {
		t.Fatalf("beside a silent instance the mesh started %d times, last on %v; want IPv6 alone", n, addrs)
	}
	if c := h.s.Status().HostConflict; c == nil || !c.Unanswered || c.Instance != 0 {
		t.Fatalf("conflict %+v, want instance 0 unanswered", c)
	}
	// It answers, claiming elsewhere: IPv4 follows after the usual checks.
	h.mu.Lock()
	h.lower = &ipc.Status{InNetwork: true, Network: types.Hash{9}, Device: "juist0",
		V4Claims: []netip.Prefix{netip.MustParsePrefix("198.18.4.0/22")}}
	h.mu.Unlock()
	for range conflictClearChecks {
		h.s.checkHost()
	}
	if addrs, n := h.holding(); n != 1 || !hasV4(addrs) {
		t.Fatalf("once it answered the mesh started %d times and holds %v; want with IPv4", n, addrs)
	}

	// Once a mesh has run, one below that goes quiet is no reason to drop
	// IPv4: it is restarting, and it held nothing of this network's.
	h.mu.Lock()
	h.lower = nil
	h.mu.Unlock()
	h.s.checkHost()
	if addrs, n := h.holding(); n != 1 || !hasV4(addrs) {
		t.Fatalf("a lower instance going quiet restarted the mesh or took IPv4")
	}
}

// Beside a directory that holds no network, or where no home is known,
// nothing is waited for.
func TestAnInstanceBesideAnEmptyHomeTakesIPv4(t *testing.T) {
	h := newHostFixtureBeside(t, t.TempDir())
	if addrs, n := h.lastStart(); n != 1 || !hasV4(addrs) {
		t.Fatalf("the mesh started %d times, last on %v", n, addrs)
	}
}

func TestLowerHomesBeside(t *testing.T) {
	if lowerHomesBeside("/var/lib/juist", 0) != nil || lowerHomesBeside("/tmp/dev", 2) != nil {
		t.Fatal("homes derived outside the packaged layout")
	}
	f := lowerHomesBeside("/var/lib/juist/juist3/", 3)
	if f(0) != "/var/lib/juist" || f(2) != "/var/lib/juist/juist2" {
		t.Fatalf("lower homes %q, %q", f(0), f(2))
	}
}
