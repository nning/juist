package conn

import (
	"math"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"tailscale.com/net/dns"
	"tailscale.com/types/key"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

// TestSetPeersRejects covers the validation SetPeers does before touching any
// state. All of these mean a bug upstream, and the point is that they fail
// loudly rather than binding an overlay address to the wrong key. Only
// rejection paths, so no engine is needed.
func TestSetPeersRejects(t *testing.T) {
	selfKey, selfDisco := key.NewNode(), key.NewDisco()
	m := &tsManager{
		logf: t.Logf,
		self: Self{
			ID:       1,
			NodeKey:  selfKey,
			DiscoKey: selfDisco,
			Addrs:    []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		},
	}
	m.state.Store(&peerState{})
	k1, k2 := key.NewNode().Public(), key.NewNode().Public()
	d1, d2 := key.NewDisco().Public(), key.NewDisco().Public()
	addr := func(s string) []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix(s)} }

	tests := []struct {
		name  string
		peers []Peer
		want  string
	}{
		{
			name:  "zero node key",
			peers: []Peer{{ID: 2, DiscoKey: d1, Addrs: addr("100.64.0.5/32")}},
			want:  "zero node key",
		},
		{
			name:  "zero ID",
			peers: []Peer{{ID: 0, NodeKey: k1, DiscoKey: d1, Addrs: addr("100.64.0.5/32")}},
			want:  "must be non-zero",
		},
		{
			name:  "ID overflows NodeID",
			peers: []Peer{{ID: math.MaxUint64, NodeKey: k1, DiscoKey: d1, Addrs: addr("100.64.0.5/32")}},
			want:  "overflows",
		},
		{
			name: "two peers share a disco key",
			peers: []Peer{
				{ID: 2, NodeKey: k1, DiscoKey: d1, Addrs: addr("100.64.0.5/32")},
				{ID: 3, NodeKey: k2, DiscoKey: d1, Addrs: addr("100.64.0.6/32")},
			},
			want: "same disco key",
		},
		{
			name:  "peer claims our disco key",
			peers: []Peer{{ID: 2, NodeKey: k1, DiscoKey: selfDisco.Public(), Addrs: addr("100.64.0.5/32")}},
			want:  "own disco key",
		},
		{
			name:  "peer shares our ID",
			peers: []Peer{{ID: 1, NodeKey: k1, DiscoKey: d1, Addrs: addr("100.64.0.5/32")}},
			want:  "shares our node ID",
		},
		{
			name: "two peers share an ID",
			peers: []Peer{
				{ID: 2, NodeKey: k1, DiscoKey: d1, Addrs: addr("100.64.0.5/32")},
				{ID: 2, NodeKey: k2, DiscoKey: d2, Addrs: addr("100.64.0.6/32")},
			},
			want: "share ID 2",
		},
		{
			name: "same key twice",
			peers: []Peer{
				{ID: 2, NodeKey: k1, DiscoKey: d1, Addrs: addr("100.64.0.5/32")},
				{ID: 3, NodeKey: k1, DiscoKey: d1, Addrs: addr("100.64.0.6/32")},
			},
			want: "appears twice",
		},
		{
			name:  "zero disco key",
			peers: []Peer{{ID: 2, NodeKey: k1, Addrs: addr("100.64.0.5/32")}},
			want:  "no disco key",
		},
		{
			name:  "no overlay address",
			peers: []Peer{{ID: 2, NodeKey: k1, DiscoKey: d1}},
			want:  "no overlay address",
		},
		{
			// The security-relevant one: AllowedIPs authorizes source
			// addresses, so a broad prefix would let this peer impersonate
			// any member inside it.
			name:  "broad prefix",
			peers: []Peer{{ID: 2, NodeKey: k1, DiscoKey: d1, Addrs: addr("100.64.0.0/10")}},
			want:  "not a single-IP prefix",
		},
		{
			name: "two peers claim one address",
			peers: []Peer{
				{ID: 2, NodeKey: k1, DiscoKey: d1, Addrs: addr("100.64.0.5/32")},
				{ID: 3, NodeKey: k2, DiscoKey: d2, Addrs: addr("100.64.0.5/32")},
			},
			want: "claimed by both",
		},
		{
			name:  "peer claims our own address",
			peers: []Peer{{ID: 2, NodeKey: k1, DiscoKey: d1, Addrs: addr("100.64.0.1/32")}},
			want:  "our own address",
		},
		{
			// A v4-mapped v6 prefix aliases the plain v4 address while
			// comparing unequal to it, so it would slip past the
			// duplicate-address checks above — and never match a packet.
			name:  "v4-mapped v6 prefix",
			peers: []Peer{{ID: 2, NodeKey: k1, DiscoKey: d1, Addrs: addr("::ffff:100.64.0.5/128")}},
			want:  "v4-mapped",
		},
		{
			// An entry carrying our own node key is this node's own
			// rendering, but only if it agrees with Self.
			name:  "self entry with wrong ID",
			peers: []Peer{{ID: 9, NodeKey: selfKey.Public(), DiscoKey: selfDisco.Public(), Addrs: addr("100.64.0.1/32")}},
			want:  "diverges from Self",
		},
		{
			name:  "self entry with wrong address",
			peers: []Peer{{ID: 1, NodeKey: selfKey.Public(), DiscoKey: selfDisco.Public(), Addrs: addr("100.64.0.9/32")}},
			want:  "diverges from Self",
		},
		{
			// The operationally fatal divergence: peers reach us with the
			// disco key the log records, so a mismatch is every inbound
			// disco exchange failing with no other symptom.
			name:  "self entry with wrong disco key",
			peers: []Peer{{ID: 1, NodeKey: selfKey.Public(), DiscoKey: d1, Addrs: addr("100.64.0.1/32")}},
			want:  "diverges from Self",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The bare test manager has no engine, so a rejection check
			// that regresses to acceptance would die on a nil pointer deep
			// in SetPeers; turn that into a diagnosis instead of a crash.
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("SetPeers accepted %s and panicked on the engine-less test manager: %v", tc.name, r)
				}
			}()
			if err := validatePeers(m.self, tc.peers); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("validatePeers: %v, want an error mentioning %q", err, tc.want)
			}
			err := m.SetPeers(tc.peers)
			if err == nil {
				t.Fatalf("SetPeers accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			// Rejection must leave no trace: a partially applied peer set is
			// worse than a refused one.
			if n := len(m.state.Load().peers); n != 0 {
				t.Errorf("rejected call left %d peers behind", n)
			}
		})
	}
}

// TestNewRejectsBadSelf covers the Self fields whose absence or malformation
// would otherwise produce a silent connectivity failure rather than an error.
func TestNewRejectsBadSelf(t *testing.T) {
	addrs := []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}
	for _, tc := range []struct {
		name string
		self Self
		want string
	}{
		{"no node key", Self{ID: 1, DiscoKey: key.NewDisco(), Addrs: addrs}, "NodeKey"},
		{"no disco key", Self{ID: 1, NodeKey: key.NewNode(), Addrs: addrs}, "DiscoKey"},
		{"zero ID", Self{NodeKey: key.NewNode(), DiscoKey: key.NewDisco(), Addrs: addrs}, "non-zero"},
		{"no addresses", Self{ID: 1, NodeKey: key.NewNode(), DiscoKey: key.NewDisco()}, "Addrs"},
		{
			"broad prefix",
			Self{ID: 1, NodeKey: key.NewNode(), DiscoKey: key.NewDisco(),
				Addrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}},
			"single-IP",
		},
		{
			"v4-mapped v6 prefix",
			Self{ID: 1, NodeKey: key.NewNode(), DiscoKey: key.NewDisco(),
				Addrs: []netip.Prefix{netip.MustParsePrefix("::ffff:100.64.0.1/128")}},
			"v4-mapped",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr, err := New(Options{Self: tc.self, Logf: t.Logf})
			if err == nil {
				mgr.Close()
				t.Fatalf("New accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestPeerDelta covers which previous peers SetPeers resets. Getting it wrong
// is invisible in a single run: it shows up as a restarted peer blackholing
// until WireGuard's rekey timers expire.
func TestPeerDelta(t *testing.T) {
	keys := make([]key.NodePublic, 5)
	for i := range keys {
		keys[i] = key.NewNode().Public()
	}
	kUnchanged, kDiscoRotated, kAddrChanged, kRemoved, kNew := keys[0], keys[1], keys[2], keys[3], keys[4]
	d1, d2 := key.NewDisco().Public(), key.NewDisco().Public()
	addr := func(s string) []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix(s)} }

	prev := map[key.NodePublic]Peer{
		kUnchanged:    {DiscoKey: d1, Addrs: addr("100.64.0.2/32")},
		kDiscoRotated: {DiscoKey: d1, Addrs: addr("100.64.0.3/32")},
		kAddrChanged:  {DiscoKey: d1, Addrs: addr("100.64.0.4/32")},
		kRemoved:      {DiscoKey: d1, Addrs: addr("100.64.0.5/32")},
	}
	next := map[key.NodePublic]Peer{
		kUnchanged:    {DiscoKey: d1, Addrs: addr("100.64.0.2/32")},
		kDiscoRotated: {DiscoKey: d2, Addrs: addr("100.64.0.3/32")},
		kAddrChanged:  {DiscoKey: d1, Addrs: addr("100.64.0.40/32")},
		kNew:          {DiscoKey: d1, Addrs: addr("100.64.0.6/32")},
	}

	resets := peerDelta(prev, next)

	sortKeys := func(ks []key.NodePublic) {
		slices.SortFunc(ks, func(a, b key.NodePublic) int { return strings.Compare(a.String(), b.String()) })
	}
	wantResets := []key.NodePublic{kDiscoRotated, kRemoved}
	sortKeys(resets)
	sortKeys(wantResets)
	if !slices.Equal(resets, wantResets) {
		t.Errorf("resets = %v, want removed + disco-rotated peers %v", resets, wantResets)
	}
}

// TestDiscoKeyAgrees pins what NewDiscoKey claims: the public half it derives
// through crypto/ecdh equals the one the connectivity stack derives. If they
// disagreed over clamping, every announcement would carry a key its owner does
// not answer to, and discovery would work while no tunnel came up.
func TestDiscoKeyAgrees(t *testing.T) {
	for range 32 {
		priv, pub, err := NewDiscoKey()
		if err != nil {
			t.Fatalf("NewDiscoKey: %v", err)
		}
		got := DiscoKeyFromRaw32(priv).Public()
		want := DiscoPublicFromRaw32(pub)
		if got != want {
			t.Fatalf("stack derives %v from the private key, announcement would carry %v",
				got.ShortString(), want.ShortString())
		}
	}
}

// fakeEngine implements just enough of [wgengine.Engine] for a reconfiguration.
// The embedded nil interface means any other method panics rather than
// silently doing nothing, which is what a test wants of a method it did not
// expect to be called. Like wgengine, it records a router config before it
// hands it to router, and never hands one it recorded again.
type fakeEngine struct {
	wgengine.Engine
	router *flakyRouter
	last   *router.Config
}

func (f *fakeEngine) GetFilter() *filter.Filter { return nil }
func (f *fakeEngine) SetFilter(*filter.Filter)  {}
func (f *fakeEngine) Reconfig(_ *wgcfg.Config, rt *router.Config, _ *dns.Config) error {
	if f.last != nil && reflect.DeepEqual(f.last, rt) {
		return wgengine.ErrNoChanges
	}
	f.last = rt
	return f.router.Set(rt)
}

// TestReconfigRetriesAfterAFailedRouter: a router that fails once must be
// reprogrammed by the next reconfiguration, even though the peer set has not
// changed. Without the retry the engine reports ErrNoChanges forever and the
// host keeps the routes it had when the failure happened.
func TestReconfigRetriesAfterAFailedRouter(t *testing.T) {
	r := &flakyRouter{fail: true}
	m := &tsManager{
		logf:     t.Logf,
		eng:      &fakeEngine{router: r},
		osRouter: r,
		self: Self{
			ID:      1,
			NodeKey: key.NewNode(),
			Addrs:   []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		},
	}
	m.state.Store(&peerState{})

	if err := m.reconfig(); err == nil {
		t.Fatal("a failing router did not surface an error")
	}
	if !m.routerStale {
		t.Fatal("a failed reconfiguration was not recorded as stale")
	}
	if n := r.set(false); n != 0 {
		t.Fatalf("the router took %d configs despite failing", n)
	}
	if err := m.reconfig(); err != nil {
		t.Fatalf("the retry failed: %v", err)
	}
	if m.routerStale {
		t.Fatal("a successful reconfiguration left the router marked stale")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.took) == 0 {
		t.Fatal("the retry never reached the router: the host keeps the old routes")
	}
	for _, c := range r.took {
		if !slices.Equal(c.LocalAddrs, m.self.Addrs) {
			t.Fatalf("the router took %v, want this node's addresses %v alone", c.LocalAddrs, m.self.Addrs)
		}
	}
}

// validatePeers accepts what a healthy log produces: peers on both families,
// and this node's own entry however its addresses are ordered.
func TestValidatePeersAccepts(t *testing.T) {
	selfKey, selfDisco := key.NewNode(), key.NewDisco()
	self := Self{ID: 1, NodeKey: selfKey, DiscoKey: selfDisco, Addrs: []netip.Prefix{
		netip.MustParsePrefix("198.18.0.1/32"), netip.MustParsePrefix("fd00::1/128")}}
	k1, k2 := key.NewNode().Public(), key.NewNode().Public()
	d1, d2 := key.NewDisco().Public(), key.NewDisco().Public()
	pfx := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	for _, tc := range []struct {
		name  string
		peers []Peer
	}{
		{"none", nil},
		{"one", []Peer{{ID: 2, NodeKey: k1, DiscoKey: d1, Addrs: pfx("198.18.0.2/32")}}},
		{"both families", []Peer{
			{ID: 2, NodeKey: k1, DiscoKey: d1, Addrs: pfx("198.18.0.2/32", "fd00::2/128")},
			{ID: 3, NodeKey: k2, DiscoKey: d2, Addrs: pfx("fd00::3/128", "198.18.0.3/32"),
				Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.3:41641")}},
		}},
		{"self entry, reordered", []Peer{
			{ID: 1, NodeKey: selfKey.Public(), DiscoKey: selfDisco.Public(), Addrs: pfx("fd00::1/128", "198.18.0.1/32")},
			{ID: 2, NodeKey: k1, DiscoKey: d1, Addrs: pfx("198.18.0.2/32")},
		}},
	} {
		if err := validatePeers(self, tc.peers); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// What SetPeers stores is its own copy, without this node's entry, indexed by
// every address.
func TestNewPeerStateIndexesACopy(t *testing.T) {
	selfKey := key.NewNode()
	k1 := key.NewNode().Public()
	addrs := []netip.Prefix{netip.MustParsePrefix("198.18.0.2/32"), netip.MustParsePrefix("fd00::2/128")}
	peers := []Peer{
		{ID: 1, NodeKey: selfKey.Public(), Addrs: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")}},
		{ID: 2, NodeKey: k1, DiscoKey: key.NewDisco().Public(), Addrs: addrs},
	}
	st, nodes := newPeerState(selfKey.Public(), clonePeers(peers), sameHome)
	addrs[0] = netip.MustParsePrefix("198.18.0.9/32")
	if len(st.peers) != 1 || len(nodes) != 1 || st.nodes[k1].Key() != k1 {
		t.Fatalf("state holds %d peers and %d views, want only the other peer", len(st.peers), len(nodes))
	}
	for _, a := range []string{"198.18.0.2", "fd00::2"} {
		if st.byIP[netip.MustParseAddr(a)] != k1 {
			t.Errorf("%s does not route to its peer", a)
		}
	}
	if got := st.peers[k1].Addrs[0]; got != netip.MustParsePrefix("198.18.0.2/32") {
		t.Errorf("a caller's later write reached the stored state: %v", got)
	}
}
