package conn

import (
	"math"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"tailscale.com/types/key"
)

// TestSetPeersRejects covers the validation SetPeers does before touching any
// state. These are all conditions the membership log is supposed to prevent, so
// reaching one means a bug upstream — the point is that it fails loudly here
// rather than silently binding an overlay address to the wrong key.
//
// Only rejection paths are exercised, so no engine is needed.
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
			// An entry carrying our own node key is skipped as the
			// reconciler's rendering of this node itself — but only if it
			// agrees with Self. A diverging one means the log and the data
			// plane disagree about who we are.
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

// TestPeerDelta covers the device-convergence decision SetPeers makes for
// each previous peer: whose sessions are dead and must be reset. Getting it
// wrong is invisible in a single-run test — it shows up as a restarted peer
// blackholing until WireGuard's rekey timers expire — so the decision is
// pinned here. (Everything retained is re-synced wholesale; there is no
// decision to pin on that side.)
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

// TestDiscoKeyAgrees pins the property NewDiscoKey's comment claims: the
// public half it derives through crypto/ecdh equals the one the connectivity
// stack derives from the same private bytes. If the two ever disagreed — say,
// over clamping — every announcement would carry a disco key its owner does
// not answer to, and the only symptom would be a mesh where discovery works
// and no tunnel ever comes up.
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
