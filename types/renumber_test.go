package types

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestRenumberingShape(t *testing.T) {
	a, b := mustIdentity(t).Public(), mustIdentity(t).Public()
	if a.Compare(b) > 0 {
		a, b = b, a
	}
	prev := Hash{1}
	to := netip.MustParsePrefix("10.7.0.0/22")
	addr := netip.MustParseAddr
	pfx := netip.MustParsePrefix
	v4 := addr("10.7.0.9")
	network := func(r Renumbering) AUM {
		return AUM{Kind: KindRenumberNetwork, Prev: &prev, Renumber: &r}
	}
	node := func(r Renumbering) AUM {
		return AUM{Kind: KindRenumberNode, Prev: &prev, Subject: &a, Renumber: &r}
	}
	valid := []AUM{
		network(Renumbering{Until: 9, Prefix: &to, Addrs: []MemberV4{{a, addr("10.7.0.1")}, {b, addr("10.7.0.2")}}}),
		node(Renumbering{Until: 9, V4: &v4}),
		{Kind: KindRetireAddresses, Prev: &prev},
	}
	for _, rec := range valid {
		if err := rec.ValidateUnsigned(); err != nil {
			t.Errorf("valid %v refused: %v", rec.Kind, err)
		}
	}
	public, own := pfx("8.8.8.0/24"), addr("10.7.0.1")
	for _, tc := range []struct {
		name string
		rec  AUM
		want string
	}{
		{"no deadline", node(Renumbering{V4: &v4}), "deadline"},
		{"a node record with no address", node(Renumbering{Until: 9}), "names no address"},
		{"a node record with a prefix", node(Renumbering{Until: 9, V4: &v4, Prefix: &to}), "network renumbering"},
		{"a node record without a subject", AUM{Kind: KindRenumberNode, Prev: &prev,
			Renumber: &Renumbering{Until: 9, V4: &v4}}, "want exactly"},
		{"a public prefix", network(Renumbering{Until: 9, Prefix: &public}), "not private"},
		{"a network record with one address", network(Renumbering{Until: 9, Prefix: &to, V4: &v4}),
			"single address"},
		{"an address outside the prefix", network(Renumbering{Until: 9, Prefix: &to,
			Addrs: []MemberV4{{a, addr("10.8.0.1")}}}), "outside"},
		{"members out of order", network(Renumbering{Until: 9, Prefix: &to,
			Addrs: []MemberV4{{b, addr("10.7.0.1")}, {a, addr("10.7.0.2")}}}), "sorted"},
		{"one address for two members", network(Renumbering{Until: 9, Prefix: &to,
			Addrs: []MemberV4{{a, own}, {b, own}}}), "two members"},
		{"a retirement with a payload", AUM{Kind: KindRetireAddresses, Prev: &prev,
			Renumber: &Renumbering{Until: 9, V4: &v4}}, "want exactly"},
	} {
		err := tc.rec.ValidateUnsigned()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error naming %q", tc.name, err, tc.want)
		}
	}
}

func TestRetiringAddressesInState(t *testing.T) {
	rec, _ := testAUM(t)
	base := rec.State
	base.Schema = CurrentSchema
	own := netip.MustParsePrefix("10.7.0.0/22")
	old := base.Nodes[0].V4
	moved := netip.MustParseAddr("10.7.0.1")

	gh := Hash{7}
	renumbered := func() *Snapshot {
		s := base.Clone()
		s.GenesisHash = &gh
		s.V4Prefix = &own
		s.V4Retiring = &RetiringRanges{Prefixes: []netip.Prefix{CGNAT}, Until: 9}
		v4 := moved
		s.Nodes[0].V4, s.Nodes[0].Retiring = &v4, &RetiringV4{Addr: *old, Until: 9}
		s.Nodes[0].Routes = nil
		a := mustIdentity(t)
		ak, nk := a.SigningKey(), mustIdentity(t).SigningKey()
		s.Admins[0].Public, s.Admins[0].Signing, s.Admins[0].Endorsement, s.Nodes[0].Signing = a.Public(), &ak, a.Endorsement(), &nk
		return s
	}
	if err := renumbered().StaticValidate(false); err != nil {
		t.Fatalf("a renumbered state refused: %v", err)
	}
	s := renumbered()
	if err := s.ValidateInNetwork(); err != nil {
		t.Fatalf("a renumbered state refused in its network: %v", err)
	}
	if got := s.V4Ranges(); !slices.Equal(got, []netip.Prefix{own, CGNAT}) {
		t.Errorf("ranges %v, want the prefix and the one it retires", got)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"below schema 5", func(s *Snapshot) { s.Schema = SchemaOverlayV4 }},
		{"a node retiring below schema 5", func(s *Snapshot) { s.Schema = SchemaOverlayV4; s.V4Retiring = nil }},
		{"retiring ranges with no prefix", func(s *Snapshot) { s.V4Prefix = nil }},
		{"retiring ranges with no deadline", func(s *Snapshot) { s.V4Retiring.Until = 0 }},
		{"no retiring ranges named", func(s *Snapshot) { s.V4Retiring.Prefixes = nil }},
		{"a node retiring what it holds", func(s *Snapshot) { s.Nodes[0].Retiring.Addr = moved }},
		{"a node retiring with no address", func(s *Snapshot) { s.Nodes[0].V4 = nil }},
		{"a node retiring with no deadline", func(s *Snapshot) { s.Nodes[0].Retiring.Until = 0 }},
	} {
		s := renumbered()
		tc.mutate(s)
		if err := s.StaticValidate(false); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
	genesis := renumbered()
	genesis.GenesisHash = nil
	if err := genesis.StaticValidate(true); err == nil {
		t.Error("a genesis retiring what it never had was accepted")
	}

	// In its network, a retiring address is held like any other, and must lie
	// in a range the state names; an address held for good may not lie in a
	// retiring one.
	two := renumbered()
	two.V4Retiring = nil
	*two.Nodes[0].V4, two.Nodes[0].Retiring.Addr = netip.MustParseAddr("10.7.0.5"), moved
	other := two.Nodes[0]
	other.Identity = mustIdentity(t).Public()
	other.WireGuard, other.X25519, other.MLKEM = WGKey{9}, X25519Key{9}, MLKEMKey{9}
	other.Retiring = nil
	claim := moved
	other.V4 = &claim
	two.Nodes = append(two.Nodes, other)
	if err := two.ValidateInNetwork(); err == nil || !strings.Contains(err.Error(), "both claim") {
		t.Errorf("a member at another's retiring address: %v", err)
	}
	seated := renumbered()
	*seated.Nodes[0].V4 = netip.MustParseAddr("100.64.0.9")
	if err := seated.ValidateInNetwork(); err == nil {
		t.Error("a member holding an address in a retiring range was accepted")
	}
	outside := renumbered()
	outside.V4Retiring = nil
	if err := outside.ValidateInNetwork(); err == nil {
		t.Error("a retiring address outside every range the state names was accepted")
	}
}

func TestRetiringLiveness(t *testing.T) {
	r := &RetiringV4{Until: 100}
	if !r.Live(99) || r.Live(100) || r.Live(101) {
		t.Error("a retiring address is live exactly until its deadline")
	}
	var none *RetiringV4
	if none.Live(0) {
		t.Error("no retiring address is live")
	}
}

func TestRenameShape(t *testing.T) {
	prev := Hash{1}
	rename := func(name string) AUM { return AUM{Kind: KindRenameNetwork, Prev: &prev, Network: &name} }
	if rec := rename("office"); rec.ValidateUnsigned() != nil {
		t.Errorf("a valid rename refused: %v", rec.ValidateUnsigned())
	}
	for _, tc := range []struct {
		name string
		rec  AUM
		want string
	}{
		{"no name", rename(""), "names no name"},
		{"a control character", rename("off\u202eice"), "formatting character"},
		{"padding", rename(" office"), "whitespace"},
		{"too long", rename(strings.Repeat("n", MaxNameLen+1)), "over the"},
		{"no payload", AUM{Kind: KindRenameNetwork, Prev: &prev}, "want exactly"},
	} {
		err := tc.rec.ValidateUnsigned()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error naming %q", tc.name, err, tc.want)
		}
	}
}
