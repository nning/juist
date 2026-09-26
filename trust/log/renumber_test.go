package log

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/nning/juist/types"
)

// admitAt admits a member at an IPv4 address.
func (h *harness) admitAt(name, v4 string) types.NodeRecord {
	h.t.Helper()
	n := h.newNode(name)
	a := netip.MustParseAddr(v4)
	n.V4 = &a
	aum, err := h.auth.Builder().AddNode(n, h.sealer())
	if err != nil {
		h.t.Fatalf("admitting %s at %s: %v", name, v4, err)
	}
	h.signQuorum(&aum)
	if err := h.auth.Inform(aum); err != nil {
		h.t.Fatalf("admitting %s at %s: %v", name, v4, err)
	}
	return n
}

// apply signs a built record and informs the harness of it.
func (h *harness) apply(aum types.AUM, err error) types.AUM {
	h.t.Helper()
	if err != nil {
		h.t.Fatalf("building a record: %v", err)
	}
	h.signQuorum(&aum)
	if err := h.auth.Inform(aum); err != nil {
		h.t.Fatalf("%v: %v", aum.Kind, err)
	}
	return aum
}

// signed signs a record for mustReject, which the builder would not have
// produced.
func (h *harness) signed(aum types.AUM) types.AUM {
	h.t.Helper()
	prev := h.auth.Head()
	aum.Prev = &prev
	h.signQuorum(&aum)
	return aum
}

func moves(pairs ...any) []types.MemberV4 {
	var out []types.MemberV4
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, types.MemberV4{Identity: pairs[i].(types.NodeRecord).Identity,
			V4: netip.MustParseAddr(pairs[i+1].(string))})
	}
	return out
}

func host(a string) netip.Prefix { return netip.PrefixFrom(netip.MustParseAddr(a), 32) }

// A network renumbering moves every member, and both addresses are each
// member's until the deadline: in its AllowedIPs, old first to send from, and
// in the ranges the log holds addresses to.
func TestRenumberNetworkKeepsOldAddressesUntilTheDeadline(t *testing.T) {
	h := newHarness(t, 1, 1)
	a, b := h.admitAt("a", "198.18.0.1"), h.admitAt("b", "198.18.0.2")
	to := netip.MustParsePrefix("10.7.0.0/22")
	const until = 1000
	h.apply(h.auth.Builder().RenumberNetwork(to, moves(a, "10.7.0.1", b, "10.7.0.2"), until))

	st := h.auth.State()
	if st.V4Range() != to {
		t.Fatalf("new members come from %v, want %v", st.V4Range(), to)
	}
	v6 := netip.PrefixFrom(st.Addr6(a.Identity), 128)
	if got, want := st.Addrs(a.Identity, until-1), []netip.Prefix{v6, host("198.18.0.1"), host("10.7.0.1")}; !slices.Equal(got, want) {
		t.Errorf("before the deadline a holds %v, want %v", got, want)
	}
	if got, want := st.Addrs(a.Identity, until), []netip.Prefix{v6, host("10.7.0.1")}; !slices.Equal(got, want) {
		t.Errorf("at the deadline a holds %v, want %v", got, want)
	}
	if got := st.V4Ranges(); !slices.Contains(got, types.OverlayV4) || !slices.Contains(got, to) {
		t.Errorf("the log holds addresses to %v, want the old ranges kept until they retire", got)
	}
	if got := st.V4RangesAt(until); !slices.Equal(got, []netip.Prefix{to}) {
		t.Errorf("ranges in use after the deadline: %v, want %v alone", got, to)
	}

	// Both addresses are held: no one else may take the old one.
	c := h.newNode("c")
	c.V4 = new(netip.MustParseAddr("198.18.0.1"))
	h.mustReject("an admission at a retiring address", RuleState, h.handAssembledAddNode(c))
	c.V4 = new(netip.MustParseAddr("198.18.0.9"))
	h.mustReject("an admission in a range being renumbered away from", RuleState, h.handAssembledAddNode(c))

	// The whole state states and restates itself.
	cp := h.apply(h.auth.Builder().Checkpoint())
	boot, err := Bootstrap(NewMemStorage(), cp)
	if err != nil {
		t.Fatalf("bootstrapping from a checkpoint mid-renumbering: %v", err)
	}
	if !slices.Equal(boot.State().Addrs(b.Identity, until-1), st.Addrs(b.Identity, until-1)) {
		t.Error("a device bootstrapped from the checkpoint holds other addresses for b")
	}
}

// Growing the prefix around the old one keeps members where they are, with
// nothing to retire for those that stay put.
func TestRenumberIntoALargerPrefix(t *testing.T) {
	own := netip.MustParsePrefix("10.7.0.0/24")
	h := newHarnessWith(t, 1, 1, func(s *types.Snapshot) { s.V4Prefix = &own })
	a, b := h.admitAt("a", "10.7.0.1"), h.admitAt("b", "10.7.0.2")
	wide := netip.MustParsePrefix("10.7.0.0/22")

	// b's old address is b's until the deadline, so a cannot move to it.
	h.mustReject("a moving to b's old address", RuleState, h.signed(types.AUM{Kind: types.KindRenumberNetwork,
		Renumber: &types.Renumbering{Until: 9, Prefix: &wide, Addrs: sortedMoves(moves(a, "10.7.0.2", b, "10.7.0.3"))}}))

	h.apply(h.auth.Builder().RenumberNetwork(wide, moves(a, "10.7.0.1", b, "10.7.2.2"), 9))
	st := h.auth.State()
	if n, _ := st.Node(a.Identity); n.Retiring != nil {
		t.Errorf("a stayed at its address and retires %v", n.Retiring.Addr)
	}
	if n, _ := st.Node(b.Identity); n.Retiring == nil || n.Retiring.Addr != netip.MustParseAddr("10.7.0.2") {
		t.Errorf("b retires %v, want 10.7.0.2", n.Retiring)
	}
	if _, ok := st.V4Retiring(); ok {
		t.Error("a prefix inside the new one is kept as a retiring range")
	}
}

func sortedMoves(m []types.MemberV4) []types.MemberV4 {
	slices.SortFunc(m, func(x, y types.MemberV4) int { return x.Identity.Compare(y.Identity) })
	return m
}

// Every node rejects a network renumbering that leaves a member behind, moves
// a non-member, reuses the prefix, or overlaps a granted route; and one before
// schema 5.
func TestRenumberNetworkRejects(t *testing.T) {
	h := newHarness(t, 1, 1)
	a, b := h.admitAt("a", "198.18.0.1"), h.admitAt("b", "198.18.0.2")
	stranger := h.newNode("stranger")
	to := netip.MustParsePrefix("10.7.0.0/22")
	renumber := func(prefix netip.Prefix, m []types.MemberV4) types.AUM {
		return h.signed(types.AUM{Kind: types.KindRenumberNetwork,
			Renumber: &types.Renumbering{Until: 9, Prefix: &prefix, Addrs: sortedMoves(m)}})
	}
	h.mustReject("a renumbering leaving b behind", RuleState, renumber(to, moves(a, "10.7.0.1")))
	h.mustReject("a renumbering moving a non-member", RuleState, renumber(to, moves(a, "10.7.0.1", b, "10.7.0.2",
		stranger, "10.7.0.3")))
	h.mustReject("a renumbering moving a non-member in a member's place", RuleState,
		renumber(to, moves(a, "10.7.0.1", stranger, "10.7.0.3")))
	if _, err := h.auth.Builder().RenumberNetwork(to, moves(a, "10.7.0.1"), 9); err == nil {
		t.Error("the builder authored a renumbering leaving a member behind")
	}

	h.apply(h.auth.Builder().SetNodeRoutes(a.Identity, nil, []netip.Prefix{netip.MustParsePrefix("10.7.1.0/24")}))
	h.mustReject("a renumbering over a granted route", RuleState, renumber(to, moves(a, "10.7.0.1", b, "10.7.0.2")))

	other := netip.MustParsePrefix("10.9.0.0/22")
	h.apply(h.auth.Builder().RenumberNetwork(other, moves(a, "10.9.0.1", b, "10.9.0.2"), 9))
	h.mustReject("a renumbering to the prefix it has", RuleState, renumber(other, moves(a, "10.9.0.5", b, "10.9.0.6")))

	old := newHarnessAt(t, 1, 1, types.SchemaOverlayV4)
	n := old.admitAt("n", "198.18.0.1")
	aum := old.signed(types.AUM{Kind: types.KindRenumberNetwork,
		Renumber: &types.Renumbering{Until: 9, Prefix: &to, Addrs: moves(n, "10.7.0.1")}})
	old.mustReject("a renumbering at schema 4", RuleState, aum)
	old.mustReject("a retirement at schema 4", RuleState, old.signed(types.AUM{Kind: types.KindRetireAddresses}))
}

// One member moves on its own, to an address in the network's range that no
// other member holds, old or new; it may move back to the one it retires.
func TestRenumberNode(t *testing.T) {
	h := newHarness(t, 1, 1)
	a, b := h.admitAt("a", "198.18.0.1"), h.admitAt("b", "198.18.0.2")
	to := func(n types.NodeRecord, v4 string) types.AUM {
		addr := netip.MustParseAddr(v4)
		return h.signed(types.AUM{Kind: types.KindRenumberNode, Subject: &n.Identity,
			Renumber: &types.Renumbering{Until: 50, V4: &addr}})
	}
	h.mustReject("a moving to b's address", RuleState, to(a, "198.18.0.2"))
	h.mustReject("a moving outside the network's range", RuleState, to(a, "10.7.0.1"))
	h.mustReject("a moving to the address it holds", RuleState, to(a, "198.18.0.1"))
	h.mustReject("a non-member moving", RuleState, to(h.newNode("x"), "198.18.0.9"))

	h.apply(h.auth.Builder().RenumberNode(a.Identity, netip.MustParseAddr("198.18.0.9"), 50))
	st := h.auth.State()
	v6 := netip.PrefixFrom(st.Addr6(a.Identity), 128)
	if got, want := st.Addrs(a.Identity, 49), []netip.Prefix{v6, host("198.18.0.1"), host("198.18.0.9")}; !slices.Equal(got, want) {
		t.Errorf("a holds %v before the deadline, want %v", got, want)
	}
	if got, want := st.Addrs(a.Identity, 50), []netip.Prefix{v6, host("198.18.0.9")}; !slices.Equal(got, want) {
		t.Errorf("a holds %v after the deadline, want %v", got, want)
	}
	h.mustReject("b moving to a's old address", RuleState, to(b, "198.18.0.1"))
	c := h.newNode("c")
	c.V4 = new(netip.MustParseAddr("198.18.0.1"))
	h.mustReject("an admission at a's old address", RuleState, h.handAssembledAddNode(c))

	h.apply(h.auth.Builder().RenumberNode(a.Identity, netip.MustParseAddr("198.18.0.1"), 60))
	if n, _ := h.auth.State().Node(a.Identity); *n.V4 != netip.MustParseAddr("198.18.0.1") ||
		n.Retiring.Addr != netip.MustParseAddr("198.18.0.9") || n.Retiring.Until != 60 {
		t.Errorf("after moving back a is at %v retiring %+v", n.V4, n.Retiring)
	}

	// An identity rotation takes the retiring address along.
	rotated := h.newNode("a2")
	rot, err := h.auth.Builder().RotateIdentity(a.Identity, rotated.Identity, h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&rot)
	if err := SignAsDevice(&rot, h.auth.State().Schema(), h.nodeIDs[a.Identity], h.nodeIDs[rotated.Identity]); err != nil {
		t.Fatal(err)
	}
	if err := h.auth.Inform(rot); err != nil {
		t.Fatalf("rotating a's identity: %v", err)
	}
	if n, _ := h.auth.State().Node(rotated.Identity); n.Retiring == nil {
		t.Error("the identity rotation dropped the address a retires")
	}
}

// A renumbering during a network one moves the member into the new prefix
// only, and replaces the address it retired.
func TestRenumberNodeDuringANetworkRenumbering(t *testing.T) {
	h := newHarness(t, 1, 1)
	a := h.admitAt("a", "198.18.0.1")
	to := netip.MustParsePrefix("10.7.0.0/22")
	h.apply(h.auth.Builder().RenumberNetwork(to, moves(a, "10.7.0.1"), 9))
	if _, err := h.auth.Builder().RenumberNode(a.Identity, netip.MustParseAddr("198.18.0.7"), 9); err == nil {
		t.Error("a member was moved into the range being renumbered away from")
	}
	h.apply(h.auth.Builder().RenumberNode(a.Identity, netip.MustParseAddr("10.7.0.5"), 9))
	if n, _ := h.auth.State().Node(a.Identity); n.Retiring.Addr != netip.MustParseAddr("10.7.0.1") {
		t.Errorf("a retires %v, want the address it just left", n.Retiring.Addr)
	}
}

// Retiring ends every transition at once, and only when there is one.
func TestRetireAddresses(t *testing.T) {
	h := newHarness(t, 1, 1)
	if _, err := h.auth.Builder().RetireAddresses(); err == nil {
		t.Error("a retirement with nothing to retire was built")
	}
	a := h.admitAt("a", "198.18.0.1")
	to := netip.MustParsePrefix("10.7.0.0/22")
	h.apply(h.auth.Builder().RenumberNetwork(to, moves(a, "10.7.0.1"), 1<<40))
	h.apply(h.auth.Builder().RetireAddresses())
	st := h.auth.State()
	if got := st.Addrs(a.Identity, 0); len(got) != 2 || got[1] != host("10.7.0.1") {
		t.Errorf("a holds %v after the retirement, want its v6 and 10.7.0.1", got)
	}
	if got := st.V4Ranges(); !slices.Equal(got, []netip.Prefix{to}) {
		t.Errorf("ranges %v after the retirement, want %v", got, to)
	}
	b := h.newNode("b")
	b.V4 = new(netip.MustParseAddr("198.18.0.1"))
	h.mustReject("an admission in the retired range", RuleState, h.handAssembledAddNode(b))
}

// A renumbering and an admission made at once are changes to start again,
// whichever wins: what they allocate is where they sit, not what they say.
func TestConcurrentRenumberingAndAdmissionNeedOnlyReissuing(t *testing.T) {
	h := newHarness(t, 1, 1)
	a := h.admitAt("a", "198.18.0.1")
	b := h.auth.Builder()
	renumber, err := b.RenumberNetwork(netip.MustParsePrefix("10.7.0.0/22"), moves(a, "10.7.0.1"), 9)
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&renumber)
	n := h.newNode("n")
	n.V4 = new(netip.MustParseAddr("198.18.0.2"))
	admit, err := b.AddNode(n, h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&admit)
	for i, order := range [][]types.AUM{{renumber, admit}, {admit, renumber}} {
		auth := h.fork()
		if err := auth.Inform(order...); err != nil {
			t.Fatalf("order %d: %v", i, err)
		}
		if alarm := auth.Alarm(); alarm != nil {
			t.Fatalf("order %d: a renumbering beside an admission stopped the network: %v", i, alarm)
		}
		var lost int
		for _, o := range auth.Orphans() {
			lost += len(o.Records)
		}
		if lost != 1 {
			t.Fatalf("order %d: %d changes to reissue, want one", i, lost)
		}
	}
}

// Two admins making the same change at once do not stop the network: the
// loser is already in effect.
func TestConcurrentLikeRenumberingsDoNotAlarm(t *testing.T) {
	h := newHarness(t, 2, 1)
	a := h.admitAt("a", "198.18.0.1")
	to := netip.MustParsePrefix("10.7.0.0/22")
	must := func(aum types.AUM, err error) types.AUM {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return aum
	}
	signedBy := func(i int, aum types.AUM) types.AUM {
		t.Helper()
		if err := aum.Sign(h.admins[i]); err != nil {
			t.Fatal(err)
		}
		return aum
	}
	b := h.auth.Builder()
	pairs := [][2]types.AUM{
		{signedBy(0, must(b.RenumberNetwork(to, moves(a, "10.7.0.1"), 9))), signedBy(1, must(b.RenumberNetwork(to, moves(a, "10.7.0.5"), 10)))},
		{signedBy(0, must(b.RenumberNode(a.Identity, netip.MustParseAddr("198.18.0.7"), 9))),
			signedBy(1, must(b.RenumberNode(a.Identity, netip.MustParseAddr("198.18.0.7"), 10)))},
	}
	for i, p := range pairs {
		auth := h.fork()
		if err := auth.Inform(p[0], p[1]); err != nil {
			t.Fatalf("pair %d: %v", i, err)
		}
		if alarm := auth.Alarm(); alarm != nil {
			t.Errorf("pair %d: two like changes at once stopped the network: %v", i, alarm)
		}
	}

	h.apply(h.auth.Builder().RenumberNetwork(to, moves(a, "10.7.0.1"), 9))
	b = h.auth.Builder()
	one, two := signedBy(0, must(b.RetireAddresses())), signedBy(1, must(b.RetireAddresses()))
	auth := h.fork()
	if err := auth.Inform(one, two); err != nil {
		t.Fatal(err)
	}
	if alarm := auth.Alarm(); alarm != nil {
		t.Errorf("two retirements at once stopped the network: %v", alarm)
	}
}
