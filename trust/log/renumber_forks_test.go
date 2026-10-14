package log

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// An admission made while another admin renumbers the network and finishes
// it needs only reissuing, as one beside a renumbering alone does.
func TestAnAdmissionBesideAFinishedRenumberingNeedsOnlyReissuing(t *testing.T) {
	for attempt := 0; ; attempt++ {
		if attempt > 64 {
			t.Fatal("never drew a renumbering that wins fork choice")
		}
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
		if renumber.SigHash().Compare(admit.SigHash()) > 0 {
			continue // the admission wins; redraw both
		}
		retire, err := NewBuilder(h.project(renumber)).RetireAddresses()
		if err != nil {
			t.Fatal(err)
		}
		h.signQuorum(&retire)

		auth := h.fork()
		if err := auth.Inform(renumber, retire, admit); err != nil {
			t.Fatal(err)
		}
		if alarm := auth.Alarm(); alarm != nil {
			t.Fatalf("an admission beside a finished renumbering stopped the network: %v", alarm)
		}
		return
	}
}

// A genesis states no retiring ranges: one seating a member in them would
// leave, once they retire, a state whose checkpoint nobody bootstraps from.
func TestAGenesisRetiresNothing(t *testing.T) {
	admin, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	founder := founderRecord(t)
	founder.V4 = new(netip.MustParseAddr("10.9.0.1"))
	own, old := netip.MustParsePrefix("10.7.0.0/22"), netip.MustParsePrefix("10.9.0.0/22")
	g, err := Genesis("test-net", 1, []types.AdminKey{{Public: admin.Public(), Signing: new(admin.SigningKey()), Endorsement: admin.Endorsement(), Votes: 1}},
		[]types.Hash{{1}}, []types.NodeRecord{founder}, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	g.State.V4Prefix = &own
	g.State.V4Retiring = &types.RetiringRanges{Prefixes: []netip.Prefix{old}, Until: 9}
	if err := g.Sign(admin); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(NewMemStorage(), g); err == nil {
		t.Fatal("a genesis retiring a range it never had was accepted")
	}
}

func founderRecord(t *testing.T) types.NodeRecord {
	id, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := secrets.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	x, m, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}
	var wg types.WGKey
	wg[0] = 1
	k := id.SigningKey()
	return types.NodeRecord{Identity: id.Public(), Name: "founder", WireGuard: wg, X25519: x, MLKEM: m, Signing: &k}
}

// A snapshot is a copy: changing it leaves the state as it was.
func TestASnapshotDoesNotShareTheStatesRanges(t *testing.T) {
	h := newHarness(t, 1, 1)
	a := h.admitAt("a", "198.18.0.1")
	h.apply(h.auth.Builder().RenumberNetwork(netip.MustParsePrefix("10.7.0.0/22"), moves(a, "10.7.0.1"), 9))
	st := h.auth.State()
	before := st.V4Ranges()
	st.Snapshot().V4Retiring.Prefixes[0] = netip.MustParsePrefix("192.168.0.0/16")
	if after := st.V4Ranges(); !slices.Equal(before, after) {
		t.Errorf("mutating a snapshot changed the immutable state: %v -> %v", before, after)
	}
}

// A device moved by one admin while another renumbers the network needs
// only moving again, whichever wins.
func TestANodeMoveBesideANetworkRenumberingNeedsOnlyReissuing(t *testing.T) {
	for attempt := 0; ; attempt++ {
		if attempt > 64 {
			t.Fatal("never drew")
		}
		h := newHarness(t, 1, 1)
		a := h.admitAt("a", "198.18.0.1")
		b := h.auth.Builder()
		net, err := b.RenumberNetwork(netip.MustParsePrefix("10.7.0.0/22"), moves(a, "10.7.0.1"), uint64(9+attempt))
		if err != nil {
			t.Fatal(err)
		}
		h.signQuorum(&net)
		node, err := b.RenumberNode(a.Identity, netip.MustParseAddr("198.18.0.9"), uint64(100+attempt))
		if err != nil {
			t.Fatal(err)
		}
		h.signQuorum(&node)
		if net.SigHash().Compare(node.SigHash()) > 0 {
			continue
		}
		auth := h.fork()
		if err := auth.Inform(net, node); err != nil {
			t.Fatal(err)
		}
		if alarm := auth.Alarm(); alarm != nil {
			t.Fatalf("a node move beside a network renumbering stopped the network: %v", alarm)
		}
		return
	}
}

// A network renumbering gives no member an address another still retires,
// as a single move may not.
func TestANetworkRenumberingKeepsAnotherMembersRetiringAddress(t *testing.T) {
	own := netip.MustParsePrefix("10.7.0.0/24")
	h := newHarnessWith(t, 1, 1, func(s *types.Snapshot) { s.V4Prefix = &own })
	x, y := h.admitAt("x", "10.7.0.1"), h.admitAt("y", "10.7.0.2")
	h.apply(h.auth.Builder().RenumberNode(y.Identity, netip.MustParseAddr("10.7.0.7"), 1000))
	if _, err := h.auth.Builder().RenumberNode(x.Identity, netip.MustParseAddr("10.7.0.2"), 1000); err == nil {
		t.Fatal("control: a node move onto y's retiring address was accepted")
	}
	wide := netip.MustParsePrefix("10.7.0.0/22")
	_, err := h.auth.Builder().RenumberNetwork(wide, moves(x, "10.7.0.2", y, "10.7.0.7"), 1000)
	if err == nil {
		t.Fatal("a network renumbering gave y's live retiring address 10.7.0.2 to x")
	}
}
