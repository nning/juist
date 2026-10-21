package log

import (
	"bytes"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/nning/juist/types"
)

// Inputs to memberSet: a member in a retiring range, two answering for one
// name, and two apart.
var (
	seedRetiring = []byte{1, 2, 0x01, 0, 0, 0, 0, 0, 3, 0, 1}
	seedOneName  = []byte{1, 0, 0x03, 0, 0, 0, 0x02, 0, 1, 0, 1, 2, 0, 0, 0x02, 0, 2, 0, 1}
	seedApart    = []byte{1, 0, 0x03, 0, 0x08, 0, 0, 0x04, 1, 0, 1, 2, 0, 0x02, 0x02, 0, 2, 0, 1}
)

// FuzzAdmissibleAlike holds the record path and the snapshot path to one
// verdict on a member set: every member admissible against the others, as
// records check it, exactly where the state is admissible whole, as a genesis
// or checkpoint is checked. A set the one takes and the other refuses is a
// checkpoint of a chain no new member can anchor at, or a state no record
// could reach.
func FuzzAdmissibleAlike(f *testing.F) {
	for _, seed := range [][]byte{{}, seedRetiring, seedOneName, seedApart} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		snap := memberSet(t, data)
		byRecords := admitByRecords(t, snap)
		whole := snap.StaticValidate(false)
		if whole == nil {
			whole = snap.ValidateInNetwork()
		}
		if (byRecords == nil) != (whole == nil) {
			t.Fatalf("records say %v, the whole state %v", byRecords, whole)
		}
	})
}

// A member holding an address in a range the network renumbers away from is
// refused by records as by a whole state.
func TestRecordsRefuseAnAddressInARetiringRange(t *testing.T) {
	snap := memberSet(t, seedRetiring)
	if len(snap.Nodes) != 1 || snap.V4Retiring == nil || !snap.V4Retiring.Prefixes[0].Contains(*snap.Nodes[0].V4) {
		t.Fatalf("the seed draws no member in a retiring range: %+v", snap.Nodes)
	}
	if err := admitByRecords(t, snap); err == nil || !strings.Contains(err.Error(), "outside 10.1.0.0/16") {
		t.Fatalf("records took a member in a retiring range: %v", err)
	}
	if err := snap.ValidateInNetwork(); err == nil {
		t.Fatal("a whole state took a member in a retiring range")
	}
	if err := admitByRecords(t, memberSet(t, seedApart)); err != nil {
		t.Fatalf("two members apart: %v", err)
	}
	if err := admitByRecords(t, memberSet(t, seedOneName)); err == nil {
		t.Fatal("two members answering for one name taken")
	}
}

// admitByRecords checks each member of snap as a record leaving it so would
// be, against the others.
func admitByRecords(t *testing.T, snap *types.Snapshot) error {
	st, err := stateFromSnapshot(snap, types.Hash{1})
	if err != nil {
		t.Fatal(err)
	}
	for i := range snap.Nodes {
		if err := st.checkNodeAdmissible(&snap.Nodes[i]); err != nil {
			return err
		}
	}
	return nil
}

var (
	admissibleOnce  sync.Once
	admissibleBase  *types.Snapshot
	admissibleNodes []types.NodeRecord
	admissibleErr   error
)

// memberSet draws a network's domain, IPv4 ranges and up to four members from
// data, each member valid alone, from a few values each so that members
// collide.
func memberSet(t *testing.T, data []byte) *types.Snapshot {
	admissibleOnce.Do(func() {
		genesis, _, err := fixedGenesis()
		if err != nil {
			admissibleErr = err
			return
		}
		h := genesis.Hash()
		admissibleBase = genesis.State.Clone()
		admissibleBase.GenesisHash = &h
		for n := byte(1); n <= 4; n++ {
			admissibleNodes = append(admissibleNodes, fixedNode(n))
		}
	})
	if admissibleErr != nil {
		t.Fatal(admissibleErr)
	}
	next := func() byte {
		if len(data) == 0 {
			return 0
		}
		b := data[0]
		data = data[1:]
		return b
	}
	pick := func(n int) int { return int(next()) % n }
	subset := func(n int) []int {
		b := next()
		var out []int
		for i := range n {
			if b&(1<<i) != 0 {
				out = append(out, i)
			}
		}
		return out
	}
	addr := netip.MustParseAddr
	prefix := netip.MustParsePrefix

	snap := admissibleBase.Clone()
	snap.Domain = []string{"", "pub.example.org", "example.org"}[pick(3)]
	switch pick(3) {
	case 1:
		snap.V4Prefix = new(prefix("10.1.0.0/16"))
	case 2:
		snap.V4Prefix = new(prefix("10.1.0.0/16"))
		snap.V4Retiring = &types.RetiringRanges{Prefixes: []netip.Prefix{types.OverlayV4}, Until: 1}
	}

	names := []string{"alpha", "Alpha", "web", "x", "two words"}
	roles := []types.Role{types.RoleAdmin, types.RoleExit, types.RoleIngress, types.RolePublish, types.RoleService}
	routes := []netip.Prefix{prefix("0.0.0.0/0"), prefix("10.2.0.0/24"), prefix("10.2.0.0/25"),
		prefix("192.168.5.0/24"), prefix("10.1.2.0/24"), prefix("::/0")}
	pointed := []string{"alpha.pub.example.org", "mx.org", "pub.example.org", "web.example.org",
		"web.pub.example.org"}
	published := []types.PublishedName{{Label: "", Port: 80}, {Label: "alpha", Port: 8080},
		{Label: "web", Port: 8443, Public: 8443}, {Label: "web", Port: 9000}, {Label: "x", Port: 443, Public: 2222},
		{Label: "mail", Port: 443, Members: true}, {Label: "alt", Port: 2222, Public: 8443}}
	// Two addresses in the range the network assigns from, one in OverlayV4,
	// retiring or outside it.
	cur := "198.18.0."
	if snap.V4Prefix != nil {
		cur = "10.1.0."
	}
	v4s := []netip.Addr{{}, addr(cur + "5"), addr(cur + "6"), addr("198.18.0.7")}

	for _, i := range subset(len(admissibleNodes)) {
		n := admissibleNodes[i]
		n.Name = names[pick(len(names))]
		for _, r := range subset(len(roles)) {
			n.Roles = append(n.Roles, roles[r])
		}
		slices.Sort(n.Roles)
		for _, r := range subset(len(routes)) {
			n.Routes = append(n.Routes, routes[r])
		}
		slices.SortFunc(n.Routes, types.ComparePrefix)
		for _, p := range subset(len(pointed)) {
			n.Names = append(n.Names, pointed[p])
		}
		for _, p := range subset(len(published)) {
			n.Published = append(n.Published, published[p])
		}
		slices.SortStableFunc(n.Published, func(a, b types.PublishedName) int { return strings.Compare(a.Label, b.Label) })
		if v := v4s[pick(len(v4s))]; v.IsValid() {
			n.V4 = &v
		}
		if v := v4s[pick(len(v4s))]; v.IsValid() {
			n.Retiring = &types.RetiringV4{Addr: v, Until: 1}
		}
		// Shared keys, which only the member set refuses.
		if next()%8 == 0 {
			n.WireGuard = admissibleNodes[0].WireGuard
		}
		// What makes a member invalid alone goes, a field at a time.
		for _, strip := range []func(*types.NodeRecord){
			func(*types.NodeRecord) {},
			func(n *types.NodeRecord) { n.Retiring = nil },
			func(n *types.NodeRecord) { n.Routes = nil },
			func(n *types.NodeRecord) {
				n.Roles = slices.DeleteFunc(n.Roles, func(r types.Role) bool { return r != types.RolePublish })
			},
			func(n *types.NodeRecord) { n.Published = nil },
			func(n *types.NodeRecord) { n.Names = nil },
			func(n *types.NodeRecord) { n.Roles = nil },
		} {
			if strip(&n); n.StaticValidate() == nil {
				snap.Nodes = append(snap.Nodes, n)
				break
			}
		}
	}
	slices.SortFunc(snap.Nodes, func(a, b types.NodeRecord) int { return a.Identity.Compare(b.Identity) })
	snap.EpochWraps = nil
	for _, n := range snap.Nodes {
		snap.EpochWraps = append(snap.EpochWraps, types.EpochWrap{Recipient: n.Identity,
			Sealed: bytes.Repeat([]byte{1}, types.SealedSecretSize)})
	}
	return snap
}
