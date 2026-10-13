package log

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/nning/juist/types"
)

// TestRecordSizeAtMaxNodes is the measurement docs/05-roadmap.md requires
// before the M3 record-schema freeze, kept as a regression guard: the epoch
// group secret fans out one 1168-byte wrap per member, inline, in every record
// that changes the member set and in every checkpoint. What the numbers
// decided is in docs/08-trust-layer-notes.md.
//
// It also bounds what one record may cost a receiver: a checkpoint at
// [types.MaxNodes] must stay inside [types.MaxRecordSize], and an epoch bump
// inside a single gossip frame, or a network at the schema's ceiling could
// author a record its own members refuse.
func TestRecordSizeAtMaxNodes(t *testing.T) {
	h := newHarness(t, 1, 1)
	members := make([]types.NodeRecord, 0, types.MaxNodes)
	for i := range types.MaxNodes {
		members = append(members, h.newNode(fmt.Sprintf("n%d", i)))
	}

	cp := h.handAssembledCheckpoint(members)
	checkpoint, err := cp.Encode()
	if err != nil {
		t.Fatalf("encoding the checkpoint: %v", err)
	}
	epoch, err := h.sealer()(2, members)
	if err != nil {
		t.Fatalf("sealing an epoch: %v", err)
	}
	prev := h.auth.Head()
	bump := types.AUM{Kind: types.KindEpochBump, Prev: &prev, Epoch: epoch}
	h.signQuorum(&bump)
	bumped, err := bump.Encode()
	if err != nil {
		t.Fatalf("encoding the epoch bump: %v", err)
	}

	t.Logf("at %d members: checkpoint %d bytes (%.0f KiB), epoch bump %d bytes (%.0f KiB)",
		types.MaxNodes, len(checkpoint), float64(len(checkpoint))/1024,
		len(bumped), float64(len(bumped))/1024)
	t.Logf("one membership change costs each member %.0f KiB and the network %.0f MiB",
		float64(len(bumped))/1024, float64(len(bumped))*(types.MaxNodes-1)/(1024*1024))

	if len(checkpoint) > types.MaxRecordSize {
		t.Errorf("a checkpoint at %d members is %d bytes, over the %d-byte record limit "+
			"every node enforces", types.MaxNodes, len(checkpoint), types.MaxRecordSize)
	}
	if len(bumped) > types.MaxRecordSize {
		t.Errorf("an epoch bump at %d members is %d bytes, over the %d-byte record limit",
			types.MaxNodes, len(bumped), types.MaxRecordSize)
	}
}

// readCounting counts the records read from the store.
type readCounting struct {
	*MemStorage
	reads int
}

func (c *readCounting) AUM(h types.Hash) (types.AUM, error) {
	c.reads++
	return c.MemStorage.AUM(h)
}

// Resolving a chain reads each record a bounded number of times. Every read
// of the persisted store decodes and verifies from disk, and the daemon
// resolves holding the lock reconciliation and IPC wait on.
func TestResolutionReadsEachRecordBoundedTimes(t *testing.T) {
	h := newHarness(t, 1, 1)
	const n = 100
	for i := range n {
		aum, err := h.auth.Builder().RenameNetwork(fmt.Sprintf("n%d", i))
		if err != nil {
			t.Fatal(err)
		}
		h.signQuorum(&aum)
		if err := h.auth.Inform(aum); err != nil {
			t.Fatal(err)
		}
	}
	st := &readCounting{MemStorage: h.copyStorage()}
	if _, err := Open(st); err != nil {
		t.Fatal(err)
	}
	if st.reads > 4*n {
		t.Fatalf("opening a chain of %d records read %d", n, st.reads)
	}
}

// atCaps is a member with its names, published names, roles and routes at
// their caps, each name and route its own in the network, i.
func atCaps(n types.NodeRecord, i int) types.NodeRecord {
	n.Roles = []types.Role{types.RoleAdmin, types.RoleExit, types.RoleRelayCapable}
	for r := range types.MaxRoutesPerNode {
		n.Routes = append(n.Routes, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 2), byte(i&3<<6 | r), 0}), 24))
	}
	// The published labels take their share of the bytes first.
	budget := types.MaxNameBytes
	for p := range types.MaxPublishedPerNode {
		label := fmt.Sprintf("p%03d%02d", i, p)
		n.Published = append(n.Published, types.PublishedName{Label: label, Port: 1024 + uint16(p), Proxy: true,
			Public: 20000 + uint16(i)*16 + uint16(p)})
		budget -= len(label)
	}
	per := budget / types.MaxNamesPerNode
	for k := range types.MaxNamesPerNode {
		head := fmt.Sprintf("n%03d-%02d.", i, k)
		n.Names = append(n.Names, head+strings.Repeat("a", per-len(head)-4)+".org")
	}
	slices.Sort(n.Names)
	return n
}

// A checkpoint at MaxNodes, its members' names, published names and routes
// at their caps, past the cut-over and signed by every admin key, stays
// within MaxRecordSize; and so does the cut-over at MaxNodes, with every
// admin key's signature. Exit criterion (5) for records.
func TestRecordsPastTheCutOverFitAtTheCaps(t *testing.T) {
	h := newHarnessWith(t, types.MaxAdmins, types.MaxAdmins, func(s *types.Snapshot) { s.Domain = "example.org" })
	members := make([]types.NodeRecord, 0, types.MaxNodes)
	for i := range types.MaxNodes {
		members = append(members, atCaps(h.newNode(fmt.Sprintf("n%d", i)), i))
	}
	cp := h.handAssembledCheckpoint(members)
	if err := cp.StaticValidate(); err != nil {
		t.Fatalf("the checkpoint at the caps: %v", err)
	}
	for _, n := range cp.State.Nodes[:1] {
		if n.NameBytes() < types.MaxNameBytes-types.MaxNamesPerNode {
			t.Fatalf("a member's names take %d bytes, short of the cap; this test proves nothing", n.NameBytes())
		}
	}
	checkpoint, err := cp.Encode()
	if err != nil {
		t.Fatalf("encoding the checkpoint: %v", err)
	}
	t.Logf("a checkpoint at the caps: %.2f MiB of %d", float64(len(checkpoint))/(1<<20), types.MaxRecordSize>>20)

	// The cut-over, as a network at the schema before it would author it.
	var keys []types.MemberKey
	for _, n := range members {
		priv := h.nodeIDs[n.Identity]
		e, err := priv.Endorse()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, types.MemberKey{Identity: n.Identity, Key: priv.SigningKey(), Endorsement: e})
	}
	slices.SortFunc(keys, func(x, y types.MemberKey) int { return x.Identity.Compare(y.Identity) })
	epoch, err := h.sealer()(2, cp.State.Nodes)
	if err != nil {
		t.Fatal(err)
	}
	cut := types.AUM{Kind: types.KindSetSigningKeys, Prev: &types.Hash{1}, Signing: &types.SigningKeys{Members: keys},
		Epoch: epoch}
	for _, a := range h.admins {
		if err := cut.SignUnder(a, types.SchemaSigning); err != nil {
			t.Fatal(err)
		}
	}
	b, err := cut.Encode()
	if err != nil {
		t.Fatalf("encoding the cut-over at the caps: %v", err)
	}
	t.Logf("a cut-over at the caps: %.2f MiB of %d", float64(len(b))/(1<<20), types.MaxRecordSize>>20)
	if _, err := types.DecodeAUM(b); err != nil {
		t.Fatalf("the cut-over at the caps: %v", err)
	}
}
