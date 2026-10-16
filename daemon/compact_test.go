package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// renames builds n records after the genesis, each renaming the network,
// signed by the admin: a long log built quickly.
func (nw *network) renames(t *testing.T, n int) []types.AUM {
	t.Helper()
	auth, _ := nw.authorityFor(t)
	b := auth.Builder()
	out := make([]types.AUM, 0, n)
	for i := range n {
		rec, err := b.RenameNetwork(fmt.Sprintf("net-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		if err := rec.Sign(nw.admin); err != nil {
			t.Fatal(err)
		}
		next, err := b.Dry(&rec)
		if err != nil {
			t.Fatal(err)
		}
		b = log.NewBuilder(next)
		out = append(out, rec)
	}
	return out
}

// A log longer than a hello lists, with no checkpoint, still converges on a
// change: a peer stands what it lists for the ancestors it holds.
func TestALogPastWhatAHelloListsConverges(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a log past the hello's cap")
	}
	m := &mesh{t: t, nw: newNetwork(t, 2), hub: &lanHub{}}
	// Enough past the cap that what a hello leaves out fills a records frame.
	records := m.nw.renames(t, gossip.MaxHashesPerFrame+gossip.MaxRecordsPerFrame+64)
	for i := range 2 {
		m.nodes = append(m.nodes, m.start(t, i, records...))
	}
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	m.apply(t, m.nodes[0], func(b *log.Builder) (types.AUM, error) { return b.RenameNetwork("after") })
	waitFor(t, 60*time.Second, "the change past the cap to arrive", func() bool {
		return m.nodes[1].d.Status().Head == m.nodes[0].d.Status().Head
	})
}

func (n *meshNode) anchor() types.Hash {
	n.d.authMu.Lock()
	defer n.d.authMu.Unlock()
	return n.d.authority.Anchor()
}

func (n *meshNode) holds(h types.Hash) bool {
	n.d.authMu.Lock()
	defer n.d.authMu.Unlock()
	_, err := n.d.storage.AUM(h)
	return err == nil
}

// The devices compact, to the checkpoint before the newest, only once every
// live member is heard past the newest, so that one away is not left behind
// it; then they all do, and go on taking changes.
func TestDevicesCompactOnceEveryMemberIsPastTheCheckpoint(t *testing.T) {
	m := &mesh{t: t, nw: newNetwork(t, 3), hub: &lanHub{}}
	for i := range 3 {
		m.nodes = append(m.nodes, m.start(t, i))
	}
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	genesis := m.nw.genesis.Hash()
	away := m.nodes[2]
	away.halt()
	m.nodes = m.nodes[:2]
	m.apply(t, m.nodes[0], func(b *log.Builder) (types.AUM, error) { return b.RenameNetwork("before") })
	m.apply(t, m.nodes[0], func(b *log.Builder) (types.AUM, error) { return b.Checkpoint() })
	first := m.nodes[0].d.Status().Head
	m.apply(t, m.nodes[0], func(b *log.Builder) (types.AUM, error) { return b.RenameNetwork("between") })
	m.apply(t, m.nodes[0], func(b *log.Builder) (types.AUM, error) { return b.Checkpoint() })
	head := m.nodes[0].d.Status().Head
	waitFor(t, 30*time.Second, "the other to hold the checkpoint", func() bool {
		return m.nodes[1].d.Status().Head == head
	})
	for range 3 {
		for _, n := range m.nodes {
			if err := n.d.Reconcile(); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(time.Second)
	}
	for _, n := range m.nodes {
		if n.anchor() != genesis {
			t.Fatal("a device compacted while a member it has not heard past the checkpoint was away")
		}
	}

	m.nodes = append(m.nodes, m.startOn(t, 2, away.dev, away.auth, away.d.storage, m.mutate))
	for _, n := range m.nodes {
		waitFor(t, 30*time.Second, "every device to start at the checkpoint before the newest", func() bool {
			return n.anchor() == first
		})
	}
	// The chain leading up to it stays for a peer behind.
	if !m.nodes[0].holds(genesis) {
		t.Fatal("compaction dropped the chain up to the checkpoint")
	}
	m.apply(t, m.nodes[0], func(b *log.Builder) (types.AUM, error) { return b.RenameNetwork("after") })
	for _, n := range m.nodes[1:] {
		waitFor(t, 30*time.Second, "a change past the checkpoint to arrive", func() bool {
			return n.d.Status().Head == m.nodes[0].d.Status().Head
		})
	}
}

// A device behind a peer that compacted catches up from what the peer kept
// below its anchor.
func TestADeviceBehindACompactedPeerCatchesUp(t *testing.T) {
	m := &mesh{t: t, nw: newNetwork(t, 2), hub: &lanHub{}}
	for i := range 2 {
		m.nodes = append(m.nodes, m.start(t, i))
	}
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	behind := m.nodes[1]
	behind.halt()
	m.nodes = m.nodes[:1]
	ahead := m.nodes[0]
	m.apply(t, ahead, func(b *log.Builder) (types.AUM, error) { return b.RenameNetwork("missed") })
	m.apply(t, ahead, func(b *log.Builder) (types.AUM, error) { return b.Checkpoint() })
	cp := ahead.d.Status().Head
	m.apply(t, ahead, func(b *log.Builder) (types.AUM, error) { return b.RenameNetwork("after") })
	m.apply(t, ahead, func(b *log.Builder) (types.AUM, error) { return b.Checkpoint() })
	m.apply(t, ahead, func(b *log.Builder) (types.AUM, error) { return b.RenameNetwork("later") })
	// As a member lying about the one away would have it.
	ahead.d.authMu.Lock()
	_, err := ahead.d.authority.Compact()
	ahead.d.authMu.Unlock()
	if err != nil || ahead.anchor() != cp {
		t.Fatalf("compacting: %v", err)
	}

	m.nodes = append(m.nodes, m.startOn(t, 1, behind.dev, behind.auth, behind.d.storage, m.mutate))
	waitFor(t, 30*time.Second, "the device behind to catch up", func() bool {
		return m.nodes[1].d.Status().Head == ahead.d.Status().Head
	})
}

// A device compacts once every other live member is heard past the
// checkpoint, or once one heard has compacted to it or past it; a member not
// heard, or heard below it, holds it back otherwise.
func TestCompactionWaitsForEveryMemberOrOneThatCompacted(t *testing.T) {
	f := newReconcileFixture(t, 3)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	genesis := f.nw.genesis.Hash()
	checkpoint := func() types.AUM {
		t.Helper()
		f.d.authMu.Lock()
		cp, err := f.auth.Builder().Checkpoint()
		f.d.authMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if err := cp.Sign(f.nw.admin); err != nil {
			t.Fatal(err)
		}
		if err := f.d.Inform([]types.AUM{cp}); err != nil {
			t.Fatal(err)
		}
		return cp
	}
	cp, newest := checkpoint(), checkpoint()
	one, two := f.nw.devices[1].record.Identity, f.nw.devices[2].record.Identity
	anchor := func() types.Hash {
		f.d.authMu.Lock()
		defer f.d.authMu.Unlock()
		return f.d.authority.Anchor()
	}
	settle := func() {
		t.Helper()
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
	}

	f.d.onHave(one, newest.Hash(), genesis, nil)
	settle()
	if anchor() != genesis {
		t.Fatal("compacted with a member not heard")
	}
	f.d.onHave(two, cp.Hash(), genesis, nil)
	settle()
	if anchor() != genesis {
		t.Fatal("compacted with a member heard below the newest checkpoint")
	}
	f.d.onHave(one, newest.Hash(), cp.Hash(), nil)
	settle()
	if anchor() != cp.Hash() {
		t.Fatal("a member that compacted to the checkpoint did not have this device follow")
	}
}

// Every live member heard past the checkpoint is enough on its own.
func TestCompactionFollowsEveryMemberHeardPastIt(t *testing.T) {
	f := newReconcileFixture(t, 3)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	checkpoint := func() types.AUM {
		t.Helper()
		f.d.authMu.Lock()
		cp, err := f.auth.Builder().Checkpoint()
		f.d.authMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if err := cp.Sign(f.nw.admin); err != nil {
			t.Fatal(err)
		}
		if err := f.d.Inform([]types.AUM{cp}); err != nil {
			t.Fatal(err)
		}
		return cp
	}
	cp, newest := checkpoint(), checkpoint()
	genesis := f.nw.genesis.Hash()
	for _, dev := range f.nw.devices[1:] {
		f.d.onHave(dev.record.Identity, newest.Hash(), genesis, nil)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.authMu.Lock()
	defer f.d.authMu.Unlock()
	if f.d.authority.Anchor() != cp.Hash() {
		t.Fatal("every member heard past the checkpoint and no compaction")
	}
	// Nothing left to compact to: the next reconcile compacts nothing again.
	if !f.d.compacting.target.IsZero() {
		t.Fatal("a compaction is due again at once")
	}
}

// A device that peers answer only from a checkpoint past all its log holds,
// at a later epoch, says so once that has lasted, and stops once a batch
// brings news; one at no later epoch, as a device further behind sends one
// ahead, says nothing.
func TestADeviceOvertakenByItsPeersSaysSo(t *testing.T) {
	now := time.Now()
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = func() time.Time { return now } })
	ahead, _ := f.nw.authorityFor(t)
	signed := func(rec types.AUM, err error) types.AUM {
		t.Helper()
		if err == nil {
			err = rec.Sign(f.nw.admin)
		}
		if err == nil {
			err = ahead.Inform(rec)
		}
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	adapter := (*logAdapter)(f.d)
	overtaken := func() bool {
		t.Helper()
		now = now.Add(overtakenAfter + time.Minute)
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		return f.d.Status().Overtaken
	}

	rename := signed(ahead.Builder().RenameNetwork("missed"))
	same := signed(ahead.Builder().Checkpoint())
	if err := adapter.Inform([]types.AUM{same}); err == nil {
		t.Fatal("a checkpoint past all this log holds was taken")
	}
	if overtaken() {
		t.Fatal("overtaken by a checkpoint at no later epoch")
	}

	bump := signed(ahead.Builder().EpochBump(f.nw.sealer()))
	cp := signed(ahead.Builder().Checkpoint())
	if err := adapter.Inform([]types.AUM{cp}); err == nil {
		t.Fatal("a checkpoint past all this log holds was taken")
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if f.d.Status().Overtaken {
		t.Fatal("overtaken at once, before a peer that kept the way could answer")
	}
	if !overtaken() {
		t.Fatal("not said to be overtaken")
	}
	if err := adapter.Inform([]types.AUM{rename, same, bump, cp}); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if f.d.Status().Overtaken {
		t.Fatal("still overtaken once a peer brought the way")
	}
}

// A removal drafted beside the newest checkpoint reaches a device that
// compacted through sync, and what follows it too: its anchor stays a
// checkpoint behind.
func TestARemovalBesideACheckpointReachesACompactedPeer(t *testing.T) {
	m := &mesh{t: t, nw: newNetwork(t, 3), hub: &lanHub{}}
	for i := range 2 {
		m.nodes = append(m.nodes, m.start(t, i))
	}
	waitFor(t, 30*time.Second, "the two to meet", func() bool {
		return m.nodes[0].d.Status().Peers >= 1 && m.nodes[1].d.Status().Peers >= 1
	})
	m.apply(t, m.nodes[0], func(b *log.Builder) (types.AUM, error) { return b.Checkpoint() })
	first := m.nodes[0].d.Status().Head
	m.apply(t, m.nodes[0], func(b *log.Builder) (types.AUM, error) { return b.RenameNetwork("before") })
	m.nodes[0].d.authMu.Lock()
	at := m.nodes[0].auth.State()
	m.nodes[0].d.authMu.Unlock()
	m.apply(t, m.nodes[0], func(b *log.Builder) (types.AUM, error) { return b.Checkpoint() })
	cp := m.nodes[0].d.Status().Head
	compacted := m.nodes[1]
	waitFor(t, 30*time.Second, "the other to hold the checkpoint", func() bool {
		return compacted.d.Status().Head == cp
	})
	compacted.d.authMu.Lock()
	_, err := compacted.d.authority.Compact()
	compacted.d.authMu.Unlock()
	if err != nil || compacted.anchor() != first {
		t.Fatalf("compacting: %v", err)
	}
	removal, err := log.NewBuilder(at).RemoveNode(m.nw.devices[2].record.Identity, m.nw.sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := removal.Sign(m.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := m.nodes[0].d.Inform([]types.AUM{removal}); err != nil {
		t.Fatal(err)
	}
	m.apply(t, m.nodes[0], func(b *log.Builder) (types.AUM, error) { return b.RenameNetwork("later") })
	later := m.nodes[0].d.Status().Head
	waitFor(t, 60*time.Second, "the compacted device to follow the removal", func() bool {
		return compacted.d.Status().Head == later
	})
}
