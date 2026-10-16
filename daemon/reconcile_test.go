package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/internal/statedir"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// reconcileFixture is a daemon with a recording data plane, LAN discovery off
// and no IPC: everything except the decision under test.
type reconcileFixture struct {
	nw      *network
	d       *Daemon
	mgr     *fakeManager
	auth    *log.Authority
	storage log.Storage
	self    *device
}

func newReconcileFixture(t *testing.T, members int) *reconcileFixture {
	t.Helper()
	return newReconcileFixtureWith(t, members, nil)
}

// newReconcileFixtureWith is [newReconcileFixture] with the daemon's options
// adjusted before it starts.
func newReconcileFixtureWith(t *testing.T, members int, mutate func(*Options)) *reconcileFixture {
	t.Helper()
	return newReconcileFixtureOn(t, newNetwork(t, members), mutate)
}

// newReconcileFixtureOn is [newReconcileFixtureWith] in nw.
func newReconcileFixtureOn(t *testing.T, nw *network, mutate func(*Options)) *reconcileFixture {
	t.Helper()
	auth, st := nw.authorityFor(t)
	mgr := &fakeManager{}
	self := nw.devices[0]

	opts := Options{
		Authority:        auth,
		Storage:          st,
		Identity:         self.identity,
		Recipient:        self.recipient,
		WireGuard:        self.wgPrivate,
		Connect:          func(conn.Options) (conn.Manager, error) { return mgr, nil },
		DisableDiscovery: true,
		DisableDHT:       true,
		Logf:             safeLogf(t, ""),
	}
	if mutate != nil {
		mutate(&opts)
	}
	d, err := New(opts)
	if err != nil {
		t.Fatalf("starting the daemon: %v", err)
	}
	// The recording data plane confirms a direct path with the probe's answer.
	d.pathSettle = time.Millisecond
	t.Cleanup(func() { d.Close() })
	return &reconcileFixture{nw: nw, d: d, mgr: mgr, auth: auth, storage: st, self: self}
}

// learn hands the daemon a peer's announcement, standing in for what LAN
// discovery or a gossip session would have delivered.
func (f *reconcileFixture) learn(t *testing.T, dev *device, port uint16) gossip.Endpoint {
	t.Helper()
	_, discoPub, err := conn.NewDiscoKey()
	if err != nil {
		t.Fatal(err)
	}
	e := gossip.Endpoint{
		Identity:   dev.record.Identity,
		Disco:      gossip.DiscoKey(discoPub),
		Addrs:      []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), port)},
		GossipPort: port,
		Seq:        1,
		Epoch:      f.auth.State().Epoch(),
		PairStore:  1,
		Schema:     types.CurrentSchema,
	}
	if err := e.SignPQ(dev.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatalf("learning an announcement: %v", err)
	}
	return e
}

// TestStatusNamesTheNetworkBeforeTheFirstReconcile pins what the startup
// banner reads: a status taken before the first reconcile. The network's
// identity is fixed at genesis, so an empty name there reads as "the daemon
// lost my network".
func TestStatusNamesTheNetworkBeforeTheFirstReconcile(t *testing.T) {
	f := newReconcileFixture(t, 2)
	st := f.d.Status()
	if st.NetworkName != "m2-testnet" {
		t.Errorf("status before the first reconcile names the network %q, want m2-testnet", st.NetworkName)
	}
	if want := f.auth.State().GenesisHash(); st.Network != want {
		t.Errorf("status before the first reconcile carries genesis %v, want %v", st.Network, want)
	}
}

// TestMemberWithoutAnAnnouncementIsNotAPeer is the shape of the join: the log
// says who may connect, and an announcement says where they are. Neither alone
// produces a peer, and the log is the half that cannot be skipped.
func TestMemberWithoutAnAnnouncementIsNotAPeer(t *testing.T) {
	f := newReconcileFixture(t, 3)
	if err := f.d.Reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := len(f.mgr.snapshot()); got != 0 {
		t.Fatalf("installed %d peers with no announcements held", got)
	}
	if st := f.d.Status(); st.Members != 3 || st.Unreachable != 2 {
		t.Errorf("status says %d members and %d unreachable, want 3 and 2", st.Members, st.Unreachable)
	}

	f.learn(t, f.nw.devices[1], 4001)
	if err := f.d.Reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !f.mgr.has([32]byte(f.nw.devices[1].record.WireGuard)) {
		t.Error("a member whose announcement arrived is still not a peer")
	}
	if f.mgr.has([32]byte(f.nw.devices[2].record.WireGuard)) {
		t.Error("a member with no announcement became a peer")
	}
}

// TestAnnouncementAloneGrantsNothing is M2's first exit criterion at the
// reconciler: good keys and a correct announcement, absent from the log, get
// no peer entry and so nothing to handshake against.
func TestAnnouncementAloneGrantsNothing(t *testing.T) {
	f := newReconcileFixture(t, 2)
	outsider := newDevice(t, "outsider", netip.AddrFrom4([4]byte{198, 18, 9, 9}))
	f.learn(t, outsider, 4009)

	if err := f.d.Reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if f.mgr.has([32]byte(outsider.record.WireGuard)) {
		t.Fatal("a non-member became a peer by announcing itself")
	}
	// Kept deliberately: an announcement whose subject the log does not carry
	// yet is the normal arrival order for a joining member, and it is inert
	// until the log catches up.
	if _, held := f.d.Endpoints().Get(outsider.record.Identity); !held {
		t.Error("an early announcement was dropped, which would hide a joining member")
	}
}

// TestAnEarlyAnnouncementSurvivesUntilTheRecordArrives is the ordering the
// cache exists to tolerate: discovery finds a joining node before gossip
// delivers the record admitting it.
func TestAnEarlyAnnouncementSurvivesUntilTheRecordArrives(t *testing.T) {
	f := newReconcileFixture(t, 1)
	joiner := newDevice(t, "joiner", netip.AddrFrom4([4]byte{198, 18, 0, 5}))
	f.learn(t, joiner, 4005)

	// Several reconciles pass while the record is still in flight.
	for range 3 {
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	if _, held := f.d.Endpoints().Get(joiner.record.Identity); !held {
		t.Fatal("the announcement was forgotten before its record arrived")
	}

	add, err := f.auth.Builder().AddNode(joiner.record, f.nw.sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := add.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{add}); err != nil {
		t.Fatal(err)
	}
	if !f.mgr.has([32]byte(joiner.record.WireGuard)) {
		t.Fatal("the new member is not a peer, so the early announcement bought nothing")
	}
}

// TestRemovalDropsThePeer is the reconciler's half of revocation.
func TestRemovalDropsThePeer(t *testing.T) {
	f := newReconcileFixture(t, 3)
	victim := f.nw.devices[1]
	f.learn(t, victim, 4001)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if !f.mgr.has([32]byte(victim.record.WireGuard)) {
		t.Fatal("the member was never a peer to begin with")
	}

	removal := f.nw.removeNode(t, f.auth, victim.record.Identity)
	if err := f.d.Inform([]types.AUM{removal}); err != nil {
		t.Fatalf("applying the removal: %v", err)
	}
	if f.mgr.has([32]byte(victim.record.WireGuard)) {
		t.Fatal("a removed member is still a WireGuard peer")
	}
	if _, held := f.d.Endpoints().Get(victim.record.Identity); held {
		t.Error("a removed member's announcement stayed in the cache")
	}
}

// TestExpiredMembershipIsNotAPeer consumes the expiry backstop. It is not the
// revocation mechanism — a signed removal is — but an expiry the reconciler
// ignores is a field that promises something nothing delivers.
func TestExpiredMembershipIsNotAPeer(t *testing.T) {
	nw := newNetwork(t, 1)
	// A second member whose membership expires an hour from the fixed clock.
	expiring := newDevice(t, "expiring", netip.AddrFrom4([4]byte{198, 18, 0, 2}))
	base := time.Unix(1_700_000_000, 0)
	expiring.record.Expiry = uint64(base.Add(time.Hour).Unix())

	auth, st := nw.authorityFor(t)
	add, err := auth.Builder().AddNode(expiring.record, nw.sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := add.Sign(nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := auth.Inform(add); err != nil {
		t.Fatal(err)
	}

	now := base
	mgr := &fakeManager{}
	d, err := New(Options{
		Authority: auth, Storage: st,
		Identity: nw.devices[0].identity, Recipient: nw.devices[0].recipient,
		WireGuard:        nw.devices[0].wgPrivate,
		Connect:          func(conn.Options) (conn.Manager, error) { return mgr, nil },
		DisableDiscovery: true,
		DisableDHT:       true,
		Clock:            func() time.Time { return now },
		Logf:             safeLogf(t, ""),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	f := &reconcileFixture{nw: nw, d: d, mgr: mgr, auth: auth, self: nw.devices[0]}
	f.learn(t, expiring, 4002)
	if err := d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if !mgr.has([32]byte(expiring.record.WireGuard)) {
		t.Fatal("a member inside its expiry is not a peer")
	}
	if _, held := d.pairs.Generations()[expiring.record.WireGuard]; !held {
		t.Fatal("no pair with a member that announces preshared keys")
	}

	now = base.Add(2 * time.Hour)
	if err := d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if mgr.has([32]byte(expiring.record.WireGuard)) {
		t.Fatal("an expired membership is still a WireGuard peer")
	}
	// The backstop has to mean the same thing in every layer. A device denied
	// the data plane but still gossiped with is still being handed the member
	// set and every member's address.
	if _, held := d.Endpoints().Get(expiring.record.Identity); held {
		t.Error("an expired member's announcement is still cached")
	}
	for _, id := range d.memberList() {
		if id == expiring.record.Identity {
			t.Error("an expired member is still in the set this node gossips with")
		}
	}
	if st := d.Status(); st.Expired != 1 {
		t.Errorf("status reports %d expired memberships, want 1", st.Expired)
	}
	// Its pair stays, as on its own side: one dropped while the other
	// kept it would meet again on different keys.
	if _, kept := d.pairs.Generations()[expiring.record.WireGuard]; !kept {
		t.Error("the pair with an expired member was dropped")
	}
}

// TestForkAlarmDropsEveryPeer is the fail-closed rule applied to fork choice:
// a node that cannot tell who is a member must deny, not guess — including for
// peers both branches agree on.
func TestForkAlarmDropsEveryPeer(t *testing.T) {
	f := newReconcileFixture(t, 3)
	a, b := f.nw.devices[1], f.nw.devices[2]
	f.learn(t, a, 4001)
	f.learn(t, b, 4002)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := len(f.mgr.snapshot()); got != 2 {
		t.Fatalf("installed %d peers, want 2", got)
	}

	// A removal and a grant to the same member with the same parent: the
	// removal wins, and the grant cannot be reissued on a chain without the
	// member, which is precisely the case trust/log refuses to resolve.
	first, second := f.nw.conflictingFork(t, f.auth, a.record.Identity)
	_ = b
	if err := f.auth.Inform(first, second); err != nil {
		t.Fatalf("informing the fork: %v", err)
	}
	if f.auth.Alarm() == nil {
		t.Fatal("a conflicting fork did not raise an alarm")
	}

	err := f.d.Reconcile()
	if err == nil {
		t.Fatal("reconcile succeeded under a fork alarm")
	}
	if got := len(f.mgr.snapshot()); got != 0 {
		t.Fatalf("%d peers survived a fork alarm", got)
	}
	if st := f.d.Status(); !strings.Contains(st.Alarm, "fork alarm") {
		t.Errorf("status alarm is %q, want it to mention the fork", st.Alarm)
	}
}

// A branch this node applied that lost fork choice to one below its epoch floor
// takes the mesh down and says so, rather than the node staying on the loser
// and refusing what sync brings, the winner's removals included.
func TestAForkSwitchBelowTheEpochFloorDropsEveryPeer(t *testing.T) {
	f := newReconcileFixture(t, 3)
	a, b := f.nw.devices[1], f.nw.devices[2]
	f.learn(t, a, 4001)
	f.learn(t, b, 4002)
	winner, _ := f.nw.authorityFor(t)
	var won []types.AUM
	for _, id := range []types.Identity{a.record.Identity, b.record.Identity} {
		rec := f.nw.removeNode(t, winner, id)
		if err := winner.Inform(rec); err != nil {
			t.Fatal(err)
		}
		won = append(won, rec)
	}
	for range 3 {
		rec, err := f.auth.Builder().EpochBump(f.nw.sealer())
		if err != nil {
			t.Fatal(err)
		}
		if err := rec.Sign(f.nw.admin); err != nil {
			t.Fatal(err)
		}
		if err := f.d.Inform([]types.AUM{rec}); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(f.mgr.snapshot()); got != 2 {
		t.Fatalf("installed %d peers, want 2", got)
	}

	synced := (*logAdapter)(f.d).Inform(won)
	if err := f.d.Reconcile(); err == nil {
		t.Fatalf("%d peers stay up, alarm %q, after sync of the winning branch answered %v",
			len(f.mgr.snapshot()), f.d.Status().Alarm, synced)
	}
	if synced != nil {
		t.Fatalf("sync of the winning branch: %v", synced)
	}
	if got := len(f.mgr.snapshot()); got != 0 {
		t.Fatalf("%d peers survived a rollback alarm", got)
	}
	if st := f.d.Status(); !strings.Contains(st.Alarm, "rollback alarm") {
		t.Errorf("status alarm is %q, want it to name the rollback", st.Alarm)
	}
}

// A disabled network is down for good, and says so rather than raising an alarm.
func TestDisableDropsEveryPeer(t *testing.T) {
	f := newReconcileFixture(t, 3)
	f.learn(t, f.nw.devices[1], 4001)
	f.learn(t, f.nw.devices[2], 4002)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := len(f.mgr.snapshot()); got != 2 {
		t.Fatalf("installed %d peers, want 2", got)
	}
	aum, err := f.auth.Builder().Disable(f.nw.disablement)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{aum}); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatalf("reconcile of a disabled network: %v", err)
	}
	if got := len(f.mgr.snapshot()); got != 0 {
		t.Fatalf("%d peers survived the network's end", got)
	}
	if st := f.d.Status(); st.Disabled != aum.Hash().String() || st.Alarm != "" {
		t.Fatalf("status disabled %q, alarm %q", st.Disabled, st.Alarm)
	}
	// It still tells the members, or the end would not spread past it.
	if got := len(f.d.memberList()); got != 2 {
		t.Fatalf("a disabled node gossips with %d members, want 2", got)
	}
}

// A disable record no walk from a peer's anchor reaches still goes to the peer,
// as do catch-ups, so that it reaches members which are behind.
func TestADisabledNodeHandsTheRecordOn(t *testing.T) {
	f := newReconcileFixture(t, 2)
	f.learn(t, f.nw.devices[1], 4001)
	parent := types.Hash{7, 7, 7}
	aum := types.AUM{Kind: types.KindDisable, Prev: &parent, Secret: &f.nw.disablement}
	if err := f.d.Inform([]types.AUM{aum}); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	adapter := (*logAdapter)(f.d)
	view, err := adapter.View()
	if err != nil {
		t.Fatal(err)
	}
	have := slices.DeleteFunc(view.Have, func(h types.Hash) bool { return h == aum.Hash() })
	out, err := adapter.Missing(have, view.Anchor)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Hash() != aum.Hash() {
		t.Fatalf("a peer lacking the disable record is sent %d records", len(out))
	}
	if _, ok, err := adapter.Member(f.nw.devices[1].record.Identity); !ok || err != nil {
		t.Fatalf("a disabled node grants no catch-up: %v", err)
	}
	// Where log sync runs in the tunnels, it needs their addresses to hand
	// the record on before it drops them.
	f.d.overlayOnly = true
	if addrs := f.d.overlayGossipAddrs(f.nw.devices[1].record.Identity); len(addrs) == 0 {
		t.Fatal("a disabled node has no address to hand the record on at")
	}
}

// TestDaemonRefusesANetworkItIsNotIn catches a device pointed at somebody
// else's state directory: starting anyway fails in three confusing places
// rather than one clear one.
func TestDaemonRefusesANetworkItIsNotIn(t *testing.T) {
	nw := newNetwork(t, 1)
	auth, st := nw.authorityFor(t)
	stranger := newDevice(t, "stranger", netip.Addr{})

	_, err := New(Options{
		Authority: auth, Storage: st,
		Identity: stranger.identity, Recipient: stranger.recipient,
		WireGuard:        stranger.wgPrivate,
		Connect:          func(conn.Options) (conn.Manager, error) { return &fakeManager{}, nil },
		DisableDiscovery: true,
		DisableDHT:       true,
	})
	if err == nil {
		t.Fatal("a daemon started for a network its key is not a member of")
	}
	if !errors.Is(err, ErrNotMember) {
		t.Errorf("error %q is not ErrNotMember", err)
	}
}

// TestEpochSecretIsAdopted is what makes gossip and discovery work at all:
// the daemon has to open its own wrap of the current group secret, and it has
// to follow the epoch as membership changes.
func TestEpochSecretIsAdopted(t *testing.T) {
	f := newReconcileFixture(t, 3)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	epoch, got, ok := f.d.keyring.Latest()
	if !ok {
		t.Fatal("the daemon did not open the genesis epoch's group secret")
	}
	f.nw.mu.Lock()
	want := f.nw.secretByEpoch[epoch]
	f.nw.mu.Unlock()
	if !got.Equal(want) {
		t.Fatal("the daemon opened a different secret than the one that was sealed")
	}

	removal := f.nw.removeNode(t, f.auth, f.nw.devices[1].record.Identity)
	if err := f.d.Inform([]types.AUM{removal}); err != nil {
		t.Fatal(err)
	}
	next, _, ok := f.d.keyring.Latest()
	if !ok || next != epoch+1 {
		t.Fatalf("keyring is at epoch %d after a removal, want %d", next, epoch+1)
	}
	// The old secret stays, which is what lets this node keep talking to
	// members that have not applied the removal yet.
	if _, held := f.d.keyring.Secret(epoch); !held {
		t.Error("the previous epoch's secret was dropped immediately")
	}
}

// TestMissingRespectsThePeersAnchor is the sync-after-compaction property: a
// node with full history must send a checkpoint-only peer exactly the records
// descending from that checkpoint. Anything older is refused, and Inform being
// atomic, one refused record poisons the whole batch.
func TestMissingRespectsThePeersAnchor(t *testing.T) {
	f := newReconcileFixture(t, 2)

	// The chain grows a checkpoint, then a record after it.
	cp, err := f.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if err := cp.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{cp}); err != nil {
		t.Fatalf("informing the checkpoint: %v", err)
	}
	grant, err := f.auth.Builder().SetNodeRoutes(f.nw.devices[1].record.Identity,
		[]types.Role{types.RoleRelayCapable}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := grant.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{grant}); err != nil {
		t.Fatalf("informing the post-checkpoint record: %v", err)
	}

	// A second node that bootstrapped from the checkpoint: it holds exactly
	// one record, and its anchor is that record.
	bootSt := log.NewMemStorage()
	bootAuth, err := log.Bootstrap(bootSt, cp)
	if err != nil {
		t.Fatalf("bootstrapping from the checkpoint: %v", err)
	}
	bootHave, err := bootSt.Hashes()
	if err != nil {
		t.Fatal(err)
	}

	adapter := (*logAdapter)(f.d)
	batch, err := adapter.Missing(bootHave, bootAuth.Anchor())
	if err != nil {
		t.Fatalf("Missing: %v", err)
	}
	for _, aum := range batch {
		if aum.Hash() == f.nw.genesis.Hash() {
			t.Fatal("the batch contains the genesis record, which the bootstrapped peer cannot accept")
		}
	}
	// The proof that the batch is right is that the peer takes it whole and
	// lands on the same head.
	if err := bootAuth.Inform(batch...); err != nil {
		t.Fatalf("the bootstrapped peer rejected the batch: %v", err)
	}
	if bootAuth.Head() != f.auth.Head() {
		t.Fatalf("after sync the bootstrapped peer is at %v, the full node at %v",
			bootAuth.Head(), f.auth.Head())
	}

	checkpoint := func() types.AUM {
		t.Helper()
		cp, err := f.auth.Builder().Checkpoint()
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

	// The mirror case: once this node compacts, to the checkpoint before the
	// newest, it keeps the chain up to its anchor, and a peer anchored at the
	// genesis is offered what hangs from it.
	cp2 := checkpoint()
	if _, err := f.auth.Compact(); err != nil || f.auth.Anchor() != cp.Hash() {
		t.Fatalf("compacting: %v", err)
	}
	batch, err = adapter.Missing([]types.Hash{f.nw.genesis.Hash()}, f.nw.genesis.Hash())
	if err != nil {
		t.Fatalf("Missing after compaction: %v", err)
	}
	if len(batch) != 3 || batch[0].Hash() != cp.Hash() || batch[1].Hash() != grant.Hash() || batch[2].Hash() != cp2.Hash() {
		t.Fatalf("a compacted node offered %d records, not those from the genesis on", len(batch))
	}

	// Once a second compaction drops the genesis, such a peer is offered
	// what hangs from this node's anchor, which it takes where it holds the
	// checkpoint's parent.
	cp3 := checkpoint()
	if _, err := f.auth.Compact(); err != nil || f.auth.Anchor() != cp2.Hash() {
		t.Fatalf("compacting: %v", err)
	}
	batch, err = adapter.Missing([]types.Hash{f.nw.genesis.Hash()}, f.nw.genesis.Hash())
	if err != nil {
		t.Fatalf("Missing after compaction: %v", err)
	}
	if len(batch) != 2 || batch[0].Hash() != cp2.Hash() || batch[1].Hash() != cp3.Hash() {
		t.Fatalf("a compacted node offered %d records, not those from its anchor on", len(batch))
	}
}

// A peer anchored at one copy of a checkpoint is offered the others, and
// what hangs from them.
func TestMissingOffersWhatHangsFromAnotherCopyOfThePeersAnchor(t *testing.T) {
	f := newReconcileFixture(t, 2)
	second, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	add, err := f.auth.Builder().AddAdminKey(types.AdminKey{Public: second.Public(), Votes: 1, Name: "second",
		Signing: new(second.SigningKey()), Endorsement: second.Endorsement()})
	if err != nil {
		t.Fatal(err)
	}
	if err := add.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{add}); err != nil {
		t.Fatal(err)
	}
	cp, err := f.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if err := cp.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	both := *cp.Clone()
	if err := both.Sign(second); err != nil {
		t.Fatal(err)
	}
	low, high := cp, both
	if high.Hash().Compare(low.Hash()) < 0 {
		low, high = high, low
	}
	onHigh, err := log.Bootstrap(log.NewMemStorage(), high)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := onHigh.Builder().SetNodeRoutes(f.nw.devices[1].record.Identity,
		[]types.Role{types.RoleRelayCapable}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := grant.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{low, high, grant}); err != nil {
		t.Fatal(err)
	}

	peerSt := log.NewMemStorage()
	peer, err := log.Bootstrap(peerSt, low)
	if err != nil {
		t.Fatal(err)
	}
	have, err := peerSt.Hashes()
	if err != nil {
		t.Fatal(err)
	}
	batch, err := (*logAdapter)(f.d).Missing(have, peer.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Inform(batch...); err != nil {
		t.Fatalf("the peer refused the batch: %v", err)
	}
	if peer.Head() != grant.Hash() || f.auth.Head() != grant.Hash() {
		t.Fatalf("the peer is at %v, this node at %v, want %v", peer.Head(), f.auth.Head(), grant.Hash())
	}
}

// A peer anchored at a copy of a checkpoint above the two lowest, which
// carries no key's signature they lack, is sent what it can take: this node,
// anchored below, keeps that copy.
func TestMissingServesAPeerAnchoredAtAThirdCopyOfACheckpoint(t *testing.T) {
	f := newReconcileFixture(t, 2)
	second, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	add, err := f.auth.Builder().AddAdminKey(types.AdminKey{Public: second.Public(), Votes: 1, Name: "second",
		Signing: new(second.SigningKey()), Endorsement: second.Endorsement()})
	if err != nil {
		t.Fatal(err)
	}
	if err := add.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{add}); err != nil {
		t.Fatal(err)
	}
	cp, err := f.auth.Builder().Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	var copies []types.AUM
	for _, keys := range [][]types.PrivateIdentity{{f.nw.admin}, {second}, {f.nw.admin, second}} {
		c := *cp.Clone()
		for _, k := range keys {
			if err := c.Sign(k); err != nil {
				t.Fatal(err)
			}
		}
		copies = append(copies, c)
	}
	slices.SortFunc(copies, func(a, b types.AUM) int { return a.Hash().Compare(b.Hash()) })
	if err := f.d.Inform(copies); err != nil {
		t.Fatal(err)
	}
	grant, err := f.auth.Builder().SetNodeRoutes(f.nw.devices[1].record.Identity,
		[]types.Role{types.RoleRelayCapable}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := grant.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{grant}); err != nil {
		t.Fatal(err)
	}

	peerSt := log.NewMemStorage()
	peer, err := log.Bootstrap(peerSt, copies[2])
	if err != nil {
		t.Fatal(err)
	}
	have, err := peerSt.Hashes()
	if err != nil {
		t.Fatal(err)
	}
	batch, err := (*logAdapter)(f.d).Missing(have, peer.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Inform(batch...); err != nil {
		t.Fatalf("the peer refused the batch: %v", err)
	}
	if peer.Head() != grant.Hash() {
		t.Fatalf("the peer is at %v, want %v", peer.Head(), grant.Hash())
	}
}

// Records the log holds already are no news to gossip, which relays news
// alone.
func TestRecordsTheLogHoldsAreNoNewsToGossip(t *testing.T) {
	f := newReconcileFixture(t, 2)
	grant, err := f.auth.Builder().SetNodeRoutes(f.nw.devices[1].record.Identity,
		[]types.Role{types.RoleRelayCapable}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := grant.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	adapter := (*logAdapter)(f.d)
	if err := adapter.Inform([]types.AUM{grant}); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Inform([]types.AUM{grant}); !errors.Is(err, gossip.ErrNothingNew) {
		t.Fatalf("a record held already: %v", err)
	}
}

// TestOwnRemovalTearsDownTheDataPlane: when the removal reaches the removed
// device, its daemon takes its own tunnels down. Peers enforce membership
// anyway; this is so it stops probing them.
func TestOwnRemovalTearsDownTheDataPlane(t *testing.T) {
	f := newReconcileFixture(t, 3)
	f.learn(t, f.nw.devices[1], 4001)
	f.learn(t, f.nw.devices[2], 4002)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := len(f.mgr.snapshot()); got != 2 {
		t.Fatalf("installed %d peers, want 2", got)
	}

	removal := f.nw.removeNode(t, f.auth, f.self.record.Identity)
	if err := f.d.Inform([]types.AUM{removal}); err != nil {
		t.Fatalf("informing this device's own removal: %v", err)
	}
	if got := len(f.mgr.snapshot()); got != 0 {
		t.Fatalf("%d peers survived this device's own removal", got)
	}
	st := f.d.Status()
	if !st.NotMember {
		t.Error("status does not say this device is no longer a member")
	}
	if st.Peers != 0 {
		t.Errorf("status reports %d peers, want 0", st.Peers)
	}
	if peers := f.d.memberList(); len(peers) != 0 {
		t.Errorf("a removed device still plans to gossip with %d members", len(peers))
	}
}

// TestRotationAppliedElsewhereIsReportedStale: a rotation applied while the
// daemon runs leaves the log naming keys it does not hold, and everything
// fails from there looking like a network problem unless it says otherwise.
func TestRotationAppliedElsewhereIsReportedStale(t *testing.T) {
	f := newReconcileFixture(t, 2)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if f.d.Status().StaleKeys {
		t.Fatal("fresh daemon already reports stale keys")
	}

	fresh := newDevice(t, "", netip.Addr{})
	rec, err := f.auth.Builder().RotateNodeKey(f.self.record.Identity, types.NodeKeys{
		WireGuard: fresh.record.WireGuard,
		X25519:    fresh.record.X25519,
		MLKEM:     fresh.record.MLKEM,
	}, f.nw.sealer())
	if err != nil {
		t.Fatal(err)
	}
	// A rotation needs the device's own signature as well as quorum.
	if err := rec.Sign(f.self.identity); err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{rec}); err != nil {
		t.Fatalf("informing the rotation: %v", err)
	}

	st := f.d.Status()
	if !st.StaleKeys {
		t.Fatal("the daemon did not notice the log names keys it does not hold")
	}
	// The new epoch is sealed to the new recipient key, which this process
	// does not hold either; that failure is reported on its own channel.
	if st.EpochError == "" {
		t.Error("the daemon claims to have opened an epoch sealed to keys it does not hold")
	}
}

// TestOwnRemovalGoesQuietOnTheLAN is the discovery half of
// TestOwnRemovalTearsDownTheDataPlane: a removed device stops producing an
// announcement, so it neither beacons nor answers queries nor offers a Self.
// Behaviour rather than access control — it still holds old epoch secrets.
func TestOwnRemovalGoesQuietOnTheLAN(t *testing.T) {
	f := newReconcileFixture(t, 2)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.d.Announcement(); !ok {
		t.Fatal("a member daemon has no announcement to make")
	}

	removal := f.nw.removeNode(t, f.auth, f.self.record.Identity)
	if err := f.d.Inform([]types.AUM{removal}); err != nil {
		t.Fatalf("informing this device's own removal: %v", err)
	}
	if _, ok := f.d.Announcement(); ok {
		t.Fatal("a removed device still offers an announcement to the LAN")
	}
}

// TestRestartRecoversPastEpochs: a daemon that opened only its newest epoch
// would lose the keyring's purpose on every restart, leaving it with no epoch
// in common with a peer that is behind — in a two-node network, a partition
// nothing heals.
func TestRestartRecoversPastEpochs(t *testing.T) {
	f := newReconcileFixture(t, 3)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	genesisEpoch, _, ok := f.d.keyring.Latest()
	if !ok {
		t.Fatal("no epoch secret after the first reconcile")
	}

	// Two membership changes, so the log carries three epochs.
	removal := f.nw.removeNode(t, f.auth, f.nw.devices[2].record.Identity)
	if err := f.d.Inform([]types.AUM{removal}); err != nil {
		t.Fatal(err)
	}
	bump, err := f.auth.Builder().EpochBump(f.nw.sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := bump.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{bump}); err != nil {
		t.Fatal(err)
	}
	newest, _, _ := f.d.keyring.Latest()
	if newest != genesisEpoch+2 {
		t.Fatalf("keyring is at epoch %d, want %d", newest, genesisEpoch+2)
	}

	// A fresh daemon over the same state directory: what a restart is.
	restarted, err := New(Options{
		Authority:        f.auth,
		Storage:          f.storage,
		Identity:         f.self.identity,
		Recipient:        f.self.recipient,
		WireGuard:        f.self.wgPrivate,
		Connect:          func(conn.Options) (conn.Manager, error) { return &fakeManager{}, nil },
		DisableDiscovery: true,
		DisableDHT:       true,
		Logf:             safeLogf(t, ""),
	})
	if err != nil {
		t.Fatalf("restarting: %v", err)
	}
	t.Cleanup(func() { restarted.Close() })

	if got := restarted.keyring.Epochs(); len(got) != 0 {
		t.Fatalf("a daemon that has not run yet already holds epochs %v", got)
	}
	restarted.backfillEpochs()
	got := restarted.keyring.Epochs()
	for _, want := range []uint64{genesisEpoch, genesisEpoch + 1, genesisEpoch + 2} {
		if !slices.Contains(got, want) {
			t.Errorf("a restarted daemon lost the epoch %d secret; it holds %v", want, got)
		}
	}
}

// TestADisplacedPushIsDeferredNotDropped: only one anti-entropy round runs at
// a time, and one asked for while another is running must not be forgotten —
// epidemic propagation depends on relaying, so a revocation arriving mid-round
// would otherwise converge at the two-minute backstop.
func TestADisplacedPushIsDeferredNotDropped(t *testing.T) {
	f := newReconcileFixture(t, 2)
	ctx := t.Context()

	// Drain the signal the fixture's own construction may have left.
	select {
	case <-f.d.dirty:
	default:
	}

	release := make(chan struct{})
	running := make(chan struct{})
	f.d.inBackground(ctx, func(context.Context) {
		close(running)
		<-release
	})
	<-running

	// A second round, asked for while the first is in flight.
	f.d.inBackground(ctx, func(context.Context) { t.Error("two rounds ran at once") })
	select {
	case <-f.d.dirty:
		t.Fatal("the displaced round was signalled before the first one finished")
	default:
	}

	close(release)
	select {
	case <-f.d.dirty:
	case <-time.After(2 * time.Second):
		t.Fatal("a push displaced by a running round was dropped; nothing will relay it")
	}
}

// TestDiscoveryOfANonMemberDoesNotWakeTheLoop: an announcement for a subject
// the log does not carry is cached, as the early-join contract needs, but must
// not drive a reconcile, a gossip round or a log line — an epoch-secret holder
// can mint identities without limit. A member's announcement still wakes it.
func TestDiscoveryOfANonMemberDoesNotWakeTheLoop(t *testing.T) {
	f := newReconcileFixture(t, 3)

	// Close the pre-first-reconcile window, so membership — not the startup
	// escape hatch — decides what is actionable.
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	drain := func() {
		select {
		case <-f.d.dirty:
		default:
		}
	}
	drain()

	// A minted non-member, validly signed by a key the log never carried.
	stranger, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, discoPub, err := conn.NewDiscoKey()
	if err != nil {
		t.Fatal(err)
	}
	nonMember := gossip.Endpoint{
		Identity:   stranger.Public(),
		Disco:      gossip.DiscoKey(discoPub),
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("192.0.2.99:5001")},
		GossipPort: 5001,
		Seq:        1,
		Schema:     types.CurrentSchema,
	}
	if err := nonMember.SignPQ(stranger); err != nil {
		t.Fatal(err)
	}

	f.d.onDiscovered(nonMember)

	if _, cached := f.d.endpoints.Get(stranger.Public()); !cached {
		t.Error("a non-member's announcement was not cached; the early-join contract is broken")
	}
	select {
	case <-f.d.dirty:
		t.Fatal("a non-member's LAN announcement woke the reconcile loop")
	default:
	}

	// A rising Seq for the same non-member — the sustained-churn shape — still
	// does not wake it.
	nonMember.Seq = 2
	if err := nonMember.SignPQ(stranger); err != nil {
		t.Fatal(err)
	}
	f.d.onDiscovered(nonMember)
	select {
	case <-f.d.dirty:
		t.Fatal("a rising-Seq non-member announcement woke the loop; the churn vector is open")
	default:
	}

	// A real member becoming reachable does wake it.
	member := f.nw.devices[1]
	_, memberDisco, err := conn.NewDiscoKey()
	if err != nil {
		t.Fatal(err)
	}
	memberEndpoint := gossip.Endpoint{
		Identity:   member.record.Identity,
		Disco:      gossip.DiscoKey(memberDisco),
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("192.0.2.11:5002")},
		GossipPort: 5002,
		Seq:        1,
		Schema:     types.CurrentSchema,
	}
	if err := memberEndpoint.SignPQ(member.identity); err != nil {
		t.Fatal(err)
	}
	f.d.onDiscovered(memberEndpoint)
	select {
	case <-f.d.dirty:
	default:
		t.Fatal("a member becoming reachable on the LAN did not wake the loop")
	}
}

// TestADuplicateDiscoKeyDropsOnlyTheColliders: the disco key is the one part
// of a peer entry the peer chooses, and conn refuses a set containing two of
// the same — so passing a collision through would hand any member a kill
// switch. The colliders lose their entries and the rest of the mesh stays up.
func TestADuplicateDiscoKeyDropsOnlyTheColliders(t *testing.T) {
	f := newReconcileFixture(t, 4)
	victim, attacker, bystander := f.nw.devices[1], f.nw.devices[2], f.nw.devices[3]

	e := f.learn(t, victim, 4001)
	f.learn(t, bystander, 4003)

	// The attacker announces the victim's disco key.
	copycat := gossip.Endpoint{
		Identity:   attacker.record.Identity,
		Disco:      e.Disco,
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("192.0.2.20:4002")},
		GossipPort: 4002,
		Seq:        1,
		Schema:     types.CurrentSchema,
	}
	if err := copycat.SignPQ(attacker.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(copycat); err != nil {
		t.Fatal(err)
	}

	if err := f.d.Reconcile(); err != nil {
		t.Fatalf("one member's announcement broke the whole reconcile: %v", err)
	}
	installed := f.mgr.snapshot()
	if len(installed) != 1 {
		t.Fatalf("installed %d peers, want only the bystander", len(installed))
	}
	if got := f.d.Status().Conflicted; got != 2 {
		t.Errorf("status reports %d conflicted members, want 2", got)
	}
	if f.d.Status().Peers != 1 {
		t.Errorf("status reports %d peers, want 1", f.d.Status().Peers)
	}
}

// A node that rotated its own keys can no longer open the chain's older
// wraps, which are sealed to the keys it had. The secrets it held are kept in
// the keyring file, and taken back where the chain's record commits to them —
// so it keeps an epoch in common with every peer that has not applied the
// rotation yet, and a planted file adds nothing.
func TestKeptSecretsOutliveARotationOfTheKeys(t *testing.T) {
	f := newReconcileFixture(t, 3)
	f.d.keyringPath = filepath.Join(t.TempDir(), statedir.KeyringFile)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	removal := f.nw.removeNode(t, f.auth, f.nw.devices[2].record.Identity)
	if err := f.d.Inform([]types.AUM{removal}); err != nil {
		t.Fatal(err)
	}
	held := f.d.keyring.Epochs()
	if len(held) < 2 {
		t.Fatalf("the keyring holds %v", held)
	}

	// The same device with other sealing keys: nothing older opens for it.
	other, err := secrets.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	restart := func() *Daemon {
		d, err := New(Options{
			Authority: f.auth, Storage: f.storage, Identity: f.self.identity, Recipient: other,
			WireGuard: f.self.wgPrivate, KeyringPath: f.d.keyringPath,
			Connect:          func(conn.Options) (conn.Manager, error) { return &fakeManager{}, nil },
			DisableDiscovery: true, DisableDHT: true, Logf: safeLogf(t, ""),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { d.Close() })
		d.backfillEpochs()
		return d
	}
	if got := restart().keyring.Epochs(); !slices.Equal(got, held) {
		t.Fatalf("after the rotation the node holds %v, want the %v it held", got, held)
	}

	// A file whose secrets the chain does not commit to buys nothing.
	b, err := os.ReadFile(f.d.keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	forged := strings.Map(func(r rune) rune {
		if r == 'a' {
			return 'b'
		}
		return r
	}, string(b))
	if err := os.WriteFile(f.d.keyringPath, []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := restart().keyring.Epochs(); len(got) >= len(held) {
		t.Fatalf("a forged keyring file was taken back: %v", got)
	}
}

// xorSealer seals by XOR, enough to tell a sealed file from a plain one.
type xorSealer struct{}

func (xorSealer) Seal(plain []byte) ([]byte, error)  { return xorBytes(plain), nil }
func (xorSealer) Open(sealed []byte) ([]byte, error) { return xorBytes(sealed), nil }

func xorBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ 0x5a
	}
	return out
}

// Where the node's keys are sealed, the epoch secrets kept beside them are
// too, and are read back.
func TestKeptSecretsAreSealedAsTheNodesKeys(t *testing.T) {
	keys.SealWith(xorSealer{})
	t.Cleanup(func() { keys.SealWith(nil) })
	f := newReconcileFixture(t, 2)
	f.d.keyringPath = filepath.Join(t.TempDir(), statedir.KeyringFile)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	epochs, held := f.d.keyring.Held()
	if len(held) == 0 {
		t.Fatal("the keyring holds nothing")
	}
	b, err := os.ReadFile(f.d.keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), keys.SealedTag) || strings.Contains(string(b), hex.EncodeToString(held[0][:])) {
		t.Fatalf("the kept secrets are not sealed:\n%s", b)
	}
	if got := f.d.loadKeyring(); got[epochs[0]] != held[0] {
		t.Errorf("the sealed secrets read back as %v", got)
	}
}

// Two removals at once do not take the mesh down: the status names the one
// that is not in effect, for an admin to run again.
func TestAConcurrentRemovalIsNamedNotStopped(t *testing.T) {
	f := newReconcileFixture(t, 3)
	a, b := f.nw.devices[1], f.nw.devices[2]
	first := f.nw.removeNode(t, f.auth, a.record.Identity)
	second := f.nw.removeNode(t, f.auth, b.record.Identity)
	if err := f.auth.Inform(first, second); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatalf("two removals at once stopped the mesh: %v", err)
	}
	st := f.d.Status()
	if st.Alarm != "" || len(st.Unrevoked) != 1 || !strings.HasPrefix(st.Unrevoked[0], "the removal of ") {
		t.Fatalf("alarm %q, unrevoked %q", st.Alarm, st.Unrevoked)
	}
}

// An admission that lost fork choice to one made at the same time is named in
// the status: the device it admitted is left out of the network, and nothing
// but "juist log" said so.
func TestALostAdmissionIsNamed(t *testing.T) {
	f := newReconcileFixture(t, 2)
	b := f.auth.Builder()
	var records []types.AUM
	for i, name := range []string{"one", "two"} {
		dev := newDevice(t, name, netip.AddrFrom4([4]byte{198, 18, 0, byte(50 + i)}))
		rec, err := b.AddNode(dev.record, f.nw.sealer())
		if err != nil {
			t.Fatal(err)
		}
		if err := rec.Sign(f.nw.admin); err != nil {
			t.Fatal(err)
		}
		records = append(records, rec)
	}
	if err := f.d.Inform(records); err != nil {
		t.Fatal(err)
	}
	lost := f.d.Status().Lost
	if len(lost) != 1 || !strings.HasPrefix(lost[0], "the admission of ") {
		t.Fatalf("status names %v as lost, want one admission", lost)
	}
}

// A change lost to a concurrent one is said in words, a rename included.
func TestALostRenameIsSaid(t *testing.T) {
	id := types.Identity{1}
	got := describeLost(types.AUM{Kind: types.KindRenameNode, Subject: &id, NodeName: new("desk")}, "laptop")
	if got != `the renaming of laptop to "desk"` {
		t.Errorf("a lost rename is %q", got)
	}
}

// learnHint hands the daemon e as a quantum computer forges it, signed by
// Ed25519 alone, with change made, and checks it is held as a hint alone.
func (f *reconcileFixture) learnHint(t *testing.T, dev *device, e gossip.Endpoint, change func(*gossip.Endpoint)) {
	t.Helper()
	h := e.Hint()
	change(&h)
	if err := h.Sign(dev.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(h); err != nil {
		t.Fatal(err)
	}
	if !f.d.endpoints.IsHint(dev.record.Identity) {
		t.Fatal("the forged announcement is not held as a hint alone")
	}
}

// A hint alone naming another member's disco key, as forged, costs that
// member nothing: it keeps its peer entry, and the hint's member gets none.
func TestAHintAloneNamingAMembersDiscoKeyLeavesThatMembersPeer(t *testing.T) {
	f := newReconcileFixture(t, 3)
	member, forged := f.nw.devices[1], f.nw.devices[2]
	full := f.learn(t, member, 7001)
	e, err := endpointFor(forged, 7002)
	if err != nil {
		t.Fatal(err)
	}
	f.learnHint(t, forged, e, func(h *gossip.Endpoint) { h.Seq, h.Disco = 2, full.Disco })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.installed(t, 1)
	for _, p := range f.mgr.snapshot() {
		if p.NodeKey == conn.NodePublicFromRaw32([32]byte(forged.record.WireGuard)) {
			t.Fatal("a hint alone naming another member's disco key got a peer entry")
		}
	}
}

// A member that restarted announces a new disco key, which reaches this
// device by a hint alone until their tunnel is up, log sync running through
// it: installed on the announcement's stale key, the two would never meet.
// One whose tunnel is up on the announcement's key keeps it against a hint,
// which may be forged, until it is found down.
func TestANewerHintsDiscoKeyIsInstalledWhileItsMemberIsNotReached(t *testing.T) {
	f := newReconcileFixture(t, 3)
	restarted, up := f.nw.devices[1], f.nw.devices[2]
	before := []gossip.Endpoint{f.learn(t, restarted, 7001), f.learn(t, up, 7002)}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	answering := f.installed(t, 2).Addrs[0].Addr()
	f.mgr.mu.Lock()
	f.mgr.answers = map[netip.Addr]bool{answering: true}
	f.mgr.mu.Unlock()
	f.d.refreshReach(t.Context())

	var rerun []gossip.DiscoKey
	for i, dev := range []*device{restarted, up} {
		h := before[i].Hint()
		_, k, err := conn.NewDiscoKey()
		if err != nil {
			t.Fatal(err)
		}
		h.Seq, h.Disco = 2, gossip.DiscoKey(k)
		if err := h.Sign(dev.identity); err != nil {
			t.Fatal(err)
		}
		if err := f.d.Learn(h); err != nil {
			t.Fatal(err)
		}
		rerun = append(rerun, h.Disco)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	on := func(i int, k gossip.DiscoKey) bool { return f.installed(t, i).DiscoKey == conn.DiscoPublicFromRaw32(k) }
	if !on(1, rerun[0]) {
		t.Fatal("a member not reached is installed on its announcement's disco key, not the newer hint's")
	}
	if !on(2, before[1].Disco) {
		t.Fatal("a hint moved the disco key of a member reached on its announcement's")
	}

	// Found down, the member reached moves to the hint's key too.
	f.mgr.mu.Lock()
	f.mgr.answers = nil
	f.mgr.mu.Unlock()
	for len(f.d.dirty) > 0 {
		<-f.d.dirty
	}
	f.d.refreshReach(t.Context())
	if len(f.d.dirty) == 0 {
		t.Fatal("a member found down with a newer hint's disco key held asks for no reconcile")
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if !on(2, rerun[1]) {
		t.Fatal("a member found down is not installed on the newer hint's disco key")
	}
}
