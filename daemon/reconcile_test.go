package daemon

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/trust/log"
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
	nw := newNetwork(t, members)
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
	}
	if err := e.Sign(dev.identity); err != nil {
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
	outsider := newDevice(t, "outsider", netip.AddrFrom4([4]byte{100, 64, 9, 9}))
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
	joiner := newDevice(t, "joiner", netip.AddrFrom4([4]byte{100, 64, 0, 5}))
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
	expiring := newDevice(t, "expiring", netip.AddrFrom4([4]byte{100, 64, 0, 2}))
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

	// Two conflicting removals with the same parent: fork choice picks one,
	// and the loser is a revocation that would be silently discarded, which
	// is precisely the case trust/log refuses to resolve.
	first := f.nw.removeNode(t, f.auth, a.record.Identity)
	second := f.nw.removeNode(t, f.auth, b.record.Identity)
	if err := f.auth.Inform(first, second); err != nil {
		t.Fatalf("informing the fork: %v", err)
	}
	if f.auth.Alarm() == nil {
		t.Fatal("two conflicting revocations did not raise a fork alarm")
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
	if !strings.Contains(err.Error(), "never enrolled") {
		t.Errorf("error %q does not say what is wrong", err)
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

	// The mirror case: once this node compacts, a peer anchored at the genesis
	// it no longer holds gets nothing — that peer is the one with history to
	// offer.
	if _, err := f.auth.Compact(); err != nil {
		t.Fatalf("compacting: %v", err)
	}
	batch, err = adapter.Missing(nil, f.nw.genesis.Hash())
	if err != nil {
		t.Fatalf("Missing after compaction: %v", err)
	}
	if len(batch) != 0 {
		t.Fatalf("a compacted node offered %d records below an anchor it does not hold", len(batch))
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
	}
	if err := nonMember.Sign(stranger); err != nil {
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
	if err := nonMember.Sign(stranger); err != nil {
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
	}
	if err := memberEndpoint.Sign(member.identity); err != nil {
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
	}
	if err := copycat.Sign(attacker.identity); err != nil {
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
