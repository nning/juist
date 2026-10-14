package daemon

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nning/juist/internal/statedir"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/types"
)

// fakeClock is a clock a test moves by hand.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

const testTTL = 48 * time.Hour

// freshFixture is a victim daemon (device 0) in a network whose device 1 is
// an admin device and device 2 is the member that will be revoked.
type freshFixture struct {
	*reconcileFixture
	clock *fakeClock
	start time.Time
}

func newFreshFixture(t *testing.T, leasePath string, adminDevices ...int) *freshFixture {
	t.Helper()
	if adminDevices == nil {
		adminDevices = []int{1}
	}
	return newFreshFixtureWith(t, leasePath, func(nw *network) {
		for _, i := range adminDevices {
			nw.devices[i].record.Roles = []types.Role{types.RoleAdmin}
		}
	})
}

// newFreshFixtureWith founds the network after mutate has adjusted its
// devices.
func newFreshFixtureWith(t *testing.T, leasePath string, mutate func(*network)) *freshFixture {
	t.Helper()
	nw := newNetworkMutated(t, 3, mutate)
	auth, st := nw.authorityFor(t)
	mgr := &fakeManager{}
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	self := nw.devices[0]
	d, err := New(Options{
		Authority:        auth,
		Storage:          st,
		Identity:         self.identity,
		Recipient:        self.recipient,
		WireGuard:        self.wgPrivate,
		Connect:          func(conn.Options) (conn.Manager, error) { return mgr, nil },
		DisableDiscovery: true,
		DisableDHT:       true,
		LeasePath:        leasePath,
		FreshnessTTL:     testTTL,
		Clock:            clock.Now,
		Logf:             safeLogf(t, ""),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	f := &freshFixture{
		reconcileFixture: &reconcileFixture{nw: nw, d: d, mgr: mgr, auth: auth, storage: st, self: self},
		clock:            clock,
		start:            clock.Now(),
	}
	f.learn(t, nw.devices[1], 7001)
	f.learn(t, nw.devices[2], 7002)
	return f
}

// leaseFrom signs a lease by device i over head, as that device's daemon would.
func (f *freshFixture) leaseFrom(t *testing.T, i int, head types.Hash, at time.Time) []byte {
	t.Helper()
	l := types.Lease{Network: f.auth.State().GenesisHash(), Head: head, Issued: uint64(at.Unix())}
	if err := l.Sign(f.nw.devices[i].identity); err != nil {
		t.Fatal(err)
	}
	b, err := l.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *freshFixture) reconcileAt(t *testing.T, at time.Time) {
	t.Helper()
	f.clock.Set(at)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
}

// TestPartitionedVictimRefusesARevokedPeerAtTheTTL is M4's second exit
// criterion. The victim is cut off from every fresh member, so it never hears
// that a peer it can still reach was removed. It keeps that peer exactly until
// its newest lease is TTL old and not a second longer; it keeps its tunnel to
// the admin device, through which a newer view can arrive; and a lease naming
// a head it does not hold does not make it fresh, since that head is the
// removal it is missing.
func TestPartitionedVictimRefusesARevokedPeerAtTheTTL(t *testing.T) {
	f := newFreshFixture(t, "")
	admin, revoked := f.nw.devices[1], f.nw.devices[2]
	f.d.offerLeases([][]byte{f.leaseFrom(t, 1, f.auth.Head(), f.start)})

	f.reconcileAt(t, f.start.Add(time.Minute))
	if !f.mgr.has([32]byte(revoked.record.WireGuard)) || !f.mgr.has([32]byte(admin.record.WireGuard)) {
		t.Fatal("a fresh node does not carry its members")
	}

	// Elsewhere the revoked member is removed; the victim never hears of it.
	elsewhere, _ := f.nw.authorityFor(t)
	removal := f.nw.removeNode(t, elsewhere, revoked.record.Identity)
	if err := elsewhere.Inform(removal); err != nil {
		t.Fatal(err)
	}

	f.reconcileAt(t, f.start.Add(testTTL-time.Second))
	if !f.mgr.has([32]byte(revoked.record.WireGuard)) {
		t.Fatal("the victim dropped a peer before its view went stale")
	}
	if f.d.Status().Stale {
		t.Fatal("reported stale one second before the TTL")
	}

	f.reconcileAt(t, f.start.Add(testTTL))
	if f.mgr.has([32]byte(revoked.record.WireGuard)) {
		t.Fatal("a stale victim still carries a peer it cannot know is not revoked")
	}
	if !f.mgr.has([32]byte(admin.record.WireGuard)) {
		t.Fatal("a stale victim dropped the admin device it would catch up through")
	}
	if !f.d.Status().Stale {
		t.Fatal("the victim does not report being stale")
	}

	// The admin device vouches again, for the head that includes the
	// removal. The victim lacks that record, so it is not vouched for.
	f.d.offerLeases([][]byte{f.leaseFrom(t, 1, elsewhere.Head(), f.start.Add(testTTL+time.Minute))})
	f.reconcileAt(t, f.start.Add(testTTL+time.Minute))
	if !f.d.Status().Stale || f.mgr.has([32]byte(revoked.record.WireGuard)) {
		t.Fatal("a lease for a head the victim lacks made it fresh")
	}

	// Once the removal arrives the same lease vouches, and the revoked member
	// is gone for the ordinary reason.
	if err := f.d.Inform([]types.AUM{removal}); err != nil {
		t.Fatal(err)
	}
	f.d.offerLeases([][]byte{f.leaseFrom(t, 1, elsewhere.Head(), f.start.Add(testTTL+time.Minute))})
	f.reconcileAt(t, f.start.Add(testTTL+2*time.Minute))
	if f.d.Status().Stale || !f.mgr.has([32]byte(admin.record.WireGuard)) || f.mgr.has([32]byte(revoked.record.WireGuard)) {
		t.Fatalf("after catching up: stale=%v admin=%v revoked=%v",
			f.d.Status().Stale, f.mgr.has([32]byte(admin.record.WireGuard)), f.mgr.has([32]byte(revoked.record.WireGuard)))
	}
}

// A lease from a member that is not an admin device vouches for nothing, so a
// revoked member cannot keep a victim fresh by signing its own leases.
func TestOnlyAdminDevicesVouch(t *testing.T) {
	f := newFreshFixture(t, "")
	f.d.offerLeases([][]byte{f.leaseFrom(t, 2, f.auth.Head(), f.start)})
	f.reconcileAt(t, f.start.Add(time.Minute))
	if !f.d.Status().Stale {
		t.Fatal("a plain member's lease made the node fresh")
	}
}

// TestStartupGate: a node restarted with nothing but an old lease comes up
// stale, carrying only admin devices, rather than trusting a week-old view
// for as long as it takes to hear from someone.
func TestStartupGate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.cbor")
	first := newFreshFixture(t, path)
	first.d.offerLeases([][]byte{first.leaseFrom(t, 1, first.auth.Head(), first.start)})
	first.d.Close()

	// The same device, restarted over the same lease file a week later.
	nw := first.nw
	auth, st := nw.authorityFor(t)
	mgr := &fakeManager{}
	clock := &fakeClock{now: first.start.Add(7 * 24 * time.Hour)}
	d, err := New(Options{
		Authority: auth, Storage: st,
		Identity: nw.devices[0].identity, Recipient: nw.devices[0].recipient, WireGuard: nw.devices[0].wgPrivate,
		Connect:          func(conn.Options) (conn.Manager, error) { return mgr, nil },
		DisableDiscovery: true, DisableDHT: true,
		LeasePath: path, FreshnessTTL: testTTL, Clock: clock.Now,
		Logf: safeLogf(t, ""),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	f := &reconcileFixture{nw: nw, d: d, mgr: mgr, auth: auth, storage: st, self: nw.devices[0]}
	f.learn(t, nw.devices[1], 7001)
	f.learn(t, nw.devices[2], 7002)
	if err := d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if !d.Status().Stale || mgr.has([32]byte(nw.devices[2].record.WireGuard)) || !mgr.has([32]byte(nw.devices[1].record.WireGuard)) {
		t.Fatalf("a node restarted on an old lease: stale=%v, plain member=%v, admin device=%v",
			d.Status().Stale, mgr.has([32]byte(nw.devices[2].record.WireGuard)), mgr.has([32]byte(nw.devices[1].record.WireGuard)))
	}

	// Restarted within the TTL instead, the persisted lease still counts.
	clock.Set(first.start.Add(time.Hour))
	if err := d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if d.Status().Stale || !mgr.has([32]byte(nw.devices[2].record.WireGuard)) {
		t.Fatal("a persisted lease within the TTL did not count after a restart")
	}
}

// TestAdminDeviceVouchesForItself: an admin device issues a lease as soon as
// it runs, renews it on schedule and whenever its head moves, and so is never
// stale on its own account.
func TestAdminDeviceVouchesForItself(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.cbor")
	f := newFreshFixture(t, path, 0)
	f.reconcileAt(t, f.start)
	st := f.d.Status()
	if st.Stale || st.FreshSince != f.start.Unix() || st.LeaseSigners != 1 {
		t.Fatalf("an admin device is not vouching for itself: %+v", st)
	}
	if !f.mgr.has([32]byte(f.nw.devices[2].record.WireGuard)) {
		t.Fatal("an admin device dropped a member")
	}

	f.reconcileAt(t, f.start.Add(DefaultLeaseInterval/2))
	if got := f.d.Status().FreshSince; got != f.start.Unix() {
		t.Fatal("the lease was renewed before its interval with nothing changed")
	}
	f.reconcileAt(t, f.start.Add(DefaultLeaseInterval))
	if got := f.d.Status().FreshSince; got != f.start.Add(DefaultLeaseInterval).Unix() {
		t.Fatal("the lease was not renewed on schedule")
	}

	removal := f.nw.removeNode(t, f.auth, f.nw.devices[2].record.Identity)
	f.clock.Set(f.start.Add(DefaultLeaseInterval + time.Minute))
	if err := f.d.Inform([]types.AUM{removal}); err != nil {
		t.Fatal(err)
	}
	var names types.Hash
	for _, b := range f.d.encodedLeases() {
		l, err := types.DecodeLease(b)
		if err != nil {
			t.Fatal(err)
		}
		if l.Signer == f.nw.devices[0].record.Identity {
			names = l.Head
		}
	}
	if names != f.auth.Head() {
		t.Fatal("the admin device did not vouch for its new head after a change")
	}

	// And what it vouched for is on disk, for the next start.
	if loaded, err := decodeLeaseFileAt(path); err != nil || len(loaded) == 0 {
		t.Fatalf("no lease was persisted: %v", err)
	}
}

func decodeLeaseFileAt(path string) ([][]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return statedir.DecodeLeaseFile(b)
}

// TestLeasesTravelByGossip: in a running mesh, the admin device's lease
// reaches every member without anything but gossip carrying it.
func TestLeasesTravelByGossip(t *testing.T) {
	m := startMesh(t, 3, 0)
	waitFor(t, 30*time.Second, "every member to hold the admin device's lease", func() bool {
		for _, n := range m.nodes {
			if st := n.d.Status(); st.FreshSince == 0 || st.Stale {
				return false
			}
		}
		return true
	})
	if !m.converged() {
		waitFor(t, 30*time.Second, "a full mesh", m.converged)
	}
}

// TestAClockThatRanAheadDoesNotStickTheLease: an admin device whose clock was
// once ahead holds a lease from the future. Once its clock is corrected, that
// lease must neither block the next one nor count, or every member goes stale.
func TestAClockThatRanAheadDoesNotStickTheLease(t *testing.T) {
	f := newFreshFixture(t, filepath.Join(t.TempDir(), "leases.cbor"), 0)
	f.reconcileAt(t, f.start.Add(24*time.Hour))
	f.reconcileAt(t, f.start)
	f.reconcileAt(t, f.start.Add(2*time.Hour))
	if st := f.d.Status(); st.Stale || st.FreshSince != f.start.Add(2*time.Hour).Unix() {
		t.Fatalf("after the clock was corrected: %+v", st)
	}
}

// TestExpiredAdminDevicesDoNotSwitchFreshnessOff: once every admin device's
// membership has expired, nobody can vouch, which is stale, not "never asked".
func TestExpiredAdminDevicesDoNotSwitchFreshnessOff(t *testing.T) {
	var expiry time.Time
	f := newFreshFixtureWith(t, "", func(nw *network) {
		expiry = time.Unix(1_800_000_000, 0).Add(72 * time.Hour)
		nw.devices[1].record.Roles = []types.Role{types.RoleAdmin}
		nw.devices[1].record.Expiry = uint64(expiry.Unix())
	})
	revoked := [32]byte(f.nw.devices[2].record.WireGuard)
	f.d.offerLeases([][]byte{f.leaseFrom(t, 1, f.auth.Head(), f.start)})
	f.reconcileAt(t, f.start.Add(49*time.Hour))
	if !f.d.Status().Stale || f.mgr.has(revoked) {
		t.Fatal("not stale past the TTL")
	}
	f.reconcileAt(t, expiry.Add(time.Hour))
	if st := f.d.Status(); !st.Stale || f.mgr.has(revoked) {
		t.Fatalf("freshness switched off when the admin device expired: stale=%v", st.Stale)
	}
}

// An admin device stopped at a schema upgrade it does not implement must not
// keep vouching for the head before it: every node that was not upgraded
// would stay fresh for as long as it runs, and miss every later removal
// without limit.
func TestAnAdminDeviceStoppedAtASchemaUpgradeStopsVouching(t *testing.T) {
	f := newFreshFixture(t, "", 0) // this daemon is the admin device
	f.reconcileAt(t, f.start)
	prev := f.auth.Head()
	v := types.CurrentSchema + 1
	up := types.AUM{Kind: types.KindSchemaUpgrade, Prev: &prev, Schema: &v}
	if err := up.Sign(f.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{up}); err != nil {
		t.Fatal(err)
	}
	if f.auth.SchemaAlarm() == nil {
		t.Fatal("no schema alarm")
	}
	f.reconcileAt(t, f.start.Add(DefaultFreshnessTTL+time.Hour))
	for _, b := range f.d.encodedLeases() {
		if l, _ := types.DecodeLease(b); l.Signer == f.nw.devices[0].record.Identity {
			t.Fatalf("the admin device still vouches, %v after the upgrade stopped it",
				time.Unix(int64(l.Issued), 0).Sub(f.start))
		}
	}
	if !f.d.Status().Stale {
		t.Fatal("the node is fresh a TTL after its admin device stopped vouching")
	}
}

// Two sessions delivering one signer's leases at once must leave the newer.
func TestConcurrentOffersKeepTheNewerLease(t *testing.T) {
	f := newFreshFixture(t, "")
	older := f.leaseFrom(t, 1, f.auth.Head(), f.start)
	newer := f.leaseFrom(t, 1, f.auth.Head(), f.start.Add(10*time.Second))
	f.clock.Set(f.start.Add(time.Minute))
	want := uint64(f.start.Add(10 * time.Second).Unix())
	for range 2000 {
		f.d.leaseMu.Lock()
		f.d.leases = map[types.Identity]types.Lease{}
		f.d.leaseMu.Unlock()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); f.d.offerLeases([][]byte{newer}) }()
		go func() { defer wg.Done(); f.d.offerLeases([][]byte{older}) }()
		wg.Wait()
		f.d.leaseMu.Lock()
		got := f.d.leases[f.nw.devices[1].record.Identity].Issued
		f.d.leaseMu.Unlock()
		if got != want {
			t.Fatalf("the older lease replaced the newer one")
		}
	}
}

// A head that moves within the same second as the last lease is still
// vouched for at once, not a reconcile later.
func TestANewHeadInTheSameSecondIsVouchedFor(t *testing.T) {
	f := newFreshFixture(t, "", 0)
	f.reconcileAt(t, f.start)
	removal := f.nw.removeNode(t, f.auth, f.nw.devices[2].record.Identity)
	if err := f.d.Inform([]types.AUM{removal}); err != nil {
		t.Fatal(err)
	}
	f.d.leaseMu.Lock()
	l := f.d.leases[f.nw.devices[0].record.Identity]
	f.d.leaseMu.Unlock()
	if l.Head != f.auth.Head() {
		t.Fatal("the admin device's lease still names the head before the removal")
	}
}

// A lease decoded again is the one held, though its ML-DSA signature sits
// elsewhere in memory: it is not checked again on every frame.
func TestALeaseDecodedAgainIsTheOneHeld(t *testing.T) {
	a := types.Lease{Issued: 7, Sig: types.Sig{1}, MLDSA: &types.PQSig{2}}
	b := a
	b.MLDSA = &types.PQSig{2}
	if !sameLease(&a, &b) {
		t.Fatal("one lease, decoded twice, reads as two")
	}
	b.MLDSA[0] = 3
	if sameLease(&a, &b) {
		t.Fatal("leases with different ML-DSA signatures read as one")
	}
}
