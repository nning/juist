package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/nning/juist/internal/pairkey"
	"github.com/nning/juist/ipc"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/types"
)

// A peer that answers its probe is live, and so is one with a handshake just
// now; one whose probes go unanswered twice in a row is down, though its last
// handshake is only a minute behind — as a peer that restarted leaves it. One
// lost probe is not enough.
func TestTunnelsCountFreshHandshakesAndAnswers(t *testing.T) {
	f := newReconcileFixture(t, 5)
	for i, dev := range f.nw.devices[1:] {
		f.learn(t, dev, uint16(4001+i))
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	fresh, answering, restarted, gone := f.installed(t, 1), f.installed(t, 2), f.installed(t, 3), f.installed(t, 4)
	f.mgr.mu.Lock()
	f.mgr.tunnels = map[uint64]conn.Tunnel{
		fresh.ID:     {LastHandshake: time.Now().Add(-5 * time.Second)},
		restarted.ID: {LastHandshake: time.Now().Add(-time.Minute)},
		gone.ID:      {LastHandshake: time.Now().Add(-10 * time.Minute)},
	}
	f.mgr.answers = map[netip.Addr]bool{answering.Addrs[0].Addr(): true}
	f.mgr.mu.Unlock()

	live, down := f.d.Tunnels(time.Second)
	if want := []string{f.nw.devices[4].record.Name}; live != 3 || !slices.Equal(down, want) {
		t.Fatalf("after one lost probe: live %d, down %v; want 3 and %v", live, down, want)
	}
	live, down = f.d.Tunnels(time.Second)
	if want := []string{f.nw.devices[3].record.Name, f.nw.devices[4].record.Name}; live != 2 || !slices.Equal(down, want) {
		t.Fatalf("after two: live %d, down %v; want 2 and %v", live, down, want)
	}
}

// A live peer naming no epoch is called outdated once it has had the time
// to catch up, and no longer once it names one.
func TestACheckCallsAPeerNamingNoEpochOutdated(t *testing.T) {
	f := newReconcileFixture(t, 3)
	pq, behind := f.nw.devices[1], f.nw.devices[2]
	f.learn(t, pq, 4001)
	f.learnNoEpoch(t, behind, 4002, false)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	answers := map[netip.Addr]bool{f.installed(t, 1).Addrs[0].Addr(): true, f.installed(t, 2).Addrs[0].Addr(): true}
	f.mgr.mu.Lock()
	f.mgr.answers = answers
	f.mgr.mu.Unlock()
	now := time.Now()
	f.d.clock = func() time.Time { return now }
	outdated := func() []string {
		f.d.refreshReach(t.Context())
		st := f.d.Status()
		var marked []string
		for _, r := range st.Reach {
			if r.Outdated {
				marked = append(marked, r.Identity.ShortString())
			}
		}
		if len(marked) != len(st.Outdated) {
			t.Fatalf("%d marked, %d named: %v", len(marked), len(st.Outdated), st.Outdated)
		}
		return st.Outdated
	}
	if got := outdated(); len(got) != 0 {
		t.Fatalf("outdated at once: %v", got)
	}
	now = now.Add(outdatedAfter)
	if got := outdated(); !slices.Equal(got, []string{behind.record.Name}) {
		t.Fatalf("outdated after %v: %v", outdatedAfter, got)
	}
	e, err := endpointFor(behind, 4002)
	if err != nil {
		t.Fatal(err)
	}
	e.Seq, e.Epoch, e.PairStore = 3, f.auth.State().Epoch(), 1
	if err := e.SignPQ(behind.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := outdated(); len(got) != 0 {
		t.Fatalf("outdated though it names an epoch: %v", got)
	}
}

// A failing sync is put down to a firewall only where no connection came up
// and a host firewall stands before the tunnel.
func TestSyncVerdicts(t *testing.T) {
	for _, c := range []struct {
		f    gossip.Failure
		tun  bool
		want int
	}{
		{0, true, syncNone}, {gossip.FailRefused, true, syncNone},
		{gossip.FailNewer, true, syncNewerBuild}, {gossip.FailNewer, false, syncNewerBuild},
		{gossip.FailUnconnected, true, syncFirewalled}, {gossip.FailUnconnected, false, syncBrokenElse},
		{gossip.FailOther, true, syncBrokenElse},
	} {
		if got := syncVerdict(c.f, c.tun); got != c.want {
			t.Errorf("failure %d, tun %v: %d, want %d", c.f, c.tun, got, c.want)
		}
	}
}

// A live peer whose log sync connects nowhere is blamed on a firewall, one
// naming no epoch among them, since nothing shows it is not catching up.
func TestASyncThatConnectsNowhereIsBlamedOnAFirewall(t *testing.T) {
	t.Parallel()
	f := newReconcileFixture(t, 3)
	f.d.tunName = "juist0"
	pq, behind := f.nw.devices[1], f.nw.devices[2]
	f.learn(t, pq, 4001)
	f.learnNoEpoch(t, behind, 4002, false)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	answers := map[netip.Addr]bool{f.installed(t, 1).Addrs[0].Addr(): true, f.installed(t, 2).Addrs[0].Addr(): true}
	f.mgr.mu.Lock()
	f.mgr.answers = answers
	f.mgr.mu.Unlock()
	f.d.gossip.Sync(t.Context(), []types.Identity{pq.record.Identity, behind.record.Identity})
	now := time.Now()
	f.d.clock = func() time.Time { return now }
	f.d.refreshReach(t.Context())
	now = now.Add(outdatedAfter)
	f.d.refreshReach(t.Context())
	st := f.d.Status()
	want := []string{pq.record.Name, behind.record.Name}
	slices.Sort(want)
	if !slices.Equal(st.SyncFailing, want) || len(st.Outdated)+len(st.SyncNewer)+len(st.SyncBroken) != 0 {
		t.Fatalf("failing %v, outdated %v, newer %v, broken %v", st.SyncFailing, st.Outdated, st.SyncNewer,
			st.SyncBroken)
	}
}

// magicsock names a direct path only for a few seconds after its last pong,
// so a quiet tunnel read before its probe looks relayed. The path is read
// after the probe, which renews it.
func TestTheDirectPathIsReadAfterTheProbe(t *testing.T) {
	f := newReconcileFixture(t, 3)
	for i, dev := range f.nw.devices[1:] {
		f.learn(t, dev, uint16(4001+i))
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	quiet, relayed := f.installed(t, 1), f.installed(t, 2)
	path := netip.MustParseAddrPort("192.0.2.7:41641")
	f.mgr.mu.Lock()
	f.mgr.answers = map[netip.Addr]bool{quiet.Addrs[0].Addr(): true, relayed.Addrs[0].Addr(): true}
	f.mgr.paths = map[netip.Addr]netip.AddrPort{quiet.Addrs[0].Addr(): path}
	f.mgr.mu.Unlock()

	f.d.refreshReach(t.Context())
	got := map[types.Identity]ipc.PeerReach{}
	for _, r := range f.d.Status().Reach {
		got[r.Identity] = r
	}
	if r := got[f.nw.devices[1].record.Identity]; !r.Live || !r.Direct {
		t.Errorf("the quiet peer reads %+v, want live over %v", r, path)
	}
	if r := got[f.nw.devices[2].record.Identity]; !r.Live || r.Direct {
		t.Errorf("the relayed peer reads %+v, want live with no direct path", r)
	}
}

// installed returns the peer the data plane holds for device i.
func (f *reconcileFixture) installed(t *testing.T, i int) conn.Peer {
	t.Helper()
	want := conn.NodePublicFromRaw32([32]byte(f.nw.devices[i].record.WireGuard))
	for _, p := range f.mgr.snapshot() {
		if p.NodeKey == want {
			return p
		}
	}
	t.Fatalf("device %d is not installed", i)
	return conn.Peer{}
}

// A peer that stops answering is probed in fewer checks: every device probing
// every peer gone for good would cost relay traffic and battery for nothing.
// One that answers again starts over.
func TestProbesBackOffAPeerThatNeverAnswers(t *testing.T) {
	f := newReconcileFixture(t, 2)
	f.learn(t, f.nw.devices[1], 4001)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	silent := f.installed(t, 1).Addrs[0].Addr()
	probes := func() int {
		f.mgr.mu.Lock()
		defer f.mgr.mu.Unlock()
		n := 0
		for _, a := range f.mgr.probed {
			if a == silent {
				n++
			}
		}
		return n
	}
	for range 12 {
		f.d.refreshReach(t.Context())
	}
	if got := probes(); got != 4 {
		t.Fatalf("a silent peer was probed in %d of 12 checks, want 4", got)
	}
	f.mgr.mu.Lock()
	f.mgr.answers = map[netip.Addr]bool{silent: true}
	f.mgr.mu.Unlock()
	f.d.refreshReach(t.Context()) // the 13th: skipped, still backing off
	f.d.probes.mu.Lock()
	f.d.probes.misses = nil // as after an answer on a probed check
	f.d.probes.mu.Unlock()
	before := probes()
	// Cancelled, so the sync due to a peer back up does not dial it.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	f.d.refreshReach(ctx)
	if probes() != before+1 {
		t.Fatal("a peer that answered again was not probed")
	}
}

// signedBy has dev announce itself as signed at the given time.
func (f *reconcileFixture) signedBy(t *testing.T, dev *device, at time.Time) gossip.Endpoint {
	t.Helper()
	e, err := endpointFor(dev, 4001)
	if err != nil {
		t.Fatal(err)
	}
	if held, ok := f.d.endpoints.Get(dev.record.Identity); ok {
		e.Disco = held.Disco // the same announcement, renewed
	}
	e.Seq = uint64(at.Unix())
	if err := e.SignPQ(dev.identity); err != nil {
		t.Fatal(err)
	}
	return e
}

// renewing has dev seen signing its announcement at at, as a build that
// renews does.
func (f *reconcileFixture) renewing(t *testing.T, dev *device, at time.Time) {
	t.Helper()
	if err := f.d.Learn(f.signedBy(t, dev, at)); err != nil {
		t.Fatal(err)
	}
}

// A device quiet since before this one started, so never seen renewing, is
// called offline once a renewal had time to come: every build it can run
// renews.
func TestADeviceQuietSinceBeforeAStartReadsAsOffline(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	peer := f.nw.devices[1]
	if err := f.d.Learn(f.signedBy(t, peer, t0.Add(-3*time.Minute))); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.refreshReach(t.Context())
	c.set(t0.Add(f.d.settles() + time.Hour))
	f.d.refreshReach(t.Context())
	if st := f.d.Status(); !slices.Equal(st.Absent, []string{peer.record.Name}) || len(st.Seeking) != 0 {
		t.Fatalf("a device quiet since before the start reads as absent %v, seeking %v", st.Absent, st.Seeking)
	}
}

// A device that went quiet — suspended, say — is found again only as it was
// signed before: that is no sign of it running, so it reads as undecided and
// then offline, never as blocked on the way.
func TestASuspendedDeviceReadsAsOffline(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	peer := f.nw.devices[1]
	f.renewing(t, peer, t0.Add(-8*time.Minute))
	last := f.signedBy(t, peer, t0.Add(-3*time.Minute))
	if err := f.d.Learn(last); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.refreshReach(t.Context())
	if st := f.d.Status(); !slices.Equal(st.Seeking, []string{peer.record.Name}) {
		t.Fatalf("a peer just gone quiet is not undecided: seeking %v, absent %v", st.Seeking, st.Absent)
	}
	c.set(t0.Add(time.Minute))
	f.d.onFoundInDHT(last) // what it published before it went quiet
	f.d.refreshReach(t.Context())
	if st := f.d.Status(); len(st.Seeking) != 1 {
		t.Fatalf("finding its last announcement again decided it: seeking %v", st.Seeking)
	}
	c.set(t0.Add(f.d.settles()))
	f.d.refreshReach(t.Context())
	st := f.d.Status()
	if len(st.Seeking) != 0 || !slices.Equal(st.Absent, []string{peer.record.Name}) {
		t.Fatalf("a peer quiet for %v reads as seeking %v, absent %v", f.d.settles(), st.Seeking, st.Absent)
	}
	if st.Reach[0].Heard != int64(last.Seq) || st.Reach[0].Since != t0.Unix() {
		t.Errorf("the status says it was last heard at %d and down since %d", st.Reach[0].Heard, st.Reach[0].Since)
	}
}

// A device that signs its announcement again while its tunnel is down runs,
// so the way to it is to blame; the renewal alone reconciles nothing.
func TestARunningDeviceBehindAFirewallReadsAsBlocked(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	peer := f.nw.devices[1]
	if err := f.d.Learn(f.signedBy(t, peer, t0.Add(-3*time.Minute))); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.refreshReach(t.Context())
	select {
	case <-f.d.dirty:
	default:
	}
	c.set(t0.Add(3 * time.Minute))
	f.d.onFoundInDHT(f.signedBy(t, peer, t0.Add(3*time.Minute)))
	select {
	case <-f.d.dirty:
		t.Error("a renewed signature alone asked for a reconcile and a push")
	default:
	}
	f.d.refreshReach(t.Context())
	if st := f.d.Status(); len(st.Seeking)+len(st.Absent) != 0 || !slices.Equal(st.TunnelsDown, []string{peer.record.Name}) {
		t.Fatalf("a device signing while down reads as seeking %v, absent %v", st.Seeking, st.Absent)
	}
}

// A device that wakes for a moment while its tunnel is down, as a sleeping
// Mac does for Power Nap, is blocked on the way only until the renewal that
// would follow had time to come, and is looked up often enough meanwhile to
// find one; with none, it reads as offline again.
func TestADeviceWakingForAMomentReadsAsOfflineAgain(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	peer := f.nw.devices[1]
	id := peer.record.Identity
	if err := f.d.Learn(f.signedBy(t, peer, t0.Add(-3*time.Minute))); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.refreshReach(t.Context())
	woke := t0.Add(2 * time.Hour)
	c.set(woke)
	f.d.refreshReach(t.Context())
	f.d.mu.Lock()
	f.d.down[id].lookEvery, f.d.down[id].lookAt = maxLookupGap, woke.Add(maxLookupGap)
	f.d.mu.Unlock()
	f.d.onFoundInDHT(f.signedBy(t, peer, woke))
	f.d.refreshReach(t.Context())
	if st := f.d.Status(); !slices.Equal(st.Blocked(), []string{peer.record.Name}) {
		t.Fatalf("a device signing while down reads as blocked %v, absent %v", st.Blocked(), st.Absent)
	}
	c.set(woke.Add(seekLookupGap))
	if !slices.Contains(f.d.wanted(), id) {
		t.Errorf("not looked up %v after it signed, its lookups backed off to %v", seekLookupGap, maxLookupGap)
	}
	c.set(woke.Add(f.d.settles()))
	f.d.refreshReach(t.Context())
	if st := f.d.Status(); len(st.Blocked()) != 0 || !slices.Equal(st.Absent, []string{peer.record.Name}) {
		t.Fatalf("quiet for %v after it signed: blocked %v, absent %v", f.d.settles(), st.Blocked(), st.Absent)
	}
}

// A device that keeps signing while its tunnel is down stays blocked.
func TestADeviceRenewingWhileDownStaysBlocked(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	peer := f.nw.devices[1]
	if err := f.d.Learn(f.signedBy(t, peer, t0.Add(-3*time.Minute))); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.refreshReach(t.Context())
	for at := 3 * time.Minute; at < 3*f.d.settles(); at += announceRenewal {
		c.set(t0.Add(at))
		f.d.onFoundInDHT(f.signedBy(t, peer, c.get()))
		f.d.refreshReach(t.Context())
		if st := f.d.Status(); !slices.Equal(st.Blocked(), []string{peer.record.Name}) {
			t.Fatalf("renewing at %v: blocked %v, seeking %v, absent %v", at, st.Blocked(), st.Seeking, st.Absent)
		}
	}
}

// A device that runs while its tunnel is down and names no epoch has yet to
// catch up, and knows no member that joined since: it is called outdated once
// its newer announcement had the time to arrive, and only one that names an
// epoch is blamed on the way.
func TestARunningDeviceThatNamesNoEpochIsOutdatedNotBlocked(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 3, func(o *Options) { o.Clock = c.get })
	current, noEpoch := f.nw.devices[1], f.nw.devices[2]
	announce := func(at time.Time) {
		for _, dev := range []*device{current, noEpoch} {
			e := f.signedBy(t, dev, at)
			e.Epoch = f.auth.State().Epoch()
			if dev == noEpoch {
				e.Epoch, e.PairStore = 0, 0
			}
			if err := e.SignPQ(dev.identity); err != nil {
				t.Fatal(err)
			}
			if err := f.d.Learn(e); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		f.d.refreshReach(t.Context())
	}
	announce(t0.Add(-3 * time.Minute))
	c.set(t0.Add(3 * time.Minute))
	announce(c.get())
	st := f.d.Status()
	if len(st.Outdated) != 0 || !slices.Equal(st.Blocked(), []string{current.record.Name, noEpoch.record.Name}) {
		t.Fatalf("at once: outdated %v, blocked %v", st.Outdated, st.Blocked())
	}
	c.set(t0.Add(3*time.Minute + max(outdatedAfter, f.d.settles())))
	announce(c.get())
	st = f.d.Status()
	if want := []string{noEpoch.record.Name}; !slices.Equal(st.Outdated, want) ||
		!slices.Equal(st.Blocked(), []string{current.record.Name}) {
		t.Fatalf("later: outdated %v, blocked %v; want %v outdated", st.Outdated, st.Blocked(), want)
	}
	for _, r := range st.Reach {
		if r.Outdated != (r.Identity != current.record.Identity) {
			t.Errorf("%v marked outdated: %v", r.Identity.ShortString(), r.Outdated)
		}
	}
}

// A hint alone naming an older build has no say in whether its member is
// outdated, nor in the build the status shows for it.
func TestAHintAloneNamingAnOlderBuildIsNotOutdated(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	dev := f.nw.devices[1]
	announce := func(at time.Time) {
		e := f.signedBy(t, dev, at)
		e.Epoch = f.auth.State().Epoch()
		f.learnHint(t, dev, e, func(h *gossip.Endpoint) { h.Schema = types.MinSchema })
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		f.d.refreshReach(t.Context())
	}
	announce(t0.Add(-3 * time.Minute))
	c.set(t0.Add(3 * time.Minute))
	announce(c.get())
	c.set(t0.Add(3*time.Minute + max(outdatedAfter, f.d.settles())))
	announce(c.get())
	st := f.d.Status()
	if len(st.Outdated) != 0 || len(st.OlderBuild) != 0 {
		t.Fatalf("outdated %v, older build %v", st.Outdated, st.OlderBuild)
	}
	for _, d := range st.Devices {
		if d.Identity == dev.record.Identity && d.Build != 0 {
			t.Fatalf("the status shows build %d for a member held by a hint alone", d.Build)
		}
	}
}

// A live member held by a hint alone naming an older build is not said to
// run one.
func TestALiveMemberHeldByAHintIsNoOlderBuild(t *testing.T) {
	f := newReconcileFixture(t, 2)
	dev := f.nw.devices[1]
	e, err := endpointFor(dev, 4001)
	if err != nil {
		t.Fatal(err)
	}
	e.Epoch = f.auth.State().Epoch()
	f.learnHint(t, dev, e, func(h *gossip.Endpoint) { h.Schema = types.MinSchema })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	answers := map[netip.Addr]bool{f.installed(t, 1).Addrs[0].Addr(): true}
	f.mgr.mu.Lock()
	f.mgr.answers = answers
	f.mgr.mu.Unlock()
	now := time.Now()
	f.d.clock = func() time.Time { return now }
	f.d.refreshReach(t.Context())
	now = now.Add(outdatedAfter)
	f.d.refreshReach(t.Context())
	if st := f.d.Status(); len(st.Reach) != 1 || !st.Reach[0].Live || len(st.OlderBuild) != 0 || len(st.Outdated) != 0 {
		t.Fatalf("reach %+v, older build %v, outdated %v", st.Reach, st.OlderBuild, st.Outdated)
	}
}

// A device that restarted or moved says something new: it runs, and is
// probed at once, past the probe backoff.
func TestANewAnnouncementIsProbedAtOnce(t *testing.T) {
	c := &clock{now: time.Unix(1_700_000_000, 0)}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	peer := f.nw.devices[1]
	held := f.learn(t, peer, 4001)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		f.d.refreshReach(t.Context())
	}
	addr := f.installed(t, 1).Addrs[0].Addr()
	probes := func() int {
		f.mgr.mu.Lock()
		defer f.mgr.mu.Unlock()
		return len(slices.DeleteFunc(slices.Clone(f.mgr.probed), func(a netip.Addr) bool { return a != addr }))
	}
	before := probes()
	f.d.refreshReach(t.Context())
	if probes() != before {
		t.Fatal("the backoff did not hold, so the test tests nothing")
	}
	newer, err := endpointFor(peer, 4002)
	if err != nil {
		t.Fatal(err)
	}
	newer.Seq = held.Seq + 1
	if err := newer.SignPQ(peer.identity); err != nil {
		t.Fatal(err)
	}
	f.d.onFoundInDHT(newer)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.refreshReach(t.Context())
	if probes() != before+1 {
		t.Error("a peer with a new announcement was not probed past its backoff")
	}
	if st := f.d.Status(); len(st.Seeking)+len(st.Absent) != 0 {
		t.Errorf("a peer that said something new reads as seeking %v, absent %v", st.Seeking, st.Absent)
	}
}

// A device signs its announcement again every renewal though nothing in it
// changed, and for the DHT unless it just did.
func TestAnAnnouncementIsRenewed(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 1, func(o *Options) { o.Clock = c.get })
	first, _ := f.d.announcement()
	c.set(t0.Add(announceRenewal - time.Second))
	if again, _ := f.d.announcement(); again.Seq != first.Seq {
		t.Fatal("an unchanged announcement was signed again before its renewal")
	}
	if pub, _ := f.d.publishedAnnouncement(); pub.Seq == first.Seq || !pub.SameAs(&first) {
		t.Fatal("the DHT's copy was not a fresh signature of the same announcement")
	}
	c.set(t0.Add(2 * announceRenewal))
	if later, _ := f.d.announcement(); later.Seq <= first.Seq || !later.SameAs(&first) {
		t.Fatal("an unchanged announcement was not renewed")
	}
}

// A mesh the service restarts on the same keys announces the same NAT
// traversal key, so peers reach it on what they hold; new keys take a new one.
func TestARestartedMeshKeepsItsSession(t *testing.T) {
	f := newServiceFixture(t, true)
	before := f.s.Mesh()
	restartMesh(f.s)
	after := f.s.Mesh()
	if after == nil || after == before {
		t.Fatal("the mesh did not restart")
	}
	if after.discoPublic != before.discoPublic || after.session != before.session {
		t.Error("a mesh restarted on the same keys announces a new NAT-traversal key")
	}
	f.s.mu.Lock()
	f.s.sessionKeys.WireGuard[0] ^= 1 // as a rotation leaves them
	f.s.restartMeshLocked(nil, "a test")
	f.s.mu.Unlock()
	if f.s.Mesh().discoPublic == after.discoPublic {
		t.Error("a mesh restarted on new keys kept the behind NAT-traversal key")
	}
}

// A mesh restarted within the second of its last announcement numbers the
// next one past it; peers dismiss an equal number as a replay, and with it a
// new gossip port or address.
func TestARestartedMeshAnnouncesPastItsLastNumber(t *testing.T) {
	c := &clock{now: time.Unix(1_700_000_000, 0)}
	f := newServiceFixtureWith(t, func(o *Options) { o.Clock = c.get })
	before := f.s.Mesh()
	first, ok := before.announcement()
	if !ok {
		t.Fatal("no announcement")
	}
	restartMesh(f.s)
	after := f.s.Mesh()
	if after == nil || after == before {
		t.Fatal("the mesh did not restart")
	}
	next, _ := after.announcement()
	if next.Seq <= first.Seq {
		t.Fatalf("the restarted mesh announced %d after %d", next.Seq, first.Seq)
	}
	f.s.mu.Lock()
	f.s.sessionKeys.WireGuard[0] ^= 1 // as a rotation leaves them
	f.s.restartMeshLocked(nil, "a test")
	f.s.mu.Unlock()
	if rotated, _ := f.s.Mesh().announcement(); rotated.Seq <= next.Seq {
		t.Fatalf("the mesh restarted on new keys announced %d after %d", rotated.Seq, next.Seq)
	}
}

// A previous run's announcement, signed in the same second as this run's
// and echoed back by a peer, makes the next one numbered past it.
func TestAnEchoOfAPreviousRunIsAnnouncedPast(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	mine, _ := f.d.announcement()
	f.d.ownEchoed(mine)
	if again, _ := f.d.announcement(); again.Seq != mine.Seq {
		t.Fatal("an echo of this run's announcement had it signed again")
	}
	previous := f.signedBy(t, f.self, t0)
	if previous.SameAs(&mine) || previous.Seq != mine.Seq {
		t.Fatal("the fixture's previous run is not another announcement in the same second")
	}
	forged := previous
	forged.Seq++
	f.d.ownEchoed(forged)
	if again, _ := f.d.announcement(); again.Seq != mine.Seq {
		t.Fatal("an echo that does not verify had the announcement signed again")
	}
	// Ed25519 alone is what a quantum computer forges.
	ed := previous
	ed.Seq += 1000
	if err := ed.Sign(f.self.identity); err != nil {
		t.Fatal(err)
	}
	f.d.ownEchoed(ed)
	if again, _ := f.d.announcement(); again.Seq != mine.Seq {
		t.Fatal("an echo signed by Ed25519 alone had the announcement numbered past it")
	}
	f.d.ownEchoed(previous)
	if next, _ := f.d.announcement(); next.Seq <= previous.Seq {
		t.Fatalf("announced %d after a previous run's %d", next.Seq, previous.Seq)
	}
}

// A device whose clock runs ahead of this one's, suspended a minute after it
// renewed, looks as though it signed after it went quiet; within the skew
// allowed that is no sign of it running.
func TestAClockAheadDoesNotMakeASuspendedDeviceBlocked(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	peer := f.nw.devices[1]
	f.renewing(t, peer, t0.Add(-6*time.Minute))
	if err := f.d.Learn(f.signedBy(t, peer, t0.Add(-time.Minute+90*time.Second))); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.refreshReach(t.Context())
	c.set(t0.Add(f.d.settles()))
	f.d.refreshReach(t.Context())
	if st := f.d.Status(); !slices.Equal(st.Absent, []string{peer.record.Name}) {
		t.Fatalf("a suspended device with its clock ahead reads as seeking %v, absent %v", st.Seeking, st.Absent)
	}
}

// A device homed at this one's relay and not connected to it is offline half
// a minute after its tunnel went down; unless the region is another relay's,
// as where two derive the same one.
func TestAPeerGoneFromThisRelayIsOffline(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	f.nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)
	peer := f.nw.devices[1]
	e := f.signedBy(t, peer, t0.Add(-time.Minute))
	e.HomeRelay = uint16(relayRegion(f.auth.State().GenesisHash(), f.self.record.Identity))
	if err := e.SignPQ(peer.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.refreshReach(t.Context())
	c.set(t0.Add(firstLookupGap))
	f.d.refreshReach(t.Context())
	if st := f.d.Status(); !slices.Equal(st.Absent, []string{peer.record.Name}) {
		t.Fatalf("a peer gone from this relay reads as seeking %v, absent %v", st.Seeking, st.Absent)
	}
	f.d.mu.Lock()
	f.d.ownRelay.region, f.d.down = false, nil
	f.d.mu.Unlock()
	f.d.refreshReach(t.Context())
	c.set(t0.Add(2 * firstLookupGap))
	f.d.refreshReach(t.Context())
	if st := f.d.Status(); len(st.Absent) != 0 {
		t.Fatal("a peer homed at a region this relay does not hold read as gone from it")
	}
}

// Where log sync runs through the tunnel alone, each check asks whether the
// host firewall keeps it from arriving on the TUN device, and the status names
// the device while it does; a network stack of its own has none.
func TestTheStatusNamesATunnelTheFirewallBlocks(t *testing.T) {
	f := newReconcileFixture(t, 2)
	f.learn(t, f.nw.devices[1], 4001)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	var asked []string
	blocked := true
	unsure := false
	f.d.firewalled = func(_ context.Context, iface string, port uint16) (bool, bool) {
		asked = append(asked, fmt.Sprintf("%s tcp/%d", iface, port))
		return blocked, unsure
	}

	f.d.refreshReach(t.Context())
	if len(asked) != 0 || f.d.Status().Firewalled != "" {
		t.Fatalf("with sync on the underlay the firewall was asked %v, and the status says %q",
			asked, f.d.Status().Firewalled)
	}

	f.d.overlayOnly = true // on a network stack of its own
	f.d.refreshReach(t.Context())
	if len(asked) != 0 || f.d.Status().Firewalled != "" {
		t.Fatalf("on a network stack the firewall was asked %v, and the status says %q", asked, f.d.Status().Firewalled)
	}

	f.d.tunName = "vpn0"
	f.d.refreshReach(t.Context())
	if want := fmt.Sprintf("vpn0 tcp/%d", f.d.gossipPort); len(asked) != 1 || asked[0] != want {
		t.Errorf("the firewall was asked %v, want %q", asked, want)
	}
	if st := f.d.Status(); st.Firewalled != "vpn0" || st.FirewallUnsure {
		t.Errorf("a blocked tunnel reads %q, unsure %v; want vpn0, sure", st.Firewalled, st.FirewallUnsure)
	}

	unsure = true
	f.d.refreshReach(t.Context())
	if st := f.d.Status(); st.Firewalled != "vpn0" || !st.FirewallUnsure {
		t.Errorf("a tunnel maybe blocked reads %q, unsure %v; want vpn0, unsure", st.Firewalled, st.FirewallUnsure)
	}

	blocked, unsure = false, false
	f.d.refreshReach(t.Context())
	if st := f.d.Status(); st.Firewalled != "" || st.FirewallUnsure {
		t.Errorf("once let in, the tunnel still reads %q, unsure %v", st.Firewalled, st.FirewallUnsure)
	}
}

// This device's relay counts as unreached once, for minutes, nobody has
// connected to it or been homed at it while a live peer is homed at no member
// relay; a peer offline, or homed at another relay, says nothing, and one
// homed at this one clears that and is counted.
func TestARelayNobodyReachesIsReported(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 3, func(o *Options) { o.Clock = c.get })
	f.nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)
	region := uint16(relayRegion(f.auth.State().GenesisHash(), f.self.record.Identity))
	announce := func(dev *device, at time.Time, home uint16) {
		t.Helper()
		e := f.signedBy(t, dev, at)
		e.HomeRelay = home
		if err := e.SignPQ(dev.identity); err != nil {
			t.Fatal(err)
		}
		if err := f.d.Learn(e); err != nil {
			t.Fatal(err)
		}
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	live, offline := f.nw.devices[1], f.nw.devices[2]
	announce(live, t0, region+1)
	announce(offline, t0, 0)
	answering := f.installed(t, 1).Addrs[0].Addr()
	f.mgr.mu.Lock()
	f.mgr.answers = map[netip.Addr]bool{answering: true}
	f.mgr.mu.Unlock()
	check := func(at time.Time) ipc.Status {
		t.Helper()
		c.set(at)
		f.d.refreshReach(t.Context())
		return f.d.Status()
	}

	check(t0)
	if st := check(t0.Add(relayUnreachedAfter)); st.RelayUnreached || st.RelayPort == 0 {
		t.Fatalf("with peers offline or homed elsewhere: unreached %v, port %d; want reached, and the port",
			st.RelayUnreached, st.RelayPort)
	}

	start := t0.Add(relayUnreachedAfter + time.Minute)
	announce(live, start, 0)
	if st := check(start); st.RelayUnreached {
		t.Fatal("a relay is blamed at once")
	}
	if st := check(start.Add(relayUnreachedAfter)); !st.RelayUnreached || st.RelayedFor != 0 {
		t.Fatalf("minutes on: unreached %v for %d; want unreached for none", st.RelayUnreached, st.RelayedFor)
	}

	announce(live, start.Add(relayUnreachedAfter), region)
	if st := check(start.Add(relayUnreachedAfter + time.Second)); st.RelayUnreached || st.RelayedFor != 1 {
		t.Fatalf("a peer homed here: unreached %v for %d; want reached for 1", st.RelayUnreached, st.RelayedFor)
	}
}

// A peer that answered is probed again only after quietProbeEvery where a
// relay can bring its tunnel back, so magicsock lets the tunnel go quiet, and
// its answer stands meanwhile. Without this device's relay, it is probed in
// every check, which keeps the NAT mappings towards it open.
func TestAQuietPeerARelayCanWakeIsProbedRarely(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	f.nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)
	region := uint16(relayRegion(f.auth.State().GenesisHash(), f.self.record.Identity))
	dev := f.nw.devices[1]
	e := f.signedBy(t, dev, t0)
	e.HomeRelay = region
	if err := e.SignPQ(dev.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	peer := f.installed(t, 1)
	if peer.HomeRelay == 0 {
		t.Fatal("the peer is installed without its home relay")
	}
	addr := peer.Addrs[0].Addr()
	f.mgr.mu.Lock()
	f.mgr.home = int(region)
	f.mgr.answers = map[netip.Addr]bool{addr: true}
	f.mgr.paths = map[netip.Addr]netip.AddrPort{addr: netip.MustParseAddrPort("192.0.2.7:41641")}
	f.mgr.mu.Unlock()
	probes := func() int {
		f.mgr.mu.Lock()
		defer f.mgr.mu.Unlock()
		return len(f.mgr.probed)
	}
	checks := func(n int) {
		t.Helper()
		for range n {
			f.d.refreshReach(t.Context())
			if r := f.d.Status().Reach; len(r) != 1 || !r[0].Live || !r[0].Direct {
				t.Fatalf("at %v the peer reads %+v, want live and direct", c.get().Sub(t0), r)
			}
			c.set(c.get().Add(reachEvery))
		}
	}

	checks(int(quietProbeEvery / reachEvery))
	if got := probes(); got != 1 {
		t.Fatalf("a quiet peer was probed in %d checks over %v, want 1", got, quietProbeEvery)
	}
	checks(1)
	if got := probes(); got != 2 {
		t.Fatalf("after %v the answer still stands: %d probes", quietProbeEvery, got)
	}

	f.mgr.mu.Lock()
	f.mgr.home = 0
	f.mgr.mu.Unlock()
	checks(3)
	if got := probes(); got != 5 {
		t.Fatalf("with no relay of its own, the peer was probed in %d of 3 checks", got-2)
	}
}

// A relay gone, as one whose role was revoked, wakes nothing: a peer homed
// there is probed, found down and looked up for its next home, which a device
// reaching it through relays alone has no other way to learn.
func TestAnAnswerStandsOnlyWhereThePeersRelayIsReached(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	f.nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)
	region := uint16(relayRegion(f.auth.State().GenesisHash(), f.self.record.Identity))
	dev := f.nw.devices[1]
	e := f.signedBy(t, dev, t0)
	e.HomeRelay = region
	if err := e.SignPQ(dev.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	peer := f.installed(t, 1)
	if peer.HomeRelay != int(region) {
		t.Fatalf("the peer is installed homed at %d, want %d", peer.HomeRelay, region)
	}
	addr := peer.Addrs[0].Addr()
	f.mgr.mu.Lock()
	f.mgr.home = int(region)
	f.mgr.answers = map[netip.Addr]bool{addr: true}
	f.mgr.mu.Unlock()
	for range 2 {
		f.d.refreshReach(t.Context())
		c.set(c.get().Add(reachEvery))
	}
	if got := f.mgr.probes(); got != 1 {
		t.Fatalf("a quiet peer homed at this device's relay was probed in %d of 2 checks, want 1", got)
	}

	// This device moves home and reaches the peer's relay no more; the peer,
	// homed there as far as this device knows, answers nothing.
	f.mgr.mu.Lock()
	f.mgr.home = int(region) + 1
	f.mgr.answers = nil
	f.mgr.mu.Unlock()
	f.d.refreshReach(t.Context())
	if got := f.mgr.probes(); got != 2 {
		t.Fatalf("the peer's relay is not reached, yet its answer stood: %d probes", got)
	}
	if r := f.d.Status().Reach; len(r) != 1 || r[0].Live {
		t.Fatalf("the peer reads %+v, want down", r)
	}
	if !slices.Contains(f.d.wanted(), dev.record.Identity) {
		t.Fatal("the peer is not looked up for its next home")
	}
}

func TestAnAnnouncementNamesItsBuildsSchema(t *testing.T) {
	f := newReconcileFixture(t, 2)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if e, ok := f.d.announcement(); !ok || e.Schema != types.CurrentSchema {
		t.Errorf("the announcement names %v, want %v", e.Schema, types.CurrentSchema)
	}
}

// A member that restarts, on a new disco key a hint alone brings, while its
// answer stands and its last handshake is fresh, is probed at once, found
// down by two probes missed in a row and installed on the hint's key within
// seconds, not once its answer has stood its time. A member whose tunnel
// answers keeps its key against a hint, which may be forged.
func TestARestartedMembersHintMovesItsDiscoKeyWithinSeconds(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 3, func(o *Options) { o.Clock = c.get })
	f.nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)
	region := uint16(relayRegion(f.auth.State().GenesisHash(), f.self.record.Identity))
	restarted, up := f.nw.devices[1], f.nw.devices[2]
	var held []gossip.Endpoint
	for _, dev := range []*device{restarted, up} {
		e := f.signedBy(t, dev, t0)
		e.HomeRelay = region
		if err := e.SignPQ(dev.identity); err != nil {
			t.Fatal(err)
		}
		if err := f.d.Learn(e); err != nil {
			t.Fatal(err)
		}
		held = append(held, e)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	gone, answering := f.installed(t, 1), f.installed(t, 2)
	f.mgr.mu.Lock()
	f.mgr.home = int(region)
	f.mgr.answers = map[netip.Addr]bool{gone.Addrs[0].Addr(): true, answering.Addrs[0].Addr(): true}
	f.mgr.tunnels = map[uint64]conn.Tunnel{
		gone.ID:      {LastHandshake: time.Now().Add(-10 * time.Second)},
		answering.ID: {LastHandshake: time.Now().Add(-10 * time.Second)},
	}
	f.mgr.mu.Unlock()
	f.d.refreshReach(t.Context())
	c.set(c.get().Add(reachEvery))

	f.mgr.mu.Lock()
	delete(f.mgr.answers, gone.Addrs[0].Addr())
	f.mgr.mu.Unlock()
	var hinted []gossip.DiscoKey
	for i, dev := range []*device{restarted, up} {
		h := held[i].Hint()
		_, k, err := conn.NewDiscoKey()
		if err != nil {
			t.Fatal(err)
		}
		h.Seq, h.Disco = uint64(c.get().Unix()), gossip.DiscoKey(k)
		if err := h.Sign(dev.identity); err != nil {
			t.Fatal(err)
		}
		if err := f.d.Learn(h); err != nil {
			t.Fatal(err)
		}
		hinted = append(hinted, h.Disco)
	}
	for len(f.d.recheck) > 0 {
		<-f.d.recheck
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	// Each check asks for the next: the hint, then the first probe missed.
	f.d.pushRests.Store(false)
	asked := 0
	on := func(i int, k gossip.DiscoKey) bool { return f.installed(t, i).DiscoKey == conn.DiscoPublicFromRaw32(k) }
	for range 2 {
		select {
		case <-f.d.recheck:
			asked++
		default:
		}
		c.set(c.get().Add(recheckGap))
		f.d.refreshReach(t.Context())
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	if !on(1, hinted[0]) {
		t.Fatalf("%v after the hint, the restarted member is not on its key", 2*recheckGap)
	}
	if !on(2, held[1].Disco) || on(2, hinted[1]) {
		t.Fatal("a hint moved the disco key of a member whose tunnel answers")
	}
	if asked != 2 {
		t.Fatalf("%d of the 2 checks were asked for", asked)
	}
	if f.d.pushRests.Load() {
		t.Error("a restarted member found down is pushed to every member that rests")
	}
}

// A relayed peer is reported with the member whose relay is its home, a
// direct one with none.
func TestARelayedPeerNamesItsHomeRelay(t *testing.T) {
	f := newReconcileFixture(t, 2)
	f.nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)
	region := uint16(relayRegion(f.auth.State().GenesisHash(), f.self.record.Identity))
	dev := f.nw.devices[1]
	e := f.signedBy(t, dev, time.Now())
	e.HomeRelay = region
	if err := e.SignPQ(dev.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	self, _ := f.auth.State().Node(f.self.record.Identity)
	if self.Name == "" {
		t.Fatal("this device has no name")
	}
	addr := f.installed(t, 1).Addrs[0].Addr()
	f.mgr.mu.Lock()
	f.mgr.home = int(region)
	f.mgr.answers = map[netip.Addr]bool{addr: true}
	f.mgr.mu.Unlock()
	f.d.refreshReach(t.Context())
	if r := f.d.Status().Reach; len(r) != 1 || !r[0].Live || r[0].Direct || r[0].Relay != self.Name {
		t.Fatalf("relayed: reach %+v, want live through %q", r, self.Name)
	}

	f.mgr.mu.Lock()
	f.mgr.paths = map[netip.Addr]netip.AddrPort{addr: netip.MustParseAddrPort("192.0.2.7:41641")}
	f.mgr.mu.Unlock()
	f.d.probeNow = map[types.Identity]bool{dev.record.Identity: true}
	f.d.refreshReach(t.Context())
	if r := f.d.Status().Reach; len(r) != 1 || !r[0].Direct || r[0].Relay != "" {
		t.Fatalf("direct: reach %+v, want no relay named", r)
	}
}

// classifyReach changes nothing it is given: a peer back up is synced with
// again, one down for the first time is seeking, one live and keyless past
// outdatedAfter is outdated, and what the last check left is read alone.
func TestClassifyReachSaysWhatChecksShow(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	back, fresh, keyless := types.Identity{1}, types.Identity{2}, types.Identity{3}
	checks := []tunnelCheck{
		{namedPeer: namedPeer{name: "back", id: back, stage: pairkey.StageGroup}, reach: ipc.PeerReach{Live: true}},
		{namedPeer: namedPeer{name: "fresh", id: fresh, stage: pairkey.StageGroup}},
		{namedPeer: namedPeer{name: "keyless", id: keyless, stage: pairkey.StageNone}, reach: ipc.PeerReach{Live: true}},
	}
	past := reachPast{
		down:   map[types.Identity]*downPeer{back: {since: now.Add(-time.Hour)}},
		behind: map[types.Identity]time.Time{keyless: now.Add(-outdatedAfter)},
	}
	v := classifyReach(checks, reachFacts{now: now}, past)
	if !slices.Equal(v.resync, []types.Identity{back}) {
		t.Errorf("resync %v, want the peer back up", v.resync)
	}
	if !slices.Equal(v.down, []string{"fresh"}) || !slices.Equal(v.seeking, []string{"fresh"}) || !v.reach[1].Seeking {
		t.Errorf("down %v, seeking %v", v.down, v.seeking)
	}
	if p := v.past.down[fresh]; p == nil || !p.since.Equal(now) || len(v.past.down) != 1 {
		t.Errorf("down peers left %v", v.past.down)
	}
	if !slices.Equal(v.outdated, []string{"keyless"}) || !v.reach[2].Outdated || v.live != 2 {
		t.Errorf("outdated %v, live %d", v.outdated, v.live)
	}
	if _, ok := past.down[back]; !ok || len(past.down) != 1 {
		t.Error("classifyReach changed what the last check left")
	}
}
