package daemon

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/discovery/mdns"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// While saving battery, an answer from a peer a relay can wake stands for
// savingProbeStands rather than quietProbeEvery.
func TestWhileSavingAnAnswerStandsLonger(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	pace := NewPace()
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get; o.Pace = pace })
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
	addr := f.installed(t, 1).Addrs[0].Addr()
	f.mgr.mu.Lock()
	f.mgr.home = int(region)
	f.mgr.answers = map[netip.Addr]bool{addr: true}
	f.mgr.mu.Unlock()
	checks := func(n int) {
		t.Helper()
		for range n {
			f.d.refreshReach(t.Context())
			if r := f.d.Status().Reach; len(r) != 1 || !r[0].Live {
				t.Fatalf("at %v the peer reads %+v, want live", c.get().Sub(t0), r)
			}
			c.set(c.get().Add(savingReachEvery))
		}
	}

	pace.SetSaving(true)
	checks(int(savingProbeStands / savingReachEvery))
	if got := f.mgr.probes(); got != 1 {
		t.Fatalf("saving, the peer was probed in %d checks over %v, want 1", got, savingProbeStands)
	}
	checks(1)
	if got := f.mgr.probes(); got != 2 {
		t.Fatalf("after %v the answer still stands: %d probes", savingProbeStands, got)
	}
	pace.SetSaving(false)
	checks(1)
	if got := f.mgr.probes(); got != 3 {
		t.Fatalf("back from saving, an answer %v old still stands: %d probes", savingReachEvery, got)
	}
}

// Saving, the tunnels are checked at the saving pace and the data plane stops
// its heartbeat; back from it, they are checked at once, and the heartbeat
// resumes.
func TestSavingSlowsTheChecksAndBackFromItChecksAtOnce(t *testing.T) {
	pace := NewPace()
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Pace = pace; o.ReachDelay = time.Millisecond })
	dev := f.nw.devices[1]
	e := f.signedBy(t, dev, time.Now())
	if err := e.SignPQ(dev.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	addr := f.installed(t, 1).Addrs[0].Addr()
	f.mgr.mu.Lock()
	f.mgr.answers = map[netip.Addr]bool{addr: true}
	f.mgr.mu.Unlock()
	f.d.reachEvery = 20 * time.Millisecond
	f.d.saving.reach = time.Hour
	f.d.checkInBackground(t.Context())
	t.Cleanup(f.d.waits.wait)

	wait := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
		}
	}
	wait("no checks at the normal pace", func() bool { return f.mgr.probes() >= 3 })
	pace.SetSaving(true)
	wait("saving, the data plane keeps its heartbeat", f.mgr.isSaving)
	time.Sleep(50 * time.Millisecond) // a check under way ends
	before := f.mgr.probes()
	time.Sleep(20 * f.d.reachEvery)
	if got := f.mgr.probes() - before; got != 0 {
		t.Fatalf("saving, %d checks in %v", got, 20*f.d.reachEvery)
	}
	pace.SetSaving(false)
	wait("back from saving, the heartbeat stays off", func() bool { return !f.mgr.isSaving() })
	start := time.Now()
	wait("back from saving, no check", func() bool { return f.mgr.probes() > before })
	if took := time.Since(start); took > recheckGap+time.Second {
		t.Fatalf("back from saving, the first check came after %v", took)
	}
}

// Saving, a tick due sooner than the saving pace is skipped.
func TestSavingSkipsTicksDueSooner(t *testing.T) {
	pace := NewPace()
	d := &Daemon{pace: pace}
	last := time.Now().Add(-time.Minute)
	if !d.due(last, time.Hour) {
		t.Fatal("at the normal pace a tick was skipped")
	}
	pace.SetSaving(true)
	if d.due(last, time.Hour) {
		t.Fatal("saving, a tick an hour early ran")
	}
	if !d.due(last, 30*time.Second) {
		t.Fatal("saving, a tick past the saving pace was skipped")
	}
	var none *Pace
	if none.Saving() || none.Changed() != nil {
		t.Fatal("a nil pace saves")
	}
}

// quietFixture has device 1 announce rests and answer probes, at a clock the
// test moves; no relay can wake it.
func quietFixture(t *testing.T, rests bool, pace *Pace) (*reconcileFixture, *clock, netip.Addr) {
	t.Helper()
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get; o.Pace = pace })
	dev := f.nw.devices[1]
	e := f.signedBy(t, dev, t0)
	e.Rests = rests
	if err := e.SignPQ(dev.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	addr := f.installed(t, 1).Addrs[0].Addr()
	f.mgr.mu.Lock()
	f.mgr.answers = map[netip.Addr]bool{addr: true}
	f.mgr.mu.Unlock()
	return f, c, addr
}

// checkEvery runs n checks every gap, each finding the peer live as want.
func (f *reconcileFixture) checkEvery(t *testing.T, c *clock, gap time.Duration, n int, want bool) {
	t.Helper()
	for range n {
		f.d.refreshReach(t.Context())
		if r := f.d.Status().Reach; len(r) != 1 || r[0].Live != want {
			t.Fatalf("the peer reads %+v, want live %v", r, want)
		}
		c.set(c.get().Add(gap))
	}
}

// A peer that rests is probed once in savingProbeStands, and in every other
// check between, past quietPingGap, a quiet ping holds the way to it open
// where no relay could wake it; one that does not rest is probed in every
// check.
func TestARestingPeerIsCheckedQuietly(t *testing.T) {
	f, c, _ := quietFixture(t, true, nil)
	checks := int(savingProbeStands / reachEvery)
	f.checkEvery(t, c, reachEvery, checks, true)
	if probes, quiet := f.mgr.probes(), f.mgr.quietProbes(); probes != 1 || quiet != checks/2-1 {
		t.Fatalf("over %v a resting peer had %d probes and %d quiet ones, want 1 and %d", savingProbeStands, probes, quiet, checks/2-1)
	}
	f.checkEvery(t, c, reachEvery, 1, true)
	if got := f.mgr.probes(); got != 2 {
		t.Fatalf("after %v the answer still stands: %d probes", savingProbeStands, got)
	}

	g, gc, _ := quietFixture(t, false, nil)
	g.checkEvery(t, gc, reachEvery, 4, true)
	if probes, quiet := g.mgr.probes(), g.mgr.quietProbes(); probes != 4 || quiet != 0 {
		t.Fatalf("a peer that does not rest had %d probes and %d quiet ones in 4 checks", probes, quiet)
	}
}

// While saving, every peer is checked quietly, rests or not.
func TestWhileSavingEveryPeerIsCheckedQuietly(t *testing.T) {
	pace := NewPace()
	pace.SetSaving(true)
	f, c, _ := quietFixture(t, false, pace)
	checks := int(savingProbeStands / savingReachEvery)
	f.checkEvery(t, c, savingReachEvery, checks, true)
	if probes, quiet := f.mgr.probes(), f.mgr.quietProbes(); probes != 1 || quiet != checks-1 {
		t.Fatalf("saving, %d probes and %d quiet ones over %v, want 1 and %d", probes, quiet, savingProbeStands, checks-1)
	}
	pace.SetSaving(false)
	f.checkEvery(t, c, reachEvery, 1, true)
	if got := f.mgr.probes(); got != 2 {
		t.Fatalf("back from saving, an answer stood in for a probe: %d probes", got)
	}
}

// A quiet ping unanswered is followed by a probe in the same check: a lost
// ping finds the peer live, and one gone is found down.
func TestAQuietPingUnansweredIsFollowedByAProbe(t *testing.T) {
	f, c, addr := quietFixture(t, true, nil)
	f.checkEvery(t, c, time.Minute, 1, true)
	f.mgr.mu.Lock()
	f.mgr.quietLost = map[netip.Addr]bool{addr: true}
	f.mgr.mu.Unlock()
	f.checkEvery(t, c, time.Minute, 1, true)
	if probes, quiet := f.mgr.probes(), f.mgr.quietProbes(); probes != 2 || quiet != 1 {
		t.Fatalf("a lost ping: %d probes and %d quiet ones, want 2 and 1", probes, quiet)
	}
	f.mgr.mu.Lock()
	f.mgr.quietLost = nil
	f.mgr.mu.Unlock()
	f.checkEvery(t, c, time.Minute, 1, true)
	f.mgr.mu.Lock()
	f.mgr.answers = nil
	f.mgr.mu.Unlock()
	f.checkEvery(t, c, time.Minute, 1, false)
	if probes := f.mgr.probes(); probes != 3 {
		t.Fatalf("a peer gone: %d probes, want 3", probes)
	}
}

// A quiet ping proves no WireGuard session: where the key handshakes mix in
// changed since the last answer, the peer is probed.
func TestAChangedKeyIsProbedNotPinged(t *testing.T) {
	f, c, _ := quietFixture(t, true, nil)
	f.checkEvery(t, c, time.Minute, 2, true)
	f.d.mu.Lock()
	f.d.installed[0].peer.PSK = [32]byte{7}
	f.d.mu.Unlock()
	f.checkEvery(t, c, time.Minute, 1, true)
	if probes, quiet := f.mgr.probes(), f.mgr.quietProbes(); probes != 2 || quiet != 1 {
		t.Fatalf("after the key changed: %d probes and %d quiet ones, want 2 and 1", probes, quiet)
	}
}

// The periodic sync leaves a member that rests to sync by itself, and picks
// one that does not.
func TestTheBackstopSyncLeavesARestingMemberAlone(t *testing.T) {
	var mu sync.Mutex
	dialed := map[uint16]bool{}
	f := newReconcileFixtureWith(t, 3, func(o *Options) {
		o.GossipDial = func(_ context.Context, to netip.AddrPort) (net.Conn, error) {
			mu.Lock()
			dialed[to.Port()] = true
			mu.Unlock()
			return nil, errors.New("cut off")
		}
	})
	resting, awake := f.nw.devices[1], f.nw.devices[2]
	e := f.learn(t, resting, 4001)
	e.Rests, e.Seq = true, e.Seq+1
	if err := e.SignPQ(resting.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	f.learn(t, awake, 4002)
	for range 20 {
		f.d.syncOne(t.Context())
	}
	mu.Lock()
	defer mu.Unlock()
	if dialed[4001] || !dialed[4002] {
		t.Fatalf("the backstop sync dialed the gossip ports %v, want the awake member's 4002 alone", dialed)
	}
}

// A device that rests says so where the network's schema has the field, which
// earlier builds' decoders refuse, and not below it.
func TestARestingDeviceSaysSoFromSchema20(t *testing.T) {
	nw := newNetwork(t, 2)
	v := types.SchemaRests - 1
	nw.genesis.State.Schema = v
	nw.genesis.Signatures = nil
	if err := nw.genesis.Sign(nw.admin); err != nil {
		t.Fatal(err)
	}
	f := newReconcileFixtureOn(t, nw, func(o *Options) { o.Rests = true })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if e, ok := f.d.announcement(); !ok || e.Rests {
		t.Fatalf("at %v the announcement says rests: %v", v, e.Rests)
	}
	prev := f.auth.Head()
	up := types.AUM{Kind: types.KindSchemaUpgrade, Prev: &prev, Schema: new(types.SchemaRests)}
	if err := up.Sign(nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{up}); err != nil {
		t.Fatal(err)
	}
	if e, ok := f.d.announcement(); !ok || !e.Rests {
		t.Fatalf("at %v the announcement does not say rests", types.SchemaRests)
	}

	g := newReconcileFixtureWith(t, 2, nil)
	if err := g.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if e, _ := g.d.announcement(); e.Rests {
		t.Fatal("a device that does not rest says it does")
	}
}

// A membership that expires is reconciled away at its expiry, with neither
// an event nor the backstop due.
func TestAMembershipIsReconciledAwayAtItsExpiry(t *testing.T) {
	expiry := time.Now().Add(2 * time.Second).Truncate(time.Second).Add(time.Second)
	nw := newNetworkMutated(t, 2, func(nw *network) { nw.devices[1].record.Expiry = uint64(expiry.Unix()) })
	f := newReconcileFixtureOn(t, nw, func(o *Options) { o.ReconcileInterval = time.Hour; o.ReachDelay = time.Hour })
	f.learn(t, nw.devices[1], 4001)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.d.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	member := [32]byte(nw.devices[1].record.WireGuard)
	for deadline := time.Now().Add(5 * time.Second); !f.mgr.has(member); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the member was never installed")
		}
	}
	for f.mgr.has(member) {
		if time.Now().After(expiry.Add(3 * time.Second)) {
			t.Fatalf("the member is installed %v past its expiry", time.Since(expiry).Round(time.Second))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The next reconcile is due at the soonest deadline the log, the leases, the
// announcements and the host's DNS name, and none past is kept.
func TestTheNextReconcileIsDueAtTheSoonestDeadline(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	at := func(d time.Duration) int64 { return t0.Add(d).Unix() }
	for _, tc := range []struct {
		name string
		set  func(*snapshot, *log.Freshness, map[types.Identity]gossip.Endpoint)
		want time.Duration
	}{
		{"nothing", func(*snapshot, *log.Freshness, map[types.Identity]gossip.Endpoint) {}, 0},
		{"a membership's expiry", func(s *snapshot, _ *log.Freshness, _ map[types.Identity]gossip.Endpoint) {
			s.members[1].Expiry = uint64(at(time.Hour))
		}, time.Hour},
		{"a retiring address", func(s *snapshot, _ *log.Freshness, _ map[types.Identity]gossip.Endpoint) {
			s.members[1].Retiring = &types.RetiringV4{Addr: netip.MustParseAddr("198.18.9.9"), Until: uint64(at(time.Minute))}
		}, time.Minute},
		{"the view going stale", func(_ *snapshot, fr *log.Freshness, _ map[types.Identity]gossip.Endpoint) {
			fr.Signers, fr.Until = 1, at(3*time.Hour)
		}, 3 * time.Hour},
		{"a share's end", func(_ *snapshot, _ *log.Freshness, held map[types.Identity]gossip.Endpoint) {
			held[f.nw.devices[1].record.Identity] = gossip.Endpoint{Share: &gossip.Share{Port: 1, Until: at(7 * time.Minute)}}
		}, 7 * time.Minute},
		{"one past", func(s *snapshot, _ *log.Freshness, _ map[types.Identity]gossip.Endpoint) {
			s.members[1].Expiry = uint64(at(-time.Minute))
		}, 0},
	} {
		state, err := f.d.TrustedState()
		if err != nil {
			t.Fatal(err)
		}
		s := f.d.membersOf(state)
		var fr log.Freshness
		held := map[types.Identity]gossip.Endpoint{}
		tc.set(&s, &fr, held)
		f.d.noteDue(s, fr, held)
		due := *f.d.reconcileDue.Load()
		if tc.want == 0 && !due.IsZero() || tc.want != 0 && !due.Equal(t0.Add(tc.want)) {
			t.Errorf("%s: due at %v, want %v from now", tc.name, due, tc.want)
		}
	}
	f.d.reconcileDue.Store(new(t0.Add(time.Hour)))
	if got := f.d.reconcileWait(); got != f.d.reconcileEvery {
		t.Errorf("a deadline past the backstop waits %v, want the backstop's %v", got, f.d.reconcileEvery)
	}
	f.d.reconcileDue.Store(new(t0.Add(-time.Hour)))
	if got := f.d.reconcileWait(); got != reconcileGap {
		t.Errorf("a deadline past waits %v, want %v", got, reconcileGap)
	}
}

// A hint alone, as a holder of the epoch's key could forge one, does not have
// its member checked quietly or left out of the sync.
func TestAHintAloneSaysNoMemberRests(t *testing.T) {
	f := newReconcileFixture(t, 2)
	dev := f.nw.devices[1]
	e, err := endpointFor(dev, 4001)
	if err != nil {
		t.Fatal(err)
	}
	f.learnHint(t, dev, e, func(h *gossip.Endpoint) { h.Rests = true })
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if f.d.peerRests(dev.record.Identity) {
		t.Error("a hint alone says its member rests")
	}
	f.d.mu.Lock()
	defer f.d.mu.Unlock()
	for _, p := range f.d.installed {
		if p.rests {
			t.Errorf("%s is checked quietly on a hint alone", p.name)
		}
	}
}

// Where every other member rests, the periodic sync still reaches one of
// them, once in savingSyncEvery.
func TestTheBackstopSyncReachesARestingMemberWhereAllRest(t *testing.T) {
	var mu sync.Mutex
	dials := 0
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) {
		o.Clock = c.get
		o.GossipDial = func(context.Context, netip.AddrPort) (net.Conn, error) {
			mu.Lock()
			dials++
			mu.Unlock()
			return nil, errors.New("cut off")
		}
	})
	resting := f.nw.devices[1]
	e := f.learn(t, resting, 4001)
	e.Rests, e.Seq = true, e.Seq+1
	if err := e.SignPQ(resting.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	synced := func() bool {
		mu.Lock()
		before := dials
		mu.Unlock()
		f.d.syncOne(t.Context())
		mu.Lock()
		defer mu.Unlock()
		return dials > before
	}
	if !synced() {
		t.Fatal("where all rest, the first backstop sync reached nobody")
	}
	c.set(t0.Add(DefaultSyncInterval))
	if synced() {
		t.Fatalf("a resting member was synced again after %v", DefaultSyncInterval)
	}
	c.set(t0.Add(savingSyncEvery))
	if !synced() {
		t.Fatalf("no resting member was synced after %v", savingSyncEvery)
	}
}

// A peer a relay can wake, whose key changed since its answer, is probed: the
// standing answer proves the old key's tunnel alone.
func TestAChangedKeyIsProbedThoughARelayWakes(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	f.nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)
	region := uint16(relayRegion(f.auth.State().GenesisHash(), f.self.record.Identity))
	dev := f.nw.devices[1]
	e := f.signedBy(t, dev, t0)
	e.HomeRelay, e.Rests = region, true
	if err := e.SignPQ(dev.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	addr := f.installed(t, 1).Addrs[0].Addr()
	f.mgr.mu.Lock()
	f.mgr.home = int(region)
	f.mgr.answers = map[netip.Addr]bool{addr: true}
	f.mgr.mu.Unlock()
	f.checkEvery(t, c, time.Minute, 2, true)
	if got := f.mgr.probes(); got != 1 {
		t.Fatalf("%d probes before the key changed, want 1", got)
	}
	f.d.mu.Lock()
	f.d.installed[0].peer.PSK = [32]byte{7}
	f.d.mu.Unlock()
	f.checkEvery(t, c, time.Minute, 1, true)
	if got := f.mgr.probes(); got != 2 {
		t.Fatalf("after the key changed, a relay waking the peer: %d probes, want 2", got)
	}
}

// A handshake under the key since the answer, as the peer's own probe brings,
// renews it: the pair costs one probe in savingProbeStands, not one each.
func TestAHandshakeUnderTheKeyRenewsTheAnswer(t *testing.T) {
	f, c, _ := quietFixture(t, true, nil)
	t0 := c.get()
	f.checkEvery(t, c, time.Minute, 1, true)
	c.set(t0.Add(20 * time.Minute))
	id := f.installed(t, 1).ID
	f.mgr.mu.Lock()
	f.mgr.tunnels = map[uint64]conn.Tunnel{id: {LastHandshake: c.get()}}
	f.mgr.mu.Unlock()
	f.checkEvery(t, c, time.Minute, 1, true)
	c.set(t0.Add(savingProbeStands + 5*time.Minute))
	f.checkEvery(t, c, time.Minute, 1, true)
	if got := f.mgr.probes(); got != 1 {
		t.Fatalf("%d probes, want the first alone: the handshake at 20 minutes renewed its answer", got)
	}
}

// With the clock set back past an answer, the peer is probed rather than
// kept on an answer from the future.
func TestAClockSetBackHasThePeerProbed(t *testing.T) {
	f, c, _ := quietFixture(t, true, nil)
	f.checkEvery(t, c, time.Minute, 1, true)
	c.set(c.get().Add(-10 * time.Minute))
	f.checkEvery(t, c, time.Minute, 1, true)
	if got := f.mgr.probes(); got != 2 {
		t.Fatalf("%d probes, want 2: the clock went back past the answer", got)
	}
}

// A hint newer than a member's announcement, naming another disco key, moves
// where the member is dialed and nothing else: the announcement's word that
// it rests stands, as the threat model says.
func TestANewerHintLeavesAMembersRestAlone(t *testing.T) {
	f := newReconcileFixture(t, 2)
	dev := f.nw.devices[1]
	e := f.learn(t, dev, 4001)
	e.Rests, e.Seq = true, e.Seq+1
	if err := e.SignPQ(dev.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.mu.Lock()
	rests := f.d.installed[0].rests
	f.d.mu.Unlock()
	if !rests {
		t.Fatal("the announcement alone: the member does not rest")
	}
	_, disco, err := conn.NewDiscoKey()
	if err != nil {
		t.Fatal(err)
	}
	h := e.Hint()
	h.Seq, h.Disco = e.Seq+1, gossip.DiscoKey(disco)
	if err := h.Sign(dev.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(h); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.mu.Lock()
	defer f.d.mu.Unlock()
	if !f.d.installed[0].rests {
		t.Fatal("a newer hint naming another disco key turned the member's quiet check off")
	}
}

// A device whose only live peer with a lower identity rests seeks in the DHT
// itself: that peer, answered by this device, does not take part there.
func TestADeviceWhoseLowerLivePeerRestsSeeksItself(t *testing.T) {
	f := newReconcileFixture(t, 8)
	var lower *device
	for _, dev := range f.nw.devices[1:] {
		if dev.record.Identity.Compare(f.d.self) < 0 {
			lower = dev
			break
		}
	}
	if lower == nil {
		t.Skip("no member below this device's identity among seven")
	}
	e := f.learn(t, lower, 4001)
	e.Rests, e.Seq = true, e.Seq+1
	if err := e.SignPQ(lower.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	live := map[types.Identity]bool{lower.record.Identity: true}
	f.d.reachable.Store(&live)
	if !f.d.seeksInDHT() {
		t.Fatal("this device leaves the lookups to a resting peer, which joins the DHT only while nobody awake answers it")
	}
}

func (m *fakeManager) setCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sets
}

// A device past its own expiry is torn down once and then waits for the
// backstop: the deadline that fired is not kept as one still to come.
func TestADevicePastItsExpiryWaitsForTheBackstop(t *testing.T) {
	expiry := time.Now().Add(2 * time.Second).Truncate(time.Second).Add(time.Second)
	nw := newNetworkMutated(t, 2, func(nw *network) { nw.devices[0].record.Expiry = uint64(expiry.Unix()) })
	f := newReconcileFixtureOn(t, nw, func(o *Options) { o.ReconcileInterval = time.Hour; o.ReachDelay = time.Hour })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.d.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitFor(t, 6*time.Second, "the device torn down at its expiry", func() bool { return f.d.Status().NotMember })
	sets := f.mgr.setCount()
	time.Sleep(4 * time.Second)
	if n := f.mgr.setCount() - sets; n > 0 {
		t.Fatalf("the data plane was torn down %d more times in 4 s past the device's expiry, with the backstop an hour away", n)
	}
}

// Saving, where every other member rests, the sync the loop's tick lets
// through runs, though it comes a moment short of savingSyncEvery after the
// last as syncOne reads the clock.
func TestWhileSavingTheRestingSyncFollowsTheTick(t *testing.T) {
	var mu sync.Mutex
	dials := 0
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0.Add(3 * time.Millisecond)}
	pace := NewPace()
	pace.SetSaving(true)
	f := newReconcileFixtureWith(t, 2, func(o *Options) {
		o.Clock, o.Pace = c.get, pace
		o.GossipDial = func(context.Context, netip.AddrPort) (net.Conn, error) {
			mu.Lock()
			dials++
			mu.Unlock()
			return nil, errors.New("cut off")
		}
	})
	resting := f.nw.devices[1]
	e := f.learn(t, resting, 4001)
	e.Rests, e.Seq = true, e.Seq+1
	if err := e.SignPQ(resting.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	f.d.syncOne(t.Context())
	c.set(t0.Add(savingSyncEvery + time.Millisecond))
	f.d.syncOne(t.Context())
	mu.Lock()
	defer mu.Unlock()
	if dials < 2 {
		t.Fatalf("saving, %d syncs where the tick let two through", dials)
	}
}

// A deadline sooner than the loop's timer, as a reconcile off the loop finds,
// has the loop arm it again.
func TestASoonerDeadlineRearmsTheLoop(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	state, err := f.d.TrustedState()
	if err != nil {
		t.Fatal(err)
	}
	s := f.d.membersOf(state)
	f.d.reconcileArmed.Store(new(t0.Add(time.Hour)))
	f.d.noteDue(s, log.Freshness{}, nil)
	select {
	case <-f.d.rearm:
		t.Fatal("no deadline, yet the loop was asked to arm again")
	default:
	}
	s.members[1].Expiry = uint64(t0.Add(time.Minute).Unix())
	f.d.noteDue(s, log.Freshness{}, nil)
	select {
	case <-f.d.rearm:
	default:
		t.Fatal("a deadline before the loop's timer left it armed for later")
	}
}

// Saving and homed at a relay, a new address alone pushes nothing: peers
// reach the device through its relay. A new home, or one not saving, does.
func TestWhileSavingANewAddressWaitsForTheNextSync(t *testing.T) {
	pace := NewPace()
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Pace = pace })
	f.mgr.mu.Lock()
	f.mgr.home = 7
	f.mgr.mu.Unlock()
	if _, ok := f.d.announcement(); !ok {
		t.Fatal("no announcement")
	}
	pushed := func(change func()) bool {
		t.Helper()
		select {
		case <-f.d.dirty:
		default:
		}
		change()
		select {
		case <-f.d.dirty:
			return true
		default:
			return false
		}
	}
	newAddr := func() {
		f.mgr.mu.Lock()
		f.mgr.eps = append(f.mgr.eps, netip.MustParseAddrPort("198.51.100.7:41641"))
		f.mgr.mu.Unlock()
		f.d.onConnectivityChange()
	}
	pace.SetSaving(true)
	if pushed(newAddr) {
		t.Error("saving, homed, a new address alone was pushed")
	}
	if _, ok := f.d.announcement(); !ok {
		t.Fatal("no announcement")
	}
	if !pushed(func() {
		f.mgr.mu.Lock()
		f.mgr.home = 8
		f.mgr.mu.Unlock()
		f.d.onConnectivityChange()
	}) {
		t.Error("saving, a new home was not pushed")
	}
	if _, ok := f.d.announcement(); !ok {
		t.Fatal("no announcement")
	}
	// Members awake keep the home of a walled device open, which disco
	// cannot tell; one that rests keeps none, and is not woken for it.
	f.d.pushRests.Store(false)
	if !pushed(func() {
		f.mgr.mu.Lock()
		f.mgr.walled = true
		f.mgr.mu.Unlock()
		f.d.onConnectivityChange()
	}) {
		t.Error("saving, walls coming were not pushed")
	}
	if f.d.pushRests.Load() {
		t.Error("walls coming were pushed to the members that rest")
	}
	pace.SetSaving(false)
	if !pushed(newAddr) {
		t.Error("not saving, a new address was not pushed")
	}
}

// A new address that waited is pushed once at the next reconcile while
// saving, and at once when saving ends.
func TestAWaitingAddressIsPushedLater(t *testing.T) {
	for _, end := range []string{"reconcile", "saving ends"} {
		var dials atomic.Int32
		pace := NewPace()
		pace.SetSaving(true)
		f := newReconcileFixtureWith(t, 2, func(o *Options) {
			o.Pace = pace
			o.ReachDelay = time.Hour
			o.GossipDial = func(context.Context, netip.AddrPort) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("cut off")
			}
		})
		f.learn(t, f.nw.devices[1], 4001)
		f.mgr.mu.Lock()
		f.mgr.home = 7
		f.mgr.mu.Unlock()
		f.d.saving.reconcile = time.Hour
		if end == "reconcile" {
			f.d.saving.reconcile = 3 * time.Second
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			f.d.Run(ctx)
		}()
		time.Sleep(2 * time.Second) // the push at start
		if _, ok := f.d.announcement(); !ok {
			t.Fatal("no announcement")
		}
		before := dials.Load()
		f.mgr.mu.Lock()
		f.mgr.eps = append(f.mgr.eps, netip.MustParseAddrPort("198.51.100.7:41641"))
		f.mgr.mu.Unlock()
		f.d.onConnectivityChange()
		if end == "saving ends" {
			time.Sleep(time.Second)
			if dials.Load() != before {
				t.Fatal("saving, the new address was pushed at once")
			}
			pace.SetSaving(false)
		}
		waitFor(t, 10*time.Second, "the waiting address pushed when "+end, func() bool { return dials.Load() > before })
		cancel()
		<-done
	}
}

// A new address of this device's is pushed to the members that do not rest;
// a change to the log reaches those that rest too.
func TestAnAddressIsPushedToTheAwakeAlone(t *testing.T) {
	var mu sync.Mutex
	dialed := map[uint16]int{}
	f := newReconcileFixtureWith(t, 3, func(o *Options) {
		o.ReachDelay = time.Hour
		o.GossipDial = func(_ context.Context, to netip.AddrPort) (net.Conn, error) {
			mu.Lock()
			dialed[to.Port()]++
			mu.Unlock()
			return nil, errors.New("cut off")
		}
	})
	resting, awake := f.nw.devices[1], f.nw.devices[2]
	e := f.learn(t, resting, 4001)
	e.Rests, e.Seq = true, e.Seq+1
	if err := e.SignPQ(resting.identity); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(e); err != nil {
		t.Fatal(err)
	}
	f.learn(t, awake, 4002)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.d.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	time.Sleep(2 * time.Second) // the push at start
	count := func(port uint16) int {
		mu.Lock()
		defer mu.Unlock()
		return dialed[port]
	}
	r0, a0 := count(4001), count(4002)
	f.d.onConnectivityChange()
	waitFor(t, 10*time.Second, "the new address pushed to the awake member", func() bool { return count(4002) > a0 })
	time.Sleep(time.Second)
	if count(4001) != r0 {
		t.Fatal("a new address was pushed to the member that rests")
	}
	f.d.MarkDirty()
	waitFor(t, 10*time.Second, "a change pushed to the member that rests", func() bool { return count(4001) > r0 })
}

// This device's own move is pushed as its peers push it on: its addresses
// alone to the members awake, a new home or a relay's move to all.
func TestAMoveIsPushedAsPeersPushItOn(t *testing.T) {
	nw := newNetwork(t, 3)
	f := newReconcileFixtureOn(t, nw, nil)
	if _, ok := f.d.Announcement(); !ok {
		t.Fatal("no announcement")
	}
	full := func() bool {
		t.Helper()
		select {
		case <-f.d.dirty:
		default:
		}
		f.d.pushRests.Store(false)
		f.d.onConnectivityChange()
		select {
		case <-f.d.dirty:
		default:
			t.Fatal("the move was not pushed")
		}
		return f.d.pushRests.Load()
	}
	if full() {
		t.Error("a non-relay's new addresses were pushed to every member")
	}
	f.mgr.mu.Lock()
	f.mgr.home = 7
	f.mgr.mu.Unlock()
	if !full() {
		t.Error("a new home relay was pushed to the members awake alone")
	}
	if _, ok := f.d.Announcement(); !ok {
		t.Fatal("no announcement")
	}
	nw.setRoles(t, f, f.self.record.Identity, types.RoleRelayCapable)
	if !f.d.Status().Relaying {
		t.Fatal("the grant did not start the relay")
	}
	if _, ok := f.d.Announcement(); !ok {
		t.Fatal("no announcement")
	}
	if !full() {
		t.Error("a relay's new addresses were pushed to the members awake alone")
	}
}

// The data plane may say its connectivity changed before it is handed back
// to the daemon starting it.
func TestAConnectivityChangeBeforeTheDataPlaneIsHeld(t *testing.T) {
	newReconcileFixtureWith(t, 2, func(o *Options) {
		connect := o.Connect
		o.Pace = NewPace()
		o.Pace.SetSaving(true)
		o.Connect = func(co conn.Options) (conn.Manager, error) {
			co.OnConnectivityChange()
			return connect(co)
		}
	})
}

// Another's announcement learned is pushed on to the members awake alone,
// whatever in it is new: one that rests hears it from its author.
func TestALearnedAnnouncementIsPushedOnToTheAwakeAlone(t *testing.T) {
	f := newReconcileFixture(t, 3)
	dev := f.nw.devices[1]
	e := f.learn(t, dev, 4001)
	learn := func(change func(*gossip.Endpoint)) (signalled, full bool) {
		t.Helper()
		select {
		case <-f.d.dirty:
		default:
		}
		f.d.pushRests.Store(false)
		change(&e)
		e.Seq++
		if err := e.SignPQ(dev.identity); err != nil {
			t.Fatal(err)
		}
		if err := f.d.Learn(e); err != nil {
			t.Fatal(err)
		}
		select {
		case <-f.d.dirty:
			return true, f.d.pushRests.Load()
		default:
			return false, false
		}
	}
	if s, full := learn(func(e *gossip.Endpoint) {
		e.Addrs = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.9:4001")}
	}); !s || full {
		t.Errorf("a new address alone: signalled %v, to every member %v", s, full)
	}
	if s, full := learn(func(e *gossip.Endpoint) { e.HomeRelay = 5 }); !s || full {
		t.Errorf("a new home relay: signalled %v, to every member %v", s, full)
	}
}

// The data plane may say its connectivity changed from its own goroutines
// while the daemon starting it is still wiring the rest.
func TestAConnectivityChangeDuringStartRacesNothing(t *testing.T) {
	stop, done := make(chan struct{}), make(chan struct{})
	sock := &sendCounter{closed: make(chan struct{})}
	newReconcileFixtureWith(t, 2, func(o *Options) {
		o.DisableDiscovery = false
		o.Discovery = &mdns.Options{Conn: sock}
		connect := o.Connect
		o.Connect = func(co conn.Options) (conn.Manager, error) {
			go func() {
				defer close(done)
				for {
					select {
					case <-stop:
						return
					default:
						co.OnConnectivityChange()
					}
				}
			}()
			return connect(co)
		}
	})
	close(stop)
	<-done
}

// pushFixture is a daemon among awake members and resting ones, which
// counts the members each push dials.
type pushFixture struct {
	*reconcileFixture
	mu     sync.Mutex
	dialed map[uint16]bool
}

const (
	firstAwakePort   = 4100
	firstRestingPort = 4200
)

func newPushFixture(t *testing.T, awake, resting int, mutate func(*Options)) *pushFixture {
	p := &pushFixture{dialed: map[uint16]bool{}}
	p.reconcileFixture = newReconcileFixtureWith(t, 1+awake+resting, func(o *Options) {
		o.ReachDelay = time.Hour
		o.GossipDial = func(_ context.Context, to netip.AddrPort) (net.Conn, error) {
			p.mu.Lock()
			p.dialed[to.Port()] = true
			p.mu.Unlock()
			return nil, errors.New("cut off")
		}
		if mutate != nil {
			mutate(o)
		}
	})
	for i, dev := range p.nw.devices[1:] {
		port := uint16(firstAwakePort + i)
		if i >= awake {
			port = uint16(firstRestingPort + i - awake)
		}
		e := p.learn(t, dev, port)
		if i >= awake {
			e.Rests, e.Seq = true, e.Seq+1
			if err := e.SignPQ(dev.identity); err != nil {
				t.Fatal(err)
			}
			if err := p.d.Learn(e); err != nil {
				t.Fatal(err)
			}
		}
	}
	return p
}

// push runs one push and counts the awake members and the resting ones it
// dialed.
func (p *pushFixture) push(t *testing.T, awake bool) (up, resting int) {
	t.Helper()
	p.mu.Lock()
	clear(p.dialed)
	p.mu.Unlock()
	p.d.push(t.Context(), awake)
	p.mu.Lock()
	defer p.mu.Unlock()
	for port := range p.dialed {
		if port >= firstRestingPort {
			resting++
		} else if port >= firstAwakePort {
			up++
		}
	}
	return up, resting
}

// A push reaches PushFanout members awake, and one to every member every
// member that rests too, which relays nothing.
func TestAPushReachesTheFanoutAwakeAndEveryMemberThatRests(t *testing.T) {
	p := newPushFixture(t, PushFanout+3, 3, nil)
	if up, resting := p.push(t, false); up != PushFanout || resting != 3 {
		t.Errorf("a push to every member reached %d awake and %d resting, want %d and 3", up, resting, PushFanout)
	}
	if up, resting := p.push(t, true); up != PushFanout || resting != 0 {
		t.Errorf("a push to the awake reached %d awake and %d resting, want %d and 0", up, resting, PushFanout)
	}
}

// A device that rests pushes to restingPushFanout members awake, which push
// it on: each session wakes it.
func TestADeviceThatRestsPushesToFewAwake(t *testing.T) {
	p := newPushFixture(t, PushFanout, 2, func(o *Options) { o.Rests = true })
	if up, resting := p.push(t, true); up != restingPushFanout || resting != 0 {
		t.Errorf("its push reached %d awake and %d resting, want %d and 0", up, resting, restingPushFanout)
	}
	if up, resting := p.push(t, false); up != restingPushFanout || resting != 2 {
		t.Errorf("its push to every member reached %d awake and %d resting, want %d and 2", up, resting, restingPushFanout)
	}
}

// A device that rests passes on nothing it learned while a member awake
// does, but takes it into the data plane; where every member rests, it
// passes it on.
func TestADeviceThatRestsRelaysNothing(t *testing.T) {
	for _, awake := range []int{1, 0} {
		p := newPushFixture(t, awake, 2, func(o *Options) { o.Rests = true })
		dev := p.nw.devices[1]
		e, ok := p.d.Endpoints().Get(dev.record.Identity)
		if !ok {
			t.Fatal("no announcement held")
		}
		for _, ch := range []chan struct{}{p.d.dirty, p.d.soon} {
			select {
			case <-ch:
			default:
			}
		}
		e.HomeRelay, e.Seq = 7, e.Seq+1
		if err := e.SignPQ(dev.identity); err != nil {
			t.Fatal(err)
		}
		if err := p.d.Learn(e); err != nil {
			t.Fatal(err)
		}
		pushed := len(p.d.dirty) > 0
		if awake > 0 && (pushed || len(p.d.soon) == 0) {
			t.Errorf("beside a member awake: pushed %v, reconciled %v", pushed, len(p.d.soon) > 0)
		}
		if awake == 0 && !pushed {
			t.Error("where every member rests, the news was not passed on")
		}
	}
}

// Hellos say what their sender holds where the network's schema has the
// field, which earlier builds' decoders refuse, and carry it below.
func TestHellosSayWhatTheyHoldFromSchema21(t *testing.T) {
	nw := newNetwork(t, 2)
	nw.genesis.State.Schema = types.SchemaSeen - 1
	nw.genesis.Signatures = nil
	if err := nw.genesis.Sign(nw.admin); err != nil {
		t.Fatal(err)
	}
	f := newReconcileFixtureOn(t, nw, nil)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if f.d.seenAlone() {
		t.Fatalf("at %v hellos say what they hold", types.SchemaSeen-1)
	}
	prev := f.auth.Head()
	up := types.AUM{Kind: types.KindSchemaUpgrade, Prev: &prev, Schema: new(types.SchemaSeen)}
	if err := up.Sign(nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Inform([]types.AUM{up}); err != nil {
		t.Fatal(err)
	}
	if !f.d.seenAlone() {
		t.Fatalf("at %v hellos carry what they hold", types.SchemaSeen)
	}
}

// A device that rests and takes records pushes its own announcement, which
// they may change, though it passes the records on to no one.
func TestADeviceThatRestsPushesItselfAfterRecords(t *testing.T) {
	p := newPushFixture(t, 1, 0, func(o *Options) { o.Rests = true })
	select {
	case <-p.d.dirty:
	default:
	}
	p.d.pushRests.Store(false)
	p.d.relayRecords()
	if len(p.d.dirty) == 0 || p.d.pushRests.Load() {
		t.Errorf("after records: pushed %v, to every member %v", len(p.d.dirty) > 0, p.d.pushRests.Load())
	}
}

// An exchange of preshared keys is pushed to its peer, and to the members
// awake, not to every member that rests.
func TestAPairExchangeWakesNoMemberThatRests(t *testing.T) {
	f := newFreshFixture(t, "", 0)
	select {
	case <-f.d.dirty:
	default:
	}
	f.d.pushRests.Store(false)
	f.reconcileAt(t, f.start)
	f.d.mu.Lock()
	wanted := len(f.d.pairWanted)
	f.d.mu.Unlock()
	if wanted == 0 {
		t.Fatal("the reconcile started no exchange of preshared keys")
	}
	if f.d.pushRests.Load() {
		t.Error("an exchange of preshared keys is pushed to every member that rests")
	}
}
