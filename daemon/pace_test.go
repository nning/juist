package daemon

import (
	"net/netip"
	"testing"
	"time"

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
