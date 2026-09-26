package daemon

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// dirtyStatus sets the derived and checked fields a torn-down data plane must
// not keep reporting.
func dirtyStatus(s *ipc.Status) {
	s.Conflicted, s.StaleKeys, s.Unrevoked = 1, true, []string{"the removal of x"}
	s.LeaseSigners, s.FreshSince, s.FreshUntil, s.Vouchers, s.Vouching = 1, 1, 1, 1, 1
	s.HomeRelay, s.TunnelsDown, s.Reach = "vps", []string{"n1"}, []ipc.PeerReach{{}}
	s.LastReconcile = 1
}

func assertTornDown(t *testing.T, st ipc.Status) {
	t.Helper()
	switch {
	case st.Conflicted != 0, st.StaleKeys, st.Unrevoked != nil:
		t.Errorf("conflicted %d, stale keys %v, unrevoked %q survived the teardown", st.Conflicted, st.StaleKeys, st.Unrevoked)
	case st.LeaseSigners != 0 || st.FreshSince != 0 || st.FreshUntil != 0 || st.Vouchers != 0 || st.Vouching != 0:
		t.Errorf("freshness %d/%d/%d/%d/%d survived the teardown",
			st.LeaseSigners, st.FreshSince, st.FreshUntil, st.Vouchers, st.Vouching)
	case st.HomeRelay != "" || st.TunnelsDown != nil || st.Reach != nil:
		t.Errorf("home relay %q, tunnels down %q, reach %v survived the teardown", st.HomeRelay, st.TunnelsDown, st.Reach)
	case st.LastReconcile <= 1:
		t.Errorf("the teardown left LastReconcile at %d", st.LastReconcile)
	}
}

func TestOwnRemovalClearsEveryDerivedField(t *testing.T) {
	f := newReconcileFixture(t, 3)
	f.learn(t, f.nw.devices[1], 4001)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.setStatus(dirtyStatus)
	if err := f.d.Inform([]types.AUM{f.nw.removeNode(t, f.auth, f.self.record.Identity)}); err != nil {
		t.Fatal(err)
	}
	st := f.d.Status()
	if !st.NotMember {
		t.Fatal("the removal was not noticed")
	}
	assertTornDown(t, st)
}

func TestAForkAlarmClearsEveryDerivedField(t *testing.T) {
	f := newReconcileFixture(t, 3)
	a := f.nw.devices[1]
	f.learn(t, a, 4001)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.setStatus(dirtyStatus)
	first, second := f.nw.conflictingFork(t, f.auth, a.record.Identity)
	if err := f.auth.Inform(first, second); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err == nil {
		t.Fatal("reconcile succeeded under a fork alarm")
	}
	st := f.d.Status()
	if st.Alarm == "" {
		t.Fatal("the alarm was not reported")
	}
	assertTornDown(t, st)
}

// An alarm raised before the first reconcile must still close the window in
// which any announcement's subject counts as actionable.
func TestAStartupAlarmEndsTheFirstReconcileWindow(t *testing.T) {
	f := newReconcileFixture(t, 3)
	first, second := f.nw.conflictingFork(t, f.auth, f.nw.devices[1].record.Identity)
	if err := f.auth.Inform(first, second); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err == nil {
		t.Fatal("reconcile succeeded under a fork alarm")
	}
	if f.d.Status().LastReconcile == 0 {
		t.Error("a reconcile under an alarm left LastReconcile unset")
	}
	stranger := newDevice(t, "stranger", netip.Addr{})
	if f.d.actionableSubject(stranger.record.Identity) {
		t.Error("a stranger's announcement is still actionable after the first reconcile")
	}
}

// A check that was probing when the data plane came down must not put what it
// found back into the status.
func TestATunnelCheckUnderwayDoesNotOutliveATeardown(t *testing.T) {
	f := newReconcileFixture(t, 3)
	a := f.nw.devices[1]
	f.learn(t, a, 4001)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	hold := make(chan struct{})
	f.mgr.mu.Lock()
	f.mgr.hold = hold
	f.mgr.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.d.refreshReach(context.Background())
	}()
	for f.mgr.probes() == 0 {
		time.Sleep(time.Millisecond)
	}

	first, second := f.nw.conflictingFork(t, f.auth, a.record.Identity)
	if err := f.auth.Inform(first, second); err != nil {
		t.Fatal(err)
	}
	_ = f.d.Reconcile()
	close(hold)
	<-done

	if st := f.d.Status(); st.Reach != nil || st.TunnelsDown != nil || st.TunnelsChecked {
		t.Errorf("a check from before the alarm reports reach %v, down %q", st.Reach, st.TunnelsDown)
	}
}
