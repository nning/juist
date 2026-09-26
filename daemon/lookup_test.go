package daemon

import (
	"slices"
	"testing"
	"time"

	"github.com/nning/juist/discovery/dht"
	"github.com/nning/juist/types"
)

// A member never heard from does not starve a down one of its lookups, and
// the down one's schedule moves on, so checks do not kick a round each.
func TestAnUnheardMemberDoesNotStarveADownOne(t *testing.T) {
	c := &clock{now: time.Unix(1_700_000_000, 0)}
	f := newReconcileFixtureWith(t, 3, func(o *Options) { o.Clock = c.get })
	peer := f.nw.devices[1]
	f.learn(t, peer, 4001) // devices[2] is never heard of
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	looked, due := 0, 0
	for range 6 {
		f.d.refreshReach(t.Context())
		f.d.mu.Lock()
		if p := f.d.down[peer.record.Identity]; p != nil && !c.get().Before(p.lookAt) {
			due++
		}
		f.d.mu.Unlock()
		if slices.Contains(f.d.wanted(), peer.record.Identity) {
			looked++
		}
		c.set(c.get().Add(reachEvery))
	}
	if looked == 0 || due == 6 {
		t.Fatalf("the down peer was looked up %d times, and a lookup was due at %d of 6 checks", looked, due)
	}
}

// A round looks up only so many members, and only those are rescheduled: the
// rest are next.
func TestAMemberLeftOutOfARoundKeepsItsTurn(t *testing.T) {
	c := &clock{now: time.Unix(1_700_000_000, 0)}
	f := newReconcileFixtureWith(t, 8, func(o *Options) { o.Clock = c.get })
	for i, dev := range f.nw.devices[1:] {
		f.learn(t, dev, uint16(4001+i))
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.refreshReach(t.Context())
	first, second := f.d.wanted(), f.d.wanted()
	if len(first) != dht.MaxLookupsPerRound || len(second) != 7-dht.MaxLookupsPerRound {
		t.Fatalf("rounds look up %d and then %d of 7 down members", len(first), len(second))
	}
	for _, id := range second {
		if slices.Contains(first, id) {
			t.Fatalf("%v was looked up twice while others waited", id.ShortString())
		}
	}
}

// Lookups keep their schedule though checks come only every half minute and
// a round a moment after the check that finds one due.
func TestLookupsKeepTheirSchedule(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	c := &clock{now: t0}
	f := newReconcileFixtureWith(t, 2, func(o *Options) { o.Clock = c.get })
	peer := f.nw.devices[1]
	f.learn(t, peer, 4001)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	var at []time.Duration
	for tick := time.Duration(0); tick <= 4*time.Minute; tick += reachEvery {
		c.set(t0.Add(tick))
		f.d.refreshReach(t.Context())
		// A round runs only where the check found a lookup due, a moment on.
		f.d.mu.Lock()
		due := !c.get().Before(f.d.down[peer.record.Identity].lookAt)
		f.d.mu.Unlock()
		if !due {
			continue
		}
		c.set(c.get().Add(time.Second))
		if slices.Contains(f.d.wanted(), peer.record.Identity) {
			at = append(at, tick)
		}
	}
	if want := []time.Duration{0, 30 * time.Second, 90 * time.Second, 210 * time.Second}; !slices.Equal(at, want) {
		t.Fatalf("looked up at %v, want %v", at, want)
	}
}

// Why a peer is down: blocked on the way where it has signed or changed its
// announcement since, offline where no sign of that came in time, or when its
// home relay here finds it gone; undecided until then.
func TestWhyAPeerIsDown(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	at := func(d time.Duration) time.Time { return t0.Add(d) }
	settle := 10 * time.Minute
	for _, tc := range []struct {
		name   string
		p      downPeer
		now    time.Time
		signed time.Time
		gone   bool
		want   downState
	}{
		{"just down", downPeer{since: t0}, at(time.Second), at(-time.Minute), false, stateSeeking},
		{"signed since", downPeer{since: t0}, at(4 * time.Minute), at(3 * time.Minute), false, stateBlocked},
		{"signed just before, by a clock ahead", downPeer{since: t0}, at(settle), at(90 * time.Second), false, stateAbsent},
		{"said something new", downPeer{since: t0, renewed: true}, at(time.Second), at(-time.Hour), false, stateBlocked},
		{"quiet past the window", downPeer{since: t0}, at(settle), at(-time.Minute), false, stateAbsent},
		{"its relay here finds it gone", downPeer{since: t0}, at(firstLookupGap), at(-time.Minute), true, stateAbsent},
		{"its relay here, a moment on", downPeer{since: t0}, at(time.Second), at(-time.Minute), true, stateSeeking},
	} {
		if got := tc.p.state(tc.now, tc.signed, settle, tc.gone); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

var _ = types.Identity{}
