package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/discovery/dht"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/relay"
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

// A stale node keeps no tunnel to a plain member, so it never finds it down;
// it looks it up anyway, or a relay that restarted stays pinned to its old
// certificate until the node is fresh again.
func TestAStaleNodeLooksUpTheMembersItKeepsNoTunnelTo(t *testing.T) {
	f := newFreshFixture(t, "")
	plain := f.nw.devices[2].record.Identity
	f.reconcileAt(t, f.start.Add(time.Minute))
	if !f.d.Status().Stale || f.mgr.has([32]byte(f.nw.devices[2].record.WireGuard)) {
		t.Fatal("the fixture is not a stale node without a tunnel to the plain member")
	}
	if !slices.Contains(f.d.wanted(), plain) {
		t.Fatal("a stale node does not look up a member it keeps no tunnel to")
	}
	if slices.Contains(f.d.wanted(), plain) {
		t.Fatal("the member was looked up again in the next round")
	}
	f.clock.Set(f.start.Add(time.Minute + firstLookupGap))
	if !slices.Contains(f.d.wanted(), plain) {
		t.Fatal("the member was not looked up again after the first gap")
	}
}

// A fresh node looks up only members it holds no announcement for or finds
// down: one it carries a tunnel to is not asked after every round.
func TestAFreshNodeDoesNotLookUpItsLivePeers(t *testing.T) {
	f := newFreshFixture(t, "")
	f.d.offerLeases([][]byte{f.leaseFrom(t, 1, f.auth.Head(), f.start)})
	f.reconcileAt(t, f.start.Add(time.Minute))
	if f.d.Status().Stale {
		t.Fatal("the fixture is not fresh")
	}
	if got := f.d.wanted(); len(got) != 0 {
		t.Fatalf("a fresh node with every announcement held looks up %d members", len(got))
	}
}

// A member set aside waits behind every member found down, such as the
// vouchers a stale node needs back, though it was due first.
func TestAStaleNodeLooksUpTheDownBeforeTheSetAside(t *testing.T) {
	f := newFreshFixture(t, "")
	plain := f.nw.devices[2].record.Identity
	f.reconcileAt(t, f.start.Add(time.Minute))
	if !f.d.Status().Stale {
		t.Fatal("the fixture is not stale")
	}
	f.d.mu.Lock()
	f.d.asidePlan = map[types.Identity]*lookupPlan{plain: {lookAt: f.start}}
	if f.d.down == nil {
		f.d.down = map[types.Identity]*downPeer{}
	}
	var down []types.Identity
	for i := range dht.MaxLookupsPerRound {
		id := types.Identity{0xd0, byte(i)}
		f.d.down[id] = &downPeer{lookupPlan: lookupPlan{lookAt: f.start.Add(time.Minute)}}
		down = append(down, id)
	}
	f.d.mu.Unlock()
	got := f.d.wanted()
	slices.SortFunc(got, types.Identity.Compare)
	if !slices.Equal(got, down) {
		t.Fatalf("looked up %v, want the members found down %v", got, down)
	}
}

// One device of those that reach one another asks the DHT, the lowest
// identity among them, and so does one that reaches none or is stale.
func TestOneDeviceOfAGroupSeeksInTheDHT(t *testing.T) {
	f := newReconcileFixture(t, 1)
	var lower, higher types.Identity
	higher[0] = 0xff
	if lower.Compare(f.d.self) >= 0 || higher.Compare(f.d.self) <= 0 {
		t.Fatal("the identities do not lie either side of this device's")
	}
	for _, c := range []struct {
		name  string
		live  map[types.Identity]bool
		stale bool
		want  bool
	}{
		{"reaching none", map[types.Identity]bool{lower: false, higher: false}, false, true},
		{"reaching a higher one", map[types.Identity]bool{higher: true}, false, true},
		{"reaching a lower one", map[types.Identity]bool{lower: true, higher: true}, false, false},
		{"stale, reaching a lower one", map[types.Identity]bool{lower: true}, true, true},
	} {
		f.d.reachable.Store(&c.live)
		f.d.setStatus(func(s *ipc.Status) { s.Stale = c.stale })
		if got := f.d.seeksInDHT(); got != c.want {
			t.Errorf("%s: seeks %v, want %v", c.name, got, c.want)
		}
	}
}

// A member relay is asked first, at the address and by the certificate its
// announcement pins, and what it holds counts only where it is newer.
func TestAMemberRelayIsAskedBeforeTheDHT(t *testing.T) {
	f := newReconcileFixture(t, 3)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	sought := f.nw.devices[2]
	epoch, secret, ok := f.d.keyring.Latest()
	if !ok {
		t.Fatal("no epoch secret")
	}
	key := dht.RendezvousKey(secret.TopicSeed(epoch, dht.Window(f.d.now()), sought.record.Identity))
	e, err := endpointFor(sought, 4002)
	if err != nil {
		t.Fatal(err)
	}
	e.Seq = 7
	if err := e.SignPQ(sought.identity); err != nil {
		t.Fatal(err)
	}
	sealed, err := dht.SealAnnouncement(secret, epoch, e)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != relay.RendezvousPath+hex.EncodeToString(key[:]) {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(sealed)
	}))
	defer srv.Close()
	at := netip.MustParseAddrPort(srv.Listener.Addr().String())
	pin := sha256.Sum256(srv.Certificate().Raw)
	set := func(cert [32]byte) {
		f.d.mu.Lock()
		own := relayRegion(f.d.status.Network, f.d.self)
		f.d.relays = []conn.Relay{{Region: own + 1, HostName: "r.relay.juist.invalid", Addrs: []netip.AddrPort{at}, CertHash: cert}}
		f.d.mu.Unlock()
	}

	set([32]byte{1})
	if f.d.askRelays(t.Context(), sought.record.Identity) {
		t.Error("took an answer from a relay whose certificate is not the one pinned")
	}
	set(pin)
	if !f.d.askRelays(t.Context(), sought.record.Identity) {
		t.Fatal("the relay's answer was not taken")
	}
	if got, ok := f.d.endpoints.Get(sought.record.Identity); !ok || got.Seq != 7 {
		t.Fatalf("holds %+v", got)
	}
	if f.d.askRelays(t.Context(), sought.record.Identity) {
		t.Error("an answer no newer than the one held counts as found")
	}
}

// A device that rests takes part in the public DHT only once checked and
// while no member that does not rest answers it.
func TestARestingDeviceJoinsTheDHTAloneOnly(t *testing.T) {
	f := newReconcileFixture(t, 3)
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
	if f.d.joinsDHT() {
		t.Error("joined before the first check")
	}
	r, a := resting.record.Identity, awake.record.Identity
	for _, c := range []struct {
		name string
		live map[types.Identity]bool
		want bool
	}{
		{"reaching none", map[types.Identity]bool{r: false, a: false}, true},
		{"reaching one that rests", map[types.Identity]bool{r: true, a: false}, true},
		{"reaching one awake", map[types.Identity]bool{r: false, a: true}, false},
	} {
		f.d.reachable.Store(&c.live)
		if got := f.d.joinsDHT(); got != c.want {
			t.Errorf("%s: joins %v, want %v", c.name, got, c.want)
		}
	}
}
