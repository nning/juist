package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/nning/juist/ipc"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/types"
)

// A peer that answers its probe is live, and so is one with a handshake just
// now; one whose probes go unanswered twice in a row is down, though its last
// handshake is only a minute old — as a peer that restarted leaves it. One
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
	f.d.probeMu.Lock()
	f.d.probeMisses = nil // as after an answer on a probed check
	f.d.probeMu.Unlock()
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
	if err := e.Sign(dev.identity); err != nil {
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

// A device never seen renewing its announcement may be on a build that does
// not: gone quiet, it is not called offline for want of a renewal.
func TestADeviceThatNeverRenewsIsNotCalledOffline(t *testing.T) {
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
	if st := f.d.Status(); len(st.Absent) != 0 || !slices.Equal(st.Seeking, []string{peer.record.Name}) {
		t.Fatalf("a device never seen renewing reads as absent %v, seeking %v", st.Absent, st.Seeking)
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
	if err := newer.Sign(peer.identity); err != nil {
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
	startedOn(f.s, netip.MustParsePrefix("198.18.9.9/32"))
	f.s.followAddrs()
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
		t.Error("a mesh restarted on new keys kept the old NAT-traversal key")
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
	startedOn(f.s, netip.MustParsePrefix("198.18.9.9/32"))
	f.s.followAddrs()
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
	if err := e.Sign(peer.identity); err != nil {
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
	f.d.ownRegion, f.d.down = false, nil
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
		if err := e.Sign(dev.identity); err != nil {
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
	if err := e.Sign(dev.identity); err != nil {
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
