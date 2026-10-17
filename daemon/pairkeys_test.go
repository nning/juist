package daemon

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/keyring"
	"github.com/nning/juist/internal/pairkey"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// inTunnel runs a member on a network stack of its own, so its log sync runs
// through the tunnels alone, as on a device.
// Tests on it stay serial: under CPU contention a pair's exchange can stall
// past their deadlines.
func inTunnel(o *Options) { o.Netstack = true }

// pskOf is what n gave its peer id last, and what it is.
func (n *meshNode) pskOf(id types.Identity) pskGiven {
	n.d.mu.Lock()
	defer n.d.mu.Unlock()
	return n.d.psks[id]
}

// paired reports whether every two members hold one pair key between them.
func (m *mesh) paired() bool {
	for _, a := range m.nodes {
		for _, b := range m.nodes {
			if a == b {
				continue
			}
			ga, gb := a.pskOf(b.id()), b.pskOf(a.id())
			if ga.stage != pairkey.StagePair || ga.key != gb.key {
				return false
			}
		}
	}
	return true
}

// describePairs says where every pair stands, from each end.
func (m *mesh) describePairs() string {
	var b strings.Builder
	for i, from := range m.nodes {
		for j, to := range m.nodes {
			if i == j {
				continue
			}
			g := from.pskOf(to.id())
			state := "no exchange"
			if env, ok := from.d.pairEnvFor(to.id()); ok {
				from.d.readPairs(func(s *pairkey.Store) { state = s.Describe(env) })
			}
			fmt.Fprintf(&b, "\nn%d to n%d: gives the %v %x, %s", i, j, g.stage, g.key[:4], state)
		}
	}
	return b.String()
}

// waitForPairs is waitFor, saying where every pair stands if it times out.
func (m *mesh) waitForPairs(t *testing.T, d time.Duration, what string, cond func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for !cond() {
		if time.Since(start) > d {
			t.Fatalf("timed out after %v waiting for %s:%s", d, what, m.describePairs())
		}
		time.Sleep(20 * time.Millisecond)
	}
	return time.Since(start)
}

// pairKeys is the key each member gives each other one, by their indices.
func (m *mesh) pairKeys() map[[2]int]pairkey.Key {
	out := map[[2]int]pairkey.Key{}
	for i, from := range m.nodes {
		for j, to := range m.nodes {
			if i != j {
				out[[2]int{i, j}] = from.pskOf(to.id()).key
			}
		}
	}
	return out
}

// movedOn reports whether every pair holds a pair key, none of them one of
// before.
func (m *mesh) movedOn(before map[[2]int]pairkey.Key) func() bool {
	return func() bool {
		if !m.paired() {
			return false
		}
		for k, key := range m.pairKeys() {
			if key == before[k] {
				return false
			}
		}
		return true
	}
}

// A mesh whose log sync runs through the tunnels moves every pair from the
// group key to a key of its own, which both hold, and the tunnels carry
// traffic throughout.
func TestTunnelsMoveToPairKeys(t *testing.T) {
	m := startMeshWith(t, 3, inTunnel)
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	took := m.waitForPairs(t, 30*time.Second, "every pair to hold a pair key", m.paired)
	t.Logf("pair keys in %v", took)
	if !pingUntil(m.nodes[0], m.nodes[2].overlayV4(), 20*time.Second) {
		t.Fatal("no overlay reachability on pair keys")
	}
}

// Exit criterion (2) of M15, in part: an epoch bump moves every pair to a new
// pair key, both alike, while the tunnels keep carrying traffic.
func TestAnEpochBumpMovesThePairKeys(t *testing.T) {
	m := startMeshWith(t, 3, inTunnel)
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	m.waitForPairs(t, 30*time.Second, "every pair to hold a pair key", m.paired)
	a, b := m.nodes[0], m.nodes[1]
	before := m.pairKeys()

	var lost atomic.Int32
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
			}
			if !ping(a, b.overlayV4(), 2*time.Second) {
				lost.Add(1)
			}
		}
	})
	m.apply(t, a, func(b *log.Builder) (types.AUM, error) { return b.EpochBump(m.nw.sealer()) })
	took := m.waitForPairs(t, 30*time.Second, "every pair to move to a new pair key", m.movedOn(before))
	t.Logf("moved in %v", took)
	close(stop)
	wg.Wait()
	if n := lost.Load(); n > 0 {
		t.Errorf("%d pings lost across the epoch bump", n)
	}
}

// A stoppable clock passes with the real one, ahead by what it was advanced,
// and stands still while stopped.
type stoppable struct {
	mu      sync.Mutex
	offset  time.Duration
	stopped time.Time
}

func (c *stoppable) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped.IsZero() {
		return c.stopped
	}
	return time.Now().Add(c.offset)
}

func (c *stoppable) stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopped = time.Now().Add(c.offset)
}

func (c *stoppable) resume() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopped = time.Time{}
}

func (c *stoppable) advance(by time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset += by
}

// A follower that puts an offer off, because it answered one within
// [pairkey.Pace], reaches the leader for it once the pace has passed: no
// anti-entropy round is needed to move the pair on.
func TestAnOfferPutOffByThePaceIsAnsweredOnceItPasses(t *testing.T) {
	m := &mesh{t: t, nw: newNetworkWithAdminDevices(t, 2, 0), hub: &lanHub{}}
	clocks := []*stoppable{{}, {}}
	for i, c := range clocks {
		auth, st := m.nw.authorityFor(t)
		m.nodes = append(m.nodes, m.startOn(t, i, m.nw.devices[i], auth, st, func(o *Options) {
			inTunnel(o)
			o.Clock = c.now
			o.SyncInterval = time.Hour
		}))
	}
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	m.waitForPairs(t, 30*time.Second, "the two to hold a pair key", m.paired)
	leader, follower := 0, 1
	if !pairkey.Leads(m.nw.devices[0].record.WireGuard, m.nw.devices[1].record.WireGuard) {
		leader, follower = 1, 0
	}
	// The follower stays within the pace of its answer, the leader is past
	// its own, so it offers at once.
	clocks[follower].stop()
	clocks[leader].advance(pairkey.Pace)
	before := m.pairKeys()
	m.apply(t, m.nodes[0], func(b *log.Builder) (types.AUM, error) { return b.EpochBump(m.nw.sealer()) })
	f, l := m.nodes[follower], m.nodes[leader]
	m.waitForPairs(t, 30*time.Second, "the follower to put the leader's offer off", func() bool {
		env, ok := f.d.pairEnvFor(l.id())
		if !ok {
			return false
		}
		var state string
		f.d.readPairs(func(s *pairkey.Store) { state = s.Describe(env) })
		return strings.Contains(state, "an offer put off")
	})
	clocks[follower].resume()
	took := m.waitForPairs(t, 15*time.Second, "the pair to move to a new pair key", m.movedOn(before))
	t.Logf("moved in %v once the pace passed", took)
}

// Exit criterion (2) of M15, the rest: a member whose log sync runs through
// the tunnels alone, suspended across more epoch bumps than a keyring holds
// and a rotation of the other device's identity, reaches it again on the key
// the two had, catches up, and moves on to a new pair key.
func TestASleeperReachesThePeerItPairedWith(t *testing.T) {
	m := &mesh{t: t, nw: newNetworkWithAdminDevices(t, 2, 0), hub: &lanHub{}, mutate: inTunnel}
	kept := []*persisted{keep(t, m.nw), keep(t, m.nw)}
	for _, p := range kept {
		var err error
		if p.session, err = NewSession(); err != nil {
			t.Fatal(err)
		}
		p.udp = freeUDPPort(t)
	}
	clock := &passing{}
	admin := m.startKept(t, 0, m.nw.devices[0], kept[0], clock)
	sleeper := m.startKept(t, 1, m.nw.devices[1], kept[1], clock)
	m.nodes = []*meshNode{admin, sleeper}
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	waitFor(t, 30*time.Second, "the two to hold a pair key", m.paired)
	before := sleeper.d.Status().Epoch
	paired := sleeper.pskOf(admin.id()).key
	sleeper.halt()
	clock.advance(time.Hour)

	bump := func(b *log.Builder) (types.AUM, error) { return b.EpochBump(m.nw.sealer()) }
	m.apply(t, admin, bump)
	rotated := *m.nw.devices[0]
	fresh, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rotated.identity, rotated.record.Identity = fresh, fresh.Public()
	m.apply(t, admin, func(b *log.Builder) (types.AUM, error) {
		return b.RotateIdentity(m.nw.devices[0].record.Identity, fresh.Public(), fresh.SigningKey(), m.nw.sealer())
	}, m.nw.devices[0].identity, fresh)
	admin.halt()
	admin = m.startKept(t, 0, &rotated, kept[0], clock)
	for range keyring.Depth {
		m.apply(t, admin, bump)
	}
	head := admin.d.Status()
	if head.Epoch-before <= keyring.Depth {
		t.Fatalf("the network moved %d epochs, not past the keyring's %d", head.Epoch-before, keyring.Depth)
	}
	if g := admin.pskOf(sleeper.id()); g.key != paired {
		t.Fatalf("the rotated device gives the sleeper the %v, not the pair key the two had", g.stage)
	}

	clock.advance(time.Hour)
	sleeper = m.startKept(t, 1, m.nw.devices[1], kept[1], clock)
	m.nodes = []*meshNode{admin, sleeper}
	took := waitFor(t, 60*time.Second, "the sleeper to catch up through the tunnel", func() bool {
		st := sleeper.d.Status()
		return st.Head == head.Head && st.Epoch == head.Epoch && !st.Stale
	})
	t.Logf("caught up across %d epoch bumps in %v", head.Epoch-before, took)
	waitFor(t, 30*time.Second, "a new pair key", func() bool {
		return m.paired() && sleeper.pskOf(admin.id()).key != paired
	})
	if !pingUntil(sleeper, admin.overlayV4(), 20*time.Second) {
		t.Fatal("the member that caught up does not reach the other over the overlay")
	}
}

// A blockingManager is a data plane whose handshakes, while block is set,
// never complete: no probe is answered and no handshake is recorded. It
// keeps every preshared key it is given.
type blockingManager struct {
	conn.Manager
	block atomic.Bool
	mu    sync.Mutex
	given [][32]byte
}

func (b *blockingManager) SetPeers(peers []conn.Peer) error {
	b.mu.Lock()
	for _, p := range peers {
		b.given = append(b.given, p.PSK)
	}
	b.mu.Unlock()
	return b.Manager.SetPeers(peers)
}

func (b *blockingManager) Probe(ip netip.Addr, timeout time.Duration, cb func(bool)) {
	if b.block.Load() {
		cb(false)
		return
	}
	b.Manager.Probe(ip, timeout, cb)
}

func (b *blockingManager) Tunnels() map[uint64]conn.Tunnel {
	if b.block.Load() {
		return nil
	}
	return b.Manager.Tunnels()
}

// Exit criterion (3) of M15: with handshakes blocked across an exchange and
// an epoch bump, and the checks finding the peer down again and again, no
// member that announces preshared keys is ever given none for its peer.
func TestBlockedHandshakesNeverLeaveAPairWithoutAKey(t *testing.T) {
	var mgrs []*blockingManager
	var mu sync.Mutex
	m := startMeshWith(t, 2, func(o *Options) {
		inner := o.Connect
		o.Connect = func(co conn.Options) (conn.Manager, error) {
			mgr, err := inner(co)
			if err != nil {
				return nil, err
			}
			b := &blockingManager{Manager: mgr}
			mu.Lock()
			mgrs = append(mgrs, b)
			mu.Unlock()
			return b, nil
		}
	})
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	waitFor(t, 30*time.Second, "the two to hold a pair key", m.paired)
	for _, b := range mgrs {
		b.block.Store(true)
	}
	a, b := m.nodes[0], m.nodes[1]
	m.apply(t, a, func(b *log.Builder) (types.AUM, error) { return b.EpochBump(m.nw.sealer()) })
	for range 6 {
		for _, n := range m.nodes {
			n.d.Tunnels(time.Millisecond)
			if err := n.d.Reconcile(); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	for _, mgr := range mgrs {
		mgr.mu.Lock()
		for _, k := range mgr.given {
			if k == ([32]byte{}) {
				t.Fatal("a member was given no preshared key for a peer announcing them")
			}
		}
		mgr.mu.Unlock()
	}
	for _, b := range mgrs {
		b.block.Store(false)
	}
	waitFor(t, 30*time.Second, "the pair to agree again", func() bool { return m.paired() })
	if !pingUntil(a, b.overlayV4(), 20*time.Second) {
		t.Fatal("no overlay reachability after the block")
	}
}

// A change to the preshared keys that cannot be kept is undone before any
// peer is told of it: a restart must not leave this device on a key the
// peer moved past.
func TestAPairChangeNotKeptIsUndone(t *testing.T) {
	// A file where the directory should be fails every write, root's too.
	dir := filepath.Join(t.TempDir(), "home")
	if err := os.WriteFile(dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pairs.secret")
	f := newReconcileFixtureWith(t, 6, func(o *Options) { o.PairsPath = path })
	self := f.self.record.WireGuard
	var led *device
	for _, dev := range f.nw.devices[1:] {
		f.learn(t, dev, 7001)
		if led == nil && pairkey.Leads(self, dev.record.WireGuard) {
			led = dev
		}
	}
	if led == nil {
		t.Skip("this device leads no pair in this draw")
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if m := f.d.pairMsg(led.record.Identity); m == nil {
		t.Fatal("no message for the peer")
	} else if m.CT != nil {
		t.Fatalf("generation %d, which could not be kept, is offered", m.Gen)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if m := f.d.pairMsg(led.record.Identity); m == nil || m.CT == nil {
		t.Fatal("no offer once it can be kept")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

// A device removed starts a store of its own, so should it come back under
// the same keys, no member holds a pair it gave up.
func TestARemovedDeviceGivesItsPairsUp(t *testing.T) {
	f := newReconcileFixture(t, 2)
	f.learn(t, f.nw.devices[1], 7001)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	before := f.d.pairs.ID()
	if len(f.d.pairs.Generations()) != 1 {
		t.Fatal("no pair with the member")
	}
	if err := f.d.Inform([]types.AUM{f.nw.removeNode(t, f.auth, f.self.record.Identity)}); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if f.d.pairs.ID() == before || len(f.d.pairs.Generations()) != 0 {
		t.Error("a removed device keeps its pairs")
	}
}

// A device names its epoch from its first announcement on, before its first
// reconcile: one naming none has its peers drop the keys they give it.
func TestTheFirstAnnouncementNamesTheEpoch(t *testing.T) {
	f := newReconcileFixture(t, 2)
	f.d.backfillEpochs()
	e, ok := f.d.announcement()
	if !ok || e.Epoch == 0 || e.PairStore != f.d.pairs.ID() {
		t.Fatalf("the first announcement names epoch %d, store %d", e.Epoch, e.PairStore)
	}
}

// forgedHint is dev's announcement e as a quantum computer forges it, signed
// by Ed25519 alone, numbered ahead by ahead seconds and naming a later epoch
// and another pair store.
func forgedHint(t *testing.T, dev *device, e gossip.Endpoint, ahead uint64) gossip.Endpoint {
	t.Helper()
	h := e.Hint()
	h.Seq, h.Epoch, h.PairStore = e.Seq+ahead, e.Epoch+1, e.PairStore+1
	if err := h.Sign(dev.identity); err != nil {
		t.Fatal(err)
	}
	return h
}

// From its start, before its first reconcile, a device holds what gossip and
// discovery hand it to the signing keys its log names: an announcement signed
// by Ed25519 alone is a hint.
func TestAnnouncementsAreHeldToTheSigningKeysFromTheStart(t *testing.T) {
	f := newReconcileFixture(t, 2)
	dev := f.nw.devices[1]
	e, err := endpointFor(dev, 7001)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.d.Learn(forgedHint(t, dev, e, 1)); err != nil {
		t.Fatal(err)
	}
	if !f.d.endpoints.IsHint(dev.record.Identity) {
		t.Fatal("before the first reconcile an announcement signed by Ed25519 alone was held as full")
	}
}

// A forged hint newer than a member's announcement, naming a later epoch and
// another pair store, costs the pair nothing: both keep the pair key they
// hold, and the tunnel carries traffic on it.
func TestAForgedHintLeavesThePairKey(t *testing.T) {
	m := startMeshWith(t, 2, inTunnel)
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	m.waitForPairs(t, 30*time.Second, "the pair to hold a pair key", m.paired)
	a, b := m.nodes[0], m.nodes[1]
	before := a.pskOf(b.id())
	own, _ := b.d.Announcement()
	if err := a.d.Learn(forgedHint(t, b.dev, own, 300)); err != nil {
		t.Fatal(err)
	}
	if err := a.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := a.pskOf(b.id()); got != before || !m.paired() {
		t.Fatalf("after a forged hint the peer is given the %v %x, was the %v %x:%s",
			got.stage, got.key[:4], before.stage, before.key[:4], m.describePairs())
	}
	if !pingUntil(a, b.overlayV4(), 20*time.Second) {
		t.Fatal("no overlay reachability after a forged hint")
	}
}

// Where a hint alone is held for a member, as forged, no exchange with it
// moves and the pair held stays bound to the store its announcement named.
func TestAHintAloneMovesNoPair(t *testing.T) {
	f := newReconcileFixture(t, 2)
	dev := f.nw.devices[1]
	e := f.learn(t, dev, 7001)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	env, ok := f.d.pairEnvFor(dev.record.Identity)
	if !ok {
		t.Fatal("no pair with the member")
	}
	bound := func() bool {
		var said string
		f.d.readPairs(func(s *pairkey.Store) { said = s.Describe(env) })
		return said != "no exchange"
	}
	if !bound() {
		t.Fatal("the pair is not bound to the member's store")
	}

	f.d.endpoints.Forget(dev.record.Identity)
	if err := f.d.Learn(forgedHint(t, dev, e, 1)); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if !bound() {
		t.Fatal("a hint alone bound the pair to the store it names")
	}
	if _, ok := f.d.pairEnvFor(dev.record.Identity); ok {
		t.Fatal("an exchange moves against a hint alone")
	}
}

// A hint alone, as forged, picks nothing of its member's preshared key: naming
// no epoch leaves the member keyed, and naming another store or epoch leaves
// the pair's.
func TestAHintAlonePicksNoPresharedKey(t *testing.T) {
	f := newReconcileFixture(t, 2)
	dev := f.nw.devices[1]
	id := dev.record.Identity
	e := f.learn(t, dev, 7001)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	keyed := f.installed(t, 1).PSK
	if keyed == [32]byte{} {
		t.Fatal("the member is given no preshared key")
	}
	f.d.endpoints.Forget(id)
	for i, forged := range []struct{ epoch, store uint64 }{{0, 0}, {e.Epoch + 1, e.PairStore + 1}} {
		f.learnHint(t, dev, e, func(h *gossip.Endpoint) {
			h.Seq, h.Epoch, h.PairStore = e.Seq+uint64(i)+1, forged.epoch, forged.store
		})
		if err := f.d.Reconcile(); err != nil {
			t.Fatal(err)
		}
		if got := f.installed(t, 1).PSK; got != keyed {
			t.Fatalf("a hint naming epoch %d, store %d changed the preshared key", forged.epoch, forged.store)
		}
		n, _ := f.auth.State().Node(id)
		env, ok := f.d.pairEnvOf(f.auth.State(), &n)
		if !ok || env.PeerStore != e.PairStore || env.Epoch != e.Epoch {
			t.Fatalf("a hint naming epoch %d, store %d is paired as %+v", forged.epoch, forged.store, env)
		}
	}
}
