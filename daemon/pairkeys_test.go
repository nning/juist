package daemon

import (
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/keyring"
	"github.com/nning/juist/internal/pairkey"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// inTunnel runs a member on a network stack of its own, so its log sync runs
// through the tunnels alone, as on a device.
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

// A mesh whose log sync runs through the tunnels moves every pair from the
// group key to a key of its own, which both hold, and the tunnels carry
// traffic throughout.
func TestTunnelsMoveToPairKeys(t *testing.T) {
	m := startMeshWith(t, 3, inTunnel)
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	took := waitFor(t, 30*time.Second, "every pair to hold a pair key", m.paired)
	t.Logf("pair keys in %v", took)
	// The status follows at the end of the reconcile that gave the keys.
	waitFor(t, 5*time.Second, "every member to report two pair keys", func() bool {
		for _, n := range m.nodes {
			if pq := n.d.Status().PQ; pq == nil || pq.Pair != 2 || pq.Group != 0 || len(pq.None)+len(pq.NoKey) != 0 {
				return false
			}
		}
		return true
	})
	if !pingUntil(m.nodes[0], m.nodes[2].overlayV4(), 20*time.Second) {
		t.Fatal("no overlay reachability on pair keys")
	}
}

// Exit criterion (2) of M15, in part: an epoch bump moves every pair to a new
// pair key, both alike, while the tunnels keep carrying traffic.
func TestAnEpochBumpMovesThePairKeys(t *testing.T) {
	m := startMeshWith(t, 3, inTunnel)
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	waitFor(t, 30*time.Second, "every pair to hold a pair key", m.paired)
	a, b := m.nodes[0], m.nodes[1]
	before := a.pskOf(b.id()).key

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
	waitFor(t, 30*time.Second, "every pair to move to a new pair key", func() bool {
		return m.paired() && a.pskOf(b.id()).key != before
	})
	close(stop)
	wg.Wait()
	if n := lost.Load(); n > 0 {
		t.Errorf("%d pings lost across the epoch bump", n)
	}
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
		return b.RotateIdentity(m.nw.devices[0].record.Identity, fresh.Public(), m.nw.sealer())
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
