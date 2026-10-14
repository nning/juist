package daemon

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/internal/keyring"
	"github.com/nning/juist/internal/statedir"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// freePort returns a TCP port nothing listens on, so a member restarted on it
// is where its peers' cached announcements say.
func freePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// freeUDPPort returns a UDP port nothing listens on.
func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

// persisted is what a restart keeps: the log, the gossip port, the endpoint
// cache, the epoch secrets and the preshared keys.
type persisted struct {
	auth  *log.Authority
	st    log.Storage
	port  uint16
	cache string
	home  string

	// session and udp, where set, are kept across restarts too, as by a
	// process that was suspended rather than restarted: its NAT-traversal
	// key and its data plane's port.
	session *Session
	udp     uint16
}

func keep(t *testing.T, nw *network) *persisted {
	t.Helper()
	auth, st := nw.authorityFor(t)
	home := t.TempDir()
	return &persisted{auth: auth, st: st, port: freePort(t),
		cache: filepath.Join(home, statedir.EndpointCacheFile), home: home}
}

// passing is a clock the whole mesh shares, which a test moves on while a
// member sleeps.
type passing struct{ offset atomic.Int64 }

func (c *passing) now() time.Time           { return time.Now().Add(time.Duration(c.offset.Load())) }
func (c *passing) advance(by time.Duration) { c.offset.Add(int64(by)) }

func (m *mesh) startKept(t *testing.T, i int, dev *device, p *persisted, clock *passing) *meshNode {
	t.Helper()
	return m.startOn(t, i, dev, p.auth, p.st, func(o *Options) {
		o.GossipPort = p.port
		o.EndpointCachePath = p.cache
		o.KeyringPath = statedir.KeyringPath(p.home)
		o.PairsPath = statedir.PairsPath(p.home)
		o.Session = p.session
		o.ListenPort = p.udp
		o.Clock = clock.now
		// A first round that misses is retried well inside a test's wait.
		o.SyncInterval = 3 * time.Second
		if m.mutate != nil {
			m.mutate(o)
		}
	})
}

func (n *meshNode) halt() {
	n.stop()
	n.d.Close()
}

// apply signs and applies one change on a running admin's daemon.
func (m *mesh) apply(t *testing.T, on *meshNode, build func(*log.Builder) (types.AUM, error), extra ...types.PrivateIdentity) {
	t.Helper()
	on.d.authMu.Lock()
	rec, err := build(on.auth.Builder())
	on.d.authMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range append(extra, m.nw.admin) {
		if err := rec.Sign(k); err != nil {
			t.Fatal(err)
		}
	}
	if err := on.d.Inform([]types.AUM{rec}); err != nil {
		t.Fatalf("applying a %v: %v", rec.Kind, err)
	}
}

// TestAMemberThatSleptThroughManyChangesCatchesUp is the first exit criterion
// of coming back after many changes: a member offline across more epoch bumps
// than any keyring holds, one of them a rotation of the admin device's
// identity, syncs again from that one reachable member, without an invite,
// and is fresh as soon as the voucher's lease arrives.
func TestAMemberThatSleptThroughManyChangesCatchesUp(t *testing.T) {
	m := &mesh{t: t, nw: newNetworkWithAdminDevices(t, 2, 0), hub: &lanHub{}}
	kept := []*persisted{keep(t, m.nw), keep(t, m.nw)}
	clock := &passing{}
	admin := m.startKept(t, 0, m.nw.devices[0], kept[0], clock)
	sleeper := m.startKept(t, 1, m.nw.devices[1], kept[1], clock)
	m.nodes = []*meshNode{admin, sleeper}
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	waitFor(t, 10*time.Second, "the sleeper to be vouched for and to cache the admin device's address", func() bool {
		b, err := os.ReadFile(kept[1].cache)
		return !sleeper.d.Status().Stale && err == nil && len(b) > 0
	})
	before := sleeper.d.Status().Epoch
	sleeper.halt()
	clock.advance(time.Hour)

	bump := func(b *log.Builder) (types.AUM, error) { return b.EpochBump(m.nw.sealer()) }
	m.apply(t, admin, bump)
	m.apply(t, admin, bump)

	// The admin device takes a new identity, and comes back under it.
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
	m.apply(t, admin, bump)
	m.apply(t, admin, bump)
	head := admin.d.Status()
	if head.Epoch-before <= keyring.Depth {
		t.Fatalf("the network moved %d epochs, not past the keyring's %d", head.Epoch-before, keyring.Depth)
	}

	clock.advance(time.Hour)
	sleeper = m.startKept(t, 1, m.nw.devices[1], kept[1], clock)
	m.nodes = []*meshNode{admin, sleeper}
	took := waitFor(t, 30*time.Second, "the sleeper to catch up and be vouched for", func() bool {
		st := sleeper.d.Status()
		return st.Head == head.Head && st.Epoch == head.Epoch && !st.Stale && !st.Refused
	})
	t.Logf("caught up across %d epoch bumps in %v", head.Epoch-before, took)
	waitFor(t, 30*time.Second, "the two to hold each other as peers again", m.converged)
	if !pingUntil(sleeper, admin.overlayV4(), 20*time.Second) {
		t.Fatal("the member that caught up does not reach the admin device over the overlay")
	}
}

// TestARemovedDeviceIsRefusedACatchUp is the second exit criterion: a removed
// device's catch-up is refused by every member holding the removal, while it
// still holds an epoch those members answer.
func TestARemovedDeviceIsRefusedACatchUp(t *testing.T) {
	m := startMesh(t, 3)
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	admin, victim := m.nodes[0], m.nodes[2]
	at := func(n *meshNode) netip.AddrPort {
		return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), n.d.gossipPort)
	}
	if err := victim.d.gossip.CatchUpWith(t.Context(), at(admin)); err != nil {
		t.Fatalf("a member was refused a catch-up: %v", err)
	}

	removal := m.nw.removeNode(t, admin.auth, victim.id())
	if err := admin.d.Inform([]types.AUM{removal}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "the others to apply the removal", func() bool {
		return m.nodes[0].d.Status().Members == 2 && m.nodes[1].d.Status().Members == 2
	})
	held := victim.d.keyring.Epochs()
	for _, n := range m.nodes[:2] {
		if e := n.d.Status().Epoch; !slices.Contains(n.d.keyring.Epochs(), held[len(held)-1]) {
			t.Fatalf("a member at epoch %d no longer holds the removed device's %v; the case is moot", e, held)
		}
		// Whether the removed device counts the refusal depends on whether it
		// has heard of its removal; that the member refuses is what counts.
		err := victim.d.gossip.CatchUpWith(t.Context(), at(n))
		if !errors.Is(err, gossip.ErrCatchUpRefused) && (err == nil || !strings.Contains(err.Error(), "refused a catch-up")) {
			t.Errorf("a member holding the removal answered the removed device's catch-up with %v", err)
		}
	}
}

// A device removed while it slept, and too far behind to hear it, is refused
// by every member it reaches, and says so instead of showing peers it merely
// cannot reach.
func TestARemovedSleeperSaysItWasRefused(t *testing.T) {
	removedSleeperIsRefused(t, false)
}

// A member restarted since the removal refuses the removed device too, which
// it knows only from its log.
func TestARemovedSleeperIsRefusedByMembersRestartedSince(t *testing.T) {
	removedSleeperIsRefused(t, true)
}

func removedSleeperIsRefused(t *testing.T, restart bool) {
	m := &mesh{t: t, nw: newNetwork(t, 3), hub: &lanHub{}}
	kept := []*persisted{keep(t, m.nw), keep(t, m.nw), keep(t, m.nw)}
	clock := &passing{}
	for i := range 3 {
		m.nodes = append(m.nodes, m.startKept(t, i, m.nw.devices[i], kept[i], clock))
	}
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	waitFor(t, 10*time.Second, "the victim to cache its peers' addresses", func() bool {
		b, err := os.ReadFile(kept[2].cache)
		return err == nil && len(b) > 0
	})
	admin, victim := m.nodes[0], m.nodes[2]
	victim.halt()
	if err := admin.d.Inform([]types.AUM{m.nw.removeNode(t, admin.auth, victim.id())}); err != nil {
		t.Fatal(err)
	}
	for range keyring.Depth {
		m.apply(t, admin, func(b *log.Builder) (types.AUM, error) { return b.EpochBump(m.nw.sealer()) })
	}
	waitFor(t, 10*time.Second, "the other member to follow", func() bool {
		return m.nodes[1].d.Status().Epoch == admin.d.Status().Epoch
	})
	if restart {
		for i := range 2 {
			m.nodes[i].halt()
			auth, err := log.Open(kept[i].st)
			if err != nil {
				t.Fatal(err)
			}
			kept[i].auth = auth
			m.nodes[i] = m.startKept(t, i, m.nw.devices[i], kept[i], clock)
		}
	}

	clock.advance(time.Hour)
	victim = m.startKept(t, 2, m.nw.devices[2], kept[2], clock)
	waitFor(t, 30*time.Second, "the removed device to report the refusal", func() bool {
		return victim.d.Status().Refused
	})
	if st := victim.d.Status(); st.NotMember {
		t.Fatal("the removed device learned of its removal, which the test means it cannot")
	}
}

// A node that applies several changes at once, as after a catch-up, holds the
// newest epochs rather than the ones it held before: every epoch kept is one
// more change for which a removed device is still answered.
func TestSkippedEpochsAreFilledIn(t *testing.T) {
	f := newReconcileFixture(t, 3)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	b := log.NewBuilder(f.auth.State())
	var records []types.AUM
	for range keyring.Depth + 1 {
		rec, err := b.EpochBump(f.nw.sealer())
		if err != nil {
			t.Fatal(err)
		}
		if err := rec.Sign(f.nw.admin); err != nil {
			t.Fatal(err)
		}
		next, err := b.Dry(&rec)
		if err != nil {
			t.Fatal(err)
		}
		b = log.NewBuilder(next)
		records = append(records, rec)
	}
	if err := f.d.Inform(records); err != nil {
		t.Fatal(err)
	}
	head := f.d.Status().Epoch
	want := []uint64{head - 3, head - 2, head - 1, head}
	if got := f.d.keyring.Epochs(); !slices.Equal(got, want) {
		t.Fatalf("after %d changes at once the keyring holds epochs %v, want %v", len(records), got, want)
	}
}

// A device nobody refused is not reported refused.
func TestNoRefusalIsNoRefusal(t *testing.T) {
	f := newReconcileFixture(t, 3)
	state, err := f.d.TrustedState()
	if err != nil {
		t.Fatal(err)
	}
	members := state.Nodes()
	live := map[types.Identity]bool{}
	for _, n := range members {
		live[n.Identity] = true
	}
	if f.d.refusedEverywhere(members, live) {
		t.Fatal("a device nobody refused reads as refused")
	}
}
