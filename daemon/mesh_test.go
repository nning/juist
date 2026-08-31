package daemon

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/discovery/mdns"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// This file is M2's exit criteria (docs/05-roadmap.md), run against the real
// thing: real membership logs, one per node, each independently verified; real
// group secrets opened from real HPKE wraps; the real gossip protocol over
// real TCP; and the real embedded WireGuard data plane.
//
// The one substitution is the multicast group, replaced by a loopback fan-out
// ([lanHub]) that delivers the same DNS-SD packets. A CI machine has no LAN
// segment and Linux loopback carries no multicast, so the alternative is a
// test that skips — and the parts of discovery worth asserting, the blinded
// naming and the sealed payload, are in the packets rather than in the socket.
// mdns's own tests cover the encoding against the same fan-out.

// --- a fake LAN ------------------------------------------------------------

type lanHub struct {
	mu      sync.Mutex
	members []*lanConn
}

type lanConn struct {
	h      *lanHub
	in     chan []byte
	closed chan struct{}
	once   sync.Once
}

func (h *lanHub) join() *lanConn {
	c := &lanConn{h: h, in: make(chan []byte, 128), closed: make(chan struct{})}
	h.mu.Lock()
	h.members = append(h.members, c)
	h.mu.Unlock()
	return c
}

func (c *lanConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case pkt := <-c.in:
		return copy(b, pkt), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *lanConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	pkt := append([]byte(nil), b...)
	c.h.mu.Lock()
	members := append([]*lanConn(nil), c.h.members...)
	c.h.mu.Unlock()
	for _, m := range members {
		if m == c {
			continue
		}
		select {
		case m.in <- pkt:
		default:
		}
	}
	return len(b), nil
}

func (c *lanConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

// --- the mesh --------------------------------------------------------------

type meshNode struct {
	dev  *device
	d    *Daemon
	auth *log.Authority
	stop context.CancelFunc
}

func (n *meshNode) id() types.Identity { return n.dev.record.Identity }

type mesh struct {
	t     *testing.T
	nw    *network
	hub   *lanHub
	nodes []*meshNode
}

// startMesh founds a network of n members and starts a daemon for each, with
// nothing configured about where any of them is: every peer relationship in
// the result was discovered on the "LAN" and authorized by the log.
func startMesh(t *testing.T, n int) *mesh {
	t.Helper()
	m := &mesh{t: t, nw: newNetwork(t, n), hub: &lanHub{}}
	for i := range n {
		m.nodes = append(m.nodes, m.start(t, i))
	}
	return m
}

func (m *mesh) start(t *testing.T, i int, seed ...types.AUM) *meshNode {
	t.Helper()
	dev := m.nw.devices[i]
	auth, st := m.nw.authorityFor(t, seed...)
	logf := safeLogf(t, fmt.Sprintf("n%d: ", i))

	d, err := New(Options{
		Authority: auth,
		Storage:   st,
		Identity:  dev.identity,
		Recipient: dev.recipient,
		WireGuard: dev.wgPrivate,
		Connect: func(o conn.Options) (conn.Manager, error) {
			// The engine answers overlay ICMP itself, so reachability can be
			// asserted without a TUN device or any privileges. It is IPv4
			// only (docs/07-embedding-notes.md), which is why every member
			// here carries an explicit v4 address and the pings use it.
			o.RespondToPing = true
			return conn.New(o)
		},
		Discovery: &mdns.Options{
			Conn:     m.hub.join(),
			Dst:      mdns.Group,
			Interval: 100 * time.Millisecond,
		},
		// Short enough that the periodic backstop cannot be what makes a
		// timing assertion pass: convergence has to come from push.
		SyncInterval:      30 * time.Second,
		ReconcileInterval: time.Second,
		Logf:              logf,
	})
	if err != nil {
		t.Fatalf("starting node %d: %v", i, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go d.Run(ctx)
	t.Cleanup(func() {
		cancel()
		d.Close()
	})
	return &meshNode{dev: dev, d: d, auth: auth, stop: cancel}
}

// waitFor polls until cond holds or the deadline passes, returning how long it
// took. Polling rather than an event hook on purpose: what the exit criterion
// measures is when the *observable* state is right.
func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	deadline := start.Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return time.Since(start)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for %s", d, what)
	return 0
}

// converged reports whether every node holds a full peer set: all members
// except itself.
func (m *mesh) converged() bool {
	for _, n := range m.nodes {
		if st := n.d.Status(); st.Peers != len(m.nodes)-1 {
			return false
		}
	}
	return true
}

// ping sends one overlay ICMP echo and reports whether it was answered.
func ping(from *meshNode, to netip.Addr, timeout time.Duration) bool {
	res := make(chan bool, 1)
	from.d.Manager().Ping(to, func(r conn.PingResult) {
		select {
		case res <- r.Err == "":
		default:
		}
	})
	select {
	case ok := <-res:
		return ok
	case <-time.After(timeout):
		return false
	}
}

func pingUntil(from *meshNode, to netip.Addr, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if ping(from, to, time.Second) {
			return true
		}
	}
	return false
}

func (n *meshNode) overlayV4() netip.Addr { return *n.dev.record.V4 }

// TestMeshFormsOnTheLanAlone is M2's third exit criterion: two to five nodes
// on one LAN, no internet. Nothing is configured about where anyone is — no
// bootstrap list, no relay, no DERP map, no STUN server — and the mesh forms
// anyway, from blinded multicast plus a log every node verified for itself.
func TestMeshFormsOnTheLanAlone(t *testing.T) {
	m := startMesh(t, 5)
	took := waitFor(t, 30*time.Second, "every node to hold a full peer set", m.converged)
	t.Logf("five nodes converged on a full mesh in %v", took)

	// And the tunnels actually carry traffic, which is the part a peer count
	// alone does not prove.
	a, b := m.nodes[0], m.nodes[4]
	if !pingUntil(a, b.overlayV4(), 20*time.Second) {
		t.Fatal("no overlay reachability between two members of a converged mesh")
	}
}

// TestRevocationConvergesWithinTheBudget is M2's second exit criterion:
// revocation converges across a connected five-node mesh in under five
// seconds, including WireGuard peer removal and the epoch rotation.
//
// The clock starts when the admin's signed removal reaches one member's
// daemon and stops when every remaining member has both dropped the peer and
// moved to the new epoch. Both halves matter: dropping the peer is what ends
// data-plane access, and the epoch bump is what ends the revoked device's
// ability to find or read the network at all.
func TestRevocationConvergesWithinTheBudget(t *testing.T) {
	m := startMesh(t, 5)
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)

	victim := m.nodes[4]
	admin := m.nodes[0]
	epochBefore := admin.d.Status().Epoch

	removal := m.nw.removeNode(t, admin.auth, victim.id())

	start := time.Now()
	if err := admin.d.Inform([]types.AUM{removal}); err != nil {
		t.Fatalf("applying the removal: %v", err)
	}
	took := waitFor(t, 5*time.Second, "the removal to converge", func() bool {
		for _, n := range m.nodes[:4] {
			st := n.d.Status()
			if st.Epoch != epochBefore+1 || st.Peers != 3 {
				return false
			}
			if _, held := n.d.Endpoints().Get(victim.id()); held {
				return false
			}
		}
		return true
	})
	t.Logf("revocation converged across four remaining members in %v (budget 5s)", took)
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("convergence took %v, over the 5s budget", elapsed)
	}
}

// TestRevokedDeviceLosesTheDataPlane is M2's first exit criterion from the
// harder direction: the device still holds every key it ever had — its
// WireGuard static key, its identity, its last group secret — and is on the
// same LAN as the members it used to reach. What it no longer has is a peer
// entry on any of them, and WireGuard's cryptokey routing is what turns that
// into "cannot complete a handshake".
func TestRevokedDeviceLosesTheDataPlane(t *testing.T) {
	m := startMesh(t, 3)
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)

	victim, survivor, admin := m.nodes[2], m.nodes[1], m.nodes[0]
	if !pingUntil(victim, survivor.overlayV4(), 20*time.Second) {
		t.Fatal("the member could not reach its peer before being removed")
	}

	removal := m.nw.removeNode(t, admin.auth, victim.id())
	if err := admin.d.Inform([]types.AUM{removal}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "the survivors to drop the removed member", func() bool {
		return survivor.d.Status().Peers == 1
	})

	// The victim's own daemon still believes it is a member: it has not been
	// told, and telling it is not what makes the revocation effective. Its
	// packets are refused by the peers, not withheld by itself.
	if got := victim.d.Status().Members; got != 3 {
		t.Logf("the removed node's own view has %d members (it may have learned already)", got)
	}
	if ping(victim, survivor.overlayV4(), 3*time.Second) {
		t.Fatal("a removed device still reaches a member over the overlay")
	}
	if ping(survivor, victim.overlayV4(), 3*time.Second) {
		t.Fatal("a member still reaches a removed device over the overlay")
	}
}

// TestNonMemberIsNeverAPeer is the other half of default-deny: a device that
// was never in the log, holding valid WireGuard and identity keys, announcing
// itself on the same LAN. Nothing it can say makes any member configure it,
// because the only input that creates a peer is the log.
func TestNonMemberIsNeverAPeer(t *testing.T) {
	m := startMesh(t, 3)
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)

	outsider := newDevice(t, "outsider", netip.AddrFrom4([4]byte{100, 64, 7, 7}))
	// Give it the strongest hand it could have short of the log: a correctly
	// signed announcement, handed straight to a member's daemon, skipping
	// discovery and the group secret entirely.
	e, err := endpointFor(outsider, 4444)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.nodes[0].d.Learn(e); err != nil {
		t.Fatalf("learning the outsider's announcement: %v", err)
	}
	if err := m.nodes[0].d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	for _, n := range m.nodes {
		if st := n.d.Status(); st.Peers != 2 {
			t.Errorf("node %v holds %d peers, want the 2 members that are not itself",
				n.id().ShortString(), st.Peers)
		}
	}
	// The announcement is kept — an early announcement is how a joining
	// member arrives — but it is inert: the gossip set comes from the log
	// too, so nothing dials it.
	for _, id := range m.nodes[0].d.memberList() {
		if id == outsider.record.Identity {
			t.Error("a non-member ended up in the set this node gossips with")
		}
	}
}

// TestNewMemberJoinsAConvergedMesh is the growth case: a device enrolled after
// the network is already running is discovered, configured and reachable
// without anyone restarting anything.
func TestNewMemberJoinsAConvergedMesh(t *testing.T) {
	m := startMesh(t, 2)
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)

	joiner := newDevice(t, "joiner", netip.AddrFrom4([4]byte{100, 64, 0, 9}))
	admin := m.nodes[0]
	add, err := admin.auth.Builder().AddNode(joiner.record, m.nw.sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := add.Sign(m.nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := admin.d.Inform([]types.AUM{add}); err != nil {
		t.Fatal(err)
	}

	// The joining device is given the genesis record and the record that
	// admitted it — what M4's enrollment will hand over — and catches the
	// rest up by gossip like any node that has been offline.
	m.nw.devices = append(m.nw.devices, joiner)
	node := m.start(t, len(m.nw.devices)-1, add)
	m.nodes = append(m.nodes, node)

	took := waitFor(t, 30*time.Second, "the joiner to become a full member of the mesh", m.converged)
	t.Logf("a new member joined a running mesh in %v", took)
	if !pingUntil(node, m.nodes[0].overlayV4(), 20*time.Second) {
		t.Fatal("the new member cannot reach the network it just joined")
	}
}
