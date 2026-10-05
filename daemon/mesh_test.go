package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/discovery/mdns"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// M2's exit criteria (docs/05-roadmap.md) against the real thing: a real
// membership log per node, real group secrets from real HPKE wraps, the real
// gossip protocol over TCP, and the real embedded data plane. The one
// substitution is the multicast group, replaced by a loopback fan-out
// ([lanHub]) carrying the same DNS-SD packets, since Linux loopback carries no
// multicast and the alternative is a test that skips.

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
	t      *testing.T
	nw     *network
	hub    *lanHub
	nodes  []*meshNode
	mutate func(*Options) // applied to every member's options, where set
}

// startMesh founds a network of n members and starts a daemon for each, with
// nothing configured about where any of them is: every peer relationship in
// the result was discovered on the "LAN" and authorized by the log.
func startMesh(t *testing.T, n int, adminDevices ...int) *mesh {
	t.Helper()
	return startMeshWith(t, n, nil, adminDevices...)
}

// startMeshWith is startMesh with every member's options adjusted by mutate.
func startMeshWith(t *testing.T, n int, mutate func(*Options), adminDevices ...int) *mesh {
	t.Helper()
	m := &mesh{t: t, nw: newNetworkWithAdminDevices(t, n, adminDevices...), hub: &lanHub{}, mutate: mutate}
	for i := range n {
		m.nodes = append(m.nodes, m.start(t, i))
	}
	return m
}

func (m *mesh) start(t *testing.T, i int, seed ...types.AUM) *meshNode {
	t.Helper()
	auth, st := m.nw.authorityFor(t, seed...)
	return m.startOn(t, i, m.nw.devices[i], auth, st, m.mutate)
}

// startOn starts member i as dev over a log it already holds, as a restart
// does; mutate adjusts the options first.
func (m *mesh) startOn(t *testing.T, i int, dev *device, auth *log.Authority, st log.Storage,
	mutate func(*Options)) *meshNode {
	t.Helper()
	logf := safeLogf(t, fmt.Sprintf("n%d: ", i))

	opts := Options{
		Authority: auth,
		Storage:   st,
		Identity:  dev.identity,
		Recipient: dev.recipient,
		WireGuard: dev.wgPrivate,
		Connect: func(o conn.Options) (conn.Manager, error) {
			// The engine answers overlay ICMP itself, so reachability needs
			// no TUN device or privileges. It is IPv4 only, which is why
			// every member here carries an explicit v4 address.
			o.RespondToPing = true
			return conn.New(o)
		},
		Discovery: &mdns.Options{
			Conn:     m.hub.join(),
			Dst:      mdns.Group,
			Interval: 100 * time.Millisecond,
		},
		// These nodes meet on the (simulated) LAN, and a test must not put
		// traffic on the public DHT to find that out.
		DisableDHT: true,
		// Short enough that the periodic backstop cannot be what makes a
		// timing assertion pass: convergence has to come from push.
		SyncInterval:      30 * time.Second,
		ReconcileInterval: time.Second,
		Logf:              logf,
	}
	if mutate != nil {
		mutate(&opts)
	}
	d, err := New(opts)
	if err != nil {
		t.Fatalf("starting node %d: %v", i, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.Run(ctx)
	}()
	// Run done, so that a node restarted on auth shares it with no old run.
	stop := func() {
		cancel()
		<-done
	}
	t.Cleanup(func() {
		stop()
		d.Close()
	})
	return &meshNode{dev: dev, d: d, auth: auth, stop: stop}
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

// TestMeshFormsOnTheLanAlone is M2's third exit criterion: five nodes on one
// LAN with no internet, nothing configured about where anyone is, and the mesh
// forms from blinded multicast plus a log every node verified for itself.
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

// TestRevocationConvergesWithinTheBudget is M2's second exit criterion: under
// five seconds across a five-node mesh. The clock starts when the signed
// removal reaches one daemon and stops when every remaining member has both
// dropped the peer — which ends data-plane access — and moved to the new epoch
// — which ends the device's ability to find the network.
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
// harder direction: the device still holds every key it ever had and is on the
// same LAN. What it lacks is a peer entry anywhere, which cryptokey routing
// turns into "cannot complete a handshake".
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

// TestNonMemberIsNeverAPeer is the other half of default-deny: a device never
// in the log, with valid keys, announcing itself on the LAN. Nothing it says
// makes any member configure it.
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

// startUnlinked starts a member's daemon that finds nobody by itself: no LAN
// discovery, no DHT, and a data plane that carries nothing.
func startUnlinked(t *testing.T, nw *network, i int) *Daemon {
	t.Helper()
	dev := nw.devices[i]
	auth, st := nw.authorityFor(t)
	d, err := New(Options{
		Authority: auth, Storage: st,
		Identity: dev.identity, Recipient: dev.recipient, WireGuard: dev.wgPrivate,
		Connect:          func(conn.Options) (conn.Manager, error) { return &fakeManager{}, nil },
		DisableDiscovery: true,
		DisableDHT:       true,
		Logf:             safeLogf(t, fmt.Sprintf("n%d: ", i)),
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
	return d
}

// A device that admitted a member reaches it where the admission ran: a new
// member with a public address, admitted from behind NAT, is announced to the
// others by nothing else, since it cannot open a session into the NAT.
func TestTheAdmittingDeviceGreetsTheNewMember(t *testing.T) {

	nw := newNetwork(t, 2)
	start := func(i int) *Daemon { return startUnlinked(t, nw, i) }
	host, guest := start(0), start(1)
	host.greetAfter = []time.Duration{10 * time.Millisecond, 200 * time.Millisecond, time.Second}
	hostID, guestID := nw.devices[0].record.Identity, nw.devices[1].record.Identity
	if _, held := host.endpoints.Get(guestID); held {
		t.Fatal("the host holds the guest's announcement before any session")
	}
	addr := netip.MustParseAddrPort(guest.gossip.Addr().String())
	host.greetAt(guestID, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), addr.Port()))
	waitFor(t, 5*time.Second, "both to hold the other's announcement", func() bool {
		_, a := host.endpoints.Get(guestID)
		_, b := guest.endpoints.Get(hostID)
		return a && b
	})
}

// A greeting session that the far end holds open does not hold up Close: a
// reset, which closes the mesh while holding the service, would otherwise
// stall every status request with it.
func TestAGreetingDoesNotHoldUpClose(t *testing.T) {
	nw := newNetwork(t, 2)
	d := startUnlinked(t, nw, 0)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // accepted, and never answered
		}
	}()
	d.greetAfter = []time.Duration{0}
	d.greetAt(nw.devices[1].record.Identity, netip.MustParseAddrPort(ln.Addr().String()))
	time.Sleep(200 * time.Millisecond) // the session is under way
	start := time.Now()
	d.Close()
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("Close waited %v for a greeting", took)
	}
}

// A member's identity rotation keeps its WireGuard key, so the data plane must
// see the same peer under the new identity: a local handle that moved with
// the identity would put one key under two handles, which the data plane
// refuses. Here the rotated member's new announcement is held before its
// record applies, as when both arrive in one session.
func TestAPeerThatRotatedItsIdentityStaysAPeer(t *testing.T) {
	m := startMesh(t, 2)
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	rotating, peer := m.nodes[0], m.nodes[1]

	fresh, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rotated := *rotating.dev
	rotated.identity, rotated.record.Identity = fresh, fresh.Public()
	e, err := endpointFor(&rotated, 1)
	if err != nil {
		t.Fatal(err)
	}
	e.Seq = uint64(time.Now().Unix())
	if err := e.Sign(fresh); err != nil {
		t.Fatal(err)
	}
	peer.d.Endpoints().Add(e)

	rec, err := peer.auth.Builder().RotateIdentity(rotating.id(), fresh.Public(), m.nw.sealer())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []types.PrivateIdentity{rotating.dev.identity, fresh, m.nw.admin} {
		if err := rec.Sign(k); err != nil {
			t.Fatal(err)
		}
	}
	if err := peer.d.Inform([]types.AUM{rec}); err != nil {
		t.Fatal(err)
	}
	if st := peer.d.Status(); st.Peers != 1 || st.DataPlaneError != "" {
		t.Fatalf("after the rotation: %d peers, data plane error %q", st.Peers, st.DataPlaneError)
	}
}

// The device a removal removes is told of it by the device that applies it,
// before that one drops its tunnel: afterwards nothing could reach it, and
// it would go on believing it is a member.
func TestARemovedDeviceIsToldFirst(t *testing.T) {
	// Log sync runs in the tunnel, which a removal takes away; here, with no
	// tunnel to take, cut is what takes it: no session with the victim once
	// it is set.
	var cut atomic.Bool
	var victimPort atomic.Uint32
	var victimIdentity atomic.Pointer[types.Identity]
	m := startMeshWith(t, 3, func(o *Options) {
		me := o.Identity.Public()
		o.GossipDial = func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			if v := victimIdentity.Load(); cut.Load() && (me == *v || uint32(addr.Port()) == victimPort.Load()) {
				return nil, errors.New("no tunnel")
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr.String())
		}
	})
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	victim, admin := m.nodes[2], m.nodes[0]
	id := victim.id()
	victimIdentity.Store(&id)
	victimPort.Store(uint32(victim.d.Status().GossipPort))
	removal := m.nw.removeNode(t, admin.auth, victim.id())

	admin.d.farewell(t.Context(), []types.AUM{removal})
	cut.Store(true)
	// Sessions under way when the tunnel went finish before the removal
	// applies, so none of them can be what carries it.
	time.Sleep(time.Second)
	if err := admin.d.Inform([]types.AUM{removal}); err != nil {
		t.Fatal(err)
	}
	// Well inside the periodic sync, so only the handover explains it.
	waitFor(t, 5*time.Second, "the removed device to learn of its removal", func() bool {
		return victim.d.Status().NotMember
	})
	if st := admin.d.Status(); st.Peers != 1 {
		t.Fatalf("the admin kept %d peers, want the survivor alone", st.Peers)
	}
}

// A change that removes nobody hands nothing over, and neither does one that
// would not apply; one that removes a member hands it to that member alone.
func TestAFarewellIsOnlyForTheRemoved(t *testing.T) {
	m := startMesh(t, 3)
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	admin, other := m.nodes[0], m.nodes[1]
	removal := m.nw.removeNode(t, admin.auth, other.id())
	unsigned := removal
	unsigned.Signatures = nil
	if told := admin.d.farewell(t.Context(), []types.AUM{unsigned}); len(told) != 0 {
		t.Fatalf("an unauthorized removal was handed to %v", told)
	}
	bump, err := admin.auth.Builder().EpochBump(m.nw.sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := bump.Sign(m.nw.admin); err != nil {
		t.Fatal(err)
	}
	if told := admin.d.farewell(t.Context(), []types.AUM{bump}); len(told) != 0 {
		t.Fatalf("a change that removes nobody was handed to %v", told)
	}
	if told := admin.d.farewell(t.Context(), []types.AUM{removal}); len(told) != 1 || told[0] != other.id() {
		t.Fatalf("the removal was handed to %v, want the removed member alone", told)
	}
}

func TestPingAnswersWithTheRoundTrip(t *testing.T) {
	m := startMesh(t, 2)
	waitFor(t, 30*time.Second, "the mesh to converge", m.converged)
	a, b := m.nodes[0], m.nodes[1]
	ctx := context.Background()
	waitFor(t, 20*time.Second, "an echo from the other member", func() bool {
		p, err := a.d.Ping(ctx, b.id())
		if err != nil {
			t.Fatalf("pinging a member: %v", err)
		}
		return p.Err == "" && p.Micros > 0
	})
	if _, err := a.d.Ping(ctx, a.id()); !errors.Is(err, errNotInstalled) {
		t.Errorf("pinging itself: %v, want %v", err, errNotInstalled)
	}
}
