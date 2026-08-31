package gossip

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// fakeLog is a membership log that holds no records.
//
// The four-frame exchange, the network check and announcement propagation are
// all independent of what the log contains, so they are asserted here where a
// test needs no genesis ceremony. Record transfer over a real chain is
// asserted end to end in daemon's mesh tests.
type fakeLog struct {
	network types.Hash
	head    types.Hash
	epoch   uint64

	mu       sync.Mutex
	informed [][]types.AUM
}

func (l *fakeLog) View() (View, error) {
	return View{Network: l.network, Head: l.head, Epoch: l.epoch, Anchor: types.Hash{0xa}}, nil
}

func (l *fakeLog) Missing([]types.Hash, types.Hash) ([]types.AUM, error) { return nil, nil }

func (l *fakeLog) Inform(records []types.AUM) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.informed = append(l.informed, records)
	return nil
}

// testNode is a gossip node wired to a loopback listener.
type testNode struct {
	priv    types.PrivateIdentity
	id      types.Identity
	keyring *secrets.Keyring
	cache   *Cache
	log     *fakeLog
	node    *Node
	port    uint16
	real    netip.AddrPort
}

// testAddrs maps each node's announced address to the loopback address its
// listener is really on.
var (
	testAddrsMu sync.Mutex
	testAddrs   = map[netip.AddrPort]netip.AddrPort{}
)

func loopbackFor(announced netip.AddrPort) netip.AddrPort {
	testAddrsMu.Lock()
	defer testAddrsMu.Unlock()
	if real, ok := testAddrs[announced]; ok {
		return real
	}
	// An address no node registered: keep it on loopback so a test that
	// expects the dial to fail gets a refusal rather than the timeout an
	// unroutable address would spend.
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), announced.Port())
}

func newTestNode(t *testing.T, network types.Hash, epoch uint64, s secrets.Secret) *testNode {
	t.Helper()
	priv, err := types.GenerateIdentity()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	kr := secrets.NewKeyring()
	kr.Adopt(epoch, s)
	tn := &testNode{
		priv:    priv,
		id:      priv.Public(),
		keyring: kr,
		cache:   NewCache(),
		log:     &fakeLog{network: network, epoch: epoch},
		port:    uint16(ln.Addr().(*net.TCPAddr).Port),
	}
	tn.real = netip.MustParseAddrPort(ln.Addr().String())
	n, err := New(Options{
		Self:      tn.id,
		Log:       tn.log,
		Keyring:   kr,
		Endpoints: tn.cache,
		Announce:  tn.announce,
		Listener:  ln,
		// Announcements carry a routable-looking address, because loopback is
		// refused by the schema: an announcement points the whole member set
		// at an address, so "connect to your own loopback" is not something a
		// member may say. The listener really is on loopback, so the dialer
		// maps the announced address back to it — the same substitution the
		// discovery tests make for the multicast group.
		Dial: func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", loopbackFor(addr).String())
		},
		// Short, so a test that waits on an unreachable peer does not wait
		// out the production default.
		Timeout: 2 * time.Second,
		Logf:    t.Logf,
	})
	if err != nil {
		t.Fatalf("starting gossip: %v", err)
	}
	tn.node = n
	go n.Serve()
	t.Cleanup(func() { n.Close() })
	return tn
}

func (tn *testNode) announce() (Endpoint, bool) {
	e := Endpoint{
		Identity:   tn.id,
		Disco:      DiscoKey{1, 2, 3},
		Addrs:      []netip.AddrPort{tn.addr()},
		GossipPort: tn.port,
		Seq:        1,
	}
	if err := e.Sign(tn.priv); err != nil {
		panic(err)
	}
	return e, true
}

// addr is the address this node announces: TEST-NET-1, which the injected
// dialer maps back to the loopback listener.
func (tn *testNode) addr() netip.AddrPort {
	a := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), tn.port)
	testAddrsMu.Lock()
	testAddrs[a] = tn.real
	testAddrsMu.Unlock()
	return a
}

// TestSessionExchangesAnnouncements is the base case: one round leaves both
// sides holding the other's announcement. Symmetry is the point — a pull-only
// protocol would need two rounds for this.
func TestSessionExchangesAnnouncements(t *testing.T) {
	net1 := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	a := newTestNode(t, net1, 3, s)
	b := newTestNode(t, net1, 3, s)

	if err := a.node.SyncWith(t.Context(), b.addr(), types.Identity{}); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if _, ok := a.cache.Get(b.id); !ok {
		t.Errorf("initiator did not learn the responder's announcement")
	}
	if _, ok := b.cache.Get(a.id); !ok {
		t.Errorf("responder did not learn the initiator's announcement")
	}
	if _, ok := a.cache.Get(a.id); ok {
		t.Errorf("initiator cached an announcement about itself")
	}
}

// TestSessionRefusesAnotherNetwork covers two juist networks sharing a LAN:
// the group secret is what separates them, and even if it did not, the genesis
// hash in every frame does.
func TestSessionRefusesAnotherNetwork(t *testing.T) {
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	a := newTestNode(t, types.Hash{1}, 3, s)
	b := newTestNode(t, types.Hash{2}, 3, s)

	if err := a.node.SyncWith(t.Context(), b.addr(), types.Identity{}); err == nil {
		t.Fatal("sync across networks succeeded; it must not")
	}
	if _, ok := a.cache.Get(b.id); ok {
		t.Errorf("initiator kept an announcement from another network")
	}
}

// TestSessionRefusesAnotherGroupSecret is the membership check the sync layer
// actually performs: a device without the current group secret cannot produce
// a frame any member will open. It is what a revoked device looks like once
// the removal's epoch bump has converged.
func TestSessionRefusesAnotherGroupSecret(t *testing.T) {
	network := types.Hash{1}
	s1, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s2, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	a := newTestNode(t, network, 3, s1)
	outsider := newTestNode(t, network, 3, s2)

	if err := outsider.node.SyncWith(t.Context(), a.addr(), types.Identity{}); err == nil {
		t.Fatal("a node without the group secret completed a session")
	}
	if a.cache.Len() != 0 {
		t.Errorf("member cached %d announcements from a node it cannot decrypt", a.cache.Len())
	}
}

// TestSessionSealsUnderTheLaggingPeersEpoch is the property that makes
// push-on-author work across an epoch bump: the node that authored the change
// is one epoch ahead of everyone, and if it could only speak its own epoch,
// the push carrying a revocation would be unreadable to exactly the members
// that have not applied it yet.
func TestSessionSealsUnderTheLaggingPeersEpoch(t *testing.T) {
	network := types.Hash{1}
	old, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	ahead := newTestNode(t, network, 3, old)
	behind := newTestNode(t, network, 3, old)

	// One round at the shared epoch teaches each side where the other is.
	if err := ahead.node.SyncWith(t.Context(), behind.addr(), behind.id); err != nil {
		t.Fatalf("first sync: %v", err)
	}

	// Now one side bumps. The other holds only the old secret.
	ahead.keyring.Adopt(4, fresh)
	ahead.log.epoch = 4

	if err := ahead.node.SyncWith(t.Context(), behind.addr(), behind.id); err != nil {
		t.Fatalf("sync after the bump: %v", err)
	}
	if !slices.Contains(ahead.keyring.Epochs(), 3) {
		t.Fatal("the keyring dropped the epoch the peer is still on")
	}
}

// TestFrameEpochCannotChangeMidSession stops a peer from opening at an epoch
// this node holds and then switching to another one it also holds — which
// would make "what epoch is this session" unanswerable, and with it the reply
// sealing rule.
func TestFrameEpochCannotChangeMidSession(t *testing.T) {
	network := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	victim := newTestNode(t, network, 3, s)
	victim.keyring.Adopt(4, s)

	// A raw dial, so it goes to the listener's real address rather than
	// through the injected dialer.
	c, err := net.Dial("tcp", victim.real.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	attacker, err := New(Options{
		Self: types.Identity{}, Log: &fakeLog{network: network, epoch: 3},
		Keyring: victim.keyring, Endpoints: NewCache(),
		Listener: nopListener{}, Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	hello := frame{Kind: kindHello, Network: network, Epoch: 3, Anchor: types.Hash{0xa}}
	if err := attacker.writeFrame(c, 3, &hello); err != nil {
		t.Fatalf("writing the first frame: %v", err)
	}
	// Read the victim's hello so it gets as far as expecting our records.
	got := uint64(0)
	if _, err := attacker.readFrame(c, &got); err != nil {
		t.Fatalf("reading the peer hello: %v", err)
	}
	records := frame{Kind: kindRecords, Network: network, Epoch: 4, Anchor: types.Hash{0xa}}
	if err := attacker.writeFrame(c, 4, &records); err != nil {
		t.Fatalf("writing the second frame: %v", err)
	}
	// The victim must hang up rather than answer.
	var scratch [1]byte
	if _, err := c.Read(scratch[:]); err == nil {
		t.Error("peer kept talking after the sealing epoch changed mid-session")
	}
}

// nopListener stands in where a Node is built only to reuse its framing.
type nopListener struct{}

func (nopListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (nopListener) Close() error              { return nil }
func (nopListener) Addr() net.Addr            { return &net.TCPAddr{} }

// TestSyncSkipsUnknownPeers keeps a member with no cached announcement from
// costing a dial attempt, and keeps this node from gossiping with itself.
func TestSyncSkipsUnknownPeers(t *testing.T) {
	network := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	a := newTestNode(t, network, 1, s)
	other, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if n := a.node.Sync(context.Background(), []types.Identity{a.id, other.Public()}); n != 0 {
		t.Errorf("Sync reported %d successful rounds, want 0", n)
	}
}

// mintedSelfFrame builds a hello whose Self is a freshly minted, validly signed
// announcement, and whose plaintext Epoch beacon is beaconEpoch. Returns the
// frame and the identity that signed it.
func mintedSelfFrame(t *testing.T, network types.Hash, beaconEpoch uint64, seq uint64) (*frame, types.Identity) {
	t.Helper()
	priv, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	e := Endpoint{
		Identity:   priv.Public(),
		Disco:      DiscoKey{1},
		GossipPort: 1024,
		Seq:        seq,
	}
	if err := e.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return &frame{Kind: kindHello, Network: network, Epoch: beaconEpoch, Self: &e}, priv.Public()
}

// TestRememberedEpochsAreBounded: an endpoint announcement is signed only by
// the key it names, and identity keys cost nothing to mint, so anyone who can
// open a frame — a revoked device still inside the keyring window, say — could
// otherwise add one map entry per session for as long as it liked. A flood of
// minted, non-member identities cannot grow the map past its bound.
func TestRememberedEpochsAreBounded(t *testing.T) {
	network := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	n := newTestNode(t, network, 3, s)

	for i := range maxRememberedPeers + 64 {
		f, _ := mintedSelfFrame(t, network, 3, uint64(1+i))
		n.node.notePeer(f, 3)
	}
	n.node.mu.Lock()
	held := len(n.node.peerEpoch)
	n.node.mu.Unlock()
	if held > maxRememberedPeers {
		t.Errorf("node remembers %d peers, over the %d bound", held, maxRememberedPeers)
	}
}

// TestNotePeerIgnoresTheUnauthenticatedBeacon: the remembered epoch is the
// authenticated seal epoch of the session, never the frame's plaintext Epoch
// beacon. Trusting the beacon let one crafted hello pin the value at 2^64-1 and
// defeat the epoch-skew push for a targeted peer.
func TestNotePeerIgnoresTheUnauthenticatedBeacon(t *testing.T) {
	network := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	n := newTestNode(t, network, 5, s)

	// A hello whose beacon claims the maximum epoch, but whose session ran
	// under epoch 4 (an epoch the peer demonstrably held).
	f, id := mintedSelfFrame(t, network, ^uint64(0), 1)
	n.node.notePeer(f, 4)

	n.node.mu.Lock()
	got := n.node.peerEpoch[id]
	n.node.mu.Unlock()
	if got != 4 {
		t.Fatalf("remembered epoch is %d; want the seal epoch 4, not the beacon", got)
	}
}

// TestAMemberDisplacesANonMemberEpoch: once the map is full of minted
// non-members, a genuine member must still be able to take a slot — otherwise a
// one-time flood locks every real peer out of the push accommodation for the
// process's life.
func TestAMemberDisplacesANonMemberEpoch(t *testing.T) {
	network := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	n := newTestNode(t, network, 3, s)

	// Fill the map with minted non-members.
	for i := range maxRememberedPeers {
		f, _ := mintedSelfFrame(t, network, 3, uint64(1+i))
		n.node.notePeer(f, 3)
	}

	// A member arrives. The cache's membership view is what decides the
	// displacement, exactly as it decides the announcement cache's eviction.
	f, memberID := mintedSelfFrame(t, network, 3, 1)
	n.cache.SetMembership([]types.Identity{memberID}, nil)
	n.node.notePeer(f, 3)

	n.node.mu.Lock()
	_, held := n.node.peerEpoch[memberID]
	size := len(n.node.peerEpoch)
	n.node.mu.Unlock()
	if !held {
		t.Error("a member could not displace a non-member; the map is locked")
	}
	if size > maxRememberedPeers {
		t.Errorf("map grew to %d, over the %d bound", size, maxRememberedPeers)
	}
}

// TestNotePeerRefusesFormerMembers: a revoked or expired device keeps sending
// hellos for the keyring window, but there is nothing to gain from remembering
// its epoch — this node no longer pushes to it — and doing so only gives it a
// slot a real peer could use.
func TestNotePeerRefusesFormerMembers(t *testing.T) {
	network := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	n := newTestNode(t, network, 3, s)

	f, id := mintedSelfFrame(t, network, 3, 1)
	n.cache.SetMembership(nil, []types.Identity{id})
	n.node.notePeer(f, 3)

	n.node.mu.Lock()
	_, held := n.node.peerEpoch[id]
	n.node.mu.Unlock()
	if held {
		t.Error("remembered a former member's epoch")
	}
}
