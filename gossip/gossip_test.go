package gossip

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nning/juist/internal/keyring"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// fakeLog is a membership log that holds no records: the frame exchange, the
// network check and announcement propagation do not depend on what the log
// contains. Record transfer over a real chain is asserted in daemon's tests.
type fakeLog struct {
	network types.Hash
	head    types.Hash
	epoch   uint64
	have    []types.Hash

	// missing overrides what this log offers a peer. Nil offers nothing.
	missing func([]types.Hash, types.Hash) ([]types.AUM, error)

	// member answers [Log.Member]. Nil lists nobody.
	member func(types.Identity) (types.NodeRecord, bool, error)

	mu       sync.Mutex
	informed [][]types.AUM
}

func (l *fakeLog) View() (View, error) {
	return View{Network: l.network, Head: l.head, Epoch: l.epoch, Anchor: types.Hash{0xa}, Have: l.have}, nil
}

func (l *fakeLog) Missing(have []types.Hash, anchor types.Hash) ([]types.AUM, error) {
	if l.missing != nil {
		return l.missing(have, anchor)
	}
	return nil, nil
}

func (l *fakeLog) Member(id types.Identity) (types.NodeRecord, bool, error) {
	if l.member == nil {
		return types.NodeRecord{}, false, nil
	}
	return l.member(id)
}

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
	record  types.NodeRecord // as a log listing it would carry it
	keyring *keyring.Keyring
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

// blackhole is an address the test dialer never connects to or refuses, like
// a private address on another site's LAN: the SYN goes unanswered.
var blackhole = netip.MustParseAddr("10.0.0.9")

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
	// Short, so a test that waits on an unreachable peer does not wait out the
	// production default.
	return newTestNodeTimeout(t, network, epoch, s, 2*time.Second)
}

// newTestNodeTimeout is [newTestNode] with the session timeout stated. It is a
// construction parameter rather than something a test sets afterwards: the
// accept loop is already running by the time this returns, and its sessions
// read the field.
func newTestNodeTimeout(t *testing.T, network types.Hash, epoch uint64, s secrets.Secret,
	timeout time.Duration, mutate ...func(*Options)) *testNode {
	t.Helper()
	priv, err := types.GenerateIdentity()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	kr := keyring.New()
	kr.Adopt(epoch, s)
	recipient, err := secrets.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	x, m, err := recipient.Public()
	if err != nil {
		t.Fatal(err)
	}
	tn := &testNode{
		priv:    priv,
		id:      priv.Public(),
		record:  types.NodeRecord{Identity: priv.Public(), X25519: x, MLKEM: m},
		keyring: kr,
		cache:   NewCache(),
		log:     &fakeLog{network: network, epoch: epoch},
		port:    uint16(ln.Addr().(*net.TCPAddr).Port),
	}
	tn.real = netip.MustParseAddrPort(ln.Addr().String())
	opts := Options{
		Self:      tn.id,
		Log:       tn.log,
		Keyring:   kr,
		Endpoints: tn.cache,
		Announce:  tn.announce,
		Listener:  ln,
		// The schema refuses loopback, since an announcement points the whole
		// member set at an address, so these carry a routable-looking one and
		// the dialer maps it back to the loopback listener.
		Dial: func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			if addr.Addr() == blackhole {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			// Loopback answers at once; only a starved scheduler outruns the
			// 500ms dial budget, so a looser one bounds this dial.
			dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			var d net.Dialer
			return d.DialContext(dctx, "tcp", loopbackFor(addr).String())
		},
		Timeout: timeout,
		CatchUp: &CatchUpKeys{Identity: priv, Recipient: recipient},
		Logf:    t.Logf,
	}
	for _, m := range mutate {
		m(&opts)
	}
	n, err := New(opts)
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

// TestTestDialerOutlastsItsDeadline: a loopback dial never hangs, so one that
// a loaded machine delays past the 500ms dial budget must still connect.
func TestTestDialerOutlastsItsDeadline(t *testing.T) {
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	a := newTestNode(t, types.Hash{1}, 1, s)
	b := newTestNode(t, types.Hash{1}, 1, s)
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	c, err := a.node.opts.Dial(ctx, b.addr())
	if err != nil {
		t.Fatalf("dialing a listener on loopback: %v", err)
	}
	c.Close()
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

// A peer holding this node's announcement hands it back, for the node to
// judge against its own.
func TestSessionEchoesTheNodesOwnAnnouncement(t *testing.T) {
	net1 := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	echoed := make(chan Endpoint, 4)
	a := newTestNodeTimeout(t, net1, 3, s, 2*time.Second, func(o *Options) {
		o.OnOwn = func(e Endpoint) { echoed <- e }
	})
	b := newTestNode(t, net1, 3, s)
	previous, _ := a.announce()
	previous.Seq = 5
	if err := previous.Sign(a.priv); err != nil {
		t.Fatal(err)
	}
	b.cache.Add(previous)
	if err := a.node.SyncWith(t.Context(), b.addr(), types.Identity{}); err != nil {
		t.Fatalf("sync: %v", err)
	}
	select {
	case e := <-echoed:
		if e.Seq != previous.Seq {
			t.Fatalf("echoed %d, the peer holds %d", e.Seq, previous.Seq)
		}
	default:
		t.Fatal("the peer's copy of this node's announcement was not handed on")
	}
}

// Both sides of a session hear which records the other holds, under the
// identity it announces.
func TestSessionReportsWhatThePeerHolds(t *testing.T) {
	net1 := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	type heard struct {
		from types.Identity
		have []types.Hash
	}
	got := make(chan heard, 2)
	holding := func(h types.Hash) func(*Options) {
		return func(o *Options) {
			o.Log.(*fakeLog).have = []types.Hash{h}
			o.OnHave = func(from types.Identity, have []types.Hash) { got <- heard{from, have} }
		}
	}
	a := newTestNodeTimeout(t, net1, 3, s, 2*time.Second, holding(types.Hash{0xa}))
	b := newTestNodeTimeout(t, net1, 3, s, 2*time.Second, holding(types.Hash{0xb}))
	if err := a.node.SyncWith(t.Context(), b.addr(), types.Identity{}); err != nil {
		t.Fatalf("sync: %v", err)
	}
	for range 2 {
		h := <-got
		switch {
		case h.from == a.id && slices.Equal(h.have, a.log.have):
		case h.from == b.id && slices.Equal(h.have, b.log.have):
		default:
			t.Errorf("heard %v holding %v", h.from.ShortString(), h.have)
		}
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

// TestSessionRefusesAnotherGroupSecret is the sync layer's membership check: a
// device without the current group secret cannot produce a frame any member
// opens, which is what a revoked device looks like after the epoch bump.
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

// TestSessionSealsUnderTheLaggingPeersEpoch is what makes push-on-author work
// across a bump: the author is an epoch ahead, so speaking only its own would
// make the push carrying a revocation unreadable to everyone who needs it.
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

// A node that forgot where a peer is — restarted after rotating its own
// keys — seals its hello under its newest epoch, which a peer that has not
// applied the rotation cannot open. It retries under the older epochs it
// still holds, or neither side could ever catch the other up.
func TestSessionFindsTheEpochAnUnknownLaggingPeerHolds(t *testing.T) {
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
	ahead.keyring.Adopt(4, fresh)
	ahead.log.epoch = 4
	behind := newTestNode(t, network, 3, old)

	// No round before this one: nothing tells ahead that behind is at 3.
	if err := ahead.node.SyncWith(t.Context(), behind.addr(), behind.id); err != nil {
		t.Fatalf("sync with a lagging peer whose epoch nobody remembered: %v", err)
	}
}

// TestFrameEpochCannotChangeMidSession stops a peer from opening at one epoch
// this node holds and switching to another, which would leave "what epoch is
// this session" unanswerable.
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
	if err := attacker.writeSealed(c, &sessionSeal{epoch: 3}, &hello); err != nil {
		t.Fatalf("writing the first frame: %v", err)
	}
	// Read the victim's hello so it gets as far as expecting our records.
	if _, err := attacker.readSealed(c, &sessionSeal{}); err != nil {
		t.Fatalf("reading the peer hello: %v", err)
	}
	records := frame{Kind: kindRecords, Network: network, Epoch: 4, Anchor: types.Hash{0xa}}
	if err := attacker.writeSealed(c, &sessionSeal{epoch: 4}, &records); err != nil {
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

// TestAnUnansweredAddressLeavesTimeForTheNext: a peer's addresses share one
// session budget, and a member behind NAT announces private addresses first
// that nobody elsewhere can reach. If the first unanswered SYN spent the whole
// budget, the address that works would never be tried.
func TestAnUnansweredAddressLeavesTimeForTheNext(t *testing.T) {
	network := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	a := newTestNode(t, network, 1, s)
	b := newTestNode(t, network, 1, s)
	e := Endpoint{
		Identity:   b.id,
		Disco:      DiscoKey{1, 2, 3},
		Addrs:      SortAddrs([]netip.AddrPort{netip.AddrPortFrom(blackhole, b.port), b.addr()}),
		GossipPort: b.port,
		Seq:        1,
	}
	if e.Addrs[0].Addr() != blackhole {
		t.Fatalf("the unanswered address must come first: %v", e.Addrs)
	}
	if err := e.Sign(b.priv); err != nil {
		t.Fatal(err)
	}
	if !a.cache.Add(e) {
		t.Fatal("the announcement was not cached")
	}
	if n := a.node.Sync(t.Context(), []types.Identity{b.id}); n != 1 {
		t.Errorf("Sync reached %d peers, want 1: the second address was never tried", n)
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

// TestRememberedEpochsAreBounded: identity keys cost nothing to mint, so
// anyone who can open a frame could otherwise add a map entry per session. A
// flood of minted non-member identities cannot grow the map past its bound.
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
// session's authenticated seal epoch, never the plaintext beacon, which one
// crafted hello could pin at 2^64-1.
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

// TestAMemberDisplacesANonMemberEpoch: with the map full of minted
// non-members, a genuine member must still take a slot, or one flood locks
// every real peer out for the process's life.
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

// TestNotePeerRefusesFormerMembers: a revoked device keeps sending hellos for
// the keyring window, and remembering its epoch only costs a slot a real peer
// could use.
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

// TestSilentConnectionsCannotHoldEveryInboundSlot: a peer that opens
// connections and says nothing must not be able to shut inbound sync down for
// the mesh. The budget is per source address and covers only connections that
// have not authenticated, so members sharing one address — behind a NAT, or on
// one host — are not the ones it costs.
func TestSilentConnectionsCannotHoldEveryInboundSlot(t *testing.T) {
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	// A long timeout, so the hello deadline cannot be what ends these
	// connections: the cap is what this test is about, not the timeout.
	a := newTestNodeTimeout(t, types.Hash{1}, 1, s, time.Minute)

	addr := loopbackFor(a.real).String()
	var held []net.Conn
	t.Cleanup(func() {
		for _, c := range held {
			c.Close()
		}
	})
	for range maxInboundSessions + 4 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dialing: %v", err)
		}
		held = append(held, c)
	}

	// Settle: the accept loop runs on its own goroutine, so wait for it to
	// have taken the connections before reading the count — and for the
	// sessions it evicted to have given their slots back, which they do only
	// once their reads return. A peer arriving before that finds every slot
	// taken and is refused, which is the retry path, not the one under test.
	silent, peak := 0, 0
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		silent = a.node.silent.Count(netip.MustParseAddr("127.0.0.1"))
		peak = max(peak, silent)
		if peak >= maxUnauthPerSource && silent <= maxUnauthPerSource && len(a.node.slots) <= silent {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if silent > maxUnauthPerSource {
		t.Fatalf("one address holds %d unauthenticated connections, over the %d cap",
			silent, maxUnauthPerSource)
	}

	// And a real peer still gets through from the same address while they are
	// held: authenticating is what releases the budget, so members sharing an
	// address do not queue behind each other.
	b := newTestNode(t, types.Hash{1}, 1, s)
	t.Cleanup(func() { b.node.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := b.node.SyncWith(ctx, a.real, a.id); err != nil {
		t.Fatalf("a session was refused while silent connections were held: %v", err)
	}
}

// With OverlayOnly a peer is reached only at its overlay addresses: log sync
// runs through the tunnel, and the announced underlay addresses are not tried.
func TestOverlayOnlyDialsNoAnnouncedAddress(t *testing.T) {
	network := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	a := newTestNode(t, network, 1, s)
	b := newTestNode(t, network, 1, s)
	e, _ := b.announce()
	if !a.cache.Add(e) {
		t.Fatal("the announcement was not cached")
	}
	a.node.opts.OverlayOnly = true
	if n := a.node.Sync(t.Context(), []types.Identity{b.id}); n != 0 {
		t.Fatalf("Sync reached %d peers through an announced address", n)
	}
	a.node.opts.OverlayAddrs = func(types.Identity) []netip.AddrPort { return []netip.AddrPort{b.addr()} }
	if n := a.node.Sync(t.Context(), []types.Identity{b.id}); n != 1 {
		t.Fatalf("Sync reached %d peers through the overlay address, want 1", n)
	}
}

// A peer whose last round reached none of its addresses reads as failing, and
// a round that reaches it clears that: what status says when a firewall on
// the tunnel's device drops the sync port.
func TestARoundThatReachesNoAddressIsFailing(t *testing.T) {
	network := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	a := newTestNode(t, network, 1, s)
	b := newTestNode(t, network, 1, s)
	e, _ := b.announce()
	a.cache.Add(e)
	a.node.opts.OverlayOnly = true
	a.node.Sync(t.Context(), []types.Identity{b.id})
	if !a.node.Failing(b.id) {
		t.Fatal("a round that reached no address did not read as failing")
	}
	a.node.opts.OverlayAddrs = func(types.Identity) []netip.AddrPort { return []netip.AddrPort{b.addr()} }
	a.node.Sync(t.Context(), []types.Identity{b.id})
	if a.node.Failing(b.id) {
		t.Fatal("a round that reached the peer left it failing")
	}
}

// PushTo hands a member records this node has not applied, after what it
// lacks of this node's log, in an ordinary session: how a removed device is
// told of its removal while it still has a tunnel to be told through.
func TestPushToHandsOverRecordsNotApplied(t *testing.T) {
	net1 := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	a := newTestNode(t, net1, 3, s)
	b := newTestNode(t, net1, 3, s)
	// a learns where b is, as a member does before any push.
	if err := a.node.SyncWith(t.Context(), b.addr(), b.id); err != nil {
		t.Fatalf("sync: %v", err)
	}
	prev := types.Hash{9}
	v := types.SchemaVersion(3)
	pending := types.AUM{Kind: types.KindSchemaUpgrade, Prev: &prev, Schema: &v}
	signer, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.Sign(signer); err != nil {
		t.Fatal(err)
	}
	raw, err := pending.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.node.PushTo(t.Context(), b.id, [][]byte{raw}); err != nil {
		t.Fatalf("PushTo: %v", err)
	}
	// The peer applies what it was handed after answering, so after PushTo
	// has returned.
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		b.log.mu.Lock()
		n := len(b.log.informed)
		b.log.mu.Unlock()
		if n > 0 {
			break
		}
	}
	b.log.mu.Lock()
	defer b.log.mu.Unlock()
	if len(b.log.informed) != 1 || len(b.log.informed[0]) != 1 || b.log.informed[0][0].Hash() != pending.Hash() {
		t.Fatalf("the peer was informed of %v, want the record handed over", b.log.informed)
	}
	if err := a.node.PushTo(t.Context(), types.Identity{7}, [][]byte{raw}); err == nil {
		t.Fatal("a push to a member with no announcement succeeded")
	}
}
