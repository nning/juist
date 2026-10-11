package gossip

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/internal/keyring"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

type memberFunc = func(types.Identity) (types.NodeRecord, bool, error)

// catchUpPair is a node that slept through more epochs than any keyring
// holds, and a peer whose log lists it. Each side's log lists the other.
type catchUpPair struct {
	sleeper, peer *testNode
	asked         atomic.Int32 // how often the peer's log was asked

	// What each side's [Log.Member] answers, and the peer's leases.
	// Swappable, since sessions read them on their own goroutines.
	sleeperMember, peerMember atomic.Pointer[memberFunc]
	leases                    atomic.Pointer[[][]byte]
}

func newCatchUpPair(t *testing.T) *catchUpPair {
	t.Helper()
	network := types.Hash{1}
	p := &catchUpPair{}
	p.sleeper = newTestNodeTimeout(t, network, 2, mustSecret(t), 2*time.Second, func(o *Options) {
		o.Log.(*fakeLog).member = func(id types.Identity) (types.NodeRecord, bool, error) {
			return (*p.sleeperMember.Load())(id)
		}
	})
	p.peer = newTestNodeTimeout(t, network, 9, mustSecret(t), 2*time.Second, func(o *Options) {
		o.Log.(*fakeLog).member = func(id types.Identity) (types.NodeRecord, bool, error) {
			p.asked.Add(1)
			return (*p.peerMember.Load())(id)
		}
		o.Leases = func() [][]byte {
			if l := p.leases.Load(); l != nil {
				return *l
			}
			return nil
		}
	})
	p.setPeerMember(lists(p.sleeper))
	p.setSleeperMember(lists(p.peer))
	for e := uint64(6); e < 9; e++ {
		p.peer.keyring.Adopt(e, mustSecret(t))
	}
	return p
}

// lists answers [Log.Member] for a log that lists exactly these nodes.
func lists(nodes ...*testNode) memberFunc {
	return func(id types.Identity) (types.NodeRecord, bool, error) {
		for _, n := range nodes {
			if n.id == id {
				return n.record, true, nil
			}
		}
		return types.NodeRecord{}, false, nil
	}
}

func (p *catchUpPair) setPeerMember(f memberFunc)    { p.peerMember.Store(&f) }
func (p *catchUpPair) setSleeperMember(f memberFunc) { p.sleeperMember.Store(&f) }

func mustSecret(t *testing.T) secrets.Secret {
	t.Helper()
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// aRecord is a genuine log record, for a test that watches records move.
func aRecord(t *testing.T, member types.NodeRecord) types.AUM {
	t.Helper()
	admin, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	disablement := make([]byte, types.DisablementSecretSize)
	if _, err := rand.Read(disablement); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(member.WireGuard[:]); err != nil {
		t.Fatal(err)
	}
	g, err := log.Genesis("catch-up", 1, []types.AdminKey{{Public: admin.Public(), Votes: 1, Name: "admin"}},
		[]types.Hash{types.DisablementCommit(disablement)}, []types.NodeRecord{member},
		func(epoch uint64, nodes []types.NodeRecord) (*types.EpochRecord, error) {
			_, rec, err := secrets.NewEpoch(epoch, nodes)
			return rec, err
		})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Sign(admin); err != nil {
		t.Fatal(err)
	}
	return g
}

// offers is a [Log.Missing] that offers these records to every peer.
func offers(records ...types.AUM) func([]types.Hash, types.Hash) ([]types.AUM, error) {
	return func([]types.Hash, types.Hash) ([]types.AUM, error) { return records, nil }
}

// offering sets it at construction, for a node whose inbound sessions read
// it on their own goroutines.
func offering(records ...types.AUM) func(*Options) {
	return func(o *Options) { o.Log.(*fakeLog).missing = offers(records...) }
}

func (l *fakeLog) informedCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.informed)
}

// signedEndpoint is an announcement for a node no test node is.
func signedEndpoint(t *testing.T, addr netip.AddrPort) (types.Identity, Endpoint) {
	t.Helper()
	priv, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	e := Endpoint{Identity: priv.Public(), Disco: DiscoKey{9}, Addrs: []netip.AddrPort{addr},
		GossipPort: addr.Port(), Seq: 1}
	if err := e.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return priv.Public(), e
}

// A node that holds none of the epochs its peer speaks syncs again through a
// catch-up, both ways, in one round.
func TestANodeNoEpochReachesCatchesUp(t *testing.T) {
	p := newCatchUpPair(t)
	third, relayed := signedEndpoint(t, netip.MustParseAddrPort("192.0.2.9:41641"))
	p.peer.cache.Add(relayed)
	p.leases.Store(&[][]byte{{0xa1, 0x01, 0x01}})
	leases := make(chan [][]byte, 1)
	p.sleeper.node.opts.OnLeases = func(l [][]byte) { leases <- l }
	p.sleeper.log.missing = offers(aRecord(t, p.sleeper.record))

	// The peer's records, offered from construction.
	p2 := newTestNodeTimeout(t, p.peer.log.network, 9, mustSecret(t), 2*time.Second, offering(aRecord(t, p.peer.record)),
		func(o *Options) { o.Log.(*fakeLog).member = lists(p.sleeper) })
	p2.cache.Add(relayed)
	p.setSleeperMember(lists(p2, p.peer))

	e, _ := p2.announce()
	p.sleeper.cache.Add(e)
	if n := p.sleeper.node.Sync(t.Context(), []types.Identity{p2.id}); n != 1 {
		t.Fatalf("a round reached %d peers, want the one that grants a catch-up", n)
	}
	p2.node.Close()
	if p.sleeper.log.informedCount() != 1 || p2.log.informedCount() != 1 {
		t.Errorf("records moved %d times to the sleeper and %d to the peer, want once each way",
			p.sleeper.log.informedCount(), p2.log.informedCount())
	}
	if _, ok := p.sleeper.cache.Get(third); !ok {
		t.Error("the catch-up did not carry the peer's announcements")
	}
	if _, ok := p2.cache.Get(p.sleeper.id); !ok {
		t.Error("the peer did not learn the sleeper's announcement")
	}
	if p.sleeper.node.Failing(p2.id) || p.sleeper.node.Refused(p2.id) {
		t.Error("a granted catch-up left the peer failing or refused")
	}

	// And the leases, from the pair's own peer.
	if err := p.sleeper.node.CatchUpWith(t.Context(), p.peer.addr()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-leases:
	case <-time.After(time.Second):
		t.Error("the catch-up did not carry the peer's leases")
	}
}

// Whoever grants a catch-up is not yet known to be a member, so the node that
// asked says nothing of itself, the others or the log until its own log
// lists the grantor — here never, as with a former member holding the
// recipient keys the log names.
func TestAGrantFromANonMemberGetsNothing(t *testing.T) {
	p := newCatchUpPair(t)
	p.setSleeperMember(lists()) // the peer is nobody the sleeper's log lists
	p.sleeper.log.missing = offers(aRecord(t, p.sleeper.record))
	third, relayed := signedEndpoint(t, netip.MustParseAddrPort("192.0.2.9:41641"))
	p.sleeper.cache.Add(relayed)
	p.sleeper.node.opts.Leases = func() [][]byte { return [][]byte{{0xa1, 0x01, 0x01}} }
	var leases atomic.Int32
	impostor := newTestNodeTimeout(t, p.peer.log.network, 9, mustSecret(t), 2*time.Second, func(o *Options) {
		o.Log.(*fakeLog).member = lists(p.sleeper)
		o.OnLeases = func([][]byte) { leases.Add(1) }
	})

	if err := p.sleeper.node.SyncWith(t.Context(), impostor.addr(), types.Identity{}); err == nil {
		t.Fatal("a catch-up granted by a non-member completed")
	}
	impostor.node.Close() // waits its session out
	if _, ok := impostor.cache.Get(p.sleeper.id); ok {
		t.Error("the non-member got the sleeper's own announcement")
	}
	if _, ok := impostor.cache.Get(third); ok {
		t.Error("the non-member got the announcements the sleeper holds")
	}
	if impostor.log.informedCount() != 0 {
		t.Error("the non-member got the sleeper's records")
	}
	if leases.Load() != 0 {
		t.Error("the non-member got the sleeper's leases")
	}
}

// A refusal counts only when a member this node's log lists signs it, and
// that member is past this node's epoch: anyone else may say anything, and a
// member behind has only not seen this node admitted yet.
func TestOnlyAMemberAheadRefuses(t *testing.T) {
	p := newCatchUpPair(t)
	p.setPeerMember(lists())

	p.setSleeperMember(lists())
	if err := p.sleeper.node.CatchUpWith(t.Context(), p.peer.addr()); err == nil || errors.Is(err, ErrCatchUpRefused) {
		t.Errorf("a refusal by a non-member: %v, want a failure that is not a refusal", err)
	}
	p.setSleeperMember(lists(p.peer))
	if err := p.sleeper.node.CatchUpWith(t.Context(), p.peer.addr()); !errors.Is(err, ErrCatchUpRefused) {
		t.Errorf("a refusal by a member ahead: %v, want a refusal", err)
	}

	behind := newTestNodeTimeout(t, p.peer.log.network, 2, mustSecret(t), 2*time.Second)
	p.setSleeperMember(lists(behind))
	if err := p.sleeper.node.CatchUpWith(t.Context(), behind.addr()); err == nil || errors.Is(err, ErrCatchUpRefused) {
		t.Errorf("a refusal by a member not ahead: %v, want a failure that is not a refusal", err)
	}
}

// A refusal whose signature does not verify is no refusal, whoever it names.
func TestAnUnsignedRefusalIsNoRefusal(t *testing.T) {
	p := newCatchUpPair(t)
	at := fakeResponder(t, func(c net.Conn) {
		if _, err := readBlob(c); err != nil {
			return
		}
		if writeCatchUp(c, &catchUpMsg{Step: stepChallenge, Nonce: make([]byte, catchUpNonceSize)}) != nil {
			return
		}
		if _, err := readCatchUp(c); err != nil {
			return
		}
		id, sig := p.peer.id, types.Sig{1}
		_ = writeCatchUp(c, &catchUpMsg{Step: stepRefused, Identity: &id, Sig: &sig, Epoch: 99})
	})
	if err := p.sleeper.node.CatchUpWith(t.Context(), at); err == nil || errors.Is(err, ErrCatchUpRefused) {
		t.Fatalf("a forged refusal: %v, want a failure that is not a refusal", err)
	}
}

// fakeResponder serves every connection with serve, returning its address.
func fakeResponder(t *testing.T, serve func(net.Conn)) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				serve(c)
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

// A node that still shares an epoch with its peer never asks: the ordinary
// session is what runs.
func TestASharedEpochNeedsNoCatchUp(t *testing.T) {
	network := types.Hash{1}
	shared := mustSecret(t)
	var asked atomic.Bool
	behind := newTestNode(t, network, 2, shared)
	ahead := newTestNodeTimeout(t, network, 2, shared, 2*time.Second, func(o *Options) {
		o.Log.(*fakeLog).epoch = 5
		o.Log.(*fakeLog).member = func(types.Identity) (types.NodeRecord, bool, error) {
			asked.Store(true)
			return types.NodeRecord{}, false, nil
		}
	})
	for e := uint64(3); e <= 5; e++ {
		ahead.keyring.Adopt(e, mustSecret(t))
	}
	if err := behind.node.SyncWith(t.Context(), ahead.addr(), ahead.id); err != nil {
		t.Fatal(err)
	}
	if asked.Load() {
		t.Fatal("a node that shares an epoch with its peer asked for a catch-up")
	}
}

// A node whose keyring is empty — its wraps sealed to keys it no longer
// holds — catches up too.
func TestAnEmptyKeyringCatchesUp(t *testing.T) {
	p := newCatchUpPair(t)
	empty := newTestNodeTimeout(t, p.peer.log.network, 2, mustSecret(t), 2*time.Second, func(o *Options) {
		o.Keyring = keyring.New()
		o.Log.(*fakeLog).member = lists(p.peer)
	})
	p.setPeerMember(lists(empty))
	if err := empty.node.SyncWith(t.Context(), p.peer.addr(), p.peer.id); err != nil {
		t.Fatalf("a node holding no epoch did not catch up: %v", err)
	}
}

// A device the peer's log does not list is told so, which is what status
// reports as most likely removed; a later round that does not reach the peer,
// or one that is granted, clears it.
func TestACatchUpForAnUnlistedDeviceIsRefused(t *testing.T) {
	p := newCatchUpPair(t)
	var listed atomic.Bool
	p.setPeerMember(func(id types.Identity) (types.NodeRecord, bool, error) {
		return p.sleeper.record, listed.Load(), nil
	})
	err := p.sleeper.node.SyncWith(t.Context(), p.peer.addr(), p.peer.id)
	if !errors.Is(err, ErrCatchUpRefused) {
		t.Fatalf("an unlisted device's sync ended in %v, want a refusal", err)
	}
	e, _ := p.peer.announce()
	p.sleeper.cache.Add(e)
	p.sleeper.node.Sync(t.Context(), []types.Identity{p.peer.id})
	if !p.sleeper.node.Refused(p.peer.id) || !p.sleeper.node.Failing(p.peer.id) {
		t.Fatal("a refused round did not read as refused and failing")
	}
	p.sleeper.node.opts.OverlayOnly = true // a round that reaches no address
	p.sleeper.node.Sync(t.Context(), []types.Identity{p.peer.id})
	if p.sleeper.node.Refused(p.peer.id) {
		t.Fatal("a round that did not reach the peer left its old refusal standing")
	}
	p.sleeper.node.opts.OverlayOnly = false
	listed.Store(true)
	p.sleeper.node.Sync(t.Context(), []types.Identity{p.peer.id})
	if p.sleeper.node.Refused(p.peer.id) || p.sleeper.node.Failing(p.peer.id) {
		t.Fatal("a granted round left the peer refused or failing")
	}
}

// A peer that cannot say who is listed — under an alarm, or removed itself —
// answers nothing rather than a refusal the device would read as its own
// removal.
func TestAPeerThatCannotVouchAnswersNoCatchUp(t *testing.T) {
	p := newCatchUpPair(t)
	p.setPeerMember(func(types.Identity) (types.NodeRecord, bool, error) {
		return types.NodeRecord{}, false, errors.New("alarm")
	})
	err := p.sleeper.node.SyncWith(t.Context(), p.peer.addr(), p.peer.id)
	if err == nil || errors.Is(err, ErrCatchUpRefused) {
		t.Fatalf("got %v, want a failure that is not a refusal", err)
	}
}

// The grant is sealed to the recipient keys the peer's log names, so a device
// holding other keys cannot open it.
func TestAGrantOpensOnlyUnderTheListedKeys(t *testing.T) {
	p := newCatchUpPair(t)
	other, err := secrets.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	p.sleeper.node.SetRecipient(other)
	if err := p.sleeper.node.CatchUpWith(t.Context(), p.peer.addr()); err == nil {
		t.Fatal("a grant sealed to the listed keys opened under others")
	}
}

// A build without catch-up hangs up on the ask, as on any frame under an
// epoch it does not hold; the asker reports it and marks nothing refused.
func TestAnOlderBuildHangsUpOnTheAsk(t *testing.T) {
	p := newCatchUpPair(t)
	var asks atomic.Int32
	real := fakeResponder(t, func(c net.Conn) {
		// What a session before catch-up did with its first frame.
		blob, err := readBlob(c)
		if err != nil {
			return
		}
		if isCatchUp(blob) {
			asks.Add(1)
		}
		if _, _, err := open(p.peer.keyring, blob); err == nil {
			t.Error("an older build could open a frame from a node holding none of its epochs")
		}
	})
	announced := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), real.Port())
	testAddrsMu.Lock()
	testAddrs[announced] = real
	testAddrsMu.Unlock()
	old, e := signedEndpoint(t, announced)
	p.sleeper.cache.Add(e)

	err := p.sleeper.node.SyncWith(t.Context(), announced, old)
	if err == nil || errors.Is(err, ErrCatchUpRefused) || !errors.Is(err, errNoHelloBack) {
		t.Fatalf("against an older build: %v", err)
	}
	if asks.Load() != 1 {
		t.Fatalf("the older build was asked for %d catch-ups, want 1", asks.Load())
	}
	p.sleeper.node.Sync(t.Context(), []types.Identity{old})
	if p.sleeper.node.Refused(old) || !p.sleeper.node.Failing(old) {
		t.Fatal("an older build hanging up read as a refusal, or not as failing")
	}
}

// rawAsk opens a connection to the peer and reads the challenge an ask draws.
func rawAsk(t *testing.T, to *testNode) (net.Conn, []byte) {
	t.Helper()
	c, err := net.Dial("tcp", to.real.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := writeCatchUp(c, &catchUpMsg{Step: stepAsk}); err != nil {
		t.Fatal(err)
	}
	ch, err := readCatchUp(c)
	if err != nil || ch.Step != stepChallenge {
		t.Fatalf("an ask drew %v, %v; want a challenge", ch.Step, err)
	}
	return c, ch.Nonce
}

// hangsUp asserts the peer closes the connection without answering, rather
// than letting it time out.
func hangsUp(t *testing.T, c net.Conn, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var scratch [1]byte
	_, err := c.Read(scratch[:])
	if err == nil {
		t.Fatalf("%s: the peer answered", what)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("%s: the peer neither answered nor hung up", what)
	}
}

// A proof counts only as a signature by the identity it names, over the
// nonce this peer drew for this connection, in this network. Anything else
// gets nothing — not even a refusal, and not a look at the log.
func TestACatchUpProofMustBeFreshAndOwn(t *testing.T) {
	p := newCatchUpPair(t)
	network := p.peer.log.network
	id := p.sleeper.id
	sign := func(priv types.PrivateIdentity, net types.Hash, nonce []byte) *types.Sig {
		sig, err := priv.Sign(catchUpProofBytes(net, nonce, id))
		if err != nil {
			t.Fatal(err)
		}
		return &sig
	}
	stranger, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	// Recorded from a session that was granted.
	c, nonce := rawAsk(t, p.peer)
	replayed := sign(p.sleeper.priv, network, nonce)
	if err := writeCatchUp(c, &catchUpMsg{Step: stepProof, Identity: &id, Sig: replayed}); err != nil {
		t.Fatal(err)
	}
	if m, err := readCatchUp(c); err != nil || m.Step != stepGrant {
		t.Fatalf("an honest proof drew %v, %v; want a grant", m.Step, err)
	}
	p.asked.Store(0)

	cases := []struct {
		name string
		sig  func(nonce []byte) *types.Sig
	}{
		{"a replayed proof", func([]byte) *types.Sig { return replayed }},
		{"a foreign signature", func(n []byte) *types.Sig { return sign(stranger, network, n) }},
		{"a nonce the peer did not draw", func([]byte) *types.Sig {
			return sign(p.sleeper.priv, network, make([]byte, catchUpNonceSize))
		}},
		{"another network's proof", func(n []byte) *types.Sig { return sign(p.sleeper.priv, types.Hash{2}, n) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, nonce := rawAsk(t, p.peer)
			if err := writeCatchUp(c, &catchUpMsg{Step: stepProof, Identity: &id, Sig: tc.sig(nonce)}); err != nil {
				t.Fatal(err)
			}
			hangsUp(t, c, tc.name)
			if p.asked.Load() != 0 {
				t.Fatalf("%s reached the log", tc.name)
			}
		})
	}
}

// An ask counts against the budget for connections that have said nothing
// until its proof is granted.
func TestAnUnprovedAskHoldsOnlyASilentSlot(t *testing.T) {
	p := newCatchUpPair(t)
	var held []net.Conn
	for range maxUnauthPerSource + 2 {
		c, _ := rawAsk(t, p.peer)
		held = append(held, c)
	}
	silent := p.peer.node.silent.Count(netip.MustParseAddr("127.0.0.1"))
	if silent > maxUnauthPerSource {
		t.Fatalf("%d unproved asks hold silent slots, over the %d cap", silent, maxUnauthPerSource)
	}
	hangsUp(t, held[0], "an evicted ask")

	// A granted catch-up from the same address still gets through.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := p.sleeper.node.CatchUpWith(ctx, p.peer.real); err != nil {
		t.Fatalf("a catch-up was refused while unproved asks were held: %v", err)
	}
}

// Once granted, a session stays under the grant's key: a frame sealed under
// an epoch, even one the peer holds, ends it.
func TestACatchUpSessionCannotMoveToAnEpoch(t *testing.T) {
	p := newCatchUpPair(t)
	c, nonce := rawAsk(t, p.peer)
	id := p.sleeper.id
	sig, err := p.sleeper.priv.Sign(catchUpProofBytes(p.peer.log.network, nonce, id))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeCatchUp(c, &catchUpMsg{Step: stepProof, Identity: &id, Sig: &sig}); err != nil {
		t.Fatal(err)
	}
	if m, err := readCatchUp(c); err != nil || m.Step != stepGrant {
		t.Fatalf("got %v, %v; want a grant", m.Step, err)
	}
	hello := frame{Kind: kindHello, Network: p.peer.log.network, Epoch: 9, Anchor: types.Hash{0xa}}
	if err := p.peer.node.writeSealed(c, &sessionSeal{epoch: 9}, &hello); err != nil {
		t.Fatal(err)
	}
	hangsUp(t, c, "a frame sealed under an epoch in a granted session")
}

// Every step decodes to exactly what was encoded, and a step carrying
// another's fields is refused.
func TestCatchUpMessagesAreStrict(t *testing.T) {
	id := types.Identity{1}
	sig := types.Sig{2}
	sealed := make([]byte, types.SealedSecretSize)
	good := []catchUpMsg{
		{Step: stepAsk},
		{Step: stepChallenge, Nonce: make([]byte, catchUpNonceSize)},
		{Step: stepProof, Identity: &id, Sig: &sig},
		{Step: stepGrant, Sealed: sealed, Identity: &id, Sig: &sig},
		{Step: stepRefused, Identity: &id, Sig: &sig, Epoch: 3},
	}
	for i := range good {
		b, err := encode(&good[i])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeCatchUp(b); err != nil {
			t.Errorf("%v: %v", good[i].Step, err)
		}
	}
	bad := []catchUpMsg{
		{Step: stepInvalid},
		{Step: 9},
		{Step: stepAsk, Nonce: make([]byte, catchUpNonceSize)},
		{Step: stepAsk, Epoch: 1},
		{Step: stepChallenge, Nonce: make([]byte, 16)},
		{Step: stepChallenge, Nonce: make([]byte, catchUpNonceSize), Sealed: []byte{1}},
		{Step: stepProof, Identity: &id},
		{Step: stepProof, Sig: &sig},
		{Step: stepGrant, Sealed: sealed},
		{Step: stepGrant, Sealed: make([]byte, 16), Identity: &id, Sig: &sig},
		{Step: stepRefused, Identity: &id, Sig: &sig},
		{Step: stepRefused, Epoch: 3},
	}
	for i := range bad {
		b, err := encode(&bad[i])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeCatchUp(b); err == nil {
			t.Errorf("accepted %+v", bad[i])
		}
	}
}

// Whatever well-formed step a peer answers the proof with, the node that
// asked fails the session and nothing more.
func TestAnyAnswerToTheProofIsSurvived(t *testing.T) {
	p := newCatchUpPair(t)
	for _, answer := range []catchUpMsg{
		{Step: stepAsk},
		{Step: stepChallenge, Nonce: make([]byte, catchUpNonceSize)},
	} {
		at := fakeResponder(t, func(c net.Conn) {
			if _, err := readBlob(c); err != nil {
				return
			}
			if writeCatchUp(c, &catchUpMsg{Step: stepChallenge, Nonce: make([]byte, catchUpNonceSize)}) != nil {
				return
			}
			if _, err := readCatchUp(c); err != nil {
				return
			}
			_ = writeCatchUp(c, &answer)
		})
		if err := p.sleeper.node.CatchUpWith(t.Context(), at); err == nil {
			t.Errorf("a %v in answer to the proof was taken for a grant", answer.Step)
		}
	}
}
