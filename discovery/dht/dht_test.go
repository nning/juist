package dht

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	anacrolix "github.com/anacrolix/dht/v2"
	"github.com/anacrolix/dht/v2/krpc"
	alog "github.com/anacrolix/log"
	"golang.org/x/time/rate"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// swarm is a private DHT on loopback: the storage nodes a member's puts and
// gets actually reach. Nothing here talks to the public network, and the
// crawler is one of these nodes rather than a separate observer, which is the
// strongest position a DHT participant can take.
type swarm struct {
	t     *testing.T
	nodes []*anacrolix.Server
	addrs []string

	mu      sync.Mutex
	queries []krpc.Msg
}

func newSwarm(t *testing.T, n int) *swarm {
	t.Helper()
	sw := &swarm{t: t}
	for range n {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("binding a swarm socket: %v", err)
		}
		cfg := anacrolix.NewDefaultServerConfig()
		cfg.Conn = conn
		// A loopback swarm cannot satisfy the node-ID-from-IP rule.
		cfg.NoSecurity = true
		cfg.Logger = alog.Default.FilterLevel(alog.Critical)
		// Its own budget per node: the library's default limiter is a package
		// global, so a swarm sharing it drops one another's replies under any
		// burst — which reads as a DHT that simply does not answer.
		cfg.SendLimiter = rate.NewLimiter(rate.Inf, 0)
		cfg.StartingNodes = func() ([]anacrolix.Addr, error) { return sw.starting() }
		cfg.OnQuery = func(q *krpc.Msg, _ net.Addr) bool {
			sw.mu.Lock()
			sw.queries = append(sw.queries, *q)
			sw.mu.Unlock()
			return true
		}
		srv, err := anacrolix.NewServer(cfg)
		if err != nil {
			conn.Close()
			t.Fatalf("starting a swarm node: %v", err)
		}
		t.Cleanup(func() { srv.Close() })
		sw.nodes = append(sw.nodes, srv)
		sw.addrs = append(sw.addrs, srv.Addr().String())
	}
	// Everyone learns everyone: a three-node swarm has no depth to traverse,
	// which keeps these tests about what is published rather than about
	// Kademlia.
	for _, s := range sw.nodes {
		if _, err := s.Bootstrap(); err != nil {
			t.Logf("bootstrapping a swarm node: %v", err)
		}
	}
	return sw
}

func (sw *swarm) starting() ([]anacrolix.Addr, error) { return resolveAll(sw.addrs) }

// seen returns every query the swarm answered.
func (sw *swarm) seen() []krpc.Msg {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return append([]krpc.Msg(nil), sw.queries...)
}

// member is one node of a test network: an identity, an announcement and a
// DHT node wired to the swarm.
type member struct {
	priv types.PrivateIdentity
	id   types.Identity
	ann  gossip.Endpoint
	node *Node

	mu    sync.Mutex
	found map[types.Identity]gossip.Endpoint
}

func newMember(t *testing.T, sw *swarm, kr *secrets.Keyring, name byte, wanted func() []types.Identity) *member {
	t.Helper()
	priv, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	m := &member{priv: priv, id: priv.Public(), found: map[types.Identity]gossip.Endpoint{}}
	var disco gossip.DiscoKey
	if _, err := rand.Read(disco[:]); err != nil {
		t.Fatal(err)
	}
	m.ann = gossip.Endpoint{
		Identity:   m.id,
		Disco:      disco,
		Addrs:      []netip.AddrPort{netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, name}), 41641)},
		GossipPort: 41641,
		Seq:        1,
	}
	if err := m.ann.Sign(priv); err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if wanted == nil {
		wanted = func() []types.Identity { return nil }
	}
	n, err := New(Options{
		Self:       m.id,
		Keyring:    kr,
		Announce:   func() (gossip.Endpoint, bool) { return m.ann, true },
		Wanted:     wanted,
		OnPeer:     m.record,
		Bootstrap:  sw.addrs,
		Conn:       conn,
		NoSecurity: true,
		Clock:      func() time.Time { return time.Unix(1_700_000_000, 0) },
		Logf:       t.Logf,
	})
	if err != nil {
		t.Fatalf("starting a DHT node: %v", err)
	}
	t.Cleanup(func() { n.Close() })
	if _, err := n.srv.Bootstrap(); err != nil {
		t.Logf("bootstrapping: %v", err)
	}
	m.node = n
	return m
}

func (m *member) record(e gossip.Endpoint) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.found[e.Identity] = e
}

func testKeyring(t *testing.T, epoch uint64) *secrets.Keyring {
	t.Helper()
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	kr := secrets.NewKeyring()
	kr.Adopt(epoch, s)
	return kr
}

// TestMembersFindEachOtherThroughTheDHT is the cold start: two members with no
// LAN in common and no cached address meet through the public DHT alone.
func TestMembersFindEachOtherThroughTheDHT(t *testing.T) {
	sw := newSwarm(t, 3)
	kr := testKeyring(t, 4)

	a := newMember(t, sw, kr, 1, nil)
	var bWants []types.Identity
	b := newMember(t, sw, kr, 2, func() []types.Identity { return bWants })
	bWants = []types.Identity{a.id}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := a.node.Publish(ctx); err != nil {
		t.Fatalf("publishing a's announcement: %v", err)
	}
	b.node.Round(ctx)

	b.mu.Lock()
	got, ok := b.found[a.id]
	b.mu.Unlock()
	if !ok {
		t.Fatal("b did not find a through the DHT")
	}
	if got.Disco != a.ann.Disco || len(got.Addrs) != 1 || got.Addrs[0] != a.ann.Addrs[0] {
		t.Errorf("b found %+v, want a's announcement %+v", got, a.ann)
	}
	if err := got.Verify(); err != nil {
		t.Errorf("what came back does not verify: %v", err)
	}
}

// TestCrawlerLearnsNothing is M3b exit criterion (2). The observer here is a
// storage node of the swarm, which is the best-placed participant there is: it
// sees every query and holds the items themselves. It must be able to extract
// neither the network's identity, nor who is a member, nor how many there are.
func TestCrawlerLearnsNothing(t *testing.T) {
	sw := newSwarm(t, 3)
	kr := testKeyring(t, 9)

	const members = 5
	ms := make([]*member, 0, members)
	for i := range members {
		ms = append(ms, newMember(t, sw, kr, byte(i+1), nil))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, m := range ms {
		if err := m.node.Publish(ctx); err != nil {
			t.Fatalf("publishing: %v", err)
		}
	}

	seen := sw.seen()
	if len(seen) == 0 {
		t.Fatal("the swarm saw no queries at all, so this test proves nothing")
	}

	// Whatever an item's bytes are, they must not contain anything a member
	// would recognize: not an identity, not a disco key, not an address.
	var secretsInTheClear []string
	needles := map[string][]byte{}
	for i, m := range ms {
		needles[m.id.ShortString()] = m.id[:]
		needles["disco "+m.id.ShortString()] = m.ann.Disco[:]
		a := m.ann.Addrs[0].Addr().As4()
		needles["address "+m.id.ShortString()] = a[:]
		_ = i
	}
	var puts int
	for _, q := range seen {
		blob := queryBytes(q)
		if q.Q == "put" {
			puts++
		}
		for name, needle := range needles {
			if len(needle) >= 4 && containsBytes(blob, needle) {
				secretsInTheClear = append(secretsInTheClear, name)
			}
		}
	}
	if len(secretsInTheClear) > 0 {
		t.Errorf("a storage node can read %v out of what it was asked to store",
			uniqueStrings(secretsInTheClear))
	}
	if puts == 0 {
		t.Fatal("no put reached the swarm, so nothing was actually observed")
	}

	// Member count. Every item of a network must look like an item of a
	// different network, so nothing may be shared between two of them — and
	// the publisher key is the one field that travels in the clear with every
	// put. One key per member is what makes the count unavailable; one key
	// per network, with per-member salts, would have handed it over.
	keys := map[string]bool{}
	targets := map[string]bool{}
	for _, q := range seen {
		if q.A == nil {
			continue
		}
		if q.A.K != [32]byte{} {
			keys[string(q.A.K[:])] = true
		}
		if q.Q == "get" || q.Q == "put" {
			targets[string(q.A.Target[:])] = true
		}
	}
	if len(keys) != members {
		t.Errorf("%d distinct publisher keys for %d members; items of one network must share nothing",
			len(keys), members)
	}
	if len(targets) != 0 && len(targets) < members {
		t.Errorf("%d distinct addresses for %d members: items are landing on one another",
			len(targets), members)
	}
}

// TestAnItemIsUselessWithoutTheGroupSecret: a device that holds no epoch
// secret — a revoked member past the keyring window, or a stranger — can
// neither compute where a member publishes nor read what is there.
func TestAnItemIsUselessWithoutTheGroupSecret(t *testing.T) {
	sw := newSwarm(t, 3)
	kr := testKeyring(t, 2)
	a := newMember(t, sw, kr, 1, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := a.node.Publish(ctx); err != nil {
		t.Fatalf("publishing: %v", err)
	}

	// An outsider holding a different secret at the same epoch looks in the
	// wrong place and finds nothing.
	outsider := newMember(t, sw, testKeyring(t, 2), 9, nil)
	if _, err := outsider.node.Lookup(ctx, a.id); err == nil {
		t.Error("a device with another network's secret found a member's announcement")
	}
}

// TestARotatedWindowMovesTheRendezvous: the address a member publishes at is
// bound to a time window, so one that leaked stops naming a place members will
// be. Publishing in one window and looking in a much later one must miss.
func TestARotatedWindowMovesTheRendezvous(t *testing.T) {
	sw := newSwarm(t, 3)
	kr := testKeyring(t, 3)
	a := newMember(t, sw, kr, 1, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := a.node.Publish(ctx); err != nil {
		t.Fatalf("publishing: %v", err)
	}

	later := newMember(t, sw, kr, 2, nil)
	// Two windows on, so the lookup's one-window fallback does not reach it.
	later.node.opts.Clock = func() time.Time {
		return time.Unix(1_700_000_000, 0).Add(3 * WindowPeriod)
	}
	if _, err := later.node.Lookup(ctx, a.id); err == nil {
		t.Error("an announcement was found at a rendezvous three windows old")
	}
}

// TestAnnouncementFitsTheItemLimit: BEP 44 caps a value at 1000 bytes, and a
// member whose announcement outgrew it would simply stop being publishable —
// silently, and only for the members with the most addresses.
func TestAnnouncementFitsTheItemLimit(t *testing.T) {
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	e := gossip.Endpoint{
		Identity:   priv.Public(),
		Disco:      gossip.DiscoKey{1},
		GossipPort: 41641,
		Seq:        1,
		HomeRelay:  65535,
		Relay: &gossip.RelayInfo{
			Port: 4443, STUNPort: 4443,
			Cert:     make([]byte, gossip.RelayCertSize),
			HostName: strings.Repeat("a", gossip.MaxRelayHostNameLen),
		},
	}
	// The worst case the schema admits: every address slot filled with the
	// longer family.
	for i := range gossip.MaxEndpointAddrs {
		e.Addrs = append(e.Addrs, netip.AddrPortFrom(
			netip.AddrFrom16([16]byte{0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i + 1)}),
			65535))
	}
	e.Addrs = gossip.SortAddrs(e.Addrs)
	if err := e.Sign(priv); err != nil {
		t.Fatal(err)
	}
	value, err := sealAnnouncement(s, 1, e)
	if err != nil {
		t.Fatalf("the largest announcement the schema admits is not publishable: %v", err)
	}
	t.Logf("largest sealed announcement: %d bytes of the %d BEP 44 allows", len(value), MaxValueSize)
}

// queryBytes renders the parts of a query a storage node actually holds.
func queryBytes(q krpc.Msg) []byte {
	var out []byte
	if q.A != nil {
		switch v := q.A.V.(type) {
		case string:
			out = append(out, v...)
		case []byte:
			out = append(out, v...)
		}
		out = append(out, q.A.Target[:]...)
		out = append(out, q.A.InfoHash[:]...)
		out = append(out, q.A.K[:]...)
		out = append(out, q.A.Salt...)
		out = append(out, q.A.ID[:]...)
	}
	return out
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// FuzzOpenItem covers the one input this package takes from strangers: the
// bytes a DHT storage node hands back. Everything else it touches is its own.
func FuzzOpenItem(f *testing.F) {
	s, err := secrets.NewSecret()
	if err != nil {
		f.Fatal(err)
	}
	kr := secrets.NewKeyring()
	kr.Adopt(3, s)

	priv, err := types.GenerateIdentity()
	if err != nil {
		f.Fatal(err)
	}
	e := gossip.Endpoint{
		Identity:   priv.Public(),
		Disco:      gossip.DiscoKey{1, 2, 3},
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("198.51.100.1:41641")},
		GossipPort: 41641,
		Seq:        1,
	}
	if err := e.Sign(priv); err != nil {
		f.Fatal(err)
	}
	good, err := sealAnnouncement(s, 3, e)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte{})
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := openAnnouncement(kr, in)
		if err != nil {
			return
		}
		// Anything that opens must be a record this node would act on, which
		// means it verified: the seal proves a member wrote it, and only the
		// signature says who it is about.
		if err := got.Verify(); err != nil {
			t.Fatalf("openAnnouncement returned an unverified record: %v", err)
		}
	})
}
