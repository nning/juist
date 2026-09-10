package mdns

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/nettest"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// hub is a fake multicast group: every datagram one member writes reaches all
// the others. Linux loopback carries no multicast, so a real join would leave
// these tests skipping — and what matters here is the DNS encoding, the
// blinded naming and the sealing, which this exercises as the socket would.
type hub struct {
	mu      sync.Mutex
	members []*hubConn
}

type hubConn struct {
	h      *hub
	in     chan []byte
	closed chan struct{}
	once   sync.Once
}

func (h *hub) join() *hubConn {
	c := &hubConn{h: h, in: make(chan []byte, 64), closed: make(chan struct{})}
	h.mu.Lock()
	h.members = append(h.members, c)
	h.mu.Unlock()
	return c
}

func (c *hubConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case pkt := <-c.in:
		return copy(b, pkt), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *hubConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	pkt := append([]byte(nil), b...)
	c.h.mu.Lock()
	members := append([]*hubConn(nil), c.h.members...)
	c.h.mu.Unlock()
	for _, m := range members {
		if m == c {
			// A sender does not hear its own multicast, and nothing here
			// may depend on doing so.
			continue
		}
		select {
		case m.in <- pkt:
		default: // a congested group drops, as a real one would
		}
	}
	return len(b), nil
}

func (c *hubConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

type beaconNode struct {
	id     types.Identity
	beacon *Beacon
	seen   chan gossip.Endpoint
}

func newBeaconNode(t *testing.T, h *hub, kr *secrets.Keyring, port uint16) *beaconNode {
	t.Helper()
	priv, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	n := &beaconNode{id: priv.Public(), seen: make(chan gossip.Endpoint, 16)}
	announce := func() (gossip.Endpoint, bool) {
		e := gossip.Endpoint{
			Identity:   priv.Public(),
			Disco:      gossip.DiscoKey{4, 2},
			Addrs:      []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), port)},
			GossipPort: port,
			Seq:        1,
		}
		if err := e.Sign(priv); err != nil {
			t.Errorf("signing an announcement: %v", err)
			return gossip.Endpoint{}, false
		}
		return e, true
	}
	b, err := New(Options{
		Keyring:  kr,
		Announce: announce,
		OnPeer: func(e gossip.Endpoint) {
			select {
			case n.seen <- e:
			default:
			}
		},
		Interval: 50 * time.Millisecond,
		Conn:     h.join(),
		Dst:      netip.MustParseAddrPort("224.0.0.251:5353"),
		Logf:     t.Logf,
	})
	if err != nil {
		t.Fatalf("opening a beacon: %v", err)
	}
	n.beacon = b
	go b.Run(t.Context())
	t.Cleanup(func() { b.Close() })
	return n
}

func keyringAt(t *testing.T, epoch uint64, s secrets.Secret) *secrets.Keyring {
	t.Helper()
	kr := secrets.NewKeyring()
	kr.Adopt(epoch, s)
	return kr
}

func mustSecret(t *testing.T) secrets.Secret {
	t.Helper()
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func waitFor(t *testing.T, n *beaconNode, want types.Identity, d time.Duration) {
	t.Helper()
	if !sawWithin(n, want, d) {
		t.Fatalf("node did not discover %v within %v", want.ShortString(), d)
	}
}

// sawWithin reports whether n discovered want before d elapsed.
func sawWithin(n *beaconNode, want types.Identity, d time.Duration) bool {
	deadline := time.After(d)
	for {
		select {
		case e := <-n.seen:
			if e.Identity == want {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

// TestMembersFindEachOther is the LAN half of M2's third exit criterion: two
// members on one network segment, no internet and no coordination server, and
// each learns where the other is.
func TestMembersFindEachOther(t *testing.T) {
	h := &hub{}
	s := mustSecret(t)
	a := newBeaconNode(t, h, keyringAt(t, 7, s), 4001)
	b := newBeaconNode(t, h, keyringAt(t, 7, s), 4002)

	waitFor(t, a, b.id, 5*time.Second)
	waitFor(t, b, a.id, 5*time.Second)
}

// TestAnotherNetworkIsInvisible covers both halves: the name is blinded, so a
// foreign network's beacons are not recognized as questions, and the payload
// is sealed, so an eavesdropper learns nothing. It is also what a revoked
// device looks like after the epoch bump.
func TestAnotherNetworkIsInvisible(t *testing.T) {
	h := &hub{}
	member := newBeaconNode(t, h, keyringAt(t, 7, mustSecret(t)), 4001)
	stranger := newBeaconNode(t, h, keyringAt(t, 7, mustSecret(t)), 4002)

	select {
	case e := <-member.seen:
		t.Fatalf("member accepted an announcement from another network: %v", e.Identity.ShortString())
	case e := <-stranger.seen:
		t.Fatalf("stranger read a member's announcement: %v", e.Identity.ShortString())
	case <-time.After(500 * time.Millisecond):
	}
}

// TestDiscoverySurvivesAnEpochBump is why a beacon answers to every name in
// its keyring: during a convergence round the network holds two adjacent
// epochs, and speaking only its own would go dark to the peers that matter.
func TestDiscoverySurvivesAnEpochBump(t *testing.T) {
	h := &hub{}
	old := mustSecret(t)
	fresh := mustSecret(t)

	behind := newBeaconNode(t, h, keyringAt(t, 7, old), 4001)

	aheadKR := keyringAt(t, 7, old)
	aheadKR.Adopt(8, fresh)
	ahead := newBeaconNode(t, h, aheadKR, 4002)

	waitFor(t, behind, ahead.id, 5*time.Second)
	waitFor(t, ahead, behind.id, 5*time.Second)
}

// TestAnnouncementSealIsBoundToItsEpoch keeps a beacon from opening a payload
// under a key the name did not select — the mDNS-side form of the frame check
// in gossip.
func TestAnnouncementSealIsBoundToItsEpoch(t *testing.T) {
	s := mustSecret(t)
	sealed, err := sealPayload(s, 3, []byte("announcement"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openPayload(s, 4, sealed); err == nil {
		t.Fatal("a payload sealed under epoch 3 opened as epoch 4")
	}
	got, err := openPayload(s, 3, sealed)
	if err != nil {
		t.Fatalf("opening at the right epoch: %v", err)
	}
	if string(got) != "announcement" {
		t.Errorf("payload came back as %q", got)
	}
}

// TestNameIsAValidBlindedLabel pins the two properties the naming has to keep:
// it is a legal DNS name, and it differs per epoch and per network.
func TestNameIsAValidBlindedLabel(t *testing.T) {
	s1, s2 := mustSecret(t), mustSecret(t)
	n1 := name(s1, 1)
	if got := n1.dns.String(); len(got) > 255 || !strings.HasSuffix(got, Service) {
		t.Errorf("name %q is not a %s name", got, Service)
	}
	if name(s1, 2).dns == n1.dns {
		t.Error("the name did not change across epochs")
	}
	if name(s2, 1).dns == n1.dns {
		t.Error("two networks derive the same name")
	}
}

// TestRealMulticastSocket guards what the tests above cannot see, since they
// inject a socket: net.ListenMulticastUDP binds the group address, so
// datagrams leave with a multicast source and the kernel drops them silently.
// The wildcard bind with an explicit per-interface join is what works. A host
// that carries no multicast looks the same as a socket that sends nothing, so
// the assertion binds only where [nettest.RequireEnv] is set.
func TestRealMulticastSocket(t *testing.T) {
	s := mustSecret(t)
	mk := func(port uint16) *beaconNode {
		t.Helper()
		priv, err := types.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		n := &beaconNode{id: priv.Public(), seen: make(chan gossip.Endpoint, 16)}
		b, err := New(Options{
			Keyring: keyringAt(t, 1, s),
			Announce: func() (gossip.Endpoint, bool) {
				e := gossip.Endpoint{
					Identity: priv.Public(), Disco: gossip.DiscoKey{1},
					Addrs:      []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), port)},
					GossipPort: port, Seq: 1,
				}
				return e, e.Sign(priv) == nil
			},
			OnPeer: func(e gossip.Endpoint) {
				select {
				case n.seen <- e:
				default:
				}
			},
			Interval: 200 * time.Millisecond,
			Logf:     t.Logf,
		})
		if err != nil {
			nettest.SkipUnlessRequired(t, "no usable multicast here: %v", err)
		}
		n.beacon = b
		go b.Run(t.Context())
		t.Cleanup(func() { b.Close() })
		return n
	}

	a := mk(5001)
	b := mk(5002)
	// Only one direction is asserted. Both would be strictly better, and on a
	// host where the group loops back it holds — but the property that broke
	// was "no datagram ever leaves the socket", and one arrival disproves it.
	if !sawWithin(a, b.id, 10*time.Second) {
		nettest.SkipUnlessRequired(t,
			"nothing arrived on the multicast group within 10s, so this host "+
				"cannot say whether the socket sends")
	}
}

// TestAnswersAreRateLimited: the blinded name is public on the wire and DNS
// compression packs hundreds of questions into one datagram, so each name is
// answered at most once per [minAnswerInterval] however many arrive.
func TestAnswersAreRateLimited(t *testing.T) {
	h := &hub{}
	s := mustSecret(t)
	priv, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Options{
		Keyring: keyringAt(t, 7, s),
		Announce: func() (gossip.Endpoint, bool) {
			e := gossip.Endpoint{
				Identity: priv.Public(), Disco: gossip.DiscoKey{4, 2},
				GossipPort: 4001, Seq: 1,
			}
			return e, e.Sign(priv) == nil
		},
		// A long interval, so the beacon's own announcements stay out of
		// the count and everything observed is an answer to the flood.
		Interval: time.Minute,
		Conn:     h.join(),
		Dst:      netip.MustParseAddrPort("224.0.0.251:5353"),
		Logf:     t.Logf,
	})
	if err != nil {
		t.Fatalf("opening a beacon: %v", err)
	}
	go b.Run(t.Context())
	t.Cleanup(func() { b.Close() })

	attacker := h.join()
	t.Cleanup(func() { attacker.Close() })

	// One packet, twenty copies of the same question — what a hostile replay
	// looks like after compression, scaled down.
	q := dnsmessage.Message{}
	for range 20 {
		q.Questions = append(q.Questions, dnsmessage.Question{
			Name:  name(s, 7).dns,
			Type:  dnsmessage.TypeTXT,
			Class: dnsmessage.ClassINET,
		})
	}
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}

	// A burst of five such packets inside the interval.
	for range 5 {
		if _, err := attacker.WriteTo(raw, nil); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	answers := 0
	deadline := time.After(500 * time.Millisecond)
	buf := make([]byte, maxMessageSize)
drain:
	for {
		select {
		case pkt := <-attacker.in:
			n := copy(buf, pkt)
			var p dnsmessage.Parser
			hdr, err := p.Start(buf[:n])
			if err == nil && hdr.Response {
				answers++
			}
		case <-deadline:
			break drain
		}
	}
	if answers == 0 {
		t.Fatal("the flood was never answered at all; a real query would go unanswered too")
	}
	if answers > 1 {
		t.Errorf("100 questions inside one interval drew %d answers, want 1", answers)
	}
}
