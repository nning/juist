package gossip

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/nning/juist/internal/keyring"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// m14Endpoint and m14Frame are the wire as builds before epochs in
// announcements read it, strictly as they do.
type m14Endpoint struct {
	Identity   types.Identity   `cbor:"1,keyasint"`
	Disco      DiscoKey         `cbor:"2,keyasint"`
	Addrs      []netip.AddrPort `cbor:"3,keyasint,omitempty"`
	GossipPort uint16           `cbor:"4,keyasint"`
	Seq        uint64           `cbor:"5,keyasint"`
	Relay      *RelayInfo       `cbor:"6,keyasint,omitempty"`
	HomeRelay  uint16           `cbor:"7,keyasint,omitempty"`
	Exit       bool             `cbor:"8,keyasint,omitempty"`
	Subnets    bool             `cbor:"9,keyasint,omitempty"`
	DNS        uint16           `cbor:"10,keyasint,omitempty"`
	NoV4       bool             `cbor:"11,keyasint,omitempty"`
	Published  bool             `cbor:"12,keyasint,omitempty"`
	Share      *Share           `cbor:"13,keyasint,omitempty"`
	Sealed     []byte           `cbor:"14,keyasint,omitempty"`
	Sig        types.Sig        `cbor:"23,keyasint"`
}

type m14Frame struct {
	Kind      frameKind     `cbor:"1,keyasint"`
	Network   types.Hash    `cbor:"2,keyasint"`
	Epoch     uint64        `cbor:"3,keyasint"`
	Head      types.Hash    `cbor:"4,keyasint"`
	Have      []types.Hash  `cbor:"5,keyasint,omitempty"`
	Anchor    types.Hash    `cbor:"9,keyasint"`
	Records   [][]byte      `cbor:"6,keyasint,omitempty"`
	Self      *m14Endpoint  `cbor:"7,keyasint,omitempty"`
	Endpoints []m14Endpoint `cbor:"8,keyasint,omitempty"`
	Leases    [][]byte      `cbor:"10,keyasint,omitempty"`
	Waiting   []byte        `cbor:"11,keyasint,omitempty"`
	Keys      []AddrKey     `cbor:"12,keyasint,omitempty"`
}

// A peer that takes the connection and says nothing failed otherwise than
// one whose address takes none, though the catch-up asked of it then finds
// none: only the latter is a firewall's doing.
func TestAConnectionThatSaysNothingIsNoFirewall(t *testing.T) {
	network := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	a := newTestNode(t, network, 3, s)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		// One connection, closed unanswered; the catch-up that follows
		// then finds no listener.
		c, err := ln.Accept()
		ln.Close()
		if err == nil {
			c.Close()
		}
	}()
	peer := newTestNode(t, network, 3, s)
	e, _ := peer.announce()
	e.Addrs, e.GossipPort = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.78:1")}, 1
	if err := e.Sign(peer.priv); err != nil {
		t.Fatal(err)
	}
	testAddrsMu.Lock()
	testAddrs[e.Addrs[0]] = netip.MustParseAddrPort(ln.Addr().String())
	testAddrsMu.Unlock()
	a.cache.Add(e)
	a.node.Sync(t.Context(), []types.Identity{peer.id})
	if got := a.node.Failed(peer.id); got != FailOther {
		t.Fatalf("a connection that says nothing reads as failure %d", got)
	}
	a.node.Sync(t.Context(), []types.Identity{peer.id})
	if got := a.node.Failed(peer.id); got != FailUnconnected {
		t.Fatalf("an address that takes no connection reads as failure %d", got)
	}
}

// tap keeps what passes through a connection in one direction.
type tap struct {
	net.Conn
	mu      sync.Mutex
	written bool
	buf     bytes.Buffer
}

func (t *tap) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	if !t.written {
		t.mu.Lock()
		t.buf.Write(b[:n])
		t.mu.Unlock()
	}
	return n, err
}

func (t *tap) Write(b []byte) (int, error) {
	if t.written {
		t.mu.Lock()
		t.buf.Write(b)
		t.mu.Unlock()
	}
	return t.Conn.Write(b)
}

// frames opens the blobs tapped, as a peer holding s would.
func (t *tap) frames(tb testing.TB, s secrets.Secret, epoch uint64) [][]byte {
	tb.Helper()
	t.mu.Lock()
	defer t.mu.Unlock()
	kr := keyring.New()
	kr.Adopt(epoch, s)
	var out [][]byte
	b := t.buf.Bytes()
	for len(b) >= 4 {
		size := int(binary.BigEndian.Uint32(b))
		if len(b) < 4+size {
			tb.Fatalf("a frame cut short: %d of %d bytes", len(b)-4, size)
		}
		_, pt, err := open(kr, b[4:4+size])
		if err != nil {
			tb.Fatal(err)
		}
		out = append(out, pt)
		b = b[4+size:]
	}
	return out
}

// tapping has node tn's outbound sessions keep what one direction carries:
// what it writes, or what it reads.
func tapping(written bool, taps *[]*tap) func(*Options) {
	return func(o *Options) {
		dial := o.Dial
		o.Dial = func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			c, err := dial(ctx, addr)
			if err != nil {
				return nil, err
			}
			t := &tap{Conn: c, written: written}
			*taps = append(*taps, t)
			return t, nil
		}
	}
}

// pqAnnouncing has a node announce an epoch, as every member does in a
// network at [types.SchemaPQ].
func pqAnnouncing(tn **testNode) func(*Options) {
	return func(o *Options) {
		o.Announce = func() (Endpoint, bool) {
			e, _ := (*tn).announce()
			e.Epoch, e.PairStore = 3, 7
			if err := e.Sign((*tn).priv); err != nil {
				panic(err)
			}
			return e, true
		}
	}
}

// signedPQ is an announcement of a third member naming an epoch.
func signedPQ(t *testing.T) Endpoint {
	t.Helper()
	priv, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	e := Endpoint{Identity: priv.Public(), Disco: DiscoKey{9}, Addrs: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.9:1")},
		GossipPort: 1, Seq: 1, Epoch: 3, PairStore: 9}
	if err := e.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return e
}

// A peer that announces no epoch, a build before them, is sent no
// announcement naming one, in either direction: it refuses a whole frame
// that carries one, and would never take the records that tell it to update.
func TestAPeerAnnouncingNoEpochReadsEveryFrame(t *testing.T) {
	network := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	var outbound, inbound []*tap
	var a *testNode
	a = newTestNodeTimeout(t, network, 3, s, 2*time.Second, pqAnnouncing(&a), tapping(true, &outbound))
	old := newTestNodeTimeout(t, network, 3, s, 2*time.Second, tapping(false, &inbound))
	third := signedPQ(t)
	a.cache.Add(third)
	unchanged, _ := newTestNode(t, network, 3, s).announce()
	a.cache.Add(unchanged)
	oldAnn, _ := old.announce()
	a.cache.Add(oldAnn)

	if err := a.node.SyncWith(t.Context(), old.addr(), old.id); err != nil {
		t.Fatalf("this node reaching the older one: %v", err)
	}
	if err := old.node.SyncWith(t.Context(), a.addr(), a.id); err != nil {
		t.Fatalf("the older node reaching this one: %v", err)
	}
	if len(outbound) != 1 || len(inbound) != 1 {
		t.Fatalf("%d sessions out, %d in", len(outbound), len(inbound))
	}
	sent := append(outbound[0].frames(t, s, 3), inbound[0].frames(t, s, 3)...)
	if len(sent) != 4 {
		t.Fatalf("%d frames sent to the older node, want a hello and records each way", len(sent))
	}
	for i, pt := range sent {
		var f m14Frame
		if err := decMode.Unmarshal(pt, &f); err != nil {
			t.Errorf("frame %d: an older build refuses it: %v", i, err)
		}
	}
	if _, ok := old.cache.Get(third.Identity); ok {
		t.Error("an announcement naming an epoch reached the older node")
	}
	if _, ok := old.cache.Get(unchanged.Identity); !ok {
		t.Error("an announcement naming none did not reach the older node")
	}
}

// A peer that reads epochs gets them all, though this node held nothing of it
// when its hello went out: the records frame carries what the hello held
// back.
func TestAPeerThatTurnsOutToReadEpochsGetsThemInTheRecords(t *testing.T) {
	network := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	var a, b *testNode
	a = newTestNodeTimeout(t, network, 3, s, 2*time.Second, pqAnnouncing(&a))
	b = newTestNodeTimeout(t, network, 3, s, 2*time.Second, pqAnnouncing(&b))
	third := signedPQ(t)
	a.cache.Add(third)
	if err := a.node.SyncWith(t.Context(), b.addr(), types.Identity{}); err != nil {
		t.Fatal(err)
	}
	// The responder takes the records frame's after it answered.
	for _, id := range []types.Identity{a.id, third.Identity} {
		deadline := time.Now().Add(5 * time.Second)
		for e, ok := b.cache.Get(id); !ok || !e.PQ(); e, ok = b.cache.Get(id) {
			if time.Now().After(deadline) {
				t.Fatalf("%v did not reach a peer that reads epochs", id.ShortString())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if e, ok := a.cache.Get(b.id); !ok || !e.PQ() {
		t.Error("the responder's announcement did not reach the initiator")
	}
}

// A frame naming a field this build does not know reads as a newer build's,
// not as a connection that never came up.
func TestAFrameFromANewerBuildReadsAsNewer(t *testing.T) {
	type newer struct {
		frame
		Later uint64 `cbor:"30,keyasint"`
	}
	network := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	a := newTestNode(t, network, 3, s)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if _, err := readBlob(c); err != nil {
			return
		}
		pt, err := encMode.Marshal(newer{frame: frame{Kind: kindHello, Network: network, Epoch: 3}, Later: 1})
		if err != nil {
			panic(err)
		}
		blob, err := seal(s, 3, pt)
		if err != nil {
			panic(err)
		}
		_ = writeBlob(c, blob, "hello")
		_, _ = readBlob(c)
	}()
	peer := newTestNode(t, network, 3, s)
	e, _ := peer.announce()
	e.Addrs, e.GossipPort = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.77:1")}, 1
	if err := e.Sign(peer.priv); err != nil {
		t.Fatal(err)
	}
	testAddrsMu.Lock()
	testAddrs[e.Addrs[0]] = netip.MustParseAddrPort(ln.Addr().String())
	testAddrsMu.Unlock()
	a.cache.Add(e)
	a.node.Sync(t.Context(), []types.Identity{peer.id})
	if got := a.node.Failed(peer.id); got != FailNewer {
		t.Fatalf("a newer build's frame reads as failure %d", got)
	}
}
