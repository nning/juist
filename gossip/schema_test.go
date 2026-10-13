package gossip

import (
	"net/netip"
	"testing"
	"time"

	"github.com/nning/juist/internal/pairkey"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// m15Endpoint and m15Frame are the wire as builds before announcements named
// their build's schema read it, strictly as they do.
type m15Endpoint struct {
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
	Epoch      uint64           `cbor:"15,keyasint,omitempty"`
	PairStore  uint64           `cbor:"16,keyasint,omitempty"`
	Sig        types.Sig        `cbor:"23,keyasint"`
}

type m15Frame struct {
	Kind      frameKind     `cbor:"1,keyasint"`
	Network   types.Hash    `cbor:"2,keyasint"`
	Epoch     uint64        `cbor:"3,keyasint"`
	Head      types.Hash    `cbor:"4,keyasint"`
	Have      []types.Hash  `cbor:"5,keyasint,omitempty"`
	Anchor    types.Hash    `cbor:"9,keyasint"`
	Records   [][]byte      `cbor:"6,keyasint,omitempty"`
	Self      *m15Endpoint  `cbor:"7,keyasint,omitempty"`
	Endpoints []m15Endpoint `cbor:"8,keyasint,omitempty"`
	Leases    [][]byte      `cbor:"10,keyasint,omitempty"`
	Waiting   []byte        `cbor:"11,keyasint,omitempty"`
	Keys      []AddrKey     `cbor:"12,keyasint,omitempty"`
	Pair      *pairkey.Msg  `cbor:"13,keyasint,omitempty"`
}

// schemaAnnouncing has a node announce an epoch and its build's schema, as
// every member does in a network at [types.SchemaPadded].
func schemaAnnouncing(tn **testNode) func(*Options) {
	return func(o *Options) {
		o.Announce = func() (Endpoint, bool) {
			e, _ := (*tn).announce()
			e.Epoch, e.PairStore, e.Schema = 3, 7, types.CurrentSchema
			if err := e.Sign((*tn).priv); err != nil {
				panic(err)
			}
			return e, true
		}
	}
}

// signedSchema is an announcement of a third member naming its build's
// schema.
func signedSchema(t *testing.T) Endpoint {
	t.Helper()
	e := signedPQ(t)
	priv, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	e.Identity, e.Schema = priv.Public(), types.CurrentSchema
	if err := e.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return e
}

// A peer that announces no schema, a build before them, is sent no
// announcement naming one, in either direction, but still those naming an
// epoch, which it reads.
func TestAPeerAnnouncingNoSchemaReadsEveryFrame(t *testing.T) {
	network := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	var outbound, inbound []*tap
	var a, old *testNode
	a = newTestNodeTimeout(t, network, 3, s, 2*time.Second, schemaAnnouncing(&a), tapping(true, &outbound))
	old = newTestNodeTimeout(t, network, 3, s, 2*time.Second, pqAnnouncing(&old), tapping(false, &inbound))
	third, pq := signedSchema(t), signedPQ(t)
	a.cache.Add(third)
	a.cache.Add(pq)
	oldAnn, _ := old.node.opts.Announce()
	a.cache.Add(oldAnn)
	// What the older node held of this one from before the upgrade.
	before, _ := a.announce()
	before.Epoch, before.PairStore = 3, 7
	if err := before.Sign(a.priv); err != nil {
		t.Fatal(err)
	}
	old.cache.Add(before)

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
		var f m15Frame
		if err := decMode.Unmarshal(pt, &f); err != nil {
			t.Errorf("frame %d: an older build refuses it: %v", i, err)
		}
	}
	if _, ok := old.cache.Get(third.Identity); ok {
		t.Error("an announcement naming a schema reached the older node")
	}
	if _, ok := old.cache.Get(pq.Identity); !ok {
		t.Error("an announcement naming an epoch alone did not reach the older node")
	}
}

// A peer that reads schemas gets them all, though this node held nothing of
// it when its hello went out.
func TestAPeerThatTurnsOutToReadSchemasGetsThemInTheRecords(t *testing.T) {
	network := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	var a, b *testNode
	a = newTestNodeTimeout(t, network, 3, s, 2*time.Second, schemaAnnouncing(&a))
	b = newTestNodeTimeout(t, network, 3, s, 2*time.Second, schemaAnnouncing(&b))
	third := signedSchema(t)
	a.cache.Add(third)
	if err := a.node.SyncWith(t.Context(), b.addr(), types.Identity{}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []types.Identity{a.id, third.Identity} {
		deadline := time.Now().Add(5 * time.Second)
		for e, ok := b.cache.Get(id); !ok || e.Schema == 0; e, ok = b.cache.Get(id) {
			if time.Now().After(deadline) {
				t.Fatalf("%v did not reach a peer that reads schemas", id.ShortString())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if e, ok := a.cache.Get(b.id); !ok || e.Schema == 0 {
		t.Error("the responder's announcement did not reach the initiator")
	}
}

// Below [types.SchemaPadded] an announcement naming a schema is dropped and
// refused, as older members refuse a frame that carries one.
func TestACacheBelowThePaddedSchemaRefusesSchemas(t *testing.T) {
	c := NewCache()
	e := signedSchema(t)
	if !c.Add(e) {
		t.Fatal("refused an announcement naming a schema")
	}
	c.SetSchemas(false)
	if _, ok := c.Get(e.Identity); ok {
		t.Error("kept an announcement naming a schema")
	}
	if c.Add(e) {
		t.Error("took an announcement naming a schema")
	}
}
