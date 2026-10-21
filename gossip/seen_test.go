package gossip

import (
	"testing"
	"time"

	"github.com/nning/juist/internal/addrkey"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

func seenAlone(o *Options) { o.SeenAlone = func() bool { return true } }

// A hello at SchemaSeen carries what its sender holds, not the announcements
// and keys themselves, and a records frame what the peer lacks of them: a
// key and an announcement still cross from a to b and on to c.
func TestASeenHelloCarriesWhatThePeerLacks(t *testing.T) {
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	var mine AddrKey
	a := newTestNodeTimeout(t, types.Hash{1}, 1, s, 2*time.Second, seenAlone, func(o *Options) {
		o.OwnKey = func() (AddrKey, bool) { return mine, true }
	})
	mine = signedKey(t, a.priv, 2)
	b := newTestNodeTimeout(t, types.Hash{1}, 1, s, 2*time.Second, seenAlone)
	c := newTestNodeTimeout(t, types.Hash{1}, 1, s, 2*time.Second, seenAlone)
	for _, n := range []*testNode{a, b, c} {
		n.cache.SetMembership([]types.Identity{a.id, b.id, c.id}, nil)
	}
	x, xpriv := testEndpoint(t)
	b.cache.Add(x)
	x.Seq++
	if err := x.Sign(xpriv); err != nil {
		t.Fatal(err)
	}
	a.cache.Add(x)

	view, _ := a.log.View()
	if h := a.node.hello(&view); len(h.Endpoints) > 0 || len(h.Keys) > 0 || len(h.Seen) != 2 || h.Self == nil {
		t.Fatalf("a's hello carries %d announcements, %d keys, says what it holds of %d nodes, self %v",
			len(h.Endpoints), len(h.Keys), len(h.Seen), h.Self != nil)
	}
	e, _ := a.announce()
	b.cache.Add(e)
	if n := b.node.Sync(t.Context(), []types.Identity{a.id}); n != 1 {
		t.Fatalf("b synced %d times with a", n)
	}
	if got, ok := b.cache.Key(a.id); !ok || got.Seq != 2 {
		t.Fatalf("b holds a's key as %+v, %v", got, ok)
	}
	if got, ok := b.cache.Get(x.Identity); !ok || got.Seq != x.Seq {
		t.Fatalf("b holds x's announcement at %d, want %d", got.Seq, x.Seq)
	}
	e, _ = b.announce()
	c.cache.Add(e)
	if n := c.node.Sync(t.Context(), []types.Identity{b.id}); n != 1 {
		t.Fatalf("c synced %d times with b", n)
	}
	if _, ok := c.cache.Key(a.id); !ok {
		t.Fatal("b did not carry a's key on to c")
	}
	if got, ok := c.cache.Get(x.Identity); !ok || got.Seq != x.Seq {
		t.Fatal("b did not carry x's announcement on to c")
	}
}

// A records frame answering a hello at SchemaSeen carries what is newer than
// the hello says, and all of it to a hello that says nothing.
func TestARecordsFrameCarriesWhatIsNewerThanSeen(t *testing.T) {
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	lease := types.Lease{Network: types.Hash{1}, Head: types.Hash{2}, Issued: 100}
	if err := lease.Sign(signer); err != nil {
		t.Fatal(err)
	}
	raw, err := lease.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var mine AddrKey
	a := newTestNodeTimeout(t, types.Hash{1}, 1, s, 2*time.Second, seenAlone, func(o *Options) {
		o.OwnKey = func() (AddrKey, bool) { return mine, true }
		o.Leases = func() [][]byte { return [][]byte{raw} }
	})
	mine = signedKey(t, a.priv, 2)
	x, _ := testEndpoint(t)
	a.cache.Add(x)
	view, _ := a.log.View()
	for _, c := range []struct {
		name              string
		seen              []Seen
		eps, keys, leases int
	}{
		{"nothing said", nil, 1, 1, 1},
		{"all held", []Seen{{ID: x.Identity, Seq: x.Seq}, {ID: a.id, Key: 2}, {ID: signer.Public(), Lease: 100}}, 0, 0, 0},
		{"all older", []Seen{{ID: x.Identity, Seq: x.Seq - 1}, {ID: a.id, Key: 1}, {ID: signer.Public(), Lease: 99}}, 1, 1, 1},
	} {
		f, err := a.node.records(&view, &frame{Kind: kindHello, Seen: c.seen})
		if err != nil {
			t.Fatal(err)
		}
		if len(f.Endpoints) != c.eps || len(f.Keys) != c.keys || len(f.Leases) != c.leases {
			t.Errorf("%s: %d announcements, %d keys, %d leases, want %d, %d, %d",
				c.name, len(f.Endpoints), len(f.Keys), len(f.Leases), c.eps, c.keys, c.leases)
		}
		if b, err := encode(&f); err != nil {
			t.Errorf("%s: %v", c.name, err)
		} else if _, err := types.DecodeCanonical[frame](decMode, b, MaxFrameSize); err != nil {
			t.Errorf("%s: the frame does not decode: %v", c.name, err)
		}
	}
}

// A node at SchemaSeen and one whose log is not yet there still hand each
// other what they hold, either way round.
func TestSeenAndFullHellosMeet(t *testing.T) {
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	a := newTestNodeTimeout(t, types.Hash{1}, 1, s, 2*time.Second, seenAlone)
	b := newTestNode(t, types.Hash{1}, 1, s)
	x, _ := testEndpoint(t)
	a.cache.Add(x)
	y, _ := testEndpoint(t)
	b.cache.Add(y)
	for i, pair := range [][2]*testNode{{a, b}, {b, a}} {
		from, to := pair[0], pair[1]
		e, _ := to.announce()
		from.cache.Add(e)
		if n := from.node.Sync(t.Context(), []types.Identity{to.id}); n != 1 {
			t.Fatalf("round %d: %d sessions", i, n)
		}
	}
	if _, ok := b.cache.Get(x.Identity); !ok {
		t.Error("the node with a full hello did not get what the other holds")
	}
	if _, ok := a.cache.Get(y.Identity); !ok {
		t.Error("the node at SchemaSeen did not get what the other holds")
	}
}

// Address keys in a records frame leave room for the largest record, which
// a frame must carry.
func TestKeysInARecordsFrameLeaveRoomForARecord(t *testing.T) {
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	var mine AddrKey
	a := newTestNodeTimeout(t, types.Hash{1}, 1, s, 2*time.Second, seenAlone, func(o *Options) {
		o.OwnKey = func() (AddrKey, bool) { return mine, true }
	})
	mine = signedKey(t, a.priv, 2)
	// As many wraps as a frame carries, past the room once signed.
	for len(mine.Wraps) < maxKeyBytesPerFrame/addrkey.WrapSize {
		mine.Wraps = append(mine.Wraps, mine.Wraps[0])
	}
	view, _ := a.log.View()
	f, err := a.node.records(&view, &frame{Kind: kindHello})
	if err != nil {
		t.Fatal(err)
	}
	if keyBytes(f.Keys) > maxRecordBytesPerFrame-types.MaxRecordSize {
		t.Errorf("keys take %d bytes, leaving less than a record's %d", keyBytes(f.Keys), types.MaxRecordSize)
	}
}
