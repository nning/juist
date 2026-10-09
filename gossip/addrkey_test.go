package gossip

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/nning/juist/internal/addrkey"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

func signedKey(t *testing.T, priv types.PrivateIdentity, seq uint64) AddrKey {
	t.Helper()
	k := AddrKey{Owner: priv.Public(), ID: 7, Seq: seq, Wraps: [][]byte{bytes.Repeat([]byte{1}, addrkey.WrapSize)}}
	if err := k.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return k
}

// A member's address key travels in its hello and is carried on by whoever
// holds it; one another member signed, or one older, displaces nothing.
func TestAddressKeysTravelWithTheAnnouncements(t *testing.T) {
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	var mine AddrKey
	a := newTestNodeTimeout(t, types.Hash{1}, 1, s, 2*time.Second, func(o *Options) {
		o.OwnKey = func() (AddrKey, bool) { return mine, true }
	})
	mine = signedKey(t, a.priv, 2)
	b := newTestNode(t, types.Hash{1}, 1, s)
	c := newTestNode(t, types.Hash{1}, 1, s)
	for _, n := range []*testNode{b, c} {
		n.cache.SetMembership([]types.Identity{a.id, b.id, c.id}, nil)
	}
	e, _ := a.announce()
	b.cache.Add(e)
	if n := b.node.Sync(t.Context(), []types.Identity{a.id}); n != 1 {
		t.Fatalf("b synced %d times with a", n)
	}
	if got, ok := b.cache.Key(a.id); !ok || got.Seq != 2 {
		t.Fatalf("b holds a's key as %+v, %v", got, ok)
	}
	e, _ = b.announce()
	c.cache.Add(e)
	if n := c.node.Sync(t.Context(), []types.Identity{b.id}); n != 1 {
		t.Fatalf("c synced %d times with b", n)
	}
	if _, ok := c.cache.Key(a.id); !ok {
		t.Fatal("b did not carry a's key on to c")
	}

	forged := mine
	forged.Seq = 9
	forged.Wraps = [][]byte{bytes.Repeat([]byte{2}, addrkey.WrapSize)}
	if forged.Verify() == nil {
		t.Fatal("a key changed after signing verifies")
	}
	if err := forged.Sign(b.priv); err == nil {
		t.Fatal("b signed a key of a's")
	}
	if c.cache.AddKey(signedKey(t, a.priv, 1)) {
		t.Error("an older key displaced a newer one")
	}
	stranger, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if c.cache.AddKey(signedKey(t, stranger, 1)) {
		t.Error("a non-member's key was taken")
	}
}

// An announcement holds its addresses open or sealed, never both, and
// sealed ones within the size an address set seals to.
func TestSealedAddressesStandAlone(t *testing.T) {
	priv, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	e := Endpoint{Identity: priv.Public(), Disco: DiscoKey{1}, GossipPort: 1, Sealed: make([]byte, 60)}
	if err := e.Sign(priv); err != nil {
		t.Fatalf("sealed addresses alone: %v", err)
	}
	e.Addrs = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1")}
	if err := e.StaticValidate(); err == nil {
		t.Error("sealed and open addresses together validate")
	}
	e.Addrs, e.Sealed = nil, make([]byte, addrkey.MaxSealedSize+1)
	if err := e.StaticValidate(); err == nil {
		t.Error("an oversized sealed set validates")
	}
}
