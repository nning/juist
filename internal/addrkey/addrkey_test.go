package addrkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"net/netip"
	"slices"
	"testing"

	"github.com/nning/juist/types"
)

type member struct {
	id     types.Identity
	scalar []byte
	public types.X25519Key
}

func newMember(t *testing.T, n byte) member {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return member{id: types.Identity{n}, scalar: priv.Bytes(), public: types.X25519Key(priv.PublicKey().Bytes())}
}

// A peer opens a member's addresses with the key it unwraps by the pair key
// both derive; a member that is not that peer derives another pair key and
// opens nothing.
func TestAPeerAloneOpensTheAddresses(t *testing.T) {
	network := types.Hash{9}
	owner, peer, other := newMember(t, 1), newMember(t, 2), newMember(t, 3)
	k, err := Derive(owner.scalar, network, 4, []types.Identity{peer.id})
	if err != nil {
		t.Fatal(err)
	}
	addrs := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:41641"), netip.MustParseAddrPort("[2001:db8::5]:41641")}
	sealed, err := Seal(k, addrs)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) > MaxSealedSize {
		t.Errorf("two addresses seal to %d bytes, over %d", len(sealed), MaxSealedSize)
	}
	if again, _ := Seal(k, addrs); !slices.Equal(again, sealed) {
		t.Error("the same addresses seal otherwise")
	}
	if id, err := SealedID(sealed); err != nil || id != k.ID() {
		t.Fatalf("sealed under %v, %v; want %v", id, err, k.ID())
	}

	ownerSide, err := Pair(owner.scalar, owner.id, peer.id, peer.public, network)
	if err != nil {
		t.Fatal(err)
	}
	peerSide, err := Pair(peer.scalar, peer.id, owner.id, owner.public, network)
	if err != nil || peerSide != ownerSide {
		t.Fatalf("the two sides derive different pair keys: %v", err)
	}
	wrap := Wrap(ownerSide, owner.id, k)
	if len(wrap) != WrapSize {
		t.Errorf("a wrap is %d bytes, want %d", len(wrap), WrapSize)
	}
	got, ok := Unwrap(peerSide, owner.id, k.ID(), wrap)
	if !ok || got != k {
		t.Fatal("the peer does not unwrap the key")
	}
	if opened, err := Open(got, sealed); err != nil || !slices.Equal(opened, addrs) {
		t.Fatalf("opened %v, %v", opened, err)
	}

	otherSide, err := Pair(other.scalar, other.id, owner.id, owner.public, network)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Unwrap(otherSide, owner.id, k.ID(), wrap); ok {
		t.Error("another member unwraps the peer's key")
	}
	if _, ok := Unwrap(peerSide, other.id, k.ID(), wrap); ok {
		t.Error("a wrap opens as another owner's")
	}
	if _, err := Open(Key{1}, sealed); err == nil {
		t.Error("another key opens the addresses")
	}
}

// The key follows the epoch and the peer set, so a peer gone or a removal
// takes it away.
func TestTheKeyFollowsEpochAndPeers(t *testing.T) {
	owner := newMember(t, 1)
	a, b := types.Identity{2}, types.Identity{3}
	base, _ := Derive(owner.scalar, types.Hash{9}, 4, []types.Identity{a, b})
	for _, c := range []struct {
		what  string
		epoch uint64
		peers []types.Identity
	}{{"a later epoch", 5, []types.Identity{a, b}}, {"a peer gone", 4, []types.Identity{a}}} {
		if k, _ := Derive(owner.scalar, types.Hash{9}, c.epoch, c.peers); k == base {
			t.Errorf("%s keeps the key", c.what)
		}
	}
	if k, _ := Derive(owner.scalar, types.Hash{9}, 4, []types.Identity{a, b}); k != base {
		t.Error("the same epoch and peers derive another key")
	}
}
