package addrkey

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"net/netip"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/nning/juist/internal/aead"
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

	// Under the pair's preshared key, the wrap opens with that key alone:
	// the X25519 keys the log holds no longer suffice.
	psk := [32]byte{5}
	pq := Wrap(WithPSK(ownerSide, psk), owner.id, k)
	if got, ok := Unwrap(WithPSK(peerSide, psk), owner.id, k.ID(), pq); !ok || got != k {
		t.Error("the peer does not unwrap under the pair's preshared key")
	}
	if _, ok := Unwrap(peerSide, owner.id, k.ID(), pq); ok {
		t.Error("the X25519 pair key alone unwraps a wrap under the preshared key")
	}
	if _, ok := Unwrap(WithPSK(peerSide, [32]byte{6}), owner.id, k.ID(), pq); ok {
		t.Error("another preshared key unwraps it")
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

// The sealing key is not the nonce's MAC key: the nonce is no HMAC under it.
func TestASealsNonceIsNoMACUnderItsKey(t *testing.T) {
	k := Key{7}
	addrs := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
	sealed, err := Seal(k, addrs)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := cbor.Marshal(addrs)
	mac := hmac.New(sha256.New, k[:])
	mac.Write(body)
	if bytes.Equal(sealed[aead.EpochLen:aead.EpochLen+aead.NonceLen], mac.Sum(nil)[:aead.NonceLen]) {
		t.Fatal("the nonce is an HMAC under the sealing key")
	}
	again, _ := Seal(k, addrs)
	if !bytes.Equal(sealed, again) {
		t.Fatal("the same addresses seal differently")
	}
	if got, err := Open(k, sealed); err != nil || !slices.Equal(got, addrs) {
		t.Fatalf("open: %v, %v", got, err)
	}
}

// An address set with a second encoding opens to nothing.
func TestANonCanonicalAddressSetIsRefused(t *testing.T) {
	k := Key{7}
	canon, err := cbor.Marshal([]netip.AddrPort{netip.MustParseAddrPort("[2001:db8::5]:41641")})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		what string
		body []byte
	}{
		{"a one-byte array length", append([]byte{0x98, 0x01}, canon[1:]...)},
		{"a one-byte address length", append([]byte{0x81, 0x58, canon[1] & 0x1f}, canon[2:]...)},
	} {
		sealed, err := aead.Seal(k, uint64(k.ID()), c.body)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := Open(k, sealed); err == nil {
			t.Errorf("%s opens to %v", c.what, got)
		}
	}
	sealed, err := aead.Seal(k, uint64(k.ID()), canon)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(k, sealed); err != nil {
		t.Fatalf("the canonical encoding: %v", err)
	}
}
