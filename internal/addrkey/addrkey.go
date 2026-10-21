// Package addrkey hides a member's underlay addresses from members that are
// not its peers. A member seals them under an address key of its own, which
// it hands each peer wrapped under a key the two derive from the X25519 keys
// the log holds for them, and the pair's preshared key once it has one of
// its own, which a quantum computer cannot recover.
package addrkey

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/nning/juist/internal/aead"
	"github.com/nning/juist/internal/malformed"
	"github.com/nning/juist/types"
)

// A Key seals one member's addresses.
type Key [32]byte

// An ID names a key without giving it away, so a holder knows which to use.
type ID uint64

// WrapSize is the size of one wrapped key.
const WrapSize = 32 + chacha20poly1305.Overhead

// MaxSealedSize bounds a sealed address set: the framing and sixteen
// addresses with ports.
const MaxSealedSize = aead.Overhead + 16*(1+19+3) + 3

// Derive is the address key a member whose recipient keys' secret halves are
// secret holds in network at epoch for exactly peers: a peer gone, or an
// epoch later, a key that peer cannot derive.
func Derive(secret []byte, network types.Hash, epoch uint64, peers []types.Identity) (Key, error) {
	h := sha256.New()
	for _, p := range peers {
		h.Write(p[:])
	}
	var info []byte
	info = append(info, types.LabelAddrKey+"\x00"...)
	info = binary.BigEndian.AppendUint64(info, epoch)
	info = h.Sum(info)
	b, err := hkdf.Key(sha256.New, secret, network[:], string(info), 32)
	if err != nil {
		return Key{}, fmt.Errorf("addrkey: deriving: %w", err)
	}
	return Key(b), nil
}

// ID names k.
func (k Key) ID() ID {
	h := sha256.Sum256(append([]byte(types.LabelAddrKeyID+"\x00"), k[:]...))
	return ID(binary.BigEndian.Uint64(h[:8]))
}

// Pair is the key self, holding scalar, and peer, holding public, share in
// network: either derives it, and no one else.
func Pair(scalar []byte, self types.Identity, peer types.Identity, public types.X25519Key, network types.Hash) ([32]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return [32]byte{}, fmt.Errorf("addrkey: own key: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(public[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("addrkey: peer's key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return [32]byte{}, fmt.Errorf("addrkey: agreeing: %w", err)
	}
	lo, hi := self, peer
	if hi.Compare(lo) < 0 {
		lo, hi = hi, lo
	}
	info := append(append([]byte(types.LabelPairKey+"\x00"), lo[:]...), hi[:]...)
	b, err := hkdf.Key(sha256.New, shared, network[:], string(info), 32)
	if err != nil {
		return [32]byte{}, fmt.Errorf("addrkey: deriving: %w", err)
	}
	return [32]byte(b), nil
}

// WithPSK is pair with the pair's preshared key psk mixed in, for a pair
// that has one of its own.
func WithPSK(pair, psk [32]byte) [32]byte {
	b, err := hkdf.Key(sha256.New, append(pair[:], psk[:]...), nil, types.LabelPairKeyPSK, 32)
	if err != nil {
		panic(fmt.Sprintf("addrkey: deriving: %v", err))
	}
	return [32]byte(b)
}

// Wrap seals owner's key k for the peer pair names. The nonce follows from
// owner and the key's ID, which names one key: a wrap is the same for the
// same key and pair, and never the same nonce for another.
func Wrap(pair [32]byte, owner types.Identity, k Key) []byte {
	nonce, ad := wrapNonce(owner, k.ID())
	return newAEAD(pair).Seal(nil, nonce, k[:], ad)
}

// Unwrap opens a wrap of owner's key id, reporting false where it is not
// sealed under pair.
func Unwrap(pair [32]byte, owner types.Identity, id ID, wrap []byte) (Key, bool) {
	nonce, ad := wrapNonce(owner, id)
	b, err := newAEAD(pair).Open(nil, nonce, wrap, ad)
	if err != nil || len(b) != len(Key{}) || Key(b).ID() != id {
		return Key{}, false
	}
	return Key(b), true
}

func newAEAD(key [32]byte) cipher.AEAD {
	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		panic(fmt.Sprintf("addrkey: a 32-byte key refused: %v", err))
	}
	return a
}

// The project's strict codec: an address set has one encoding.
var (
	addrsEnc = func() cbor.EncMode {
		m, err := cbor.CTAP2EncOptions().EncMode()
		if err != nil {
			panic(err)
		}
		return m
	}()
	addrsDec = func() cbor.DecMode {
		m, err := types.StrictDecOptions(4, 16, 16).DecMode()
		if err != nil {
			panic(err)
		}
		return m
	}()
)

func wrapNonce(owner types.Identity, id ID) (nonce, ad []byte) {
	ad = binary.BigEndian.AppendUint64(append([]byte(nil), owner[:]...), uint64(id))
	h := sha256.Sum256(append([]byte(types.LabelAddrWrap+"\x00"), ad...))
	return h[:chacha20poly1305.NonceSizeX], ad
}

// Seal seals addrs under k, in [aead]'s format. The nonce follows from a
// subkey of k and the addresses, so the same addresses seal alike and a renewed
// announcement reads as nothing new.
func Seal(k Key, addrs []netip.AddrPort) ([]byte, error) {
	body, err := addrsEnc.Marshal(addrs)
	if err != nil {
		return nil, fmt.Errorf("addrkey: encoding: %w", err)
	}
	nk, err := hkdf.Key(sha256.New, k[:], nil, types.LabelAddrNonce, 32)
	if err != nil {
		return nil, fmt.Errorf("addrkey: deriving: %w", err)
	}
	mac := hmac.New(sha256.New, nk)
	mac.Write(body)
	return aead.SealNonce(k, uint64(k.ID()), [aead.NonceLen]byte(mac.Sum(nil)), body), nil
}

// SealedID is the ID of the key sealed was sealed under.
func SealedID(sealed []byte) (ID, error) {
	id, err := aead.Epoch(sealed)
	return ID(id), err
}

// Open opens what [Seal] sealed under k.
func Open(k Key, sealed []byte) (_ []netip.AddrPort, err error) {
	defer malformed.Recover(&err)
	if id, err := SealedID(sealed); err != nil || id != k.ID() {
		return nil, errors.New("addrkey: sealed under another key")
	}
	body, err := aead.Open(k, sealed)
	if err != nil {
		return nil, err
	}
	var addrs []netip.AddrPort
	if err := addrsDec.Unmarshal(body, &addrs); err != nil {
		return nil, fmt.Errorf("addrkey: decoding: %w", err)
	}
	if re, err := addrsEnc.Marshal(addrs); err != nil || !bytes.Equal(re, body) {
		return nil, types.ErrNonCanonical
	}
	return addrs, nil
}
