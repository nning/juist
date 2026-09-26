package types

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"filippo.io/edwards25519"
)

// Key sizes, in bytes.
const (
	IdentitySize  = ed25519.PublicKeySize
	SigSize       = ed25519.SignatureSize
	SeedSize      = ed25519.SeedSize
	WGKeySize     = 32
	X25519KeySize = 32
	// MLKEMKeySize is the size of an ML-KEM-768 encapsulation key. Spelled
	// out rather than taken from crypto/mlkem so this package does not
	// depend on it: only trust/secrets performs ML-KEM operations.
	MLKEMKeySize = 1184
)

// Text prefixes. Identity, WireGuard and X25519 public keys are all 32 opaque
// bytes, so their text forms are tagged: pasting one where another belongs is
// caught at parse time rather than three records later.
const (
	identityPrefix = "nid:"
	wgPrefix       = "wg:"
	x25519Prefix   = "x25519:"
	mlkemPrefix    = "mlkem:"
)

var b64 = base64.RawURLEncoding

// An Identity is an Ed25519 public key. It names both member nodes and admin
// signing keys and serves as its own key ID. A node's Identity is the one key
// that never changes while it is a member — the others are rotatable
// attributes — and its overlay v6 address derives from it.
type Identity [IdentitySize]byte

// A Sig is an Ed25519 signature over an [AUM]'s signing hash.
type Sig [SigSize]byte

// A WGKey is a WireGuard static public key (Curve25519).
type WGKey [WGKeySize]byte

// An X25519Key is the classical half of a node's HPKE recipient key.
type X25519Key [X25519KeySize]byte

// An MLKEMKey is an ML-KEM-768 encapsulation key: the post-quantum half of a
// node's HPKE recipient key, and the key material reserved for the per-pair
// WireGuard preshared-key hedge (docs/07-embedding-notes.md).
type MLKEMKey [MLKEMKeySize]byte

// A Signature is one attributable signature over an AUM. Attributable by
// design: the log doubles as the audit trail that identifies a malicious
// admin, which an aggregated or threshold signature would hide.
type Signature struct {
	// KeyID is the public key that produced Sig. Both node identity keys
	// and admin keys sign records, so which of the two a KeyID must be is
	// decided per record kind by trust/log.
	KeyID Identity `cbor:"1,keyasint"`

	Sig Sig `cbor:"2,keyasint"`
}

// IsZero reports whether i is the zero value.
func (i Identity) IsZero() bool { return i == Identity{} }

// Verify reports whether sig is a valid signature by i over msg. crypto/ed25519
// rejects non-canonical points and unreduced scalars, which is what makes the
// log's verdict reproducible: a malleable encoding would let one node accept a
// record another rejects.
func (i Identity) Verify(msg []byte, sig Sig) bool {
	return ed25519.Verify(ed25519.PublicKey(i[:]), msg, sig[:])
}

// Validate reports whether i is usable as a signing key: not the zero value,
// canonically encoded, on the curve, and — the reason this is more than a
// length check — not of small order. A small-order key admits a signature
// anyone can compute, turning its votes from "held by an admin" into "held by
// anybody", which quorum cannot notice.
func (i Identity) Validate() error {
	if i.IsZero() {
		return errors.New("identity key is zero")
	}
	p, err := new(edwards25519.Point).SetBytes(i[:])
	if err != nil {
		return fmt.Errorf("identity key is not a valid Ed25519 point: %w", err)
	}
	if new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("identity key has small order")
	}
	return nil
}

func (i Identity) String() string { return identityPrefix + b64.EncodeToString(i[:]) }

// ShortString returns an abbreviated form for logs and error messages.
func (i Identity) ShortString() string {
	s := b64.EncodeToString(i[:])
	return identityPrefix + s[:8] + "…"
}

// Compare orders identities bytewise. Records holding sets of identities are
// sorted by it, which is what makes their encoding canonical.
func (i Identity) Compare(other Identity) int { return bytes.Compare(i[:], other[:]) }

func (i Identity) MarshalText() ([]byte, error)   { return []byte(i.String()), nil }
func (i Identity) MarshalBinary() ([]byte, error) { return cloneArray(i[:]) }

func (i *Identity) UnmarshalText(text []byte) error {
	return unmarshalKeyText("identity key", identityPrefix, text, i[:])
}

func (i *Identity) UnmarshalBinary(b []byte) error {
	return unmarshalKeyBinary("identity key", b, i[:])
}

// ParseIdentity parses the text form produced by [Identity.String].
func ParseIdentity(s string) (Identity, error) {
	var i Identity
	err := i.UnmarshalText([]byte(s))
	return i, err
}

func (k WGKey) IsZero() bool                   { return k == WGKey{} }
func (k WGKey) String() string                 { return wgPrefix + b64.EncodeToString(k[:]) }
func (k WGKey) MarshalText() ([]byte, error)   { return []byte(k.String()), nil }
func (k WGKey) MarshalBinary() ([]byte, error) { return cloneArray(k[:]) }

func (k *WGKey) UnmarshalText(text []byte) error {
	return unmarshalKeyText("WireGuard key", wgPrefix, text, k[:])
}
func (k *WGKey) UnmarshalBinary(b []byte) error {
	return unmarshalKeyBinary("WireGuard key", b, k[:])
}

func (k X25519Key) IsZero() bool                   { return k == X25519Key{} }
func (k X25519Key) String() string                 { return x25519Prefix + b64.EncodeToString(k[:]) }
func (k X25519Key) MarshalText() ([]byte, error)   { return []byte(k.String()), nil }
func (k X25519Key) MarshalBinary() ([]byte, error) { return cloneArray(k[:]) }

func (k *X25519Key) UnmarshalText(text []byte) error {
	return unmarshalKeyText("X25519 key", x25519Prefix, text, k[:])
}
func (k *X25519Key) UnmarshalBinary(b []byte) error {
	return unmarshalKeyBinary("X25519 key", b, k[:])
}

// IsZero reports whether k is the zero value. Unlike the 32-byte keys this is
// a 1184-byte comparison, so callers on hot paths should avoid it; nothing in
// the log is a hot path.
func (k *MLKEMKey) IsZero() bool { return *k == MLKEMKey{} }

func (k MLKEMKey) String() string                 { return mlkemPrefix + b64.EncodeToString(k[:]) }
func (k MLKEMKey) MarshalText() ([]byte, error)   { return []byte(k.String()), nil }
func (k MLKEMKey) MarshalBinary() ([]byte, error) { return cloneArray(k[:]) }

func (k *MLKEMKey) UnmarshalText(text []byte) error {
	return unmarshalKeyText("ML-KEM key", mlkemPrefix, text, k[:])
}
func (k *MLKEMKey) UnmarshalBinary(b []byte) error {
	return unmarshalKeyBinary("ML-KEM key", b, k[:])
}

func (s Sig) IsZero() bool                   { return s == Sig{} }
func (s Sig) String() string                 { return b64.EncodeToString(s[:]) }
func (s Sig) MarshalText() ([]byte, error)   { return []byte(s.String()), nil }
func (s Sig) MarshalBinary() ([]byte, error) { return cloneArray(s[:]) }

func (s *Sig) UnmarshalText(text []byte) error {
	return unmarshalKeyText("signature", "", text, s[:])
}
func (s *Sig) UnmarshalBinary(b []byte) error {
	return unmarshalKeyBinary("signature", b, s[:])
}

// A PrivateIdentity is the secret half of an [Identity]: a node's identity key
// or an admin's signing key. Admin keys live in the operator's CLI keystore,
// never in the daemon, so this is held only for a signing operation.
type PrivateIdentity struct {
	priv ed25519.PrivateKey
}

// GenerateIdentity creates a new identity keypair from the system CSPRNG.
func GenerateIdentity() (PrivateIdentity, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return PrivateIdentity{}, fmt.Errorf("types: generating identity: %w", err)
	}
	return PrivateIdentity{priv: priv}, nil
}

// NewPrivateIdentity reconstructs an identity from its 32-byte seed, the form
// [PrivateIdentity.Seed] persists.
func NewPrivateIdentity(seed []byte) (PrivateIdentity, error) {
	if len(seed) != SeedSize {
		return PrivateIdentity{}, fmt.Errorf("types: identity seed is %d bytes, want %d", len(seed), SeedSize)
	}
	return PrivateIdentity{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// IsZero reports whether p holds no key.
func (p PrivateIdentity) IsZero() bool { return p.priv == nil }

// Public returns the corresponding [Identity].
func (p PrivateIdentity) Public() Identity {
	var out Identity
	if p.priv == nil {
		return out
	}
	copy(out[:], p.priv.Public().(ed25519.PublicKey))
	return out
}

// Seed returns the 32-byte seed, the persistable form of the private key.
// Callers must treat it as secret key material.
func (p PrivateIdentity) Seed() []byte {
	if p.priv == nil {
		return nil
	}
	return p.priv.Seed()
}

// Sign signs msg.
func (p PrivateIdentity) Sign(msg []byte) (Sig, error) {
	var out Sig
	if p.priv == nil {
		return out, errors.New("types: signing with an empty identity")
	}
	copy(out[:], ed25519.Sign(p.priv, msg))
	return out, nil
}

// Equal reports whether p and other hold the same key, in constant time.
func (p PrivateIdentity) Equal(other PrivateIdentity) bool {
	if p.priv == nil || other.priv == nil {
		return p.priv == nil && other.priv == nil
	}
	return subtle.ConstantTimeCompare(p.priv, other.priv) == 1
}

func cloneArray(b []byte) ([]byte, error) {
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

// unmarshalKeyText decodes prefix + unpadded base64url into dst, which must
// already have the expected length.
func unmarshalKeyText(what, prefix string, text []byte, dst []byte) error {
	s := string(text)
	if prefix != "" {
		var ok bool
		s, ok = strings.CutPrefix(s, prefix)
		if !ok {
			return fmt.Errorf("types: %s must start with %q", what, prefix)
		}
	}
	if b64.DecodedLen(len(s)) != len(dst) {
		return fmt.Errorf("types: %s is %d base64 characters, want %d", what, len(s), b64.EncodedLen(len(dst)))
	}
	// DecodedLen only bounds the length, so a decode error still has to be
	// checked: it catches non-alphabet characters and non-zero trailing bits,
	// both of which would otherwise give one key two text forms.
	n, err := b64.Decode(dst, []byte(s))
	if err != nil {
		return fmt.Errorf("types: decoding %s: %w", what, err)
	}
	if n != len(dst) {
		return fmt.Errorf("types: %s decoded to %d bytes, want %d", what, n, len(dst))
	}
	return nil
}

func unmarshalKeyBinary(what string, b []byte, dst []byte) error {
	if len(b) != len(dst) {
		return fmt.Errorf("types: %s is %d bytes, want %d", what, len(b), len(dst))
	}
	copy(dst, b)
	return nil
}
