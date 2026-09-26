package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
)

// HashSize is the length of a [Hash] in bytes.
const HashSize = sha256.Size

// A Hash is a SHA-256 digest: a record's identity in the chain, or a
// commitment to a secret. SHA-256 rather than tka's BLAKE2s because it is in
// the standard library and hardware-accelerated everywhere; one hash function
// for everything is one less thing to get wrong.
type Hash [HashSize]byte

// base32NoPad is the text encoding for hashes. Base32 rather than base64
// because hashes name files in the on-disk store: it survives
// case-insensitive filesystems, which the post-v1 platforms include.
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

func (h Hash) String() string { return base32NoPad.EncodeToString(h[:]) }

// IsZero reports whether h is the zero value, which no real digest is
// expected to be.
func (h Hash) IsZero() bool { return h == Hash{} }

// Compare orders hashes bytewise, which is how fork choice breaks ties.
func (h Hash) Compare(other Hash) int { return bytes.Compare(h[:], other[:]) }

// MarshalText implements [encoding.TextMarshaler].
func (h Hash) MarshalText() ([]byte, error) { return []byte(h.String()), nil }

// UnmarshalText implements [encoding.TextUnmarshaler].
func (h *Hash) UnmarshalText(text []byte) error {
	if base32NoPad.DecodedLen(len(text)) != HashSize {
		return fmt.Errorf("types: hash text is %d bytes, want %d", len(text), base32NoPad.EncodedLen(HashSize))
	}
	if _, err := base32NoPad.Decode(h[:], text); err != nil {
		return fmt.Errorf("types: decoding hash: %w", err)
	}
	return nil
}

// MarshalBinary implements [encoding.BinaryMarshaler]. The CBOR codec uses it
// to encode a Hash as a fixed-length byte string.
func (h Hash) MarshalBinary() ([]byte, error) {
	out := make([]byte, HashSize)
	copy(out, h[:])
	return out, nil
}

// UnmarshalBinary implements [encoding.BinaryUnmarshaler]. Short and long
// inputs are errors, not silent truncation, so a Hash on the wire is always
// exactly 32 bytes.
func (h *Hash) UnmarshalBinary(b []byte) error {
	if len(b) != HashSize {
		return fmt.Errorf("types: hash is %d bytes, want %d", len(b), HashSize)
	}
	copy(h[:], b)
	return nil
}

// ParseHash parses the text form produced by [Hash.String].
func ParseHash(s string) (Hash, error) {
	var h Hash
	err := h.UnmarshalText([]byte(s))
	return h, err
}

// Domain-separation labels, so no digest can be reinterpreted as one of a
// different kind. A change in what is hashed under a label is a new label,
// never a redefinition.
const (
	labelAUM         = "juist/aum/v1"
	labelAUMSig      = "juist/aum-sig/v1"
	labelAddr6       = "juist/addr6/v1"
	labelULA         = "juist/ula/v1"
	labelDisablement = "juist/disablement/v1"
	labelEpochCommit = "juist/epoch-commit/v1"
	labelLease       = "juist/lease/v1"
)

// errNULInLabel guards the invariant hashLabeled relies on.
var errNULInLabel = errors.New("types: domain-separation label contains NUL")

// hashLabeled returns SHA-256 over label, a NUL terminator, and parts. The NUL
// is what makes the labels unambiguous: no label contains one, so no
// label-plus-data string reads as a different label plus different data.
func hashLabeled(label string, parts ...[]byte) Hash {
	for i := 0; i < len(label); i++ {
		if label[i] == 0 {
			// Labels are compile-time constants in this package, so this is
			// unreachable short of an edit that breaks the invariant.
			panic(errNULInLabel)
		}
	}
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0})
	for _, p := range parts {
		h.Write(p)
	}
	var out Hash
	h.Sum(out[:0])
	return out
}
