package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
)

const HashSize = sha256.Size

// A Hash is a SHA-256 digest: a record's identity in the chain, or a
// commitment to a secret.
type Hash [HashSize]byte

// base32NoPad encodes hashes as text; hashes name files, and base32 survives
// case-insensitive filesystems.
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

func (h Hash) String() string { return base32NoPad.EncodeToString(h[:]) }

func (h Hash) IsZero() bool { return h == Hash{} }

// Compare orders hashes bytewise, which is how fork choice breaks ties.
func (h Hash) Compare(other Hash) int { return bytes.Compare(h[:], other[:]) }

func (h Hash) MarshalText() ([]byte, error) { return []byte(h.String()), nil }

func (h *Hash) UnmarshalText(text []byte) error {
	if base32NoPad.DecodedLen(len(text)) != HashSize {
		return fmt.Errorf("types: hash text is %d bytes, want %d", len(text), base32NoPad.EncodedLen(HashSize))
	}
	if _, err := base32NoPad.Decode(h[:], text); err != nil {
		return fmt.Errorf("types: decoding hash: %w", err)
	}
	return nil
}

// MarshalBinary makes CBOR encode a Hash as a byte string.
func (h Hash) MarshalBinary() ([]byte, error) {
	out := make([]byte, HashSize)
	copy(out, h[:])
	return out, nil
}

// UnmarshalBinary refuses any length but HashSize.
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

var errNULInLabel = errors.New("types: domain-separation label contains NUL")

// hashLabeled returns SHA-256 over label, NUL, and parts. Labels contain no
// NUL, so no label plus data reads as another label plus other data.
func hashLabeled(label string, parts ...[]byte) Hash {
	for i := 0; i < len(label); i++ {
		if label[i] == 0 {
			// Labels are constants; unreachable.
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
