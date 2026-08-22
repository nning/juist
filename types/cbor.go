package types

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ErrNonCanonical is returned when input decodes but is not the encoding this
// package would have produced. See the package documentation: a record with
// two valid encodings is a record with two hashes, and one authorization for
// two chain entries.
var ErrNonCanonical = errors.New("types: non-canonical encoding")

// encMode is CTAP2 canonical CBOR: minimal-length integers and string
// lengths, definite lengths only, map keys sorted bytewise, no tags.
//
// Same choice tka makes, for the reason tka documents: of the encodings with a
// deterministic serialization written into the specification, CBOR in CTAP2
// mode is the one with the most implementation experience behind it, having
// carried FIDO2 signed assertions for years. JSON has no canonical form worth
// the name, and the family of near-misses (JWS, SAML, X.509 DER in practice)
// is a catalogue of signature-confusion bugs.
var encMode = func() cbor.EncMode {
	m, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		// The options are constants; failure here is a build-time mistake.
		panic(fmt.Sprintf("types: building CBOR encoder: %v", err))
	}
	return m
}()

// decMode rejects everything a permissive CBOR decoder would repair.
//
// Each option closes off a way for two byte strings to mean the same record:
// duplicate map keys (which key wins?), indefinite lengths (two ways to write
// one string), tags (a tagged item and its content), and unknown fields (a
// place to hide bytes that survive re-encoding by being dropped). The
// re-encode check in [decodeCanonical] is what catches the rest, including
// non-minimal integer encodings and misordered map keys.
var decMode = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		UTF8:              cbor.UTF8RejectInvalid,
		MaxNestedLevels:   maxNestedLevels,
		MaxArrayElements:  maxArrayElements,
		MaxMapPairs:       maxMapPairs,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("types: building CBOR decoder: %v", err))
	}
	return m
}()

// encode returns the canonical CBOR encoding of v.
func encode(v any) ([]byte, error) {
	b, err := encMode.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("types: encoding: %w", err)
	}
	if len(b) > MaxRecordSize {
		return nil, fmt.Errorf("types: encoded record is %d bytes, over the %d limit", len(b), MaxRecordSize)
	}
	return b, nil
}

// mustEncode is encode for values this package has already validated, where a
// failure means the schema and the encoder disagree — a bug, not an input
// problem. Hashing needs an encoding unconditionally, and returning an error
// from Hash() would push the impossible case into every caller.
func mustEncode(v any) []byte {
	b, err := encMode.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("types: encoding a validated value failed: %v", err))
	}
	return b
}

// decodeCanonical decodes b into a T and rejects it unless b is exactly what
// encoding that T produces.
//
// The re-encode comparison is the whole point. Strict decoder options rule out
// the ambiguities they know about, but only the round trip proves the mapping
// from bytes to records is injective, which is the property signatures and the
// hash chain rest on. It also removes any need to reason about which lenient
// behaviours the CBOR library has: whatever it accepts and normalizes away
// fails the comparison.
func decodeCanonical[T any](b []byte) (T, error) {
	var zero, v T
	if len(b) == 0 {
		return zero, errors.New("types: empty input")
	}
	if len(b) > MaxRecordSize {
		return zero, fmt.Errorf("types: input is %d bytes, over the %d limit", len(b), MaxRecordSize)
	}
	// Unmarshal, not a streaming Decoder: Unmarshal treats bytes after the
	// first item as an error, and trailing bytes are exactly the kind of
	// thing that must not be silently dropped from something we hash.
	if err := decMode.Unmarshal(b, &v); err != nil {
		return zero, fmt.Errorf("types: decoding: %w", err)
	}
	re, err := encMode.Marshal(v)
	if err != nil {
		return zero, fmt.Errorf("types: re-encoding to check canonicality: %w", err)
	}
	if !bytes.Equal(re, b) {
		return zero, ErrNonCanonical
	}
	return v, nil
}
