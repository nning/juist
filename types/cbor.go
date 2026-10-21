package types

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/nning/juist/internal/malformed"
)

// ErrNonCanonical is returned when input decodes but is not the encoding this
// package would have produced. A record with two encodings is a record with
// two hashes, and one authorization for two chain entries.
var ErrNonCanonical = errors.New("types: non-canonical encoding")

// encMode is CTAP2 canonical CBOR: minimal-length integers and string lengths,
// definite lengths only, map keys sorted bytewise, no tags. The same choice tka
// makes: of the encodings with a deterministic serialization in the spec, this
// is the one with the most implementation experience behind it.
var encMode = func() cbor.EncMode {
	m, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		// The options are constants; failure here is a build-time mistake.
		panic(fmt.Sprintf("types: building CBOR encoder: %v", err))
	}
	return m
}()

// StrictDecOptions are the decoder options every parser in the project uses,
// with its own limits: duplicate map keys, indefinite lengths, tags, unknown
// fields and invalid UTF-8 are all refused. Each is a way for two byte
// strings to mean one message.
func StrictDecOptions(maxNested, maxArray, maxPairs int) cbor.DecOptions {
	return cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		UTF8:              cbor.UTF8RejectInvalid,
		MaxNestedLevels:   maxNested,
		MaxArrayElements:  maxArray,
		MaxMapPairs:       maxPairs,
	}
}

// decMode rejects everything a permissive CBOR decoder would repair: duplicate
// map keys, indefinite lengths, tags, and unknown fields. Each is a way for two
// byte strings to mean one record. [DecodeCanonical]'s re-encode check catches
// the rest, including non-minimal integers and misordered keys.
var decMode = func() cbor.DecMode {
	m, err := StrictDecOptions(maxNestedLevels, maxArrayElements, maxMapPairs).DecMode()
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

// mustEncode is encode for already-validated values, where a failure means the
// schema and the encoder disagree. Hashing needs an encoding unconditionally,
// and an error from Hash() would push the impossible case into every caller.
func mustEncode(v any) []byte {
	b, err := encMode.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("types: encoding a validated value failed: %v", err))
	}
	return b
}

// DecodeCanonical decodes b, of at most limit bytes, by dec into a T and
// refuses it unless b is exactly what encoding that T produces: only the round
// trip proves the mapping from bytes to values injective.
func DecodeCanonical[T any](dec cbor.DecMode, b []byte, limit int) (_ T, err error) {
	defer malformed.Recover(&err)
	var zero, v T
	if len(b) == 0 || len(b) > limit {
		return zero, fmt.Errorf("types: an input of %d bytes, empty or over the %d limit", len(b), limit)
	}
	// Unmarshal, not a streaming Decoder, refuses bytes after the first item.
	if err := dec.Unmarshal(b, &v); err != nil {
		return zero, fmt.Errorf("types: decoding: %w", err)
	}
	if re, err := encMode.Marshal(v); err != nil || !bytes.Equal(re, b) {
		return zero, ErrNonCanonical
	}
	return v, nil
}
