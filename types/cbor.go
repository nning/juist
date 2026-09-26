package types

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
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
// byte strings to mean one record. [decodeCanonical]'s re-encode check catches
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

// decodeCanonical decodes b into a T and rejects it unless b is exactly what
// encoding that T produces. Only the round trip proves the mapping from bytes
// to records is injective, and it removes any need to reason about which
// lenient behaviours the CBOR library has.
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
