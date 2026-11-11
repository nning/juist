package types

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/nning/juist/internal/malformed"
)

// ErrNonCanonical is returned when input decodes but is not the encoding this
// package would produce: two encodings would be two hashes for one signature.
var ErrNonCanonical = errors.New("types: non-canonical encoding")

// encMode is CTAP2 canonical CBOR: minimal lengths, definite lengths only, map
// keys sorted bytewise, no tags.
var encMode = func() cbor.EncMode {
	m, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		// Constant options; unreachable.
		panic(fmt.Sprintf("types: building CBOR encoder: %v", err))
	}
	return m
}()

// StrictDecOptions are every parser's decoder options: duplicate keys,
// indefinite lengths, tags, unknown fields and invalid UTF-8 are refused, each
// a way for two byte strings to mean one message.
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

// decMode is [StrictDecOptions] with the record limits; [DecodeCanonical]'s
// round trip catches the rest, such as non-minimal integers and key order.
var decMode = func() cbor.DecMode {
	m, err := StrictDecOptions(maxNestedLevels, maxArrayElements, maxMapPairs).DecMode()
	if err != nil {
		panic(fmt.Sprintf("types: building CBOR decoder: %v", err))
	}
	return m
}()

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

// mustEncode is encode for validated values; it panics on failure.
func mustEncode(v any) []byte {
	b, err := encMode.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("types: encoding a validated value failed: %v", err))
	}
	return b
}

// DecodeCanonical decodes b, at most limit bytes, by dec into a T, and refuses
// it unless re-encoding yields exactly b.
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
