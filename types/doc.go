// Package types defines the membership log's wire format: identities, the
// record (AUM) schema, and the canonical CBOR that signatures and the hash
// chain cover. Pure: no I/O, no clock, no policy; policy lives in trust/log.
//
// The encoding is injective: every accepted b satisfies Encode(Decode(b)) ==
// b, checked by re-encoding. Set-valued fields are sorted and duplicate-free,
// since two encodings would be two hashes for one signature.
//
// Schema rules: CBOR key numbers are never reused or renumbered, new fields
// are optional and absent by default, a new kind never changes an existing
// one, no floats, and unknown kinds and fields are rejected so every node
// reaches the same verdict from the bytes alone.
package types
