// Package types defines the membership log's wire format: node and admin
// identities, the record (AUM) schema, and the canonical CBOR encoding that
// signatures and the hash chain are computed over. It is part of the trusted
// computing base and is pure: no I/O, no clock, no policy. Policy — quorum,
// ordering, fork choice — lives in trust/log.
//
// The encoding is injective: for every byte string b that [Decode] accepts,
// Encode(Decode(b)) == b, guaranteed by re-encoding and comparing. Two
// encodings of one record would be two hashes, and a signature gathered for
// one could be replayed onto the other, so set-valued fields must also be
// sorted and duplicate-free.
//
// Schema rules, as in Tailscale's tka: CBOR key numbers are never reused or
// renumbered, new fields are optional and absent-by-default, a new record kind
// never changes what an existing kind means, and no floats. Unlike tka,
// unknown kinds and fields are rejected: every node must reach the same
// verdict from the bytes alone.
package types
