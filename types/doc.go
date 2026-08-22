// Package types defines the membership log's wire format: node and admin
// identities, the record (AUM) schema, and the canonical CBOR encoding that
// signatures and the hash chain are computed over.
//
// This package is part of the trusted computing base described in
// docs/04-architecture.md. Everything here is pure: no I/O, no clock, no
// randomness outside explicit key generation, and no policy. Policy —
// quorum, ordering, fork choice — lives in trust/log, which consumes these
// types. The split exists so that the encoding rules can be fuzzed and
// reasoned about on their own.
//
// # Why the encoding rules matter
//
// A record's identity is the hash of its serialization, and a signature is
// over the hash of its serialization minus the signatures. If a single record
// had two valid byte encodings, it would have two hashes, and a signature
// gathered for one could be replayed onto the other: two distinct entries in
// the chain from one authorization. The rule this package enforces is
// therefore stronger than "parse carefully":
//
//	Decode is injective. For every byte string b that Decode accepts,
//	Encode(Decode(b)) == b.
//
// [Decode] guarantees that by re-encoding and comparing, so anything a lenient
// decoder might have accepted — indefinite lengths, non-minimal integers,
// unsorted or duplicated map keys, CBOR tags, null in place of an absent
// field, unknown fields — is rejected rather than silently normalized. The
// property is fuzzed by FuzzDecodeAUM.
//
// Ordering inside records is part of that: any field holding a set (admin
// keys, nodes, signatures, epoch wraps, roles, routes) must be sorted and
// duplicate-free, because two orderings of one set would otherwise be two
// encodings of one record.
//
// # Adding to the schema
//
// The schema freezes at M3 (docs/05-roadmap.md). Until then, and forever
// after, the rules from Tailscale's tka package apply, for the same reasons:
// CBOR key numbers are never reused or renumbered; new fields are optional and
// absent-by-default so older serializations keep their bytes; a new record
// kind may add semantics but never change what an existing kind means; and no
// floats, ever.
//
// Unlike tka, this package rejects record kinds and fields it does not know
// (see [AUM.StaticValidate]). Tailscale can afford forward compatibility
// because their coordination server orders the log; here every node must reach
// the same verdict on every record from the bytes alone, and "ignore what you
// do not understand" is how two nodes end up with two different views of who
// is a member.
package types
