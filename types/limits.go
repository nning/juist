package types

// Structural limits on records.
//
// These are validation bounds, not policy: they exist so that a malformed or
// hostile record is rejected before it can make a node allocate or compute
// something unbounded. Target scale is 25–100 devices with a few admins
// (docs/01-requirements.md), so every limit here is generous by design.
const (
	// MaxNodes caps the member set. A checkpoint carries every node record
	// and one epoch-secret wrap per node, so this is what bounds the largest
	// legitimate record.
	MaxNodes = 512

	// MaxAdmins caps the admin key set. Tailnet lock's comparable limit is
	// 20 signing nodes; 64 leaves room without making quorum arithmetic or
	// the O(n²) uniqueness checks interesting.
	MaxAdmins = 64

	// MaxVotes caps a single admin key's vote weight, so that total weight
	// cannot overflow: MaxAdmins * MaxVotes is far below 2^32.
	MaxVotes = 4096

	// MaxDisablementValues caps the break-glass commitments in the genesis
	// ceremony. docs/research/building-blocks.md describes tailnet lock
	// committing about ten.
	MaxDisablementValues = 32

	// MaxRoutesPerNode caps a node's advertised-route grant.
	MaxRoutesPerNode = 64

	// MaxRolesPerNode caps a node's role set. There are three roles; the
	// limit only has to stop repetition, which is already rejected as
	// non-canonical.
	MaxRolesPerNode = 8

	// MaxNameLen caps the human-readable label on a node or admin key, in
	// bytes. Names are cosmetic: nothing in the trust layer reads them.
	MaxNameLen = 64

	// MaxRecordSize caps the encoded size of a single record. The largest
	// legitimate record is a checkpoint at MaxNodes members, which is on the
	// order of 1.3 MiB; the limit is set well above that and well below
	// anything that threatens memory.
	MaxRecordSize = 4 << 20

	// maxArrayElements bounds any CBOR array during decoding. It has to
	// cover MaxNodes node records and MaxNodes epoch wraps.
	maxArrayElements = 1024

	// maxMapPairs bounds any CBOR map during decoding. Every map in the
	// schema is a struct with well under a dozen fields.
	maxMapPairs = 64

	// maxNestedLevels bounds CBOR nesting. The deepest path in the schema is
	// AUM → Snapshot → Nodes → NodeRecord → Routes, five levels.
	maxNestedLevels = 8
)
