package types

// Structural limits on records: validation bounds, not policy, so a hostile
// record is rejected before it can make a node allocate something unbounded.
// Target scale is 25–100 devices, so every limit here is generous.
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

	// MaxRolesPerNode caps a node's role set. There are six roles; the
	// limit only has to stop repetition, which is already rejected as
	// non-canonical.
	MaxRolesPerNode = 8

	// MaxNameLen caps the human-readable label on a node or admin key, in
	// bytes. The trust layer reads a node's only for the label the publish
	// role holds.
	MaxNameLen = 64

	// MaxRecordSize caps a record's encoded size. The largest is a checkpoint
	// at MaxNodes members, which names and published names at their caps push
	// past it (docs/05-roadmap.md, M18).
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
