package types

// Structural limits, so a hostile record is rejected before it makes a node
// allocate without bound. Generous for the 25–100 devices targeted.
const (
	// MaxNodes caps the member set, and so the largest legitimate record: a
	// checkpoint with every node record and wrap.
	MaxNodes = 512

	MaxAdmins = 64

	// MaxVotes caps one admin key's vote weight; MaxAdmins * MaxVotes stays
	// far below 2^32.
	MaxVotes = 4096

	// MaxDisablementValues caps the genesis's break-glass commitments.
	MaxDisablementValues = 32

	MaxRoutesPerNode = 64

	MaxRolesPerNode = 8

	// MaxNameLen caps a node or admin key's human label, in bytes.
	MaxNameLen = 64

	// MaxNameBytes caps a member's names and published labels together, so a
	// checkpoint at MaxNodes fits MaxRecordSize.
	MaxNameBytes = 2048

	// MaxRecordSize caps a record's encoded size.
	MaxRecordSize = 4 << 20

	// maxArrayElements bounds CBOR arrays; it must cover MaxNodes records and
	// wraps.
	maxArrayElements = 1024

	maxMapPairs = 64

	// maxNestedLevels bounds CBOR nesting; the schema's deepest path is five.
	maxNestedLevels = 8
)
