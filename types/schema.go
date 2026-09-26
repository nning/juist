package types

import "fmt"

// A SchemaVersion identifies the record schema a network's log is written
// under. The schema is frozen at M3b in the sense that no field can be added
// to a record without a version behind it; this is what that version is.
//
// It is a property of the *network*, carried in the state every genesis and
// checkpoint states, and raised only by a quorum-signed
// [KindSchemaUpgrade] record. A build that meets a version it does not
// implement stops applying records and says so, rather than ignoring the
// difference: a node acting on a subset of what its peers act on holds a
// different view of who is a member, which is the split the log exists to
// prevent.
type SchemaVersion uint16

// CurrentSchema is the schema this build implements. Zero is the schema frozen
// at M3b, so it is absent from every encoding and costs nothing until there is
// a second one.
//
// Version numbers are the numbers, not the project's release names: there is
// no "v1 schema", only schema 0, schema 1, and so on.
//
// Schema 1 adds how many admin devices must vouch for a node's view before it
// counts as fresh ([KindSetVouchers], and the state's [Snapshot.Vouchers]),
// and requires an identity rotation to be signed by the old key as well as
// the new one.
//
// Schema 2 adds no field, only a rule of fork choice: taking a device's admin
// role away, and raising the vouching threshold, count as revocations, as
// removing a device does. Both withdraw vouching authority, and a concurrent
// change must not orphan them on its hash.
//
// Schema 3 lets admin keys belong to a holder, a person whose keys cast one
// vote between them ([AdminKey.Holder], [KindSetHolder]).
//
// Schema 4 assigns overlay IPv4 addresses from [OverlayV4] instead of
// [CGNAT], which Tailscale owns on any host running it, or from a prefix the
// network chose at genesis ([Snapshot.V4Prefix]). Addresses assigned before
// the upgrade stay valid.
//
// Schema 5 moves overlay IPv4 addresses after admission: the network to
// another prefix ([KindRenumberNetwork]) or one member to another address
// ([KindRenumberNode]), each keeping the addresses it replaces live until a
// deadline ([NodeRecord.Retiring], [Snapshot.V4Retiring]).
//
// Schema 6 renames the network ([KindRenameNetwork]). The name is a label:
// the genesis hash stays what identifies the network.
const CurrentSchema SchemaVersion = 6

// SchemaVouchers is the first schema with a vouching threshold.
const SchemaVouchers SchemaVersion = 1

// SchemaRevokingRoles is the first schema in which withdrawing vouching
// authority is a revocation for fork choice.
const SchemaRevokingRoles SchemaVersion = 2

// SchemaHolders is the first schema in which admin keys have holders.
const SchemaHolders SchemaVersion = 3

// SchemaOverlayV4 is the first schema assigning overlay IPv4 addresses from
// [OverlayV4].
const SchemaOverlayV4 SchemaVersion = 4

// SchemaRenumber is the first schema in which overlay IPv4 addresses move.
const SchemaRenumber SchemaVersion = 5

// SchemaRename is the first schema in which the network's name changes.
const SchemaRename SchemaVersion = 6

func (v SchemaVersion) String() string { return fmt.Sprintf("schema %d", uint16(v)) }
