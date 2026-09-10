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
const CurrentSchema SchemaVersion = 0

func (v SchemaVersion) String() string { return fmt.Sprintf("schema %d", uint16(v)) }
