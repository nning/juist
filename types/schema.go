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

// CurrentSchema is the schema this build implements.
const CurrentSchema SchemaVersion = 21

// SchemaSignedRotation is the first schema in which an identity rotation
// names the new signing key in what its signers sign ([AUM.NewSigning]); below
// it, identities do not rotate.
const SchemaSignedRotation SchemaVersion = 19

// SchemaContentForkChoice is the first schema in which fork choice orders
// siblings by [AUM.SigHash], not by which copy a node holds, and counts a key
// as a branch's signer only where the record needed its signature.
const SchemaContentForkChoice SchemaVersion = 19

// SchemaRests is the first schema in which an announcement may say its device
// rests, as a phone does, which earlier builds' strict decoders refuse.
const SchemaRests SchemaVersion = 20

// SchemaSeen is the first schema in which a gossip hello says what its
// sender holds of each node rather than carrying it, which earlier builds'
// strict decoders refuse.
const SchemaSeen SchemaVersion = 21

// MinSchema is the lowest schema this build reads, where every record is
// signed by ML-DSA alone. Networks below it moved up with M17's build; the
// rules of schemas 0 to 17 are in git's history.
const MinSchema SchemaVersion = 18

func (v SchemaVersion) String() string { return fmt.Sprintf("schema %d", uint16(v)) }
