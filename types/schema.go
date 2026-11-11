package types

import "fmt"

// A SchemaVersion is the record schema a network's log is written under; no
// field is added without one. Raised only by [KindSchemaUpgrade]. A build
// meeting one it does not implement stops applying records rather than act
// on a subset of what its peers act on.
type SchemaVersion uint16

// CurrentSchema is the schema this build implements.
const CurrentSchema SchemaVersion = 25

// SchemaSignedRotation is the first schema with identity rotation, its new
// signing key signed over ([AUM.NewSigning]).
const SchemaSignedRotation SchemaVersion = 19

// SchemaContentForkChoice is the first schema in which fork choice orders
// siblings by [AUM.SigHash], not by which copy a node holds, and counts a key
// as a branch's signer only where the record needed its signature.
const SchemaContentForkChoice SchemaVersion = 19

// SchemaRests is the first schema in which an announcement may say its device
// rests, which older strict decoders refuse.
const SchemaRests SchemaVersion = 20

// SchemaSeen is the first schema in which a gossip hello says what its sender
// holds of each node, which older strict decoders refuse.
const SchemaSeen SchemaVersion = 21

// SchemaMulticast is the first schema with [PolicyRule.Multicast].
const SchemaMulticast SchemaVersion = 22

// SchemaOwnNames is the first schema with names of their own ([OwnName]).
const SchemaOwnNames SchemaVersion = 23

// SchemaPublicDERP is the first schema with a public DERP setting
// ([PublicDERP]).
const SchemaPublicDERP SchemaVersion = 24

// SchemaTakeRetired is the first schema in which a move or a subnet route
// may take an address or range another member is retiring, which ends that
// retirement.
const SchemaTakeRetired SchemaVersion = 25

// MinSchema is the lowest schema this build reads, where every record is
// signed by ML-DSA alone.
const MinSchema SchemaVersion = 18

func (v SchemaVersion) String() string { return fmt.Sprintf("schema %d", uint16(v)) }
