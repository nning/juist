package types

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

// A Kind identifies what an [AUM] does.
//
// Numbers are permanent: never reordered, never reused. Kind 0 is reserved as
// invalid so that a record whose kind field was dropped cannot be mistaken for
// a real one.
type Kind uint8

const (
	KindInvalid Kind = 0

	// KindGenesis creates the network. It is the only record with no parent,
	// and its hash names the network for the rest of its life: the overlay
	// address space derives from it, and every later record chains to it.
	//
	// Its signatures are checked against the admin keys in the record
	// itself, which is unavoidable — there is no earlier state to check
	// against — and is why the genesis ceremony is the root of trust that
	// docs/02-threat-model.md treats as such.
	KindGenesis Kind = 1

	// KindAddNode admits a member device. Carries an epoch bump so the new
	// member receives the group secret and no member is left without it.
	KindAddNode Kind = 2

	// KindRemoveNode revokes a member. Carries an epoch bump, which is what
	// takes discovery away from the removed device rather than only taking
	// away its WireGuard peer entry.
	KindRemoveNode Kind = 3

	// KindSetNodeRoutes replaces a node's roles and advertised routes. Every
	// capability a node holds is granted here or in its AddNode record and
	// nowhere else — a node can never assert a role or a route for itself,
	// and no peer's on-the-wire advertisement is ever believed.
	KindSetNodeRoutes Kind = 4

	// KindRotateNodeKey replaces a node's WireGuard and encryption keys,
	// keeping its identity and address. Requires the node's own signature in
	// addition to quorum: quorum decides that the membership may re-key,
	// while the node's signature is what shows the new keys came from the
	// device rather than from whoever asked for the rotation.
	KindRotateNodeKey Kind = 5

	// KindRotateIdentity replaces a node's identity key, and with it the
	// node's derived overlay address, keeping its roles, routes, v4 address
	// and name. Requires quorum plus a signature by the new identity key,
	// so that a membership slot cannot be bound to a key no device holds.
	KindRotateIdentity Kind = 6

	// KindAddAdminKey adds an admin signing key with a vote weight.
	KindAddAdminKey Kind = 7

	// KindRemoveAdminKey removes an admin signing key. Rejected if it would
	// leave the remaining keys unable to reach quorum, which would make the
	// network permanently unmanageable.
	KindRemoveAdminKey Kind = 8

	// KindSetQuorum changes k, the vote weight a change requires.
	//
	// Not in the record list in docs/04-architecture.md, which follows tka in
	// treating the quorum policy as fixed at genesis. Without it a network
	// that grows from three admins to ten keeps whatever k it chose on day
	// one, and there is no way to tighten policy short of recreating the
	// network. Flagged for the M3 schema freeze.
	KindSetQuorum Kind = 9

	// KindCheckpoint states the full authority state at a point in the
	// chain, so that a new node can bootstrap without replaying history and
	// so that old records can be compacted away.
	//
	// A checkpoint whose parent state is known must match it exactly; see
	// trust/log. Otherwise a quorum could rewrite membership by asserting a
	// state instead of by changing it.
	KindCheckpoint Kind = 10

	// KindEpochBump rotates the group secret without changing membership:
	// the routine half of the two-tier revocation response in
	// docs/research/building-blocks.md §5, and the response to a suspected
	// group-secret leak.
	KindEpochBump Kind = 11
)

func (k Kind) String() string {
	switch k {
	case KindInvalid:
		return "invalid"
	case KindGenesis:
		return "genesis"
	case KindAddNode:
		return "add-node"
	case KindRemoveNode:
		return "remove-node"
	case KindSetNodeRoutes:
		return "set-node-routes"
	case KindRotateNodeKey:
		return "rotate-node-key"
	case KindRotateIdentity:
		return "rotate-identity"
	case KindAddAdminKey:
		return "add-admin-key"
	case KindRemoveAdminKey:
		return "remove-admin-key"
	case KindSetQuorum:
		return "set-quorum"
	case KindCheckpoint:
		return "checkpoint"
	case KindEpochBump:
		return "epoch-bump"
	default:
		return fmt.Sprintf("kind?<%d>", uint8(k))
	}
}

// IsRevocation reports whether the kind withdraws authority.
//
// Fork choice prefers these over their siblings and never lets one be silently
// orphaned: the safety bias docs/04-architecture.md calls "revoked wins".
func (k Kind) IsRevocation() bool {
	return k == KindRemoveNode || k == KindRemoveAdminKey
}

// NodeKeys is the rotatable key material of a node: everything about a
// membership that can change without the member becoming a different member.
type NodeKeys struct {
	WireGuard WGKey     `cbor:"1,keyasint"`
	X25519    X25519Key `cbor:"2,keyasint"`
	MLKEM     MLKEMKey  `cbor:"3,keyasint"`
}

// A RouteGrant is the roles and routes [KindSetNodeRoutes] assigns to a node.
//
// It replaces the node's current set rather than adding to it, so the log
// always states the whole grant in one place and there is no accumulated
// history to reconstruct in order to know what a node is allowed to do. An
// empty grant withdraws everything.
type RouteGrant struct {
	Roles  []Role         `cbor:"1,keyasint,omitempty"`
	Routes []netip.Prefix `cbor:"2,keyasint,omitempty"`
}

// An AUM — Authority Update Message, the term tka uses — is one record of the
// membership log.
//
// Every field beyond Kind and Prev is an optional payload, and
// [AUM.StaticValidate] requires each kind to carry exactly the payload fields
// it is defined with: not a subset, not a superset. A record cannot carry a
// field its kind ignores, so there is no way to smuggle content past
// validation into something that is signed and chained.
type AUM struct {
	Kind Kind `cbor:"1,keyasint"`

	// Prev is the hash of the parent record, absent only in genesis. It is
	// what makes the log append-only: forging or reordering history means
	// finding a SHA-256 collision.
	Prev *Hash `cbor:"2,keyasint,omitempty"`

	// State is the full authority state, for genesis and checkpoints.
	State *Snapshot `cbor:"3,keyasint,omitempty"`

	// Node is the member being admitted, for AddNode.
	Node *NodeRecord `cbor:"4,keyasint,omitempty"`

	// Subject names the node or admin key a record acts on.
	Subject *Identity `cbor:"5,keyasint,omitempty"`

	// Admin is the admin key being added, for AddAdminKey.
	Admin *AdminKey `cbor:"6,keyasint,omitempty"`

	// Keys is the replacement key material, for RotateNodeKey.
	Keys *NodeKeys `cbor:"7,keyasint,omitempty"`

	// Grant is the replacement role and route set, for SetNodeRoutes.
	Grant *RouteGrant `cbor:"8,keyasint,omitempty"`

	// NewIdentity is the replacement identity key, for RotateIdentity.
	NewIdentity *Identity `cbor:"9,keyasint,omitempty"`

	// Quorum is the new vote threshold, for SetQuorum.
	Quorum *uint32 `cbor:"10,keyasint,omitempty"`

	// Epoch is the group-secret bump that membership and key changes carry.
	Epoch *EpochRecord `cbor:"11,keyasint,omitempty"`

	// Signatures authorize the record. Sorted by key ID and duplicate-free,
	// like every other set in the schema.
	//
	// CBOR key 23 is the highest that encodes in a single byte, and is where
	// tka puts its signatures for that reason; the same convention is kept
	// here so payload fields have room to grow below it.
	Signatures []Signature `cbor:"23,keyasint,omitempty"`
}

// payload field identifiers, for the exact-match table in StaticValidate.
type fieldSet uint16

const (
	fState fieldSet = 1 << iota
	fNode
	fSubject
	fAdmin
	fKeys
	fGrant
	fNewIdentity
	fQuorum
	fEpoch
)

var fieldNames = []struct {
	bit  fieldSet
	name string
}{
	{fState, "State"},
	{fNode, "Node"},
	{fSubject, "Subject"},
	{fAdmin, "Admin"},
	{fKeys, "Keys"},
	{fGrant, "Grant"},
	{fNewIdentity, "NewIdentity"},
	{fQuorum, "Quorum"},
	{fEpoch, "Epoch"},
}

func (f fieldSet) String() string {
	if f == 0 {
		return "(none)"
	}
	var names []string
	for _, fn := range fieldNames {
		if f&fn.bit != 0 {
			names = append(names, fn.name)
		}
	}
	return joinComma(names)
}

// kindFields is the exact payload each kind carries.
//
// A kind absent from this table is not a valid kind, which is how unknown
// record types are rejected: see the package documentation for why this log
// cannot afford to ignore records it does not understand.
var kindFields = map[Kind]fieldSet{
	KindGenesis:        fState,
	KindAddNode:        fNode | fEpoch,
	KindRemoveNode:     fSubject | fEpoch,
	KindSetNodeRoutes:  fSubject | fGrant,
	KindRotateNodeKey:  fSubject | fKeys | fEpoch,
	KindRotateIdentity: fSubject | fNewIdentity | fEpoch,
	KindAddAdminKey:    fAdmin,
	KindRemoveAdminKey: fSubject,
	KindSetQuorum:      fQuorum,
	KindCheckpoint:     fState,
	KindEpochBump:      fEpoch,
}

func (a *AUM) presentFields() fieldSet {
	var f fieldSet
	if a.State != nil {
		f |= fState
	}
	if a.Node != nil {
		f |= fNode
	}
	if a.Subject != nil {
		f |= fSubject
	}
	if a.Admin != nil {
		f |= fAdmin
	}
	if a.Keys != nil {
		f |= fKeys
	}
	if a.Grant != nil {
		f |= fGrant
	}
	if a.NewIdentity != nil {
		f |= fNewIdentity
	}
	if a.Quorum != nil {
		f |= fQuorum
	}
	if a.Epoch != nil {
		f |= fEpoch
	}
	return f
}

// MaxSignatures caps a record's signature set: every admin key, plus the one
// node self-signature some kinds require.
const MaxSignatures = MaxAdmins + 1

// StaticValidate checks everything about a record that can be decided from the
// record alone: that its kind is known, that it carries exactly that kind's
// payload, that its sets are canonically ordered, that it is signed, and that
// its payload values are individually well-formed.
//
// What it deliberately does not check is anything requiring state: whether the
// signatures are from keys the network trusts, whether they reach quorum,
// whether the subject exists, whether an address collides. Those are trust/log's
// job, because they are only answerable against a particular parent state.
func (a *AUM) StaticValidate() error {
	if err := a.ValidateUnsigned(); err != nil {
		return err
	}
	return a.validateSignatureSet()
}

// ValidateUnsigned is [AUM.StaticValidate] without the requirement that the
// record carry any signature, for a record still being assembled: a quorum is
// collected across machines, so a record exists unsigned for as long as the
// ceremony takes.
//
// Signatures present are still checked for shape and ordering. Only their
// absence is tolerated.
func (a *AUM) ValidateUnsigned() error {
	want, known := kindFields[a.Kind]
	if !known {
		return fmt.Errorf("unknown record kind %v", a.Kind)
	}
	if got := a.presentFields(); got != want {
		return fmt.Errorf("%v record carries fields %v, want exactly %v", a.Kind, got, want)
	}
	if a.Kind == KindGenesis {
		if a.Prev != nil {
			return errors.New("genesis record must not have a parent")
		}
	} else {
		if a.Prev == nil {
			return fmt.Errorf("%v record has no parent", a.Kind)
		}
		if a.Prev.IsZero() {
			return fmt.Errorf("%v record has a zero parent hash", a.Kind)
		}
	}

	if err := a.validateSignatureShape(); err != nil {
		return err
	}

	if a.State != nil {
		if err := a.State.StaticValidate(a.Kind == KindGenesis); err != nil {
			return fmt.Errorf("%v state: %w", a.Kind, err)
		}
	}
	if a.Node != nil {
		if err := a.Node.StaticValidate(); err != nil {
			return err
		}
	}
	if a.Subject != nil {
		if err := a.Subject.Validate(); err != nil {
			return fmt.Errorf("subject: %w", err)
		}
	}
	if a.Admin != nil {
		if err := a.Admin.StaticValidate(); err != nil {
			return err
		}
	}
	if a.Keys != nil {
		if a.Keys.WireGuard.IsZero() {
			return errors.New("replacement keys have no WireGuard key")
		}
		if a.Keys.X25519.IsZero() {
			return errors.New("replacement keys have no X25519 key")
		}
		if a.Keys.MLKEM.IsZero() {
			return errors.New("replacement keys have no ML-KEM key")
		}
	}
	if a.Grant != nil {
		if err := validateRoles(a.Grant.Roles); err != nil {
			return fmt.Errorf("route grant: %w", err)
		}
		if len(a.Grant.Routes) > MaxRoutesPerNode {
			return fmt.Errorf("route grant has %d routes, over the %d limit",
				len(a.Grant.Routes), MaxRoutesPerNode)
		}
		for i, pfx := range a.Grant.Routes {
			if i > 0 && comparePrefix(a.Grant.Routes[i-1], pfx) >= 0 {
				return fmt.Errorf("route grant routes are not sorted and unique at %v", pfx)
			}
		}
	}
	if a.NewIdentity != nil {
		if err := a.NewIdentity.Validate(); err != nil {
			return fmt.Errorf("new identity: %w", err)
		}
		if a.Subject != nil && *a.NewIdentity == *a.Subject {
			return errors.New("identity rotation to the same key")
		}
	}
	if a.Quorum != nil {
		if *a.Quorum == 0 {
			return errors.New("quorum of zero would let any single signature authorize a change")
		}
		if *a.Quorum > MaxAdmins*MaxVotes {
			return fmt.Errorf("quorum %d exceeds any reachable vote weight", *a.Quorum)
		}
	}
	if a.Epoch != nil {
		if err := a.Epoch.StaticValidate(); err != nil {
			return fmt.Errorf("%v: %w", a.Kind, err)
		}
	}
	return nil
}

func (a *AUM) validateSignatureSet() error {
	if len(a.Signatures) == 0 {
		return fmt.Errorf("%v record is unsigned", a.Kind)
	}
	return nil
}

func (a *AUM) validateSignatureShape() error {
	if len(a.Signatures) > MaxSignatures {
		return fmt.Errorf("%v record has %d signatures, over the %d limit",
			a.Kind, len(a.Signatures), MaxSignatures)
	}
	for i := range a.Signatures {
		s := &a.Signatures[i]
		if s.KeyID.IsZero() {
			return fmt.Errorf("signature %d has a zero key ID", i)
		}
		if s.Sig.IsZero() {
			return fmt.Errorf("signature %d by %v is zero", i, s.KeyID.ShortString())
		}
		// Sorted and duplicate-free: a set with two orderings would be a
		// record with two encodings, and a repeated key must not be able to
		// count its votes twice.
		if i > 0 && a.Signatures[i-1].KeyID.Compare(s.KeyID) >= 0 {
			return fmt.Errorf("signatures are not sorted and unique at %v", s.KeyID.ShortString())
		}
	}
	return nil
}

// Encode returns the record's canonical CBOR encoding.
func (a *AUM) Encode() ([]byte, error) { return encode(a) }

// Hash returns the record's identity in the chain.
//
// The record must be valid — either freshly out of [DecodeAUM], or having
// passed [AUM.StaticValidate]. Hashing an invalid record panics rather than
// returning a hash that nothing should act on.
func (a *AUM) Hash() Hash { return hashLabeled(labelAUM, mustEncode(a)) }

// SigHash returns the digest signatures are computed over: the record without
// its signatures, so that the value being signed does not depend on the
// signatures being collected.
//
// A record and its signing hash are separately labelled, so a signature can
// never be replayed as though it were over a whole record, or the reverse.
// Same precondition as [AUM.Hash].
func (a *AUM) SigHash() Hash {
	unsigned := *a
	unsigned.Signatures = nil
	return hashLabeled(labelAUMSig, mustEncode(&unsigned))
}

// Sign appends a signature by priv, keeping the signature set sorted.
//
// It is an error to sign twice with the same key: a repeated signature would
// be a second encoding of the same authorization, and vote counting must not
// be able to double-count.
func (a *AUM) Sign(priv PrivateIdentity) error {
	id := priv.Public()
	if slices.ContainsFunc(a.Signatures, func(s Signature) bool { return s.KeyID == id }) {
		return fmt.Errorf("types: %v is already a signer of this record", id.ShortString())
	}
	if len(a.Signatures)+1 > MaxSignatures {
		return fmt.Errorf("types: record already has the maximum %d signatures", MaxSignatures)
	}
	// SigHash covers everything but the signatures, so gathering them in any
	// order — and on different machines, which is the point of a quorum —
	// signs the same value.
	sig, err := priv.Sign(a.SigHash().bytes())
	if err != nil {
		return err
	}
	a.Signatures = append(a.Signatures, Signature{KeyID: id, Sig: sig})
	slices.SortFunc(a.Signatures, func(x, y Signature) int { return x.KeyID.Compare(y.KeyID) })
	return nil
}

// VerifySignature reports whether the record carries a valid signature by id.
func (a *AUM) VerifySignature(id Identity) bool {
	i := slices.IndexFunc(a.Signatures, func(s Signature) bool { return s.KeyID == id })
	if i < 0 {
		return false
	}
	return id.Verify(a.SigHash().bytes(), a.Signatures[i].Sig)
}

// Clone returns a deep copy, so that a caller holding a record cannot observe
// another caller mutating it.
func (a *AUM) Clone() *AUM {
	out := *a
	if a.Prev != nil {
		h := *a.Prev
		out.Prev = &h
	}
	if a.State != nil {
		out.State = a.State.Clone()
	}
	if a.Node != nil {
		out.Node = a.Node.Clone()
	}
	if a.Subject != nil {
		s := *a.Subject
		out.Subject = &s
	}
	if a.Admin != nil {
		adm := *a.Admin
		out.Admin = &adm
	}
	if a.Keys != nil {
		k := *a.Keys
		out.Keys = &k
	}
	if a.Grant != nil {
		g := RouteGrant{Roles: slices.Clone(a.Grant.Roles), Routes: slices.Clone(a.Grant.Routes)}
		out.Grant = &g
	}
	if a.NewIdentity != nil {
		id := *a.NewIdentity
		out.NewIdentity = &id
	}
	if a.Quorum != nil {
		q := *a.Quorum
		out.Quorum = &q
	}
	if a.Epoch != nil {
		e := EpochRecord{Epoch: a.Epoch.Epoch, Commit: a.Epoch.Commit}
		e.Wraps = make([]EpochWrap, len(a.Epoch.Wraps))
		for i := range a.Epoch.Wraps {
			e.Wraps[i] = a.Epoch.Wraps[i]
			e.Wraps[i].Sealed = slices.Clone(a.Epoch.Wraps[i].Sealed)
		}
		out.Epoch = &e
	}
	out.Signatures = slices.Clone(a.Signatures)
	return &out
}

// DecodeAUM decodes and validates a record.
//
// It rejects anything that is not the canonical encoding of a structurally
// valid record, so every AUM value produced here is one whose bytes are
// exactly what re-encoding it yields — which is what lets [AUM.Hash] be taken
// as the identity of the bytes it arrived as.
func DecodeAUM(b []byte) (AUM, error) {
	a, err := decodeCanonical[AUM](b)
	if err != nil {
		return AUM{}, err
	}
	if err := a.StaticValidate(); err != nil {
		return AUM{}, fmt.Errorf("types: invalid record: %w", err)
	}
	return a, nil
}

// DecodeUnsignedAUM is [DecodeAUM] for a record that may not carry any
// signature yet, which is every record between being assembled and finishing
// its signing ceremony. Signatures present are still checked for shape and
// ordering; only their absence is tolerated.
//
// Nothing that acts on a record should use this: a record with no signatures is
// a proposal, not an authorization, and trust/log rejects one either way.
func DecodeUnsignedAUM(b []byte) (AUM, error) {
	a, err := decodeCanonical[AUM](b)
	if err != nil {
		return AUM{}, err
	}
	if err := a.ValidateUnsigned(); err != nil {
		return AUM{}, fmt.Errorf("types: invalid record: %w", err)
	}
	return a, nil
}

// bytes returns the hash as a slice, for the signing APIs that take one.
func (h Hash) bytes() []byte { return h[:] }

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}
