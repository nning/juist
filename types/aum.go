package types

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// A Kind identifies what an [AUM] does. Numbers are permanent: never
// reordered, never reused. Kind 0 is invalid, so a record whose kind field was
// dropped cannot be mistaken for a real one.
type Kind uint8

const (
	KindInvalid Kind = 0

	// KindGenesis creates the network: the only record with no parent, and the
	// one whose hash names the network. Its signatures are checked against the
	// admin keys in the record itself — there is no earlier state — which is
	// what makes the genesis ceremony the root of trust.
	KindGenesis Kind = 1

	// KindAddNode admits a member device. Carries an epoch bump so the new
	// member receives the group secret and no member is left without it.
	KindAddNode Kind = 2

	// KindRemoveNode revokes a member. Carries an epoch bump, which is what
	// takes discovery away from the removed device rather than only taking
	// away its WireGuard peer entry.
	KindRemoveNode Kind = 3

	// KindSetNodeRoutes replaces a node's roles and advertised routes. Every
	// capability is granted here or in its AddNode record and nowhere else: a
	// node can never assert a role or a route for itself.
	KindSetNodeRoutes Kind = 4

	// KindRotateNodeKey replaces a node's WireGuard and encryption keys,
	// keeping its identity and address. Requires the node's own signature as
	// well as quorum, which is what shows the new keys came from the device.
	KindRotateNodeKey Kind = 5

	// KindRotateIdentity replaces a node's identity key, and with it its
	// derived overlay address, keeping roles, routes, v4 address and name.
	// Requires quorum plus a signature by the new key, so a membership slot
	// cannot be bound to a key no device holds.
	KindRotateIdentity Kind = 6

	// KindAddAdminKey adds an admin signing key with a vote weight.
	KindAddAdminKey Kind = 7

	// KindRemoveAdminKey removes an admin signing key. Rejected if it would
	// leave the remaining keys unable to reach quorum, which would make the
	// network permanently unmanageable.
	KindRemoveAdminKey Kind = 8

	// KindSetQuorum changes k, the vote weight a change requires, so a network
	// that grows from three admins to ten is not stuck with day-one policy.
	KindSetQuorum Kind = 9

	// KindCheckpoint states the full authority state at a point in the chain,
	// so a new node can bootstrap without replaying history and old records
	// can be compacted away. One whose parent state is known must match it
	// exactly, or a quorum could rewrite membership by asserting a state.
	KindCheckpoint Kind = 10

	// KindEpochBump rotates the group secret without changing membership: the
	// response to a suspected group-secret leak.
	KindEpochBump Kind = 11

	// KindSchemaUpgrade raises the record schema the network is written under,
	// so that a schema change costs a quorum-signed record rather than a new
	// network. It is the one record every build must be able to decode,
	// whatever it implements: a node too old to apply it has to be able to see
	// it, or it would only observe that sync had stopped.
	KindSchemaUpgrade Kind = 12

	// KindSetVouchers changes how many admin devices must vouch for a node's
	// view of the network within the freshness TTL: with one, a single
	// dishonest admin device keeps every partition fresh; with m, it takes m
	// of them. Schema 1 and later.
	KindSetVouchers Kind = 13

	// KindSetHolder sets how many votes a holder's keys cast between them,
	// and how many of them must sign for those votes to count. Schema 3 and
	// later.
	KindSetHolder Kind = 14

	// KindRenumberNetwork moves the network to another IPv4 prefix and every
	// member to an address in it. The addresses and ranges it replaces stay
	// live until its deadline, so members that have not seen it yet still
	// reach and are reached by the rest. Schema 5 and later.
	KindRenumberNetwork Kind = 15

	// KindRenumberNode moves one member to another IPv4 address in the
	// network's prefix, keeping its old one live until the deadline. Schema 5
	// and later.
	KindRenumberNode Kind = 16

	// KindRetireAddresses retires every address and range a renumbering
	// replaced, ahead of their deadlines. Schema 5 and later.
	KindRetireAddresses Kind = 17

	// KindRenameNetwork gives the network another name. Schema 6 and later.
	KindRenameNetwork Kind = 18
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
	case KindSchemaUpgrade:
		return "schema-upgrade"
	case KindSetVouchers:
		return "set-vouchers"
	case KindSetHolder:
		return "set-holder"
	case KindRenumberNetwork:
		return "renumber-network"
	case KindRenumberNode:
		return "renumber-node"
	case KindRetireAddresses:
		return "retire-addresses"
	case KindRenameNetwork:
		return "rename-network"
	default:
		return fmt.Sprintf("kind?<%d>", uint8(k))
	}
}

// IsRevocation reports whether the kind withdraws authority. Fork choice
// prefers these over their siblings and never silently orphans one: "revoked
// wins".
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
// It replaces the current set rather than adding to it, so the whole grant is
// stated in one place. An empty grant withdraws everything.
type RouteGrant struct {
	Roles  []Role         `cbor:"1,keyasint,omitempty"`
	Routes []netip.Prefix `cbor:"2,keyasint,omitempty"`
}

// An AUM — Authority Update Message, the term tka uses — is one record of the
// membership log. Every field beyond Kind and Prev is an optional payload, and
// [AUM.StaticValidate] requires each kind to carry exactly the fields it is
// defined with, so no content can be smuggled into something signed and
// chained.
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

	// Schema is the version being adopted, for SchemaUpgrade.
	Schema *SchemaVersion `cbor:"12,keyasint,omitempty"`

	// Vouchers is the new vouching threshold, for SetVouchers.
	Vouchers *uint32 `cbor:"13,keyasint,omitempty"`

	// Holder is a holder's new policy, for SetHolder.
	Holder *HolderPolicy `cbor:"14,keyasint,omitempty"`

	// Renumber is what a renumbering moves, for RenumberNetwork and
	// RenumberNode.
	Renumber *Renumbering `cbor:"15,keyasint,omitempty"`

	// Network is the network's new name, for RenameNetwork.
	Network *string `cbor:"16,keyasint,omitempty"`

	// Signatures authorize the record. Sorted by key ID and duplicate-free,
	// like every other set. CBOR key 23 is the highest that encodes in one
	// byte, leaving payload fields room to grow below it.
	Signatures []Signature `cbor:"23,keyasint,omitempty"`
}

// A HolderPolicy is what [KindSetHolder] states about a holder: the votes
// its keys cast between them, and how many of them must sign.
type HolderPolicy struct {
	Name   string `cbor:"1,keyasint"`
	Votes  uint32 `cbor:"2,keyasint"`
	Needed uint32 `cbor:"3,keyasint"`
}

// A Renumbering is what a renumbering record moves: one member to V4, for
// [KindRenumberNode], or the network to Prefix and every member to its entry
// in Addrs, for [KindRenumberNetwork]. What it replaces stays live until Until,
// in Unix seconds.
type Renumbering struct {
	Until  uint64        `cbor:"1,keyasint"`
	V4     *netip.Addr   `cbor:"2,keyasint,omitempty"`
	Prefix *netip.Prefix `cbor:"3,keyasint,omitempty"`
	Addrs  []MemberV4    `cbor:"4,keyasint,omitempty"`
}

// A MemberV4 is the address a network renumbering gives one member.
type MemberV4 struct {
	Identity Identity   `cbor:"1,keyasint"`
	V4       netip.Addr `cbor:"2,keyasint"`
}

// validate checks a renumbering's shape for kind.
func (r *Renumbering) validate(kind Kind) error {
	if r.Until == 0 {
		return fmt.Errorf("%v record sets no deadline", kind)
	}
	if kind == KindRenumberNode {
		switch {
		case r.V4 == nil:
			return errors.New("renumber-node record names no address")
		case r.Prefix != nil || len(r.Addrs) > 0:
			return errors.New("renumber-node record carries a network renumbering")
		}
		return ValidateV4(*r.V4, v4Choosable)
	}
	switch {
	case r.Prefix == nil:
		return errors.New("renumber-network record names no prefix")
	case r.V4 != nil:
		return errors.New("renumber-network record names a single address")
	case len(r.Addrs) > MaxNodes:
		return fmt.Errorf("renumber-network record has %d addresses, over the %d limit", len(r.Addrs), MaxNodes)
	}
	if err := ValidateV4Prefix(*r.Prefix); err != nil {
		return err
	}
	seen := make(map[netip.Addr]bool, len(r.Addrs))
	for i := range r.Addrs {
		e := &r.Addrs[i]
		if err := e.Identity.Validate(); err != nil {
			return fmt.Errorf("renumbered member: %w", err)
		}
		if i > 0 && r.Addrs[i-1].Identity.Compare(e.Identity) >= 0 {
			return fmt.Errorf("renumbered members are not sorted and unique at %v", e.Identity.ShortString())
		}
		if err := ValidateV4(e.V4, []netip.Prefix{*r.Prefix}); err != nil {
			return fmt.Errorf("member %v: %w", e.Identity.ShortString(), err)
		}
		if seen[e.V4] {
			return fmt.Errorf("renumbering gives %v to two members", e.V4)
		}
		seen[e.V4] = true
	}
	return nil
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
	fSchema
	fVouchers
	fHolder
	fRenumber
	fNetwork
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
	{fSchema, "Schema"},
	{fVouchers, "Vouchers"},
	{fHolder, "Holder"},
	{fRenumber, "Renumber"},
	{fNetwork, "Network"},
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
	return strings.Join(names, ", ")
}

// kindFields is the exact payload each kind carries. A kind absent from this
// table is not valid, which is how unknown record types are rejected.
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
	KindSchemaUpgrade:  fSchema,
	KindSetVouchers:    fVouchers,
	KindSetHolder:      fHolder,

	KindRenumberNetwork: fRenumber,
	KindRenumberNode:    fSubject | fRenumber,
	KindRetireAddresses: 0,
	KindRenameNetwork:   fNetwork,
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
	if a.Schema != nil {
		f |= fSchema
	}
	if a.Vouchers != nil {
		f |= fVouchers
	}
	if a.Holder != nil {
		f |= fHolder
	}
	if a.Renumber != nil {
		f |= fRenumber
	}
	if a.Network != nil {
		f |= fNetwork
	}
	return f
}

// MaxSignatures caps a record's signature set: every admin key, plus the one
// node self-signature some kinds require.
const MaxSignatures = MaxAdmins + 1

// StaticValidate checks what can be decided from the record alone: known kind,
// exactly that kind's payload, canonically ordered sets, at least one
// signature, well-formed values. Anything needing state — whether the
// signatures are trusted, reach quorum, or name an existing subject — is
// trust/log's, since it is only answerable against a parent state.
func (a *AUM) StaticValidate() error {
	if err := a.ValidateUnsigned(); err != nil {
		return err
	}
	return a.validateSignatureSet()
}

// ValidateUnsigned is [AUM.StaticValidate] for a record still being assembled,
// which a quorum ceremony leaves unsigned for as long as it takes. Signatures
// present are still checked for shape and ordering.
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
	if a.Vouchers != nil && (*a.Vouchers == 0 || *a.Vouchers > MaxAdmins) {
		return fmt.Errorf("a vouching threshold of %d; it must be between 1 and %d", *a.Vouchers, MaxAdmins)
	}
	if h := a.Holder; h != nil {
		switch {
		case h.Name == "":
			return errors.New("a holder policy names no holder")
		case h.Votes == 0 || h.Votes > MaxVotes:
			return fmt.Errorf("a holder with %d votes; it must have between 1 and %d", h.Votes, MaxVotes)
		case h.Needed == 0 || h.Needed > MaxAdmins:
			return fmt.Errorf("a holder needing %d keys; it must need between 1 and %d", h.Needed, MaxAdmins)
		}
		if err := ValidateName(h.Name); err != nil {
			return fmt.Errorf("holder: %w", err)
		}
	}
	if a.Renumber != nil {
		if err := a.Renumber.validate(a.Kind); err != nil {
			return err
		}
	}
	if a.Network != nil {
		if *a.Network == "" {
			return errors.New("rename-network record names no name")
		}
		if err := ValidateName(*a.Network); err != nil {
			return fmt.Errorf("network name: %w", err)
		}
	}
	if a.Schema != nil && *a.Schema == 0 {
		// Zero is the schema every network starts under, so an upgrade to it
		// raises nothing. Which versions this build can act on is deliberately
		// not decided here: a record that fails to decode cannot be stored,
		// and a node too old for the network still has to store this one, both
		// to report it and to keep relaying it to members that are not.
		return errors.New("schema-upgrade record adopts schema 0, which every network already has")
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

// Hash returns the record's identity in the chain. The record must be valid —
// out of [DecodeAUM] or past [AUM.StaticValidate]; hashing an invalid one
// panics rather than returning a hash nothing should act on.
func (a *AUM) Hash() Hash { return hashLabeled(labelAUM, mustEncode(a)) }

// SigHash returns the digest signatures are computed over: the record without
// its signatures, so what is signed does not depend on the signatures already
// collected. Separately labelled from [AUM.Hash], so neither can be replayed
// as the other, and with the same precondition.
func (a *AUM) SigHash() Hash {
	unsigned := *a
	unsigned.Signatures = nil
	return hashLabeled(labelAUMSig, mustEncode(&unsigned))
}

// Sign appends a signature by priv, keeping the signature set sorted. Signing
// twice with one key is an error: vote counting must not double-count.
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
	if a.Schema != nil {
		v := *a.Schema
		out.Schema = &v
	}
	if a.Vouchers != nil {
		m := *a.Vouchers
		out.Vouchers = &m
	}
	if a.Holder != nil {
		h := *a.Holder
		out.Holder = &h
	}
	if a.Renumber != nil {
		r := *a.Renumber
		if r.V4 != nil {
			v4 := *r.V4
			r.V4 = &v4
		}
		if r.Prefix != nil {
			p := *r.Prefix
			r.Prefix = &p
		}
		r.Addrs = slices.Clone(r.Addrs)
		out.Renumber = &r
	}
	if a.Network != nil {
		n := *a.Network
		out.Network = &n
	}
	if a.Epoch != nil {
		e := *a.Epoch
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

// DecodeAUM decodes and validates a record, rejecting anything that is not the
// canonical encoding of a structurally valid one — which is what lets
// [AUM.Hash] be the identity of the bytes it arrived as.
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

// DecodeUnsignedAUM is [DecodeAUM] for a record part-way through its signing
// ceremony. Nothing that acts on a record should use it: an unsigned record is
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
