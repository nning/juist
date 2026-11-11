package types

import (
	"crypto/mlkem"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/nning/juist/internal/malformed"
)

// A Kind identifies what an [AUM] does. Numbers are permanent: never
// reordered, never reused. Kind 0 is invalid, so a dropped kind field cannot
// pass for a real one.
type Kind uint8

const (
	KindInvalid Kind = 0

	// KindGenesis creates the network: no parent, its hash names the network,
	// and its signatures are checked against the admin keys it carries itself.
	KindGenesis Kind = 1

	// KindAddNode admits a member; its epoch bump hands it the group secret.
	KindAddNode Kind = 2

	// KindRemoveNode revokes a member; its epoch bump is what takes discovery
	// away, not only the WireGuard peer entry.
	KindRemoveNode Kind = 3

	// KindSetNodeRoutes replaces a node's roles and routes. Capabilities are
	// granted only here or in AddNode: a node never asserts its own.
	KindSetNodeRoutes Kind = 4

	// KindRotateNodeKey replaces a node's WireGuard and encryption keys. Needs
	// quorum plus the node's own signature, proving the keys came from it.
	KindRotateNodeKey Kind = 5

	// KindRotateIdentity replaces a node's identity, signing key and derived
	// overlay address, keeping roles, routes, v4 address and name. Needs
	// quorum plus signatures by the old key and the new one the record names.
	KindRotateIdentity Kind = 6

	// KindAddAdminKey adds an admin signing key with a vote weight.
	KindAddAdminKey Kind = 7

	// KindRemoveAdminKey removes an admin key; rejected if the rest could no
	// longer reach quorum.
	KindRemoveAdminKey Kind = 8

	// KindSetQuorum changes k, the vote weight a change requires.
	KindSetQuorum Kind = 9

	// KindCheckpoint states the full authority state, for bootstrap and
	// compaction. Where the parent state is known it must match exactly, or a
	// quorum could rewrite membership by assertion.
	KindCheckpoint Kind = 10

	// KindEpochBump rotates the group secret without changing membership.
	KindEpochBump Kind = 11

	// KindSchemaUpgrade raises the network's record schema. Every build must
	// decode it, so a node too old to apply it can still see and report it.
	KindSchemaUpgrade Kind = 12

	// KindSetVouchers sets how many admin devices must vouch for a node's view
	// within the freshness TTL; one dishonest voucher could otherwise keep
	// every partition fresh.
	KindSetVouchers Kind = 13

	// KindSetHolder sets how many votes a holder's keys cast between them,
	// and how many of them must sign for those votes to count.
	KindSetHolder Kind = 14

	// KindRenumberNetwork moves the network to another IPv4 prefix and every
	// member into it. What it replaces stays live until its deadline.
	KindRenumberNetwork Kind = 15

	// KindRenumberNode moves one member to another IPv4 address in the
	// prefix, keeping the old one live until the deadline.
	KindRenumberNode Kind = 16

	// KindRetireAddresses retires everything renumberings replaced, ahead of
	// their deadlines.
	KindRetireAddresses Kind = 17

	KindRenameNetwork Kind = 18

	// KindSetAdminRecipient sets an admin key's encryption key; that admin
	// key must sign it too.
	KindSetAdminRecipient Kind = 19

	// KindSetNodeNames replaces the public names a node answers for.
	KindSetNodeNames Kind = 20

	// KindSetDomain sets the network's public domain, or withdraws it.
	KindSetDomain Kind = 21

	// KindSetPublished replaces the names a node publishes under the domain.
	KindSetPublished Kind = 22

	// KindRenameNode renames a member; the name must not fold like another
	// member's.
	KindRenameNode Kind = 23

	// KindDisable ends the network for good by revealing a break-glass secret
	// the genesis committed to. Unsigned, counts wherever it hangs, and valid
	// under every schema, since a network without admins cannot upgrade.
	// Builds older than it cannot read it and keep running.
	KindDisable Kind = 24

	// KindSetPolicy replaces the access policy; an empty one withdraws it.
	KindSetPolicy Kind = 25

	// Kinds 26 and 27 cut a network over to schema 18, and stay unused.

	// KindSetPublicDERP sets the public DERP servers members meet through.
	KindSetPublicDERP Kind = 28
)

var kindNames = map[Kind]string{
	KindInvalid:           "invalid",
	KindGenesis:           "genesis",
	KindAddNode:           "add-node",
	KindRemoveNode:        "remove-node",
	KindSetNodeRoutes:     "set-node-routes",
	KindRotateNodeKey:     "rotate-node-key",
	KindRotateIdentity:    "rotate-identity",
	KindAddAdminKey:       "add-admin-key",
	KindRemoveAdminKey:    "remove-admin-key",
	KindSetQuorum:         "set-quorum",
	KindCheckpoint:        "checkpoint",
	KindEpochBump:         "epoch-bump",
	KindSchemaUpgrade:     "schema-upgrade",
	KindSetVouchers:       "set-vouchers",
	KindSetHolder:         "set-holder",
	KindRenumberNetwork:   "renumber-network",
	KindRenumberNode:      "renumber-node",
	KindRetireAddresses:   "retire-addresses",
	KindRenameNetwork:     "rename-network",
	KindSetAdminRecipient: "set-admin-recipient",
	KindSetNodeNames:      "set-node-names",
	KindSetDomain:         "set-domain",
	KindSetPublished:      "set-published",
	KindRenameNode:        "rename-node",
	KindDisable:           "disable",
	KindSetPolicy:         "set-policy",
	KindSetPublicDERP:     "set-public-derp",
}

func (k Kind) String() string {
	if n, ok := kindNames[k]; ok {
		return n
	}
	return fmt.Sprintf("kind?<%d>", uint8(k))
}

// IsRevocation reports whether the kind withdraws authority; fork choice
// never orphans one in favour of a sibling.
func (k Kind) IsRevocation() bool {
	return k == KindRemoveNode || k == KindRemoveAdminKey
}

// NodeKeys is a node's rotatable key material; rotating it keeps the member.
type NodeKeys struct {
	WireGuard WGKey     `cbor:"1,keyasint"`
	X25519    X25519Key `cbor:"2,keyasint"`
	MLKEM     MLKEMKey  `cbor:"3,keyasint"`
}

// A RecipientKey is an HPKE recipient key: both halves of the hybrid KEM.
type RecipientKey struct {
	X25519 X25519Key `cbor:"1,keyasint"`
	MLKEM  MLKEMKey  `cbor:"2,keyasint"`
}

func (r *RecipientKey) validate() error {
	switch {
	case r.X25519.IsZero():
		return errors.New("encryption key has no X25519 key")
	case r.MLKEM.IsZero():
		return errors.New("encryption key has no ML-KEM key")
	}
	if _, err := mlkem.NewEncapsulationKey768(r.MLKEM[:]); err != nil {
		return fmt.Errorf("encryption key: %w", err)
	}
	return nil
}

// A RouteGrant is the roles and routes [KindSetNodeRoutes] assigns, replacing
// the current set; an empty one withdraws everything.
type RouteGrant struct {
	Roles  []Role         `cbor:"1,keyasint,omitempty"`
	Routes []netip.Prefix `cbor:"2,keyasint,omitempty"`
}

// A NameGrant is the names [KindSetNodeNames] gives a node, replacing what it
// had; an empty one withdraws them all.
type NameGrant struct {
	Names []string `cbor:"1,keyasint,omitempty"`
}

// A PublishGrant is the names [KindSetPublished] gives a node to publish,
// replacing what it had; an empty one withdraws them all.
type PublishGrant struct {
	Names []PublishedName `cbor:"1,keyasint,omitempty"`
}

// An AUM (Authority Update Message) is one record of the membership log.
// Fields beyond Kind and Prev are payloads; [AUM.StaticValidate] requires
// exactly the ones each kind is defined with, so nothing can be smuggled in.
// Which kind carries which payload is the kindFields table.
type AUM struct {
	Kind Kind `cbor:"1,keyasint"`

	// Prev is the parent record's hash, absent only in genesis; it makes the
	// log append-only.
	Prev *Hash `cbor:"2,keyasint,omitempty"`

	State *Snapshot `cbor:"3,keyasint,omitempty"`

	Node *NodeRecord `cbor:"4,keyasint,omitempty"`

	// Subject names the node or admin key a record acts on.
	Subject *Identity `cbor:"5,keyasint,omitempty"`

	Admin *AdminKey `cbor:"6,keyasint,omitempty"`

	Keys *NodeKeys `cbor:"7,keyasint,omitempty"`

	Grant *RouteGrant `cbor:"8,keyasint,omitempty"`

	NewIdentity *Identity `cbor:"9,keyasint,omitempty"`

	Quorum *uint32 `cbor:"10,keyasint,omitempty"`

	// Epoch is the group-secret bump membership and key changes carry.
	Epoch *EpochRecord `cbor:"11,keyasint,omitempty"`

	Schema *SchemaVersion `cbor:"12,keyasint,omitempty"`

	Vouchers *uint32 `cbor:"13,keyasint,omitempty"`

	Holder *HolderPolicy `cbor:"14,keyasint,omitempty"`

	Renumber *Renumbering `cbor:"15,keyasint,omitempty"`

	// Network is the network's new name.
	Network *string `cbor:"16,keyasint,omitempty"`

	Recipient *RecipientKey `cbor:"17,keyasint,omitempty"`

	Names *NameGrant `cbor:"18,keyasint,omitempty"`

	// Domain is the network's new public domain; empty withdraws it.
	Domain *string `cbor:"19,keyasint,omitempty"`

	Publish *PublishGrant `cbor:"20,keyasint,omitempty"`

	// NodeName is a member's new name.
	NodeName *string `cbor:"21,keyasint,omitempty"`

	// Secret is the break-glass secret a disable record reveals.
	Secret *DisablementSecret `cbor:"22,keyasint,omitempty"`

	// Signatures are sorted by key ID and duplicate-free. Key 23 is the
	// highest one-byte CBOR key, leaving payloads room below it.
	Signatures []Signature `cbor:"23,keyasint,omitempty"`

	Policy *Policy `cbor:"24,keyasint,omitempty"`

	// NewSigning is the new identity's signing key.
	NewSigning *SigningKey `cbor:"25,keyasint,omitempty"`

	PublicDERP *PublicDERP `cbor:"26,keyasint,omitempty"`
}

// A HolderPolicy is the votes a holder's keys cast between them, and how many
// of them must sign.
type HolderPolicy struct {
	Name   string `cbor:"1,keyasint"`
	Votes  uint32 `cbor:"2,keyasint"`
	Needed uint32 `cbor:"3,keyasint"`
}

// A Renumbering moves one member to V4 ([KindRenumberNode]) or the network to
// Prefix and members to Addrs ([KindRenumberNetwork]). What it replaces stays
// live until Until, in Unix seconds.
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

type fieldSet uint32

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
	fRecipient
	fNames
	fDomain
	fPublish
	fNodeName
	fSecret
	fPolicy
	fNewSigning
	fPublicDERP
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
	{fRecipient, "Recipient"},
	{fNames, "Names"},
	{fDomain, "Domain"},
	{fPublish, "Publish"},
	{fNodeName, "NodeName"},
	{fSecret, "Secret"},
	{fPolicy, "Policy"},
	{fNewSigning, "NewSigning"},
	{fPublicDERP, "PublicDERP"},
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

// kindFields is the exact payload each kind carries; a kind absent from it is
// rejected as unknown.
var kindFields = map[Kind]fieldSet{
	KindGenesis:        fState,
	KindAddNode:        fNode | fEpoch,
	KindRemoveNode:     fSubject | fEpoch,
	KindSetNodeRoutes:  fSubject | fGrant,
	KindRotateNodeKey:  fSubject | fKeys | fEpoch,
	KindRotateIdentity: fSubject | fNewIdentity | fNewSigning | fEpoch,
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

	KindSetAdminRecipient: fSubject | fRecipient,

	KindSetNodeNames: fSubject | fNames,

	KindSetDomain:    fDomain,
	KindSetPublished: fSubject | fPublish,

	KindRenameNode: fSubject | fNodeName,

	KindDisable: fSecret,

	KindSetPolicy: fPolicy,

	KindSetPublicDERP: fPublicDERP,
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
	if a.Recipient != nil {
		f |= fRecipient
	}
	if a.Names != nil {
		f |= fNames
	}
	if a.Domain != nil {
		f |= fDomain
	}
	if a.Publish != nil {
		f |= fPublish
	}
	if a.NodeName != nil {
		f |= fNodeName
	}
	if a.Secret != nil {
		f |= fSecret
	}
	if a.Policy != nil {
		f |= fPolicy
	}
	if a.NewSigning != nil {
		f |= fNewSigning
	}
	if a.PublicDERP != nil {
		f |= fPublicDERP
	}
	return f
}

// MaxSignatures caps a record's signature set: every admin key, plus the one
// node self-signature some kinds require.
const MaxSignatures = MaxAdmins + 1

// StaticValidate checks what the record alone decides: known kind, exactly its
// payload, canonical sets, well-formed values, at least one signature (none
// for disable). Trust, quorum and subject existence are trust/log's to check.
func (a *AUM) StaticValidate() error {
	if err := a.ValidateUnsigned(); err != nil {
		return err
	}
	return a.validateSignatureSet()
}

// ValidateUnsigned is [AUM.StaticValidate] without requiring a signature, for
// a record still being signed. Signatures present are still checked.
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
		if err := validateGrant(a.Grant.Roles, a.Grant.Routes); err != nil {
			return fmt.Errorf("route grant: %w", err)
		}
		if len(a.Grant.Routes) > MaxRoutesPerNode {
			return fmt.Errorf("route grant has %d routes, over the %d limit",
				len(a.Grant.Routes), MaxRoutesPerNode)
		}
		for i, pfx := range a.Grant.Routes {
			if i > 0 && ComparePrefix(a.Grant.Routes[i-1], pfx) >= 0 {
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
	if a.NewSigning != nil {
		if err := a.NewSigning.Validate(); err != nil {
			return fmt.Errorf("new signing key: %w", err)
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
	if a.Recipient != nil {
		if err := a.Recipient.validate(); err != nil {
			return err
		}
	}
	if a.Names != nil {
		if err := validateNames(a.Names.Names); err != nil {
			return fmt.Errorf("name grant: %w", err)
		}
	}
	if a.Domain != nil && *a.Domain != "" {
		if err := ValidateHostName(*a.Domain); err != nil {
			return fmt.Errorf("domain: %w", err)
		}
	}
	if a.Publish != nil {
		if err := validatePublished(a.Publish.Names); err != nil {
			return fmt.Errorf("publish grant: %w", err)
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
	if a.Secret != nil && *a.Secret == (DisablementSecret{}) {
		return errors.New("disable record reveals a zero secret")
	}
	if a.NodeName != nil {
		if *a.NodeName == "" {
			return errors.New("rename-node record names no name")
		}
		if err := ValidateName(*a.NodeName); err != nil {
			return fmt.Errorf("node name: %w", err)
		}
	}
	if a.Policy != nil {
		if err := a.Policy.Validate(); err != nil {
			return fmt.Errorf("policy: %w", err)
		}
	}
	if a.Schema != nil && *a.Schema == 0 {
		// Deliberately no upper bound: a node too old for the schema must
		// still decode, store, report and relay this record.
		return errors.New("schema-upgrade record adopts schema 0, which every network already has")
	}
	return nil
}

func (a *AUM) validateSignatureSet() error {
	if len(a.Signatures) == 0 && a.Kind != KindDisable {
		return fmt.Errorf("%v record is unsigned", a.Kind)
	}
	return nil
}

func (a *AUM) validateSignatureShape() error {
	if a.Kind == KindDisable && len(a.Signatures) > 0 {
		// A signature would add no authority, only a second encoding.
		return errors.New("disable record is signed; its secret is its only authority")
	}
	if len(a.Signatures) > MaxSignatures {
		return fmt.Errorf("%v record has %d signatures, over the %d limit",
			a.Kind, len(a.Signatures), MaxSignatures)
	}
	for i := range a.Signatures {
		s := &a.Signatures[i]
		if s.KeyID.IsZero() {
			return fmt.Errorf("signature %d has a zero key ID", i)
		}
		if err := s.validate(); err != nil {
			return fmt.Errorf("signature %d by %v: %w", i, s.KeyID.ShortString(), err)
		}
		// Sorted, so one encoding; duplicate-free, so no key votes twice.
		if i > 0 && a.Signatures[i-1].KeyID.Compare(s.KeyID) >= 0 {
			return fmt.Errorf("signatures are not sorted and unique at %v", s.KeyID.ShortString())
		}
	}
	return nil
}

// Encode returns the record's canonical CBOR encoding.
func (a *AUM) Encode() ([]byte, error) { return encode(a) }

// Hash returns the record's identity in the chain. It panics on a record not
// from [DecodeAUM] or past [AUM.StaticValidate].
func (a *AUM) Hash() Hash { return hashLabeled(LabelAUM, mustEncode(a)) }

// SigHash returns the digest signatures cover: the record without signatures,
// labelled apart from [AUM.Hash]. Same precondition as Hash.
func (a *AUM) SigHash() Hash {
	unsigned := *a
	unsigned.Signatures = nil
	return hashLabeled(LabelAUMSig, mustEncode(&unsigned))
}

// Sign adds an ML-DSA signature by priv, keeping the set sorted. Signing twice
// with one key is an error.
func (a *AUM) Sign(priv PrivateIdentity) error {
	if a.Kind == KindDisable {
		return errors.New("types: a disable record is not signed")
	}
	id := priv.Public()
	if slices.ContainsFunc(a.Signatures, func(s Signature) bool { return s.KeyID == id }) {
		return fmt.Errorf("types: %v is already a signer of this record", id.ShortString())
	}
	if len(a.Signatures)+1 > MaxSignatures {
		return fmt.Errorf("types: record already has the maximum %d signatures", MaxSignatures)
	}

	msg := a.SigHash().bytes()
	pq, err := priv.SignPQ(msg)
	if err != nil {
		return err
	}
	a.Signatures = append(a.Signatures, Signature{KeyID: id, PQ: &pq})
	slices.SortFunc(a.Signatures, func(x, y Signature) int { return x.KeyID.Compare(y.KeyID) })
	return nil
}

// NamedSigningKey returns the signing key the record names for id (the new
// identity's in an identity rotation), or nil.
func (a *AUM) NamedSigningKey(id Identity) *SigningKey {
	if a.Kind == KindRotateIdentity && a.NewIdentity != nil && *a.NewIdentity == id {
		return a.NewSigning
	}
	return nil
}

// Signature returns the signature by id, if the record carries one.
func (a *AUM) Signature(id Identity) (*Signature, bool) {
	i := slices.IndexFunc(a.Signatures, func(s Signature) bool { return s.KeyID == id })
	if i < 0 {
		return nil, false
	}
	return &a.Signatures[i], true
}

// VerifySignature reports whether id's signature verifies against key, or if
// nil the key the record names. It does not decide whether id may sign.
func (a *AUM) VerifySignature(id Identity, key *SigningKey) bool {
	s, ok := a.Signature(id)
	if !ok {
		return false
	}
	if key == nil {
		key = a.NamedSigningKey(id)
	}
	return key != nil && key.Verify(a.SigHash().bytes(), s.PQ)
}

// Clone returns a deep copy.
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
		out.Admin = a.Admin.Clone()
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
	if a.NewSigning != nil {
		k := *a.NewSigning
		out.NewSigning = &k
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
	if a.Recipient != nil {
		r := *a.Recipient
		out.Recipient = &r
	}
	if a.Names != nil {
		out.Names = &NameGrant{Names: slices.Clone(a.Names.Names)}
	}
	if a.Domain != nil {
		d := *a.Domain
		out.Domain = &d
	}
	if a.NodeName != nil {
		n := *a.NodeName
		out.NodeName = &n
	}
	if a.Secret != nil {
		s := *a.Secret
		out.Secret = &s
	}
	if a.Publish != nil {
		out.Publish = &PublishGrant{Names: slices.Clone(a.Publish.Names)}
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
	if a.Policy != nil {
		out.Policy = a.Policy.Clone()
	}
	if a.PublicDERP != nil {
		p := *a.PublicDERP
		out.PublicDERP = &p
	}
	if a.Signatures != nil {
		out.Signatures = make([]Signature, len(a.Signatures))
		for i := range a.Signatures {
			out.Signatures[i] = *a.Signatures[i].clone()
		}
	}
	return &out
}

// DecodeAUM decodes a record, accepting only the canonical encoding of a
// statically valid one, so [AUM.Hash] identifies the bytes it arrived as.
func DecodeAUM(b []byte) (_ AUM, err error) {
	defer malformed.Recover(&err)
	a, err := DecodeCanonical[AUM](decMode, b, MaxRecordSize)
	if err != nil {
		return AUM{}, err
	}
	if err := a.StaticValidate(); err != nil {
		return AUM{}, fmt.Errorf("types: invalid record: %w", err)
	}
	return a, nil
}

// DecodeUnsignedAUM is [DecodeAUM] for a record still being signed. Never use
// it for a record to act on: unsigned is a proposal, not an authorization.
func DecodeUnsignedAUM(b []byte) (_ AUM, err error) {
	defer malformed.Recover(&err)
	a, err := DecodeCanonical[AUM](decMode, b, MaxRecordSize)
	if err != nil {
		return AUM{}, err
	}
	if err := a.ValidateUnsigned(); err != nil {
		return AUM{}, fmt.Errorf("types: invalid record: %w", err)
	}
	return a, nil
}

func (h Hash) bytes() []byte { return h[:] }
