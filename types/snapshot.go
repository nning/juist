package types

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

// A Snapshot is the complete authority state at one point in the chain: the
// payload of genesis and checkpoint records.
type Snapshot struct {
	// GenesisHash identifies the network: nil inside the genesis record, set
	// when it is applied.
	GenesisHash *Hash `cbor:"1,keyasint,omitempty"`

	// Network is the human-readable name; nothing identifies the network by it.
	Network string `cbor:"2,keyasint"`

	// Quorum is k, the vote weight a change requires.
	Quorum uint32 `cbor:"3,keyasint"`

	// Epoch is the current group-secret epoch, starting at 1.
	Epoch uint64 `cbor:"4,keyasint"`

	EpochCommit Hash `cbor:"5,keyasint"`

	// Disablement holds commitments to break-glass secrets, fixed at genesis.
	Disablement []Hash `cbor:"6,keyasint,omitempty"`

	// Admins are sorted by public key.
	Admins []AdminKey `cbor:"7,keyasint,omitempty"`

	// Nodes are sorted by identity key.
	Nodes []NodeRecord `cbor:"8,keyasint,omitempty"`

	// EpochWraps is the epoch secret sealed to each member, sorted by
	// recipient.
	EpochWraps []EpochWrap `cbor:"9,keyasint,omitempty"`

	// EpochSuite seals EpochWraps; absent means [SuiteHybridX25519MLKEM768].
	EpochSuite EpochSuite `cbor:"10,keyasint,omitempty"`

	// Schema is the network's record schema, at least [MinSchema]. A newer one
	// than this build knows must still decode; trust/log decides on it.
	Schema SchemaVersion `cbor:"11,keyasint,omitempty"`

	// Vouchers is how many admin devices must vouch for a node's view within
	// the freshness TTL; absent means one.
	Vouchers uint32 `cbor:"12,keyasint,omitempty"`

	// V4Prefix is the network's own overlay IPv4 prefix; absent means
	// [OverlayV4].
	V4Prefix *netip.Prefix `cbor:"13,keyasint,omitempty"`

	// V4Retiring are ranges a renumbering left that members may still hold.
	V4Retiring *RetiringRanges `cbor:"14,keyasint,omitempty"`

	// Domain is the public domain members publish under; empty for none.
	Domain string `cbor:"15,keyasint,omitempty"`

	// Policy is what each member may open on which; absent allows everything.
	Policy *Policy `cbor:"16,keyasint,omitempty"`

	// PublicDERP is the network's public DERP servers; absent names none.
	PublicDERP *PublicDERP `cbor:"17,keyasint,omitempty"`
}

// V4Ranges returns the ranges the network's overlay IPv4 addresses may lie in.
func (s *Snapshot) V4Ranges() []netip.Prefix {
	out := V4Ranges(s.V4Prefix)
	if s.V4Retiring != nil {
		out = append(out, s.V4Retiring.Prefixes...)
	}
	return out
}

// ValidDisablement reports whether secret is a preimage of one of the
// network's break-glass commitments.
func (s *Snapshot) ValidDisablement(secret []byte) bool {
	if len(secret) != DisablementSecretSize {
		return false
	}
	want := DisablementCommit(secret)
	// Variable-time is fine: the commitments are public and the secret is
	// compared only through its digest.
	return slices.Contains(s.Disablement, want)
}

func (s *Snapshot) Node(id Identity) (*NodeRecord, bool) {
	i := slices.IndexFunc(s.Nodes, func(n NodeRecord) bool { return n.Identity == id })
	if i < 0 {
		return nil, false
	}
	return &s.Nodes[i], true
}

func (s *Snapshot) Admin(id Identity) (*AdminKey, bool) {
	i := slices.IndexFunc(s.Admins, func(a AdminKey) bool { return a.Public == id })
	if i < 0 {
		return nil, false
	}
	return &s.Admins[i], true
}

// TotalVotes is [AchievableVotes] of the admins; [MaxAdmins] times [MaxVotes]
// keeps it from overflowing.
func (s *Snapshot) TotalVotes() uint32 { return AchievableVotes(s.Admins) }

// ULA returns the network's overlay IPv6 prefix, or the zero prefix inside an
// unapplied genesis.
func (s *Snapshot) ULA() netip.Prefix {
	if s.GenesisHash == nil {
		return netip.Prefix{}
	}
	return ULA(*s.GenesisHash)
}

// Clone returns a deep copy.
func (s *Snapshot) Clone() *Snapshot {
	out := *s
	if s.GenesisHash != nil {
		h := *s.GenesisHash
		out.GenesisHash = &h
	}
	if s.V4Prefix != nil {
		p := *s.V4Prefix
		out.V4Prefix = &p
	}
	if s.V4Retiring != nil {
		r := RetiringRanges{Prefixes: slices.Clone(s.V4Retiring.Prefixes), Until: s.V4Retiring.Until}
		out.V4Retiring = &r
	}
	if s.Policy != nil {
		out.Policy = s.Policy.Clone()
	}
	if s.PublicDERP != nil {
		p := *s.PublicDERP
		out.PublicDERP = &p
	}
	out.Disablement = slices.Clone(s.Disablement)
	out.Admins = make([]AdminKey, len(s.Admins))
	for i := range s.Admins {
		out.Admins[i] = *s.Admins[i].Clone()
	}
	out.Nodes = make([]NodeRecord, len(s.Nodes))
	for i := range s.Nodes {
		out.Nodes[i] = *s.Nodes[i].Clone()
	}
	out.EpochWraps = make([]EpochWrap, len(s.EpochWraps))
	for i := range s.EpochWraps {
		out.EpochWraps[i] = s.EpochWraps[i]
		out.EpochWraps[i].Sealed = slices.Clone(s.EpochWraps[i].Sealed)
	}
	return &out
}

// Encode returns the snapshot's canonical CBOR encoding.
func (s *Snapshot) Encode() []byte { return mustEncode(s) }

// StaticValidate checks entries, canonical sets, a reachable quorum and one
// epoch wrap per member. A genesis must not carry its own hash; a checkpoint
// must.
func (s *Snapshot) StaticValidate(genesis bool) error {
	switch {
	case s.Schema < MinSchema:
		return fmt.Errorf("the state is at %v; this juist reads %v and later", s.Schema, MinSchema)
	case s.PublicDERP != nil && s.Schema < SchemaPublicDERP:
		return fmt.Errorf("a public DERP setting needs %v; the state is at %v", SchemaPublicDERP, s.Schema)
	case s.PublicDERP != nil && *s.PublicDERP == (PublicDERP{}):
		return errors.New("a public DERP setting naming none is written as none")
	case genesis && s.GenesisHash != nil:
		return errors.New("genesis record must not carry a genesis hash")
	case !genesis && s.GenesisHash == nil:
		return errors.New("snapshot has no genesis hash")
	case !genesis && s.GenesisHash.IsZero():
		return errors.New("snapshot genesis hash is zero")
	}
	if err := ValidateName(s.Network); err != nil {
		return fmt.Errorf("network name: %w", err)
	}
	if s.Vouchers > MaxAdmins {
		return fmt.Errorf("a vouching threshold of %d exceeds the %d-admin limit", s.Vouchers, MaxAdmins)
	}
	if s.V4Prefix != nil {
		if err := ValidateV4Prefix(*s.V4Prefix); err != nil {
			return err
		}
	}
	if r := s.V4Retiring; r != nil {
		switch {
		case genesis:
			return errors.New("a genesis retires IPv4 ranges it never had")
		case s.V4Prefix == nil:
			return errors.New("retiring IPv4 ranges, but no prefix they were renumbered to")
		case len(r.Prefixes) == 0:
			return errors.New("retiring IPv4 ranges name none")
		case len(r.Prefixes) > len(v4Choosable):
			return fmt.Errorf("%d retiring IPv4 ranges, over the %d limit", len(r.Prefixes), len(v4Choosable))
		case r.Until == 0:
			return errors.New("retiring IPv4 ranges have no deadline")
		}
		for i, p := range r.Prefixes {
			if err := ValidateV4Prefix(p); err != nil {
				return fmt.Errorf("retiring: %w", err)
			}
			if i > 0 && ComparePrefix(r.Prefixes[i-1], p) >= 0 {
				return fmt.Errorf("retiring IPv4 ranges are not sorted and unique at %v", p)
			}
		}
	}
	// Not for checkpoints: removals may have left fewer admin devices than
	// the threshold, which fails closed.
	if genesis && s.Vouchers > 0 {
		if err := ValidateVouchers(s.Vouchers, s.Nodes); err != nil {
			return err
		}
	}
	if s.Network == "" {
		return errors.New("network name is empty")
	}
	if s.Domain != "" {
		if err := ValidateHostName(s.Domain); err != nil {
			return fmt.Errorf("domain: %w", err)
		}
	}

	if n := len(s.Disablement); n == 0 {
		return errors.New("no disablement commitments; the network would have no break-glass path")
	} else if n > MaxDisablementValues {
		return fmt.Errorf("%d disablement commitments, over the %d limit", n, MaxDisablementValues)
	}
	for i, d := range s.Disablement {
		if d.IsZero() {
			return fmt.Errorf("disablement commitment %d is zero", i)
		}
		if i > 0 && bytes.Compare(s.Disablement[i-1][:], d[:]) >= 0 {
			return fmt.Errorf("disablement commitments are not sorted and unique at %d", i)
		}
	}

	if n := len(s.Admins); n == 0 {
		return errors.New("no admin keys; no change could ever be authorized")
	} else if n > MaxAdmins {
		return fmt.Errorf("%d admin keys, over the %d limit", n, MaxAdmins)
	}
	for i := range s.Admins {
		if err := s.Admins[i].StaticValidate(); err != nil {
			return err
		}
		if i > 0 && s.Admins[i-1].Public.Compare(s.Admins[i].Public) >= 0 {
			return fmt.Errorf("admin keys are not sorted and unique at %v", s.Admins[i].Public.ShortString())
		}
	}
	if err := ValidateAdmins(s.Admins); err != nil {
		return err
	}
	if s.Quorum == 0 {
		return errors.New("quorum is zero; any single signature would authorize a change")
	}
	if total := s.TotalVotes(); s.Quorum > total {
		return fmt.Errorf("quorum %d exceeds the total admin vote weight %d; no change could ever be authorized",
			s.Quorum, total)
	}

	if len(s.Nodes) > MaxNodes {
		return fmt.Errorf("%d nodes, over the %d limit", len(s.Nodes), MaxNodes)
	}
	for i := range s.Nodes {
		if err := s.Nodes[i].StaticValidate(); err != nil {
			return err
		}
		if s.Nodes[i].Retiring != nil && genesis {
			return fmt.Errorf("node %v retires an address in a genesis, which never gave it one",
				s.Nodes[i].Identity.ShortString())
		}
		if i > 0 && s.Nodes[i-1].Identity.Compare(s.Nodes[i].Identity) >= 0 {
			return fmt.Errorf("nodes are not sorted and unique at %v", s.Nodes[i].Identity.ShortString())
		}
		if err := s.Nodes[i].validateUnder(s.Domain); err != nil {
			return err
		}
	}
	if err := s.validateSigning(); err != nil {
		return err
	}

	if s.Policy != nil {
		if err := s.Policy.Validate(); err != nil {
			return fmt.Errorf("policy: %w", err)
		}
		if err := s.Policy.ValidateMembers(s.Nodes); err != nil {
			return err
		}
	}

	if s.Epoch == 0 {
		return errors.New("epoch is zero; epochs start at 1")
	}
	if s.EpochCommit.IsZero() {
		return errors.New("no epoch secret commitment")
	}
	if err := validateSuite(s.EpochSuite); err != nil {
		return err
	}
	if len(s.EpochWraps) != len(s.Nodes) {
		return fmt.Errorf("%d epoch wraps for %d nodes; the epoch secret must reach every member and no one else",
			len(s.EpochWraps), len(s.Nodes))
	}
	for i := range s.EpochWraps {
		w := &s.EpochWraps[i]
		if len(w.Sealed) != SealedSecretSize {
			return fmt.Errorf("epoch wrap for %v is %d bytes, want %d",
				w.Recipient.ShortString(), len(w.Sealed), SealedSecretSize)
		}
		// Both sorted and equal in size, so pairwise equality means every
		// member has a wrap and no non-member does.
		if w.Recipient != s.Nodes[i].Identity {
			return fmt.Errorf("epoch wrap %d addresses %v but member %d is %v",
				i, w.Recipient.ShortString(), i, s.Nodes[i].Identity.ShortString())
		}
	}
	return nil
}

// validateSigning checks that every admin key and member names a signing key,
// no two alike.
func (s *Snapshot) validateSigning() error {
	for i := range s.Admins {
		if k := &s.Admins[i]; k.Signing == nil {
			return fmt.Errorf("admin key %v has no signing key", k.Public.ShortString())
		}
	}
	for i := range s.Nodes {
		if n := &s.Nodes[i]; n.Signing == nil {
			return fmt.Errorf("node %v has no signing key", n.Identity.ShortString())
		}
	}
	return ValidateSigningKeys(s.Admins, s.Nodes)
}

// ValidateInNetwork checks every member against the network and the others
// ([NodeRecord.ValidateIn]), for a state that arrives whole.
func (s *Snapshot) ValidateInNetwork() error {
	if s.GenesisHash == nil {
		return errors.New("snapshot has no genesis hash")
	}
	// Checking each against those before it suffices only while
	// [MemberIndex.Check] is symmetric.
	seated := NewMemberIndex(NetworkSpace{Genesis: *s.GenesisHash, Domain: s.Domain,
		V4Prefix: s.V4Prefix, V4Retiring: s.V4Retiring}, len(s.Nodes))
	for i := range s.Nodes {
		if err := s.Nodes[i].ValidateIn(seated); err != nil {
			return err
		}
		seated.Add(&s.Nodes[i])
	}
	return nil
}
