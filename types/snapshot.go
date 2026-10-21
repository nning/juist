package types

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

// A Snapshot is the complete authority state at one point in the chain: the
// payload of a genesis or checkpoint record, and the value the log's runtime
// state serializes to.
type Snapshot struct {
	// GenesisHash identifies the network: the hash of its genesis record, nil
	// in that record itself and set when it is applied. The overlay address
	// space derives from it, and a checkpoint proves membership of a chain
	// with it.
	GenesisHash *Hash `cbor:"1,keyasint,omitempty"`

	// Network is the network's human-readable name, set at genesis and
	// changed by [KindRenameNetwork]. Nothing identifies the network by it.
	Network string `cbor:"2,keyasint"`

	// Quorum is k: the total vote weight required to authorize a change.
	Quorum uint32 `cbor:"3,keyasint"`

	// Epoch is the current group-secret epoch, starting at 1 in the genesis
	// record.
	Epoch uint64 `cbor:"4,keyasint"`

	// EpochCommit commits to the current epoch's secret.
	EpochCommit Hash `cbor:"5,keyasint"`

	// Disablement holds commitments to break-glass secrets, fixed at genesis.
	// Revealing a preimage in a [KindDisable] record ends the network.
	Disablement []Hash `cbor:"6,keyasint,omitempty"`

	// Admins are the admin keys, sorted by public key.
	Admins []AdminKey `cbor:"7,keyasint,omitempty"`

	// Nodes are the member devices, sorted by identity key.
	Nodes []NodeRecord `cbor:"8,keyasint,omitempty"`

	// EpochWraps is the current epoch secret sealed to each member, sorted
	// by recipient.
	EpochWraps []EpochWrap `cbor:"9,keyasint,omitempty"`

	// EpochSuite names the ciphersuite EpochWraps are sealed under. Absent
	// means [SuiteHybridX25519MLKEM768].
	EpochSuite EpochSuite `cbor:"10,keyasint,omitempty"`

	// Schema is the record schema this network is written under, raised by
	// [KindSchemaUpgrade]; [Snapshot.StaticValidate] refuses one below [MinSchema].
	// Whether the version is one this build can act on is decided in
	// trust/log, not here: a snapshot at a newer schema must still decode, so
	// that a node too old for it can store and relay the record carrying it.
	Schema SchemaVersion `cbor:"11,keyasint,omitempty"`

	// Vouchers is how many admin devices must vouch for a node's view within
	// the freshness TTL; absent means one.
	Vouchers uint32 `cbor:"12,keyasint,omitempty"`

	// V4Prefix is the network's own overlay IPv4 prefix, fixed at genesis;
	// absent means [OverlayV4].
	V4Prefix *netip.Prefix `cbor:"13,keyasint,omitempty"`

	// V4Retiring are the ranges a network renumbering moved away from, while
	// members may still hold addresses in them.
	V4Retiring *RetiringRanges `cbor:"14,keyasint,omitempty"`

	// Domain is the network's public domain, under which members publish
	// names; empty for none.
	Domain string `cbor:"15,keyasint,omitempty"`

	// Policy is what each member may open on which; absent for every member
	// anything.
	Policy *Policy `cbor:"16,keyasint,omitempty"`
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
	// The commitments are public — they are in the log — so there is nothing
	// to leak by comparing them in variable time. The secret is compared only
	// through its digest.
	return slices.Contains(s.Disablement, want)
}

// Node returns the member record for an identity.
func (s *Snapshot) Node(id Identity) (*NodeRecord, bool) {
	i := slices.IndexFunc(s.Nodes, func(n NodeRecord) bool { return n.Identity == id })
	if i < 0 {
		return nil, false
	}
	return &s.Nodes[i], true
}

// Admin returns the admin key entry for an identity.
func (s *Snapshot) Admin(id Identity) (*AdminKey, bool) {
	i := slices.IndexFunc(s.Admins, func(a AdminKey) bool { return a.Public == id })
	if i < 0 {
		return nil, false
	}
	return &s.Admins[i], true
}

// TotalVotes returns the vote weight the admin keys can cast
// ([AchievableVotes]). Bounded by [MaxAdmins] times [MaxVotes], so the sum
// cannot overflow.
func (s *Snapshot) TotalVotes() uint32 { return AchievableVotes(s.Admins) }

// ULA returns the network's overlay IPv6 prefix, or the zero prefix if the
// snapshot has no genesis hash yet (which is only true inside an unapplied
// genesis record).
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

// Encode returns the snapshot's canonical CBOR encoding. Used to compare a
// checkpoint's claimed state against the state the chain actually produces.
func (s *Snapshot) Encode() []byte { return mustEncode(s) }

// StaticValidate checks a snapshot's shape: every entry valid, every set
// sorted and duplicate-free, quorum satisfiable, and the epoch invariants
// tying the wrap set to the member set. genesis selects the one difference:
// the genesis record cannot name its own hash, a checkpoint must.
func (s *Snapshot) StaticValidate(genesis bool) error {
	switch {
	case s.Schema < MinSchema:
		return fmt.Errorf("the state is at %v; this juist reads %v and later", s.Schema, MinSchema)
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
	// A genesis is held to what a SetVouchers record is. A checkpoint is
	// not: it states a chain's state, where admin devices removed after the
	// threshold was set may have left fewer, which fails closed.
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
		// Nodes are sorted by identity and wraps by recipient, and the two
		// sets have equal size, so pairwise equality proves both that every
		// member has a wrap and that no non-member does.
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
// ([NodeRecord.ValidateIn]), as the log checks a member record by record:
// for a state that arrives whole, a genesis naming founding members or a
// checkpoint adopted as an anchor.
func (s *Snapshot) ValidateInNetwork() error {
	if s.GenesisHash == nil {
		return errors.New("snapshot has no genesis hash")
	}
	// Each member is checked against those before it alone, which is against
	// all the others only as long as [MemberIndex.Check] is symmetric.
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
