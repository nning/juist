package types

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"unicode/utf8"
)

// A Role is a capability a node holds, granted by quorum in the log and never
// asserted by the node itself.
type Role string

// The defined roles. The set is closed: [validateRoles] rejects anything else,
// because a node that ignores a role its peers act on holds a different view
// of what the network authorizes. Adding one is a schema change.
const (
	// RoleAdmin marks a device operated by an admin, so tooling can find the
	// devices a signing ceremony must reach. It carries no authority:
	// authority comes from admin keys, which the daemon never holds.
	RoleAdmin Role = "admin"

	// RoleRelayCapable marks a node willing to relay for others; the DERP map
	// is built from these, and a network of hard-NAT'd nodes with no relay
	// cannot form.
	RoleRelayCapable Role = "relay-capable"

	// RoleExitNode marks a node permitted to hold a default route, which makes
	// a full-tunnel grant explicit and separately revocable from membership.
	// Nothing consumes it yet; it is validated because the schema freezes.
	RoleExitNode Role = "exit-node"
)

var knownRoles = []Role{RoleAdmin, RoleExitNode, RoleRelayCapable}

// An AdminKey is one member of the admin quorum: a signing key and the vote
// weight its signature carries.
type AdminKey struct {
	Public Identity `cbor:"1,keyasint"`

	// Votes is the weight a signature by Public contributes toward
	// [Snapshot.Quorum], so that long-lived organizational keys can outweigh
	// laptop keys.
	Votes uint32 `cbor:"2,keyasint"`

	// Name is a human label. Nothing in the trust layer reads it.
	Name string `cbor:"3,keyasint,omitempty"`
}

// A NodeRecord is a member device as the log records it. The [Identity] is the
// member; everything else is a mutable attribute, so that rotating a node's
// WireGuard key keeps it the same node.
type NodeRecord struct {
	// Identity is the node's Ed25519 identity key. Its overlay IPv6 address
	// derives from it (see [Addr6]) and is not stored, so no record can
	// claim an address its key does not produce.
	Identity Identity `cbor:"1,keyasint"`

	// Name is a human label. Nothing in the trust layer reads it.
	Name string `cbor:"2,keyasint,omitempty"`

	// WireGuard is the node's WireGuard static public key. The connectivity
	// layer binds the node's overlay addresses to exactly this key, and
	// nothing else in the system can widen that binding.
	WireGuard WGKey `cbor:"3,keyasint"`

	// X25519 and MLKEM together form the node's HPKE recipient key, the
	// classical and post-quantum halves of the hybrid KEM that epoch group
	// secrets are sealed to. MLKEM is also reserved for the per-pair WireGuard
	// preshared-key hedge; see docs/07-embedding-notes.md.
	X25519 X25519Key `cbor:"4,keyasint"`
	MLKEM  MLKEMKey  `cbor:"5,keyasint"`

	// V4 is an optional overlay IPv4 address inside [CGNAT]. Assigned
	// explicitly rather than derived: 100.64/10 has 22 host bits, where
	// hash-derived addresses start colliding in the hundreds of nodes.
	V4 *netip.Addr `cbor:"6,keyasint,omitempty"`

	// Roles are the capabilities quorum has granted this node.
	Roles []Role `cbor:"7,keyasint,omitempty"`

	// Routes are the prefixes this node may forward for. Unconsumed before
	// M7b, validated from M1. See [ValidateRoute].
	Routes []netip.Prefix `cbor:"8,keyasint,omitempty"`

	// Expiry is a Unix timestamp in seconds after which the membership is
	// stale, or 0 for no expiry. It is a backstop, not the revocation
	// mechanism: revocation is a signed record (see [KindRemoveNode]).
	Expiry uint64 `cbor:"9,keyasint,omitempty"`
}

// Sizes of the secrets the log carries and commits to.
const (
	// GroupSecretSize is the length of an epoch group secret.
	GroupSecretSize = 32

	// DisablementSecretSize is the length of a break-glass secret.
	DisablementSecretSize = 32

	// SealedSecretSize is the exact length of [EpochWrap.Sealed]: an HPKE
	// single-shot ciphertext under DHKEM(X25519)+ML-KEM-768 with
	// ChaCha20-Poly1305 over a GroupSecretSize plaintext. Pinning it lets a
	// malformed wrap be rejected by shape, before any cryptographic work.
	SealedSecretSize = 1088 + // ML-KEM-768 ciphertext
		32 + // X25519 encapsulated key
		GroupSecretSize +
		16 // Poly1305 tag
)

// An EpochSuite names the HPKE ciphersuite an epoch record's wraps are sealed
// under. It exists so that replacing the ciphersuite is a value a decoder
// already understands rather than a schema break, which the M3 freeze would
// otherwise put out of reach: a node meeting a suite it does not implement
// rejects the record and stops, instead of opening a wrap with the wrong
// algorithm or splitting the network by ignoring a field.
type EpochSuite uint64

// SuiteHybridX25519MLKEM768 is the only suite v1 implements: HPKE base mode
// with DHKEM(X25519)+ML-KEM-768, HKDF-SHA256 and ChaCha20-Poly1305. It is
// zero, and therefore absent from the encoding, so naming the suite costs
// nothing until there is a second one.
const SuiteHybridX25519MLKEM768 EpochSuite = 0

// String names the suite, so an error about an unimplemented one is readable.
func (s EpochSuite) String() string {
	if s == SuiteHybridX25519MLKEM768 {
		return "DHKEM(X25519)+ML-KEM-768/HKDF-SHA256/ChaCha20-Poly1305"
	}
	return fmt.Sprintf("suite?<%d>", uint64(s))
}

// validateSuite rejects every suite this build does not implement. The sealed
// length is pinned per suite, so accepting an unknown one would mean accepting
// a length rule that does not exist yet.
func validateSuite(s EpochSuite) error {
	if s != SuiteHybridX25519MLKEM768 {
		return fmt.Errorf("epoch secret is sealed under %v, which this version does not implement", s)
	}
	return nil
}

// An EpochWrap is one recipient's copy of an epoch group secret.
type EpochWrap struct {
	// Recipient is the node the secret is sealed to, named by identity key.
	Recipient Identity `cbor:"1,keyasint"`

	// Sealed is the HPKE single-shot ciphertext. Its exact length is fixed
	// by the ciphersuite; see trust/secrets.
	Sealed []byte `cbor:"2,keyasint"`
}

// An EpochRecord distributes a new epoch group secret to the member set. The
// secret gates discovery and gossip confidentiality, never the data plane, and
// losing it is what stops a revoked member from finding the network at all.
// Each epoch's secret is fresh randomness rather than a derivation, so an admin
// can rekey from an admin key alone.
type EpochRecord struct {
	// Epoch is the new epoch number, always exactly one more than the current
	// one: strictly sequential, so no record can jump the counter and a node's
	// persisted epoch floor has an exact meaning.
	Epoch uint64 `cbor:"1,keyasint"`

	// Commit is a commitment to the secret: see [EpochCommit]. Without it a
	// malicious quorum could seal a different secret to each member and
	// partition discovery invisibly.
	Commit Hash `cbor:"2,keyasint"`

	// Wraps holds the secret sealed to each member, sorted by recipient and
	// covering the member set exactly. Exactness is what stops a bump from
	// quietly excluding a member or including a removed one.
	Wraps []EpochWrap `cbor:"3,keyasint,omitempty"`

	// Suite names the ciphersuite Wraps are sealed under. Absent means
	// [SuiteHybridX25519MLKEM768].
	Suite EpochSuite `cbor:"4,keyasint,omitempty"`
}

// A Snapshot is the complete authority state at one point in the chain: the
// payload of a genesis or checkpoint record, and the value the log's runtime
// state serializes to.
type Snapshot struct {
	// GenesisHash identifies the network: the hash of its genesis record, nil
	// in that record itself and set when it is applied. The overlay address
	// space derives from it, and a checkpoint proves membership of a chain
	// with it.
	GenesisHash *Hash `cbor:"1,keyasint,omitempty"`

	// Network is a human-readable network name, fixed at genesis.
	Network string `cbor:"2,keyasint"`

	// Quorum is k: the total vote weight required to authorize a change.
	Quorum uint32 `cbor:"3,keyasint"`

	// Epoch is the current group-secret epoch, starting at 1 in the genesis
	// record.
	Epoch uint64 `cbor:"4,keyasint"`

	// EpochCommit commits to the current epoch's secret.
	EpochCommit Hash `cbor:"5,keyasint"`

	// Disablement holds commitments to break-glass secrets, fixed at genesis.
	// Revealing a preimage is the recovery path from losing the admin quorum;
	// losing both leaves the network unrecoverable, which is the point.
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
	// [KindSchemaUpgrade]. Absent means [CurrentSchema] as this build knows
	// it. Whether the version is one this build can act on is decided in
	// trust/log, not here: a snapshot at a newer schema must still decode, so
	// that a node too old for it can store and relay the record carrying it.
	Schema SchemaVersion `cbor:"11,keyasint,omitempty"`
}

// EpochCommit returns the commitment stored in [EpochRecord.Commit] for a
// group secret. Recipients compare it against what they decrypt.
func EpochCommit(secret []byte) Hash {
	return hashLabeled(labelEpochCommit, secret)
}

// DisablementCommit returns the value committed in [Snapshot.Disablement] for
// a break-glass secret. A plain labelled hash, not a password KDF: these are
// full-length CSPRNG output, so there is no guessing to slow down.
func DisablementCommit(secret []byte) Hash {
	return hashLabeled(labelDisablement, secret)
}

// HasRole reports whether the node holds role.
func (n *NodeRecord) HasRole(r Role) bool { return slices.Contains(n.Roles, r) }

// Expired reports whether the membership has passed its expiry at unix time
// now. A zero Expiry never expires.
func (n *NodeRecord) Expired(now int64) bool {
	return n.Expiry != 0 && now >= 0 && uint64(now) >= n.Expiry
}

// Clone returns a deep copy.
func (n *NodeRecord) Clone() *NodeRecord {
	out := *n
	if n.V4 != nil {
		v4 := *n.V4
		out.V4 = &v4
	}
	out.Roles = slices.Clone(n.Roles)
	out.Routes = slices.Clone(n.Routes)
	return &out
}

// StaticValidate checks what does not depend on the rest of the network: key
// validity, canonical ordering and route form. Rules needing the overlay
// prefix are in [NodeRecord.ValidateRoutes].
func (n *NodeRecord) StaticValidate() error {
	if err := n.Identity.Validate(); err != nil {
		return fmt.Errorf("node identity: %w", err)
	}
	if err := ValidateName(n.Name); err != nil {
		return fmt.Errorf("node %v name: %w", n.Identity.ShortString(), err)
	}
	if n.WireGuard.IsZero() {
		return fmt.Errorf("node %v has no WireGuard key", n.Identity.ShortString())
	}
	if n.X25519.IsZero() {
		return fmt.Errorf("node %v has no X25519 key", n.Identity.ShortString())
	}
	if n.MLKEM.IsZero() {
		return fmt.Errorf("node %v has no ML-KEM key", n.Identity.ShortString())
	}
	if n.V4 != nil {
		if err := ValidateV4(*n.V4); err != nil {
			return fmt.Errorf("node %v: %w", n.Identity.ShortString(), err)
		}
	}
	if err := validateRoles(n.Roles); err != nil {
		return fmt.Errorf("node %v: %w", n.Identity.ShortString(), err)
	}
	if len(n.Routes) > MaxRoutesPerNode {
		return fmt.Errorf("node %v advertises %d routes, over the %d limit",
			n.Identity.ShortString(), len(n.Routes), MaxRoutesPerNode)
	}
	for i, pfx := range n.Routes {
		if i > 0 && comparePrefix(n.Routes[i-1], pfx) >= 0 {
			return fmt.Errorf("node %v routes are not sorted and unique at %v",
				n.Identity.ShortString(), pfx)
		}
	}
	return nil
}

// ValidateRoutes checks the node's advertised routes against the network's own
// overlay prefix. Separate from [NodeRecord.StaticValidate] because it needs
// the genesis hash, which only the log knows.
func (n *NodeRecord) ValidateRoutes(ula netip.Prefix) error {
	exit := n.HasRole(RoleExitNode)
	for _, pfx := range n.Routes {
		if err := ValidateRoute(pfx, ula, exit); err != nil {
			return fmt.Errorf("node %v: %w", n.Identity.ShortString(), err)
		}
	}
	return nil
}

// StaticValidate checks an admin key entry.
func (a *AdminKey) StaticValidate() error {
	if err := a.Public.Validate(); err != nil {
		return fmt.Errorf("admin key: %w", err)
	}
	if a.Votes == 0 {
		return fmt.Errorf("admin key %v has zero votes", a.Public.ShortString())
	}
	if a.Votes > MaxVotes {
		return fmt.Errorf("admin key %v has %d votes, over the %d limit",
			a.Public.ShortString(), a.Votes, MaxVotes)
	}
	return ValidateName(a.Name)
}

// StaticValidate checks an epoch record's shape. Whether its wrap set matches
// the member set is a question about state, answered in trust/log.
func (e *EpochRecord) StaticValidate() error {
	if e.Epoch == 0 {
		return errors.New("epoch record has epoch 0; epochs start at 1")
	}
	if e.Commit.IsZero() {
		return errors.New("epoch record has no secret commitment")
	}
	if err := validateSuite(e.Suite); err != nil {
		return err
	}
	if len(e.Wraps) > MaxNodes {
		return fmt.Errorf("epoch record has %d wraps, over the %d limit", len(e.Wraps), MaxNodes)
	}
	for i := range e.Wraps {
		w := &e.Wraps[i]
		// Shape only, not a curve point: every recipient must equal a member's
		// identity key for the record to be accepted, and those are validated
		// where they are admitted.
		if w.Recipient.IsZero() {
			return fmt.Errorf("epoch wrap %d has a zero recipient", i)
		}
		if len(w.Sealed) != SealedSecretSize {
			return fmt.Errorf("epoch wrap for %v is %d bytes, want %d",
				w.Recipient.ShortString(), len(w.Sealed), SealedSecretSize)
		}
		if i > 0 && e.Wraps[i-1].Recipient.Compare(w.Recipient) >= 0 {
			return fmt.Errorf("epoch wraps are not sorted and unique at %v", w.Recipient.ShortString())
		}
	}
	return nil
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

// TotalVotes returns the summed vote weight of every admin key. Bounded by
// [MaxAdmins] times [MaxVotes], so the sum cannot overflow.
func (s *Snapshot) TotalVotes() uint32 {
	var total uint32
	for i := range s.Admins {
		total += s.Admins[i].Votes
	}
	return total
}

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
	out.Disablement = slices.Clone(s.Disablement)
	out.Admins = slices.Clone(s.Admins)
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
	if s.Network == "" {
		return errors.New("network name is empty")
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
		if i > 0 && s.Nodes[i-1].Identity.Compare(s.Nodes[i].Identity) >= 0 {
			return fmt.Errorf("nodes are not sorted and unique at %v", s.Nodes[i].Identity.ShortString())
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

// ValidateInNetwork checks the snapshot invariants that depend on the
// network's own address space: derived-address collisions, explicit v4
// collisions, key collisions, and the route rules.
//
// A state reached record by record is checked by the log as each record
// applies; this is the same set of rules for a state that arrives whole — a
// genesis naming founding members, or a checkpoint adopted as an anchor.
func (s *Snapshot) ValidateInNetwork() error {
	if s.GenesisHash == nil {
		return errors.New("snapshot has no genesis hash")
	}
	ula := s.ULA()
	seen6 := make(map[netip.Addr]Identity, len(s.Nodes))
	seen4 := make(map[netip.Addr]Identity, len(s.Nodes))
	seenWG := make(map[WGKey]Identity, len(s.Nodes))
	seenX := make(map[X25519Key]Identity, len(s.Nodes))
	seenML := make(map[MLKEMKey]Identity, len(s.Nodes))
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if err := n.ValidateRoutes(ula); err != nil {
			return err
		}
		// Two members holding one key collide where that key is used: in the
		// data plane for WireGuard, and in the epoch fan-out for the other
		// two. The log enforces this on every record that admits a member;
		// without it here a whole state could seat what no record could add.
		if other, dup := seenWG[n.WireGuard]; dup {
			return fmt.Errorf("nodes %v and %v share a WireGuard key",
				other.ShortString(), n.Identity.ShortString())
		}
		seenWG[n.WireGuard] = n.Identity
		if other, dup := seenX[n.X25519]; dup {
			return fmt.Errorf("nodes %v and %v share an X25519 key",
				other.ShortString(), n.Identity.ShortString())
		}
		seenX[n.X25519] = n.Identity
		if other, dup := seenML[n.MLKEM]; dup {
			return fmt.Errorf("nodes %v and %v share an ML-KEM key",
				other.ShortString(), n.Identity.ShortString())
		}
		seenML[n.MLKEM] = n.Identity
		a6 := Addr6(*s.GenesisHash, n.Identity)
		if other, dup := seen6[a6]; dup {
			return fmt.Errorf("nodes %v and %v derive the same overlay address %v",
				other.ShortString(), n.Identity.ShortString(), a6)
		}
		seen6[a6] = n.Identity
		if n.V4 != nil {
			if other, dup := seen4[*n.V4]; dup {
				return fmt.Errorf("nodes %v and %v both claim overlay v4 address %v",
					other.ShortString(), n.Identity.ShortString(), *n.V4)
			}
			seen4[*n.V4] = n.Identity
		}
	}
	return nil
}

func validateRoles(roles []Role) error {
	if len(roles) > MaxRolesPerNode {
		return fmt.Errorf("%d roles, over the %d limit", len(roles), MaxRolesPerNode)
	}
	for i, r := range roles {
		if !slices.Contains(knownRoles, r) {
			return fmt.Errorf("unknown role %q", r)
		}
		if i > 0 && roles[i-1] >= r {
			return fmt.Errorf("roles are not sorted and unique at %q", r)
		}
	}
	return nil
}

// ValidateName checks a human label — on a node record or an admin key: valid
// UTF-8, no control characters, no surrounding whitespace, within [MaxNameLen].
// Names are attacker-supplied strings that reach operator-facing output, so
// control characters are rejected here rather than escaped at every print site.
// Exported so tooling can ask before it persists a name.
func ValidateName(s string) error {
	if len(s) > MaxNameLen {
		return fmt.Errorf("name is %d bytes, over the %d limit", len(s), MaxNameLen)
	}
	if !utf8.ValidString(s) {
		return errors.New("name is not valid UTF-8")
	}
	for _, r := range s {
		// Unicode Cc, plus DEL, plus the bidi and zero-width formatting
		// characters (Cf) that make one string display as another.
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
			(r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) ||
			(r >= 0x2066 && r <= 0x2069) || r == 0xfeff {
			return fmt.Errorf("name contains the control or formatting character U+%04X", r)
		}
	}
	if trimmed := trimSpace(s); trimmed != s {
		return errors.New("name has leading or trailing whitespace")
	}
	return nil
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
