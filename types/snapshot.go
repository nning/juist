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

// The defined roles. The set is closed: [validateRoles] rejects anything else.
//
// Accepting unknown role strings would be the forward-compatible choice, and
// is what tka does for unknown fields. It is the wrong choice here. Tailscale
// can let old clients ignore what they do not understand because their
// coordination server orders the log and decides what it means; in this design
// every node must independently reach the same verdict on the same bytes.
// A node that ignores a role while its peers act on it holds a different view
// of what the network authorizes, which is the split-view failure the whole
// log exists to prevent. Adding a role is therefore a schema change, subject
// to the M3 freeze like any other.
const (
	// RoleAdmin marks a device operated by an admin. It carries no
	// authority: authority comes from admin keys in the log, which
	// docs/04-architecture.md keeps in the operator's CLI keystore and out
	// of the daemon entirely. The role exists so that tooling can find the
	// devices a signing ceremony has to reach.
	RoleAdmin Role = "admin"

	// RoleRelayCapable marks a node willing to relay for others. The DERP
	// map is built from nodes holding it (docs/04-architecture.md), and
	// operators are warned when fewer than two exist, because a network of
	// entirely hard-NAT'd nodes with no relay cannot form.
	RoleRelayCapable Role = "relay-capable"

	// RoleExitNode marks a node permitted to hold a default route. Nothing
	// consumes it before M7b; it is validated from M1 because the schema
	// freezes at M3. Holding it is what makes a full-tunnel grant explicit
	// and separately revocable from membership.
	RoleExitNode Role = "exit-node"
)

var knownRoles = []Role{RoleAdmin, RoleExitNode, RoleRelayCapable}

// An AdminKey is one member of the admin quorum: a signing key and the vote
// weight its signature carries.
type AdminKey struct {
	Public Identity `cbor:"1,keyasint"`

	// Votes is the weight a signature by Public contributes toward
	// [Snapshot.Quorum]. Weights rather than plain counting so that, for
	// example, two long-lived organizational keys can outweigh a handful of
	// laptop keys. Same mechanism as tka.
	Votes uint32 `cbor:"2,keyasint"`

	// Name is a human label. Nothing in the trust layer reads it.
	Name string `cbor:"3,keyasint,omitempty"`
}

// A NodeRecord is a member device as the log records it.
//
// The [Identity] is the member; everything else is a mutable attribute of the
// membership. That split is deliberate: WireGuard has no notion of identity
// rotation, so rotating a node's WireGuard key has to be a control-plane
// operation that keeps the node the same node
// (docs/research/building-blocks.md §9).
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
	// secrets are sealed to.
	//
	// MLKEM is also the key material reserved for the per-pair WireGuard
	// preshared-key hedge. docs/07-embedding-notes.md found no route to a
	// PSK through the embedded engine's current API and left the choice —
	// patch the vendored engine, or defer the hedge past v1 — open until
	// the M3 freeze, while recording that the key belongs in the schema
	// either way.
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
	// single-shot ciphertext under the DHKEM(X25519)+ML-KEM-768 hybrid KEM
	// with ChaCha20-Poly1305, over a GroupSecretSize plaintext.
	//
	// Pinning the exact length lets a malformed wrap be rejected by shape
	// alone, before any cryptographic work. trust/secrets asserts the
	// arithmetic against a real seal, so a ciphersuite change cannot leave
	// this silently wrong.
	SealedSecretSize = 1088 + // ML-KEM-768 ciphertext
		32 + // X25519 encapsulated key
		GroupSecretSize +
		16 // Poly1305 tag
)

// An EpochWrap is one recipient's copy of an epoch group secret.
type EpochWrap struct {
	// Recipient is the node the secret is sealed to, named by identity key.
	Recipient Identity `cbor:"1,keyasint"`

	// Sealed is the HPKE single-shot ciphertext. Its exact length is fixed
	// by the ciphersuite; see trust/secrets.
	Sealed []byte `cbor:"2,keyasint"`
}

// An EpochRecord distributes a new epoch group secret to the member set.
//
// The group secret gates discovery and gossip confidentiality — blinded DHT
// topics, AEAD announcement payloads — and never the data plane, which
// WireGuard secures end to end. Losing it is what stops a revoked member from
// finding the network at all, which is why every membership change carries a
// bump (docs/research/building-blocks.md §5).
//
// Each epoch's secret is fresh randomness rather than a derivation from the
// last, so producing a bump never requires knowing the previous secret. An
// admin can therefore rekey the network from an admin key alone, without
// holding any member's decryption key.
type EpochRecord struct {
	// Epoch is the new epoch number, always exactly one more than the
	// current one. Strictly sequential rather than merely increasing, so
	// that no record can jump the counter toward exhaustion, and so a node's
	// persisted epoch floor (rollback protection) has an exact meaning.
	Epoch uint64 `cbor:"1,keyasint"`

	// Commit is a commitment to the secret: see [EpochCommit].
	//
	// Without it, nothing in the log ties the wraps to one another, and a
	// malicious quorum could seal a different secret to each member —
	// partitioning discovery invisibly. With it, every recipient checks what
	// it decrypted against a value all members can see, so a mismatch is
	// detectable rather than silent.
	Commit Hash `cbor:"2,keyasint"`

	// Wraps holds the secret sealed to each member, sorted by recipient and
	// covering the member set exactly: one wrap per member, no wrap for a
	// non-member. Requiring exactness is what stops an epoch bump from
	// quietly excluding a member (locking it out of discovery without a
	// removal record appearing in the log) or including a removed one.
	Wraps []EpochWrap `cbor:"3,keyasint,omitempty"`
}

// A Snapshot is the complete authority state at one point in the chain: the
// payload of a genesis or checkpoint record, and the value the log's runtime
// state serializes to.
type Snapshot struct {
	// GenesisHash identifies the network: it is the hash of its genesis
	// record. It is nil in the genesis record itself — where it would be a
	// hash of the record carrying it — and set when that record is applied.
	//
	// It plays the role tka's StateID plays, and two more: the overlay
	// address space derives from it, and it is what a checkpoint proves it
	// belongs to the chain it is presented for.
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

	// Disablement holds commitments to break-glass secrets, fixed at
	// genesis. Revealing a preimage is the documented recovery path from
	// losing the admin quorum; losing both the quorum and every preimage
	// makes the network unrecoverable, and that unrecoverability is the
	// security property (docs/02-threat-model.md). See
	// [Snapshot.ValidDisablement].
	Disablement []Hash `cbor:"6,keyasint,omitempty"`

	// Admins are the admin keys, sorted by public key.
	Admins []AdminKey `cbor:"7,keyasint,omitempty"`

	// Nodes are the member devices, sorted by identity key.
	Nodes []NodeRecord `cbor:"8,keyasint,omitempty"`

	// EpochWraps is the current epoch secret sealed to each member, sorted
	// by recipient.
	EpochWraps []EpochWrap `cbor:"9,keyasint,omitempty"`
}

// EpochCommit returns the commitment stored in [EpochRecord.Commit] for a
// group secret. Recipients compare it against what they decrypt.
func EpochCommit(secret []byte) Hash {
	return hashLabeled(labelEpochCommit, secret)
}

// DisablementCommit returns the value committed in [Snapshot.Disablement] for
// a break-glass secret.
//
// A plain labelled hash, not a password KDF: unlike a human-chosen secret,
// these are full-length CSPRNG output (see [DisablementSecretSize]), so there
// is no low-entropy guessing to slow down and stretching would only obscure
// what the commitment is.
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

// StaticValidate checks everything about a node record that does not depend on
// the rest of the network: key validity, canonical ordering, and route form.
// The route rules that need to know the overlay prefix are in
// [NodeRecord.ValidateRoutes].
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
// overlay prefix. Kept separate from [NodeRecord.StaticValidate] because it
// needs the genesis hash, which only the log knows; trust/log applies it to
// every node record entering state.
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
	if len(e.Wraps) > MaxNodes {
		return fmt.Errorf("epoch record has %d wraps, over the %d limit", len(e.Wraps), MaxNodes)
	}
	for i := range e.Wraps {
		w := &e.Wraps[i]
		// A recipient is checked for shape only, not as a curve point. Every
		// recipient must equal a member's identity key for the record to be
		// accepted at all (trust/log checks coverage), and those are validated
		// as keys where they are admitted — so validating up to MaxNodes points
		// again here would be pure cost on a path that decodes records straight
		// off an untrusted transport.
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
// that tie the wrap set to the member set.
//
// genesis selects the one difference between the two contexts a snapshot
// appears in: the genesis record cannot name its own hash, a checkpoint must.
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
// collisions, and the route rules.
func (s *Snapshot) ValidateInNetwork() error {
	if s.GenesisHash == nil {
		return errors.New("snapshot has no genesis hash")
	}
	ula := s.ULA()
	seen6 := make(map[netip.Addr]Identity, len(s.Nodes))
	seen4 := make(map[netip.Addr]Identity, len(s.Nodes))
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if err := n.ValidateRoutes(ula); err != nil {
			return err
		}
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

// ValidateName checks a human label — the name on a node record or an admin
// key: valid UTF-8, no control characters, no surrounding whitespace, within
// [MaxNameLen]. Names are cosmetic, but they are attacker-supplied strings
// that end up in operator-facing output, so control characters that could
// rewrite a terminal line are rejected here rather than escaped at every print
// site.
//
// Exported because tooling has to be able to ask the question before it
// persists a name or prints a command built around one. A device that stores a
// name the log will refuse has not failed yet — it fails later, on the admin's
// machine, against a limit the device never mentioned.
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
