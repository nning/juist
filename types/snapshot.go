package types

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A Role is a capability a node holds, granted by quorum in the log and never
// asserted by the node itself.
type Role string

// The defined roles. The set is closed: [validateRoles] rejects anything else,
// because a node that ignores a role its peers act on holds a different view
// of what the network authorizes. Adding one is a schema change.
const (
	// RoleAdmin marks an admin device: one whose daemon signs freshness
	// leases, vouching that the view of the network it holds is current. It
	// carries no authority over membership, which comes from admin keys, and
	// the daemon never holds those.
	RoleAdmin Role = "admin"

	// RoleRelayCapable marks a node willing to relay for others; the DERP map
	// is built from these, and a network of hard-NAT'd nodes with no relay
	// cannot form.
	RoleRelayCapable Role = "relay-capable"

	// RoleExit marks an exit node: one permitted to hold a default route and
	// carry members' internet traffic, a full-tunnel grant explicit and
	// separately revocable from membership.
	RoleExit Role = "exit"

	// RoleIngress marks an ingress: a member with a public address that
	// takes connections for the names members publish and splices them to
	// their targets, terminating nothing. Never beside admin or exit, so a
	// compromised ingress holds no other authority. Schema 9 and later.
	RoleIngress Role = "ingress"

	// RoleService marks a service member: a juistd that publishes a service
	// beside it, and that every member confines with no port open to it, so
	// that a compromised service reaches none of them. Alone, and routing
	// nothing. Schema 9 and later.
	RoleService Role = "service"

	// RolePublish lets a member publish under its own name, the label its
	// name gives, without a vote each time: what and until when, it
	// announces itself. Never beside ingress. Schema 9 and later.
	RolePublish Role = "publish"
)

// roleSchemas is every role, with the schema a network must be at to grant it.
var roleSchemas = map[Role]SchemaVersion{RoleAdmin: 0, RoleExit: 0, RoleRelayCapable: 0, RoleIngress: SchemaPublish,
	RoleService: SchemaPublish, RolePublish: SchemaPublish}

// NeedsSchema returns the schema a network must be at to hold n, and what in
// n needs it; zero where the first schema does.
func (n *NodeRecord) NeedsSchema() (SchemaVersion, string) {
	var need SchemaVersion
	what := ""
	for _, r := range n.Roles {
		if v := roleSchemas[r]; v > need {
			need, what = v, fmt.Sprintf("the role %q", r)
		}
	}
	if len(n.Names) > 0 && SchemaNames > need {
		need, what = SchemaNames, "names"
	}
	if len(n.Published) > 0 && SchemaPublish > need {
		need, what = SchemaPublish, "published names"
	}
	return need, what
}

// An AdminKey is one member of the admin quorum: a signing key and the vote
// weight its signature carries.
type AdminKey struct {
	Public Identity `cbor:"1,keyasint"`

	// Votes is the weight a signature by Public contributes toward
	// [Snapshot.Quorum], so that long-lived organizational keys can outweigh
	// laptop keys.
	Votes uint32 `cbor:"2,keyasint"`

	// Name is a human label. The trust layer reads it once: the upgrade to
	// [SchemaHolders] makes it the Holder of a key whose name no other folds to.
	Name string `cbor:"3,keyasint,omitempty"`

	// Holder names the person the key belongs to, from [SchemaHolders] on.
	// The keys of one holder are one voter: they carry the holder's Votes and
	// Needed alike, and the holder's votes count once, when at least Needed
	// of its keys signed. So a person with a key on each of two devices
	// casts one vote with either, and can be made to need both. Without a
	// holder a key is a voter of its own, as before schema 3.
	Holder string `cbor:"4,keyasint,omitempty"`

	// Needed is how many of the holder's keys must sign for its votes to
	// count. Zero is one, and one is always written as zero, so that a state
	// has one encoding.
	Needed uint32 `cbor:"5,keyasint,omitempty"`

	// Recipient is the key's encryption key, from [SchemaSealing] on, which
	// only the key itself sets: a genesis naming one is signed by the key,
	// and so is a [KindSetAdminRecipient].
	Recipient *RecipientKey `cbor:"6,keyasint,omitempty"`
}

// Clone returns a deep copy of k.
func (k *AdminKey) Clone() *AdminKey {
	out := *k
	if k.Recipient != nil {
		r := *k.Recipient
		out.Recipient = &r
	}
	return &out
}

// FoldName maps a name to the one form of every name strings.EqualFold holds
// equal to it: each rune to the smallest in its case-folding orbit. Two
// holders whose names fold alike are refused, since a person reading them
// could not tell them apart.
func FoldName(s string) string {
	var b strings.Builder
	for _, r := range s {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			least = min(least, f)
		}
		b.WriteRune(least)
	}
	return b.String()
}

// NeededKeys is how many of a key's holder's keys must sign.
func (a *AdminKey) NeededKeys() uint32 { return max(a.Needed, 1) }

// voter names the voter a key belongs to: its holder, or the key itself.
func (a *AdminKey) voter() string {
	if a.Holder != "" {
		return "holder\x00" + a.Holder
	}
	return "key\x00" + string(a.Public[:])
}

// AchievableVotes is the vote weight the admin keys can cast between them:
// every voter's, counted once, except a holder's that has fewer keys than it
// needs, which can cast none.
func AchievableVotes(keys []AdminKey) uint32 {
	return CountVotes(keys, func(Identity) bool { return true })
}

// CountVotes is the vote weight the keys in signed cast: each voter's once,
// if at least as many of its keys signed as it needs.
func CountVotes(keys []AdminKey, signed func(Identity) bool) uint32 {
	type voter struct{ votes, needed, signed uint32 }
	voters := map[string]*voter{}
	for i := range keys {
		v := voters[keys[i].voter()]
		if v == nil {
			v = &voter{votes: keys[i].Votes, needed: keys[i].NeededKeys()}
			voters[keys[i].voter()] = v
		}
		if signed(keys[i].Public) {
			v.signed++
		}
	}
	var total uint32
	for _, v := range voters {
		if v.signed >= v.needed {
			total += v.votes
		}
	}
	return total
}

// ValidateAdmins checks what the keys say about their holders: holders only
// from [SchemaHolders] on, and one holder's keys agreeing on its votes and
// the keys it needs.
func ValidateAdmins(keys []AdminKey, schema SchemaVersion) error {
	type policy struct {
		name          string
		votes, needed uint32
	}
	holders := map[string]policy{}
	for i := range keys {
		k := &keys[i]
		if (k.Holder != "" || k.Needed != 0) && schema < SchemaHolders {
			return fmt.Errorf("admin key %v names a holder, which needs %v; the network is at %v",
				k.Public.ShortString(), SchemaHolders, schema)
		}
		if k.Recipient != nil && schema < SchemaSealing {
			return fmt.Errorf("admin key %v has an encryption key, which needs %v; the network is at %v",
				k.Public.ShortString(), SchemaSealing, schema)
		}
		if k.Holder == "" {
			if k.Needed != 0 {
				return fmt.Errorf("admin key %v needs %d keys and belongs to no holder", k.Public.ShortString(), k.Needed)
			}
			continue
		}
		p := policy{k.Holder, k.Votes, k.Needed}
		seen, ok := holders[FoldName(k.Holder)]
		switch {
		case ok && seen.name != k.Holder:
			return fmt.Errorf("the holders %q and %q differ only in case", seen.name, k.Holder)
		case ok && seen != p:
			return fmt.Errorf("the keys of %q disagree on its votes or the keys it needs", k.Holder)
		}
		holders[FoldName(k.Holder)] = p
	}
	return nil
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

	// V4 is an optional overlay IPv4 address inside [V4Ranges]. Assigned
	// explicitly rather than derived: too few host bits for hash-derived
	// addresses not to collide in the hundreds of nodes.
	V4 *netip.Addr `cbor:"6,keyasint,omitempty"`

	// Roles are the capabilities quorum has granted this node.
	Roles []Role `cbor:"7,keyasint,omitempty"`

	// Routes are the prefixes this node may forward for. Unconsumed before
	// M6, validated from M1. See [ValidateRoute].
	Routes []netip.Prefix `cbor:"8,keyasint,omitempty"`

	// Expiry is a Unix timestamp in seconds after which the membership is
	// stale, or 0 for no expiry. It is a backstop, not the revocation
	// mechanism: revocation is a signed record (see [KindRemoveNode]).
	Expiry uint64 `cbor:"9,keyasint,omitempty"`

	// Retiring is the IPv4 address a renumbering moved the node from, which
	// it still holds until the deadline. Schema 5 and later.
	Retiring *RetiringV4 `cbor:"10,keyasint,omitempty"`

	// Names are the public DNS names quorum points at this node, which
	// members that accept them resolve to its overlay addresses. Sorted, and
	// held by no other node. Schema 8 and later; see [ValidateHostName].
	Names []string `cbor:"11,keyasint,omitempty"`

	// Published are the names this node publishes under the network's
	// domain, each a label held by no other node. Schema 9 and later.
	Published []PublishedName `cbor:"12,keyasint,omitempty"`
}

// A RetiringV4 is an overlay IPv4 address a renumbering replaced, live until
// Until, in Unix seconds. No other member may hold it while it is recorded.
type RetiringV4 struct {
	Addr  netip.Addr `cbor:"1,keyasint"`
	Until uint64     `cbor:"2,keyasint"`
}

// Live reports whether the address is still in use at unix time now.
func (r *RetiringV4) Live(now int64) bool { return r != nil && liveUntil(r.Until, now) }

// RetireAtOnce is the deadline of a move that ends the old address as it
// applies: a time no transition can still run at, which tells such a move
// from a transition that ran out.
const RetireAtOnce uint64 = 1

// RetiringRanges are the IPv4 ranges a network renumbering moved away from,
// live until Until, in Unix seconds.
type RetiringRanges struct {
	Prefixes []netip.Prefix `cbor:"1,keyasint"`
	Until    uint64         `cbor:"2,keyasint"`
}

// Live reports whether the ranges are still in use at unix time now.
func (r *RetiringRanges) Live(now int64) bool { return r != nil && liveUntil(r.Until, now) }

func liveUntil(until uint64, now int64) bool { return now < 0 || uint64(now) < until }

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
	// [KindSchemaUpgrade]. Absent means schema 0, the schema frozen at M3b.
	// Whether the version is one this build can act on is decided in
	// trust/log, not here: a snapshot at a newer schema must still decode, so
	// that a node too old for it can store and relay the record carrying it.
	Schema SchemaVersion `cbor:"11,keyasint,omitempty"`

	// Vouchers is how many admin devices must vouch for a node's view within
	// the freshness TTL; absent means one. Schema 1 and later.
	Vouchers uint32 `cbor:"12,keyasint,omitempty"`

	// V4Prefix is the network's own overlay IPv4 prefix, fixed at genesis;
	// absent means the schema's range. Schema 4 and later.
	V4Prefix *netip.Prefix `cbor:"13,keyasint,omitempty"`

	// V4Retiring are the ranges a network renumbering moved away from, while
	// members may still hold addresses in them. Schema 5 and later.
	V4Retiring *RetiringRanges `cbor:"14,keyasint,omitempty"`

	// Domain is the network's public domain, under which members publish
	// names; empty for none. Schema 9 and later.
	Domain string `cbor:"15,keyasint,omitempty"`
}

// V4Ranges returns the ranges the network's overlay IPv4 addresses may lie in.
func (s *Snapshot) V4Ranges() []netip.Prefix {
	out := V4Ranges(s.Schema, s.V4Prefix)
	if s.V4Retiring != nil {
		out = append(out, s.V4Retiring.Prefixes...)
	}
	return out
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

// V4Addrs returns every overlay IPv4 address the node holds: its own, and the
// one it is retiring.
func (n *NodeRecord) V4Addrs() []netip.Addr {
	var out []netip.Addr
	if n.V4 != nil {
		out = append(out, *n.V4)
	}
	if n.Retiring != nil {
		out = append(out, n.Retiring.Addr)
	}
	return out
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
	if n.Retiring != nil {
		r := *n.Retiring
		out.Retiring = &r
	}
	out.Roles = slices.Clone(n.Roles)
	out.Routes = slices.Clone(n.Routes)
	out.Names = slices.Clone(n.Names)
	out.Published = slices.Clone(n.Published)
	return &out
}

// StaticValidate checks what does not depend on the rest of the network: key
// validity, canonical ordering and route form. Rules needing the overlay
// prefix or the schema are in [NodeRecord.ValidateInNetwork].
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
		if err := ValidateV4(*n.V4, v4Choosable); err != nil {
			return fmt.Errorf("node %v: %w", n.Identity.ShortString(), err)
		}
	}
	if r := n.Retiring; r != nil {
		switch {
		case n.V4 == nil:
			return fmt.Errorf("node %v retires an IPv4 address and holds none", n.Identity.ShortString())
		case r.Addr == *n.V4:
			return fmt.Errorf("node %v retires the address it holds", n.Identity.ShortString())
		case r.Until == 0:
			return fmt.Errorf("node %v retires an address with no deadline", n.Identity.ShortString())
		}
		if err := ValidateV4(r.Addr, v4Choosable); err != nil {
			return fmt.Errorf("node %v retiring: %w", n.Identity.ShortString(), err)
		}
	}
	if err := validateGrant(n.Roles, n.Routes); err != nil {
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
	if err := validateNames(n.Names); err != nil {
		return fmt.Errorf("node %v: %w", n.Identity.ShortString(), err)
	}
	if err := validatePublished(n.Published); err != nil {
		return fmt.Errorf("node %v: %w", n.Identity.ShortString(), err)
	}
	return n.ValidatePublishing()
}

// ValidateInNetwork checks the node's overlay IPv4 address and advertised
// routes against the network's overlay prefix and [V4Ranges], which only the
// log knows.
func (n *NodeRecord) ValidateInNetwork(ula netip.Prefix, v4 []netip.Prefix) error {
	if n.V4 != nil {
		if err := ValidateV4(*n.V4, v4); err != nil {
			return fmt.Errorf("node %v: %w", n.Identity.ShortString(), err)
		}
	}
	if n.Retiring != nil {
		if err := ValidateV4(n.Retiring.Addr, v4); err != nil {
			return fmt.Errorf("node %v retiring: %w", n.Identity.ShortString(), err)
		}
	}
	exit := n.HasRole(RoleExit)
	for _, pfx := range n.Routes {
		if err := ValidateRoute(pfx, ula, v4, exit); err != nil {
			return fmt.Errorf("node %v: %w", n.Identity.ShortString(), err)
		}
	}
	subnets := n.SubnetRoutes()
	for i := range subnets {
		for _, q := range subnets[i+1:] {
			if subnets[i].Overlaps(q) {
				return fmt.Errorf("node %v: routes %v and %v overlap", n.Identity.ShortString(), subnets[i], q)
			}
		}
	}
	return nil
}

// SubnetRoutes is n's routes but the default ones, which its exit role holds.
func (n *NodeRecord) SubnetRoutes() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range n.Routes {
		if p.Bits() > 0 {
			out = append(out, p)
		}
	}
	return out
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
	if a.Needed > MaxAdmins {
		return fmt.Errorf("admin key %v needs %d keys, over the %d-key limit", a.Public.ShortString(), a.Needed, MaxAdmins)
	}
	if a.Needed == 1 {
		return fmt.Errorf("admin key %v needs one key, which is written as zero", a.Public.ShortString())
	}
	if err := ValidateName(a.Holder); err != nil {
		return fmt.Errorf("admin key %v's holder: %w", a.Public.ShortString(), err)
	}
	if a.Recipient != nil {
		if err := a.Recipient.validate(); err != nil {
			return fmt.Errorf("admin key %v: %w", a.Public.ShortString(), err)
		}
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
	if s.Vouchers != 0 && s.Schema < SchemaVouchers {
		return fmt.Errorf("a vouching threshold needs %v; the state is at %v", SchemaVouchers, s.Schema)
	}
	if s.V4Prefix != nil {
		if s.Schema < SchemaOverlayV4 {
			return fmt.Errorf("an IPv4 prefix of the network's own needs %v; the state is at %v",
				SchemaOverlayV4, s.Schema)
		}
		if err := ValidateV4Prefix(*s.V4Prefix); err != nil {
			return err
		}
	}
	if r := s.V4Retiring; r != nil {
		switch {
		case genesis:
			return errors.New("a genesis retires IPv4 ranges it never had")
		case s.Schema < SchemaRenumber:
			return fmt.Errorf("retiring IPv4 ranges need %v; the state is at %v", SchemaRenumber, s.Schema)
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
			if i > 0 && comparePrefix(r.Prefixes[i-1], p) >= 0 {
				return fmt.Errorf("retiring IPv4 ranges are not sorted and unique at %v", p)
			}
		}
	}
	// A genesis is held to what a SetVouchers record is. A checkpoint is
	// not: it states a chain's state, where admin devices removed after the
	// threshold was set may have left fewer, which fails closed. Only from
	// schema 3, the newest when the bound came in, so that no genesis stored
	// before it changes its verdict.
	if genesis && s.Vouchers > 0 && s.Schema >= SchemaHolders {
		if err := ValidateVouchers(s.Vouchers, s.Nodes); err != nil {
			return err
		}
	}
	if s.Network == "" {
		return errors.New("network name is empty")
	}
	if s.Domain != "" {
		if s.Schema < SchemaPublish {
			return fmt.Errorf("a public domain needs %v; the state is at %v", SchemaPublish, s.Schema)
		}
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
	if err := ValidateAdmins(s.Admins, s.Schema); err != nil {
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
		if s.Nodes[i].Retiring != nil && s.Schema < SchemaRenumber {
			return fmt.Errorf("node %v retires an address, which needs %v; the state is at %v",
				s.Nodes[i].Identity.ShortString(), SchemaRenumber, s.Schema)
		}
		if i > 0 && s.Nodes[i-1].Identity.Compare(s.Nodes[i].Identity) >= 0 {
			return fmt.Errorf("nodes are not sorted and unique at %v", s.Nodes[i].Identity.ShortString())
		}
		if len(s.Nodes[i].Published) > 0 && s.Domain == "" {
			return fmt.Errorf("node %v publishes names, and the network has no domain", s.Nodes[i].Identity.ShortString())
		}
		if need, what := s.Nodes[i].NeedsSchema(); s.Schema < need {
			return fmt.Errorf("node %v has %s, which needs %v; the state is at %v",
				s.Nodes[i].Identity.ShortString(), what, need, s.Schema)
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

// ValidateVouchers checks a vouching threshold against the admin devices
// among nodes: more than there are would leave no node ever fresh.
func ValidateVouchers(vouchers uint32, nodes []NodeRecord) error {
	devices := 0
	for i := range nodes {
		if nodes[i].HasRole(RoleAdmin) {
			devices++
		}
	}
	if int(vouchers) > devices {
		return fmt.Errorf("%d admin devices cannot meet a vouching threshold of %d", devices, vouchers)
	}
	return nil
}

// ValidateInNetwork checks the snapshot invariants that depend on the
// network's own address space: the route rules and the collisions a
// [MemberIndex] rejects. The log applies the same rules record by record;
// this is them for a state that arrives whole — a genesis naming founding
// members, or a checkpoint adopted as an anchor.
func (s *Snapshot) ValidateInNetwork() error {
	if s.GenesisHash == nil {
		return errors.New("snapshot has no genesis hash")
	}
	ula := s.ULA()
	current := V4Ranges(s.Schema, s.V4Prefix)
	seated := NewMemberIndex(*s.GenesisHash, len(s.Nodes))
	seated.SetDomain(s.Domain)
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if err := n.ValidateInNetwork(ula, s.V4Ranges()); err != nil {
			return err
		}
		// Only an address a member is retiring may lie in a retiring range:
		// one it holds there would be left outside the network once it
		// retires.
		if n.V4 != nil && s.V4Retiring != nil {
			if err := ValidateV4(*n.V4, current); err != nil {
				return fmt.Errorf("node %v: %w", n.Identity.ShortString(), err)
			}
		}
		if err := seated.Check(n); err != nil {
			return err
		}
		seated.Add(n)
	}
	return nil
}

// A MemberIndex holds what a set of members claims — derived and IPv4 overlay
// addresses, and keys — so one more can be checked against all of them.
// Rejecting derived-address collisions deterministically is what makes
// coordination-free allocation safe; a shared key collides where it is used,
// in the data plane for WireGuard and in the epoch fan-out for the others.
type MemberIndex struct {
	genesis Hash
	addr6   map[netip.Addr]Identity
	addr4   map[netip.Addr]Identity
	wg      map[WGKey]Identity
	x25519  map[X25519Key]Identity
	mlkem   map[MLKEMKey]Identity
	routes  []routeClaim
	names   map[string]Identity
	domain  string
	labels  map[string]Identity
}

// A routeClaim is a subnet route a member is granted: one member routes each
// address, or two peers would each be sent some of its traffic.
type routeClaim struct {
	prefix netip.Prefix
	by     Identity
}

// NewMemberIndex returns an empty index for the network genesis names, sized
// for n members.
func NewMemberIndex(genesis Hash, n int) *MemberIndex {
	return &MemberIndex{
		genesis: genesis,
		addr6:   make(map[netip.Addr]Identity, n),
		addr4:   make(map[netip.Addr]Identity, 2*n),
		wg:      make(map[WGKey]Identity, n),
		x25519:  make(map[X25519Key]Identity, n),
		mlkem:   make(map[MLKEMKey]Identity, n),
		names:   map[string]Identity{},
		labels:  map[string]Identity{},
	}
}

// SetDomain is the network's public domain, which a published name and a
// name pointed at a member must not both claim. Set before the first Add.
func (ix *MemberIndex) SetDomain(domain string) { ix.domain = domain }

// Check reports what n shares with a member added before.
func (ix *MemberIndex) Check(n *NodeRecord) error {
	id := n.Identity.ShortString()
	if other, dup := ix.wg[n.WireGuard]; dup {
		return fmt.Errorf("nodes %v and %v share a WireGuard key", other.ShortString(), id)
	}
	if other, dup := ix.x25519[n.X25519]; dup {
		return fmt.Errorf("nodes %v and %v share an X25519 key", other.ShortString(), id)
	}
	if other, dup := ix.mlkem[n.MLKEM]; dup {
		return fmt.Errorf("nodes %v and %v share an ML-KEM key", other.ShortString(), id)
	}
	a6 := Addr6(ix.genesis, n.Identity)
	if other, dup := ix.addr6[a6]; dup {
		return fmt.Errorf("nodes %v and %v derive the same overlay address %v", other.ShortString(), id, a6)
	}
	for _, a := range n.V4Addrs() {
		if other, dup := ix.addr4[a]; dup {
			return fmt.Errorf("nodes %v and %v both claim overlay v4 address %v", other.ShortString(), id, a)
		}
	}
	for _, p := range n.SubnetRoutes() {
		if c, ok := ix.overlapping(p); ok {
			return fmt.Errorf("nodes %v and %v both route %v", c.by.ShortString(), id, p.Masked())
		}
	}
	// A name resolves to one member alone.
	for _, name := range n.Names {
		if other, dup := ix.names[name]; dup {
			return fmt.Errorf("nodes %v and %v both answer for %s", other.ShortString(), id, name)
		}
		if label, ok := publishedLabel(name, ix.domain); ok {
			if other, dup := ix.labels[label]; dup {
				return fmt.Errorf("node %v publishes %s, which node %v answers for", other.ShortString(), name, id)
			}
		}
	}
	if l, ok := n.ShareLabel(); ok && n.HasRole(RolePublish) {
		if other, dup := ix.labels[l]; dup {
			return fmt.Errorf("node %v publishes under its name %s, which node %v publishes", id, l, other.ShortString())
		}
		if slices.ContainsFunc(n.Published, func(p PublishedName) bool { return p.Label == l }) {
			return fmt.Errorf("node %v publishes %s, the label its own name gives", id, l)
		}
		if ix.domain != "" {
			name := l + "." + ix.domain
			if other, dup := ix.names[name]; dup || slices.Contains(n.Names, name) {
				if !dup {
					other = n.Identity
				}
				return fmt.Errorf("node %v publishes under its name %s, which node %v answers for", id, name, other.ShortString())
			}
			if len(name) > MaxHostNameLen {
				return fmt.Errorf("node %v publishes under a name of %d bytes, over the %d limit", id, len(name), MaxHostNameLen)
			}
		}
	}
	for _, p := range n.Published {
		if other, dup := ix.labels[p.Label]; dup {
			return fmt.Errorf("nodes %v and %v both publish %s", other.ShortString(), id, p.shown())
		}
		if ix.domain == "" {
			continue
		}
		name := p.Under(ix.domain)
		if len(name) > MaxHostNameLen {
			return fmt.Errorf("node %v publishes a name of %d bytes, over the %d limit", id, len(name), MaxHostNameLen)
		}
		if other, dup := ix.names[name]; dup || slices.Contains(n.Names, name) {
			if !dup {
				other = n.Identity
			}
			return fmt.Errorf("node %v publishes %s, which node %v answers for", id, name, other.ShortString())
		}
	}
	return nil
}

// overlapping is a claim overlapping p. Claims are disjoint and kept sorted
// by their first address, so only the one starting at or before p and the one
// after it can overlap it.
func (ix *MemberIndex) overlapping(p netip.Prefix) (routeClaim, bool) {
	i, _ := slices.BinarySearchFunc(ix.routes, p.Addr(), func(c routeClaim, a netip.Addr) int {
		return c.prefix.Addr().Compare(a)
	})
	for _, j := range []int{i - 1, i} {
		if j >= 0 && j < len(ix.routes) && ix.routes[j].prefix.Overlaps(p) {
			return ix.routes[j], true
		}
	}
	return routeClaim{}, false
}

// Add records what n claims, unchecked.
func (ix *MemberIndex) Add(n *NodeRecord) {
	ix.wg[n.WireGuard] = n.Identity
	ix.x25519[n.X25519] = n.Identity
	ix.mlkem[n.MLKEM] = n.Identity
	ix.addr6[Addr6(ix.genesis, n.Identity)] = n.Identity
	for _, a := range n.V4Addrs() {
		ix.addr4[a] = n.Identity
	}
	for _, p := range n.SubnetRoutes() {
		i, _ := slices.BinarySearchFunc(ix.routes, p.Addr(), func(c routeClaim, a netip.Addr) int {
			return c.prefix.Addr().Compare(a)
		})
		ix.routes = slices.Insert(ix.routes, i, routeClaim{p, n.Identity})
	}
	for _, name := range n.Names {
		ix.names[name] = n.Identity
	}
	for _, p := range n.Published {
		ix.labels[p.Label] = n.Identity
	}
	if l, ok := n.ShareLabel(); ok && n.HasRole(RolePublish) {
		ix.labels[l] = n.Identity
	}
}

// validateGrant checks roles, and that an ingress routes nothing: its peers
// confine it by its overlay addresses alone.
func validateGrant(roles []Role, routes []netip.Prefix) error {
	if err := validateRoles(roles); err != nil {
		return err
	}
	if slices.Contains(roles, RoleIngress) && len(routes) > 0 {
		return errors.New("an ingress routes nothing")
	}
	if slices.Contains(roles, RoleService) && (len(roles) > 1 || len(routes) > 0) {
		return errors.New("a service member holds no other role and routes nothing")
	}
	return nil
}

func validateRoles(roles []Role) error {
	if len(roles) > MaxRolesPerNode {
		return fmt.Errorf("%d roles, over the %d limit", len(roles), MaxRolesPerNode)
	}
	for i, r := range roles {
		if _, ok := roleSchemas[r]; !ok {
			return fmt.Errorf("unknown role %q", r)
		}
		if i > 0 && roles[i-1] >= r {
			return fmt.Errorf("roles are not sorted and unique at %q", r)
		}
	}
	if slices.Contains(roles, RoleIngress) && (slices.Contains(roles, RoleAdmin) || slices.Contains(roles, RoleExit)) {
		return errors.New("an ingress is neither a voucher nor an exit node")
	}
	if slices.Contains(roles, RoleIngress) && slices.Contains(roles, RolePublish) {
		return errors.New("an ingress publishes nothing under its own name, whose port it holds")
	}
	return nil
}

// ValidateName checks a human label — on a node record or an admin key: valid
// UTF-8, no control characters, no surrounding whitespace, within [MaxNameLen].
// Names are attacker-supplied strings that reach operator-facing output, so
// control characters are rejected here rather than escaped at every print site.
// Exported so tooling can ask before it persists a name.
func ValidateName(s string) error { return ValidateText("name", s, MaxNameLen) }

// ValidateText applies [ValidateName]'s rules to any attacker-supplied string
// bound for operator-facing output, with its own length limit. what names the
// string in the error.
func ValidateText(what, s string, limit int) error {
	if len(s) > limit {
		return fmt.Errorf("%s is %d bytes, over the %d limit", what, len(s), limit)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("%s is not valid UTF-8", what)
	}
	for _, r := range s {
		// Unicode Cc, plus DEL, plus the bidi and zero-width formatting
		// characters (Cf) that make one string display as another.
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
			(r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) ||
			(r >= 0x2066 && r <= 0x2069) || r == 0xfeff {
			return fmt.Errorf("%s contains the control or formatting character U+%04X", what, r)
		}
	}
	if trimmed := trimSpace(s); trimmed != s {
		return fmt.Errorf("%s has leading or trailing whitespace", what)
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
