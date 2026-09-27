package log

import (
	"errors"
	"maps"
	"net/netip"
	"slices"

	"github.com/nning/juist/types"
)

// State is the authority state at one position in the chain: who the members
// are, which keys may authorize changes, and which group-secret epoch is
// current. State values are immutable — applying a record produces a new one —
// so a caller holding a State keeps a stable view while the chain moves.
type State struct {
	head        types.Hash
	genesisHash types.Hash
	network     string
	quorum      uint32
	epoch       uint64
	epochCommit types.Hash
	schema      types.SchemaVersion
	vouchers    uint32 // zero reads as one
	v4Prefix    *netip.Prefix
	v4Retiring  *types.RetiringRanges
	disablement []types.Hash
	admins      map[types.Identity]types.AdminKey
	nodes       map[types.Identity]*types.NodeRecord
	wraps       map[types.Identity][]byte
}

// Head returns the hash of the last record applied.
func (s *State) Head() types.Hash { return s.head }

// GenesisHash returns the hash of the network's genesis record, which is the
// network's permanent identifier.
func (s *State) GenesisHash() types.Hash { return s.genesisHash }

// Network returns the human-readable network name.
func (s *State) Network() string { return s.network }

// Quorum returns k: the vote weight a change requires.
func (s *State) Quorum() uint32 { return s.quorum }

// Epoch returns the current group-secret epoch.
func (s *State) Epoch() uint64 { return s.epoch }

// EpochCommit returns the commitment to the current epoch's group secret.
func (s *State) EpochCommit() types.Hash { return s.epochCommit }

// Schema returns the record schema this network is written under.
func (s *State) Schema() types.SchemaVersion { return s.schema }

// Vouchers returns how many admin devices must vouch for a node's view within
// the freshness TTL.
func (s *State) Vouchers() uint32 { return max(s.vouchers, 1) }

// alreadyRevoked reports whether what a revocation withdraws is withdrawn in
// s already, so that a copy of it that lost fork choice changes nothing.
func (s *State) alreadyRevoked(a *types.AUM) bool {
	switch a.Kind {
	case types.KindRemoveNode:
		_, member := s.nodes[*a.Subject]
		return !member
	case types.KindRemoveAdminKey:
		_, admin := s.admins[*a.Subject]
		return !admin
	case types.KindSetNodeRoutes:
		n, ok := s.nodes[*a.Subject]
		return !ok || !n.HasRole(types.RoleAdmin)
	case types.KindSetVouchers:
		return s.Vouchers() >= *a.Vouchers
	case types.KindSetQuorum:
		return s.quorum >= *a.Quorum
	case types.KindSetHolder:
		for _, k := range s.admins {
			if k.Holder == a.Holder.Name {
				return k.Votes <= a.Holder.Votes && k.NeededKeys() >= a.Holder.Needed
			}
		}
		return true
	}
	return false
}

// Revokes reports whether a record applied to s withdraws authority, which
// fork choice prefers over its siblings and never silently orphans:
// "revoked wins". Removals always do. From [types.SchemaRevokingRoles] on, so
// does withdrawing vouching authority — taking a device's admin role away,
// or raising the vouching threshold — which a concurrent change could
// otherwise orphan on its hash, keeping a distrusted admin device vouching.
func (s *State) Revokes(a *types.AUM) bool {
	if a.Kind.IsRevocation() {
		return true
	}
	if s.schema < types.SchemaRevokingRoles {
		return false
	}
	switch a.Kind {
	case types.KindSetNodeRoutes:
		n, ok := s.nodes[*a.Subject]
		return ok && n.HasRole(types.RoleAdmin) && !slices.Contains(a.Grant.Roles, types.RoleAdmin)
	case types.KindSetVouchers:
		return *a.Vouchers > s.Vouchers()
	case types.KindSetHolder:
		// Fewer votes, or more keys needed to cast them, withdraw authority;
		// a policy that also grants some does not win on the withdrawal.
		for _, k := range s.admins {
			if k.Holder == a.Holder.Name {
				withdraws := a.Holder.Votes < k.Votes || a.Holder.Needed > k.NeededKeys()
				grants := a.Holder.Votes > k.Votes || a.Holder.Needed < k.NeededKeys()
				return withdraws && !grants
			}
		}
	case types.KindSetQuorum:
		// A higher threshold takes from every coalition that met the old
		// one; from schema 3, like the vouching threshold.
		return s.schema >= types.SchemaHolders && *a.Quorum > s.quorum
	}
	return false
}

// TotalVotes returns the vote weight the admin keys can cast between them:
// each holder's once, and none for a holder with fewer keys than it needs
// ([types.AchievableVotes]).
func (s *State) TotalVotes() uint32 { return types.AchievableVotes(s.Admins()) }

// ULA returns the network's overlay IPv6 prefix.
func (s *State) ULA() netip.Prefix { return types.ULA(s.genesisHash) }

// V4Prefix returns the network's own IPv4 prefix, if it has one: a network
// founded before prefixes were drawn numbers from the schema's whole range.
func (s *State) V4Prefix() (netip.Prefix, bool) {
	if s.v4Prefix == nil {
		return netip.Prefix{}, false
	}
	return *s.v4Prefix, true
}

// V4Range returns the range new overlay IPv4 addresses are assigned from.
func (s *State) V4Range() netip.Prefix { return types.V4Range(s.schema, s.v4Prefix) }

// V4Ranges returns every range an overlay IPv4 address may lie in, the
// retiring ones included until a record retires them.
func (s *State) V4Ranges() []netip.Prefix {
	out := types.V4Ranges(s.schema, s.v4Prefix)
	if s.v4Retiring != nil {
		out = append(out, s.v4Retiring.Prefixes...)
	}
	return out
}

// V4RangesAt returns the ranges in use at unix time now: [State.V4Ranges]
// without retiring ones past their deadline.
func (s *State) V4RangesAt(now int64) []netip.Prefix {
	out := types.V4Ranges(s.schema, s.v4Prefix)
	if s.v4Retiring.Live(now) {
		out = append(out, s.v4Retiring.Prefixes...)
	}
	return out
}

// V4Retiring returns the ranges a network renumbering moved away from, if a
// record has not retired them yet.
func (s *State) V4Retiring() (types.RetiringRanges, bool) {
	if s.v4Retiring == nil {
		return types.RetiringRanges{}, false
	}
	return types.RetiringRanges{Prefixes: slices.Clone(s.v4Retiring.Prefixes), Until: s.v4Retiring.Until}, true
}

// Addr6 returns a node's derived overlay IPv6 address, whether or not it is a
// member.
func (s *State) Addr6(id types.Identity) netip.Addr { return types.Addr6(s.genesisHash, id) }

// Addrs returns a member's overlay addresses at unix time now as single-host
// prefixes: the derived v6 address, the retiring v4 address while it is live,
// and the explicit v4 address if it has one. Single-host is load-bearing —
// these become AllowedIPs, which also authorize the source addresses a peer
// may originate. The first of each family is the one to send from: a
// retiring address is the one every member still accepts.
func (s *State) Addrs(id types.Identity, now int64) []netip.Prefix {
	n, ok := s.nodes[id]
	if !ok {
		return nil
	}
	out := []netip.Prefix{netip.PrefixFrom(s.Addr6(id), 128)}
	if n.Retiring.Live(now) {
		out = append(out, netip.PrefixFrom(n.Retiring.Addr, 32))
	}
	if n.V4 != nil {
		out = append(out, netip.PrefixFrom(*n.V4, 32))
	}
	return out
}

// IsMember reports whether id is currently a member.
func (s *State) IsMember(id types.Identity) bool {
	_, ok := s.nodes[id]
	return ok
}

// Node returns a copy of a member's record.
func (s *State) Node(id types.Identity) (types.NodeRecord, bool) {
	n, ok := s.nodes[id]
	if !ok {
		return types.NodeRecord{}, false
	}
	return *n.Clone(), true
}

// Nodes returns every member record, sorted by identity.
func (s *State) Nodes() []types.NodeRecord {
	out := make([]types.NodeRecord, 0, len(s.nodes))
	for _, id := range sortedIdentities(s.nodes) {
		out = append(out, *s.nodes[id].Clone())
	}
	return out
}

// NodesWithRole returns the members holding a role, sorted by identity.
func (s *State) NodesWithRole(r types.Role) []types.NodeRecord {
	var out []types.NodeRecord
	for _, n := range s.Nodes() {
		if n.HasRole(r) {
			out = append(out, n)
		}
	}
	return out
}

// Admin returns an admin key entry.
func (s *State) Admin(id types.Identity) (types.AdminKey, bool) {
	a, ok := s.admins[id]
	return *a.Clone(), ok
}

// Admins returns every admin key, sorted by public key.
func (s *State) Admins() []types.AdminKey {
	out := make([]types.AdminKey, 0, len(s.admins))
	for _, id := range sortedIdentities(s.admins) {
		out = append(out, *new(s.admins[id]).Clone())
	}
	return out
}

// Disablement returns the break-glass commitments fixed at genesis.
func (s *State) Disablement() []types.Hash { return slices.Clone(s.disablement) }

// ValidDisablement reports whether secret is a preimage of one of the
// network's break-glass commitments. Verification only: what revealing one
// authorizes is an operational question, and nothing consumes it yet.
func (s *State) ValidDisablement(secret []byte) bool {
	if len(secret) != types.DisablementSecretSize {
		return false
	}
	return slices.Contains(s.disablement, types.DisablementCommit(secret))
}

// EpochRecord reconstructs the current epoch's distribution record, so a
// member can recover the group secret from state alone — including state
// bootstrapped from a checkpoint, where the original may be compacted away.
func (s *State) EpochRecord() *types.EpochRecord {
	rec := &types.EpochRecord{
		Epoch:  s.epoch,
		Commit: s.epochCommit,
		Wraps:  make([]types.EpochWrap, 0, len(s.wraps)),
	}
	for _, id := range sortedIdentities(s.wraps) {
		rec.Wraps = append(rec.Wraps, types.EpochWrap{
			Recipient: id,
			Sealed:    slices.Clone(s.wraps[id]),
		})
	}
	return rec
}

// Snapshot returns the state in its serializable form, which is what a
// checkpoint record carries and what determinism is compared over.
func (s *State) Snapshot() *types.Snapshot {
	gh := s.genesisHash
	snap := &types.Snapshot{
		GenesisHash: &gh,
		Network:     s.network,
		Quorum:      s.quorum,
		Epoch:       s.epoch,
		EpochCommit: s.epochCommit,
		Disablement: slices.Clone(s.disablement),
		Admins:      s.Admins(),
		Nodes:       s.Nodes(),
		EpochWraps:  s.EpochRecord().Wraps,
		Schema:      s.schema,
		Vouchers:    s.vouchers,
	}
	if s.v4Prefix != nil {
		p := *s.v4Prefix
		snap.V4Prefix = &p
	}
	if s.v4Retiring != nil {
		r := types.RetiringRanges{Prefixes: slices.Clone(s.v4Retiring.Prefixes), Until: s.v4Retiring.Until}
		snap.V4Retiring = &r
	}
	return snap
}

// stateFromSnapshot builds runtime state from a validated snapshot.
func stateFromSnapshot(snap *types.Snapshot, head types.Hash) (*State, error) {
	if snap.GenesisHash == nil {
		return nil, errors.New("log: snapshot has no genesis hash")
	}
	// A state at a schema this build does not implement cannot be interpreted
	// at all: its records may carry kinds and fields this build has never
	// heard of, so acting on the part it understands would be exactly the
	// split view the closed record set exists to prevent.
	if snap.Schema > types.CurrentSchema {
		return nil, &SchemaTooNewError{Version: snap.Schema, Implemented: types.CurrentSchema, At: head}
	}
	s := &State{
		head:        head,
		genesisHash: *snap.GenesisHash,
		network:     snap.Network,
		quorum:      snap.Quorum,
		epoch:       snap.Epoch,
		epochCommit: snap.EpochCommit,
		schema:      snap.Schema,
		vouchers:    snap.Vouchers,
		disablement: slices.Clone(snap.Disablement),
		admins:      make(map[types.Identity]types.AdminKey, len(snap.Admins)),
		nodes:       make(map[types.Identity]*types.NodeRecord, len(snap.Nodes)),
		wraps:       make(map[types.Identity][]byte, len(snap.EpochWraps)),
	}
	if snap.V4Prefix != nil {
		p := *snap.V4Prefix
		s.v4Prefix = &p
	}
	if snap.V4Retiring != nil {
		r := types.RetiringRanges{Prefixes: slices.Clone(snap.V4Retiring.Prefixes), Until: snap.V4Retiring.Until}
		s.v4Retiring = &r
	}
	for i := range snap.Admins {
		s.admins[snap.Admins[i].Public] = *snap.Admins[i].Clone()
	}
	for i := range snap.Nodes {
		s.nodes[snap.Nodes[i].Identity] = snap.Nodes[i].Clone()
	}
	for _, w := range snap.EpochWraps {
		s.wraps[w.Recipient] = slices.Clone(w.Sealed)
	}
	return s, nil
}

func sortedIdentities[V any](m map[types.Identity]V) []types.Identity {
	out := slices.Collect(maps.Keys(m))
	slices.SortFunc(out, func(a, b types.Identity) int { return a.Compare(b) })
	return out
}
