package log

import (
	"bytes"
	"errors"
	"fmt"
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
	disablement []types.Hash
	admins      map[types.Identity]types.AdminKey
	nodes       map[types.Identity]*types.NodeRecord
	wraps       map[types.Identity][]byte
}

// applyMode selects between applying a record to the chain and asking a
// hypothetical question about it.
type applyMode int

const (
	// applyChain is a real application: every rule holds.
	applyChain applyMode = iota

	// applyProbe asks whether a record's substance would be acceptable against
	// a state other than the one it was signed against, for deciding whether a
	// losing branch merely needs reissuing. It skips the two rules about
	// position rather than content — epoch sequencing and wrap coverage —
	// since reissuing against a new parent is what fixes both.
	applyProbe
)

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

// TotalVotes returns the summed weight of every admin key.
func (s *State) TotalVotes() uint32 {
	var total uint32
	for _, a := range s.admins {
		total += a.Votes
	}
	return total
}

// ULA returns the network's overlay IPv6 prefix.
func (s *State) ULA() netip.Prefix { return types.ULA(s.genesisHash) }

// Addr6 returns a node's derived overlay IPv6 address, whether or not it is a
// member.
func (s *State) Addr6(id types.Identity) netip.Addr { return types.Addr6(s.genesisHash, id) }

// Addrs returns a member's overlay addresses as single-host prefixes: the
// derived v6 address, and the explicit v4 address if it has one. Single-host
// is load-bearing — these become AllowedIPs, which also authorize the source
// addresses a peer may originate.
func (s *State) Addrs(id types.Identity) []netip.Prefix {
	n, ok := s.nodes[id]
	if !ok {
		return nil
	}
	out := []netip.Prefix{netip.PrefixFrom(s.Addr6(id), 128)}
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
	return a, ok
}

// Admins returns every admin key, sorted by public key.
func (s *State) Admins() []types.AdminKey {
	out := make([]types.AdminKey, 0, len(s.admins))
	for _, id := range sortedIdentities(s.admins) {
		out = append(out, s.admins[id])
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
		disablement: slices.Clone(snap.Disablement),
		admins:      make(map[types.Identity]types.AdminKey, len(snap.Admins)),
		nodes:       make(map[types.Identity]*types.NodeRecord, len(snap.Nodes)),
		wraps:       make(map[types.Identity][]byte, len(snap.EpochWraps)),
	}
	for _, a := range snap.Admins {
		s.admins[a.Public] = a
	}
	for i := range snap.Nodes {
		s.nodes[snap.Nodes[i].Identity] = snap.Nodes[i].Clone()
	}
	for _, w := range snap.EpochWraps {
		s.wraps[w.Recipient] = slices.Clone(w.Sealed)
	}
	return s, nil
}

func (s *State) clone() *State {
	return &State{
		head:        s.head,
		genesisHash: s.genesisHash,
		network:     s.network,
		quorum:      s.quorum,
		epoch:       s.epoch,
		epochCommit: s.epochCommit,
		schema:      s.schema,
		disablement: s.disablement, // never mutated after genesis
		admins:      maps.Clone(s.admins),
		nodes:       maps.Clone(s.nodes), // records are immutable once stored
		wraps:       maps.Clone(s.wraps),
	}
}

// apply returns the state resulting from applying a record, which must already
// be verified (see verify.go). This is where the semantics live: whether the
// subject exists, whether an address or key collides, whether the epoch bump
// covers the right members — so the replay probe can reuse them alone.
func (s *State) apply(a *types.AUM, hash types.Hash, mode applyMode) (*State, error) {
	if mode == applyChain && a.Kind != types.KindGenesis {
		if a.Prev == nil || *a.Prev != s.head {
			return nil, fmt.Errorf("log: record %v does not chain to head %v", hash, s.head)
		}
	}
	next := s.clone()
	next.head = hash

	switch a.Kind {
	case types.KindGenesis:
		return nil, errors.New("log: genesis cannot be applied to an existing state")

	case types.KindAddNode:
		n := a.Node
		if _, exists := next.nodes[n.Identity]; exists {
			return nil, fmt.Errorf("log: %v is already a member", n.Identity.ShortString())
		}
		if len(next.nodes) >= types.MaxNodes {
			return nil, fmt.Errorf("log: the member set is at the %d-node limit", types.MaxNodes)
		}
		if err := next.checkNodeAdmissible(n, types.Identity{}); err != nil {
			return nil, err
		}
		next.nodes[n.Identity] = n.Clone()

	case types.KindRemoveNode:
		if _, exists := next.nodes[*a.Subject]; !exists {
			return nil, fmt.Errorf("log: %v is not a member", a.Subject.ShortString())
		}
		delete(next.nodes, *a.Subject)

	case types.KindSetNodeRoutes:
		cur, exists := next.nodes[*a.Subject]
		if !exists {
			return nil, fmt.Errorf("log: %v is not a member", a.Subject.ShortString())
		}
		updated := cur.Clone()
		updated.Roles = slices.Clone(a.Grant.Roles)
		updated.Routes = slices.Clone(a.Grant.Routes)
		// The grant's routes were checked for form at decode; the overlap
		// rules need the network's own prefix, which only state knows.
		if err := updated.ValidateRoutes(next.ULA()); err != nil {
			return nil, fmt.Errorf("log: %w", err)
		}
		next.nodes[*a.Subject] = updated

	case types.KindRotateNodeKey:
		cur, exists := next.nodes[*a.Subject]
		if !exists {
			return nil, fmt.Errorf("log: %v is not a member", a.Subject.ShortString())
		}
		updated := cur.Clone()
		updated.WireGuard = a.Keys.WireGuard
		updated.X25519 = a.Keys.X25519
		updated.MLKEM = a.Keys.MLKEM
		if err := next.checkNodeAdmissible(updated, *a.Subject); err != nil {
			return nil, err
		}
		next.nodes[*a.Subject] = updated

	case types.KindRotateIdentity:
		cur, exists := next.nodes[*a.Subject]
		if !exists {
			return nil, fmt.Errorf("log: %v is not a member", a.Subject.ShortString())
		}
		if _, taken := next.nodes[*a.NewIdentity]; taken {
			return nil, fmt.Errorf("log: %v is already a member", a.NewIdentity.ShortString())
		}
		updated := cur.Clone()
		updated.Identity = *a.NewIdentity
		delete(next.nodes, *a.Subject)
		if err := next.checkNodeAdmissible(updated, types.Identity{}); err != nil {
			return nil, err
		}
		next.nodes[*a.NewIdentity] = updated

	case types.KindAddAdminKey:
		if _, exists := next.admins[a.Admin.Public]; exists {
			return nil, fmt.Errorf("log: %v is already an admin key", a.Admin.Public.ShortString())
		}
		if len(next.admins) >= types.MaxAdmins {
			return nil, fmt.Errorf("log: the admin set is at the %d-key limit", types.MaxAdmins)
		}
		next.admins[a.Admin.Public] = *a.Admin

	case types.KindRemoveAdminKey:
		if _, exists := next.admins[*a.Subject]; !exists {
			return nil, fmt.Errorf("log: %v is not an admin key", a.Subject.ShortString())
		}
		delete(next.admins, *a.Subject)
		// Removing a key that takes the remaining weight below k would leave
		// a network nobody can ever change again — including to undo this.
		if total := next.TotalVotes(); total < next.quorum {
			return nil, fmt.Errorf(
				"log: removing %v would leave %d vote weight against a quorum of %d, "+
					"making the network permanently unmanageable",
				a.Subject.ShortString(), total, next.quorum)
		}

	case types.KindSetQuorum:
		if *a.Quorum > next.TotalVotes() {
			return nil, fmt.Errorf("log: quorum %d exceeds the total admin vote weight %d",
				*a.Quorum, next.TotalVotes())
		}
		next.quorum = *a.Quorum

	case types.KindCheckpoint:
		if a.State.GenesisHash == nil || *a.State.GenesisHash != next.genesisHash {
			return nil, errors.New("log: checkpoint belongs to a different network")
		}
		// A checkpoint states the state; it must not change it. Where the
		// ancestry is known, the claim is checked against what the chain
		// produces — otherwise a quorum could rewrite membership by asserting
		// a state rather than authoring the changes that reach it.
		derived := next.Snapshot()
		if !bytes.Equal(derived.Encode(), a.State.Encode()) {
			return nil, errors.New("log: checkpoint state does not match the state its ancestry produces")
		}

	case types.KindEpochBump:
		// Nothing but the epoch changes.

	case types.KindSchemaUpgrade:
		if *a.Schema <= next.schema {
			return nil, fmt.Errorf("log: schema upgrade to %v, but the network is already at %v",
				*a.Schema, next.schema)
		}
		if *a.Schema > types.CurrentSchema {
			// Not a rejection: the record is authorized and the network has
			// moved. This build cannot read what comes after it, so the chain
			// stops here and the caller raises an alarm. Refusing the record
			// outright would leave a node that only observed sync stopping.
			return nil, &SchemaTooNewError{Version: *a.Schema, Implemented: types.CurrentSchema, At: hash}
		}
		next.schema = *a.Schema

	default:
		// Unreachable: StaticValidate rejects unknown kinds before this.
		return nil, fmt.Errorf("log: unhandled record kind %v", a.Kind)
	}

	if a.Epoch != nil {
		if err := next.applyEpoch(s, a.Epoch, mode); err != nil {
			return nil, err
		}
	} else if next.epoch != s.epoch {
		return nil, errors.New("log: internal: epoch changed without an epoch record")
	}
	return next, nil
}

// applyEpoch installs a new group-secret epoch. prev is the state the record
// was applied to, for the sequencing rule; the member set is read from next,
// since a bump must cover the set as it will be, not as it was.
func (next *State) applyEpoch(prev *State, rec *types.EpochRecord, mode applyMode) error {
	if mode == applyChain {
		// Exactly one past the current epoch. Strict sequencing means a node's
		// persisted epoch floor has an exact meaning, and no record can jump
		// the counter — toward exhaustion, or past a floor a node is holding.
		if rec.Epoch != prev.epoch+1 {
			return fmt.Errorf("log: epoch record claims epoch %d, want %d", rec.Epoch, prev.epoch+1)
		}
		if len(rec.Wraps) != len(next.nodes) {
			return fmt.Errorf(
				"log: epoch %d carries %d wraps for %d members; the group secret must reach "+
					"every member and no one else", rec.Epoch, len(rec.Wraps), len(next.nodes))
		}
		for i := range rec.Wraps {
			if _, member := next.nodes[rec.Wraps[i].Recipient]; !member {
				return fmt.Errorf("log: epoch %d has a wrap for %v, who is not a member",
					rec.Epoch, rec.Wraps[i].Recipient.ShortString())
			}
		}
		// Wraps are sorted and duplicate-free, so equal counts plus every
		// recipient being a member proves the sets are equal: no member left
		// without the secret, no non-member handed it.
	}
	next.epoch = rec.Epoch
	next.epochCommit = rec.Commit
	next.wraps = make(map[types.Identity][]byte, len(rec.Wraps))
	for i := range rec.Wraps {
		next.wraps[rec.Wraps[i].Recipient] = slices.Clone(rec.Wraps[i].Sealed)
	}
	return nil
}

// checkNodeAdmissible checks a node record against the rest of the member set:
// route legality, address collisions, key collisions. excluding names a member
// to ignore, for a record that replaces a membership rather than adding one.
func (s *State) checkNodeAdmissible(n *types.NodeRecord, excluding types.Identity) error {
	if err := n.ValidateRoutes(s.ULA()); err != nil {
		return fmt.Errorf("log: %w", err)
	}
	addr := s.Addr6(n.Identity)
	for _, other := range s.nodes {
		if other.Identity == excluding || other.Identity == n.Identity {
			continue
		}
		// Deterministic rejection of derived-address collisions is what makes
		// coordination-free allocation safe: at 80 bits a collision is a
		// formality, but every node must reject the same records.
		if s.Addr6(other.Identity) == addr {
			return fmt.Errorf("log: %v and %v derive the same overlay address %v",
				other.Identity.ShortString(), n.Identity.ShortString(), addr)
		}
		if n.V4 != nil && other.V4 != nil && *n.V4 == *other.V4 {
			return fmt.Errorf("log: %v and %v both claim overlay v4 address %v",
				other.Identity.ShortString(), n.Identity.ShortString(), *n.V4)
		}
		// Two members holding one WireGuard key would collide in the data
		// plane, where a peer is keyed by exactly that. Duplicate encryption
		// keys are rejected on the same principle: one device's state copied
		// onto a second must not be admissible by accident.
		if other.WireGuard == n.WireGuard {
			return fmt.Errorf("log: %v and %v share a WireGuard key",
				other.Identity.ShortString(), n.Identity.ShortString())
		}
		if other.X25519 == n.X25519 {
			return fmt.Errorf("log: %v and %v share an X25519 key",
				other.Identity.ShortString(), n.Identity.ShortString())
		}
		if other.MLKEM == n.MLKEM {
			return fmt.Errorf("log: %v and %v share an ML-KEM key",
				other.Identity.ShortString(), n.Identity.ShortString())
		}
	}
	return nil
}

// applyGenesis builds the initial state from a genesis record.
func applyGenesis(a *types.AUM, hash types.Hash) (*State, error) {
	if a.Kind != types.KindGenesis {
		return nil, fmt.Errorf("log: %v is not a genesis record", a.Kind)
	}
	// The genesis record cannot name its own hash, so the applied state takes
	// the record's. The overlay prefix and every derived address follow.
	snap := a.State.Clone()
	snap.GenesisHash = &hash
	if err := snap.StaticValidate(false); err != nil {
		return nil, fmt.Errorf("log: genesis state: %w", err)
	}
	if err := snap.ValidateInNetwork(); err != nil {
		return nil, fmt.Errorf("log: genesis state: %w", err)
	}
	return stateFromSnapshot(snap, hash)
}

func sortedIdentities[V any](m map[types.Identity]V) []types.Identity {
	out := slices.Collect(maps.Keys(m))
	slices.SortFunc(out, func(a, b types.Identity) int { return a.Compare(b) })
	return out
}
