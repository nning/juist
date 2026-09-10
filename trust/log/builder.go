package log

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/nning/juist/types"
)

// A Sealer produces the epoch record that distributes a fresh group secret. A
// callback rather than a dependency, so this package does not link the HPKE and
// ML-KEM code at all. members is the set as it will be after the record being
// built, which is what the wrap set must match exactly.
type Sealer func(epoch uint64, members []types.NodeRecord) (*types.EpochRecord, error)

// A Builder assembles records against a state. Every method returns an
// unsigned record that already satisfies the semantic rules, so a signing
// ceremony spread across machines is not spent on a record that was never
// going to apply. Authorization is decided by the signatures alone.
type Builder struct {
	state *State
}

// Builder returns a builder against the current state, not the alarm-checked
// one: assembling the record that resolves a fork is what an operator does
// while an alarm is raised.
func (a *Authority) Builder() *Builder { return &Builder{state: a.state} }

// NewBuilder returns a builder against an explicit state.
func NewBuilder(s *State) *Builder { return &Builder{state: s} }

// State returns the state the builder works against.
func (b *Builder) State() *State { return b.state }

// Genesis builds a genesis record: the network-creating ceremony. Its
// arguments are the whole of the initial policy, since none of it can be
// changed by anything weaker than the quorum being established here. A genesis
// nobody can authorize under its own policy is rejected rather than stored.
func Genesis(network string, quorum uint32, admins []types.AdminKey,
	disablement []types.Hash, nodes []types.NodeRecord, sealer Sealer) (types.AUM, error) {

	snap := &types.Snapshot{
		Network:     network,
		Quorum:      quorum,
		Disablement: slices.Clone(disablement),
		Admins:      slices.Clone(admins),
		Nodes:       slices.Clone(nodes),
	}
	slices.SortFunc(snap.Disablement, func(a, b types.Hash) int { return compareHash(a, b) })
	slices.SortFunc(snap.Admins, func(a, b types.AdminKey) int { return a.Public.Compare(b.Public) })
	slices.SortFunc(snap.Nodes, func(a, b types.NodeRecord) int { return a.Identity.Compare(b.Identity) })

	// Epoch 1 from the start, so wrap coverage holds from the first record and
	// the epoch floor never treats zero as a special case. A genesis with no
	// founding members still establishes an epoch, with no recipients.
	epoch, err := sealer(1, snap.Nodes)
	if err != nil {
		return types.AUM{}, err
	}
	if epoch.Epoch != 1 {
		return types.AUM{}, fmt.Errorf("log: sealer produced epoch %d for genesis, want 1", epoch.Epoch)
	}
	snap.Epoch = epoch.Epoch
	snap.EpochCommit = epoch.Commit
	snap.EpochWraps = epoch.Wraps
	snap.EpochSuite = epoch.Suite

	aum := types.AUM{Kind: types.KindGenesis, State: snap}
	if err := aum.ValidateUnsigned(); err != nil {
		return types.AUM{}, fmt.Errorf("log: genesis: %w", err)
	}
	return aum, nil
}

// AddNode builds a record admitting a member.
func (b *Builder) AddNode(n types.NodeRecord, sealer Sealer) (types.AUM, error) {
	members := b.state.Nodes()
	if slices.ContainsFunc(members, func(m types.NodeRecord) bool { return m.Identity == n.Identity }) {
		return types.AUM{}, fmt.Errorf("log: %v is already a member", n.Identity.ShortString())
	}
	members = append(members, *n.Clone())
	slices.SortFunc(members, func(x, y types.NodeRecord) int { return x.Identity.Compare(y.Identity) })
	epoch, err := b.seal(sealer, members)
	if err != nil {
		return types.AUM{}, err
	}
	return b.finish(types.AUM{Kind: types.KindAddNode, Node: n.Clone(), Epoch: epoch})
}

// RemoveNode builds a record revoking a member.
func (b *Builder) RemoveNode(id types.Identity, sealer Sealer) (types.AUM, error) {
	members := slices.DeleteFunc(b.state.Nodes(),
		func(m types.NodeRecord) bool { return m.Identity == id })
	epoch, err := b.seal(sealer, members)
	if err != nil {
		return types.AUM{}, err
	}
	return b.finish(types.AUM{Kind: types.KindRemoveNode, Subject: &id, Epoch: epoch})
}

// SetNodeRoutes builds a record replacing a member's roles and advertised
// routes. Passing empty sets withdraws everything.
func (b *Builder) SetNodeRoutes(id types.Identity, roles []types.Role, routes []netip.Prefix) (types.AUM, error) {
	grant := &types.RouteGrant{Roles: slices.Clone(roles), Routes: slices.Clone(routes)}
	slices.Sort(grant.Roles)
	grant.Roles = slices.Compact(grant.Roles)
	slices.SortFunc(grant.Routes, comparePrefixes)
	grant.Routes = slices.Compact(grant.Routes)
	return b.finish(types.AUM{Kind: types.KindSetNodeRoutes, Subject: &id, Grant: grant})
}

// RotateNodeKey builds a record replacing a member's WireGuard and encryption
// keys. The resulting record needs the member's own signature as well as
// quorum.
func (b *Builder) RotateNodeKey(id types.Identity, keys types.NodeKeys, sealer Sealer) (types.AUM, error) {
	members := b.state.Nodes()
	i := slices.IndexFunc(members, func(m types.NodeRecord) bool { return m.Identity == id })
	if i < 0 {
		return types.AUM{}, fmt.Errorf("log: %v is not a member", id.ShortString())
	}
	members[i].WireGuard = keys.WireGuard
	members[i].X25519 = keys.X25519
	members[i].MLKEM = keys.MLKEM
	// The rotated member's wrap must be sealed to its new encryption key, so
	// the sealer sees the post-rotation set. Nothing in the log can prove that
	// happened — a wrap is opaque to everyone but its recipient — so the
	// member reports a wrap it cannot open, against the record's commitment.
	epoch, err := b.seal(sealer, members)
	if err != nil {
		return types.AUM{}, err
	}
	return b.finish(types.AUM{Kind: types.KindRotateNodeKey, Subject: &id, Keys: &keys, Epoch: epoch})
}

// RotateIdentity builds a record replacing a member's identity key, and with
// it the member's derived overlay address. The record needs a signature by the
// new key as well as quorum.
func (b *Builder) RotateIdentity(old, new types.Identity, sealer Sealer) (types.AUM, error) {
	members := b.state.Nodes()
	i := slices.IndexFunc(members, func(m types.NodeRecord) bool { return m.Identity == old })
	if i < 0 {
		return types.AUM{}, fmt.Errorf("log: %v is not a member", old.ShortString())
	}
	members[i].Identity = new
	slices.SortFunc(members, func(x, y types.NodeRecord) int { return x.Identity.Compare(y.Identity) })
	epoch, err := b.seal(sealer, members)
	if err != nil {
		return types.AUM{}, err
	}
	return b.finish(types.AUM{
		Kind: types.KindRotateIdentity, Subject: &old, NewIdentity: &new, Epoch: epoch,
	})
}

// AddAdminKey builds a record adding an admin signing key.
func (b *Builder) AddAdminKey(k types.AdminKey) (types.AUM, error) {
	return b.finish(types.AUM{Kind: types.KindAddAdminKey, Admin: &k})
}

// RemoveAdminKey builds a record removing an admin signing key.
func (b *Builder) RemoveAdminKey(id types.Identity) (types.AUM, error) {
	return b.finish(types.AUM{Kind: types.KindRemoveAdminKey, Subject: &id})
}

// SetQuorum builds a record changing the vote threshold.
func (b *Builder) SetQuorum(q uint32) (types.AUM, error) {
	return b.finish(types.AUM{Kind: types.KindSetQuorum, Quorum: &q})
}

// Checkpoint builds a record stating the current state, for compaction and for
// bootstrapping nodes that do not have the history.
func (b *Builder) Checkpoint() (types.AUM, error) {
	return b.finish(types.AUM{Kind: types.KindCheckpoint, State: b.state.Snapshot()})
}

// EpochBump builds a record rotating the group secret without changing
// membership.
func (b *Builder) EpochBump(sealer Sealer) (types.AUM, error) {
	epoch, err := b.seal(sealer, b.state.Nodes())
	if err != nil {
		return types.AUM{}, err
	}
	return b.finish(types.AUM{Kind: types.KindEpochBump, Epoch: epoch})
}

// SchemaUpgrade builds a record raising the network's record schema. It
// refuses a version this build does not implement: authoring an upgrade the
// authoring device could not then read would strand the network on a schema
// nobody present can write records under.
func (b *Builder) SchemaUpgrade(v types.SchemaVersion) (types.AUM, error) {
	if v <= b.state.schema {
		return types.AUM{}, fmt.Errorf("log: the network is already at %v", b.state.schema)
	}
	if v > types.CurrentSchema {
		return types.AUM{}, fmt.Errorf(
			"log: cannot author an upgrade to %v; this build implements %v", v, types.CurrentSchema)
	}
	return b.finish(types.AUM{Kind: types.KindSchemaUpgrade, Schema: &v})
}

func (b *Builder) seal(sealer Sealer, members []types.NodeRecord) (*types.EpochRecord, error) {
	if sealer == nil {
		return nil, errors.New("log: this record kind requires an epoch bump, so it needs a sealer")
	}
	want := b.state.epoch + 1
	rec, err := sealer(want, members)
	if err != nil {
		return nil, fmt.Errorf("log: sealing epoch %d: %w", want, err)
	}
	if rec == nil {
		return nil, errors.New("log: sealer returned no epoch record")
	}
	if rec.Epoch != want {
		return nil, fmt.Errorf("log: sealer produced epoch %d, want %d", rec.Epoch, want)
	}
	return rec, nil
}

// finish sets the parent, then rejects the record if it would not apply. The
// dry run uses a placeholder hash, since the real one is not known until the
// signatures are in and nothing but genesis depends on its own hash.
func (b *Builder) finish(aum types.AUM) (types.AUM, error) {
	head := b.state.head
	aum.Prev = &head
	if err := aum.ValidateUnsigned(); err != nil {
		return types.AUM{}, fmt.Errorf("log: %w", err)
	}
	if _, err := b.state.apply(&aum, types.Hash{}, applyChain); err != nil {
		return types.AUM{}, err
	}
	return aum, nil
}

func comparePrefixes(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

// Dry reports whether a record would apply to the builder's state, and returns
// the state it would produce, without changing anything. Authorization is
// checked too, or the answer would change the moment it is offered for real.
func (b *Builder) Dry(aum *types.AUM) (*State, error) {
	if err := verifyAgainst(aum, b.state); err != nil {
		return nil, err
	}
	return b.state.apply(aum, aum.Hash(), applyChain)
}
