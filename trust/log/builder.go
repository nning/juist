package log

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/nning/juist/types"
)

// A Sealer produces the epoch record that distributes a fresh group secret.
// members is the set after the record being built; the wraps must match it
// exactly.
type Sealer func(epoch uint64, members []types.NodeRecord) (*types.EpochRecord, error)

// A Builder assembles unsigned records against a state that already satisfy
// the semantic rules; authorization is left to the signatures.
type Builder struct {
	state *State
}

// Builder returns a builder against the current state, even under an alarm,
// since the record resolving a fork is built then.
func (a *Authority) Builder() *Builder { return &Builder{state: a.state} }

// NewBuilder returns a builder against an explicit state.
func NewBuilder(s *State) *Builder { return &Builder{state: s} }

// State returns the state the builder works against.
func (b *Builder) State() *State { return b.state }

// Genesis builds a genesis record from the whole initial policy. A genesis
// nobody can authorize under its own policy is rejected.
func Genesis(network string, quorum uint32, admins []types.AdminKey,
	disablement []types.Hash, nodes []types.NodeRecord, sealer Sealer) (types.AUM, error) {

	snap := &types.Snapshot{
		Network:     network,
		Quorum:      quorum,
		Schema:      types.CurrentSchema,
		Disablement: slices.Clone(disablement),
		Admins:      slices.Clone(admins),
		Nodes:       slices.Clone(nodes),
	}
	slices.SortFunc(snap.Disablement, types.Hash.Compare)
	slices.SortFunc(snap.Admins, func(a, b types.AdminKey) int { return a.Public.Compare(b.Public) })
	slices.SortFunc(snap.Nodes, func(a, b types.NodeRecord) int { return a.Identity.Compare(b.Identity) })

	// Epoch 1 even without members, so zero is never a special case.
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
		return types.AUM{}, reject(RuleMalformed, fmt.Errorf("log: genesis: %w", err))
	}
	return aum, nil
}

// AddNode builds a record admitting a member, which must name its signing
// key.
func (b *Builder) AddNode(n types.NodeRecord, sealer Sealer) (types.AUM, error) {
	n = *n.Clone()
	if n.Signing == nil {
		return types.AUM{}, fmt.Errorf("log: %v brings no signing key, which the network needs", n.Identity.ShortString())
	}
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
	slices.SortFunc(grant.Routes, types.ComparePrefix)
	grant.Routes = slices.Compact(grant.Routes)
	return b.finish(types.AUM{Kind: types.KindSetNodeRoutes, Subject: &id, Grant: grant})
}

// SetNodeNames builds a record replacing the public names a member answers
// for, sorted and without repeats; none withdraws them all.
func (b *Builder) SetNodeNames(id types.Identity, names []string) (types.AUM, error) {
	grant := &types.NameGrant{Names: slices.Clone(names)}
	slices.Sort(grant.Names)
	grant.Names = slices.Compact(grant.Names)
	return b.finish(types.AUM{Kind: types.KindSetNodeNames, Subject: &id, Names: grant})
}

// SetDomain builds a record setting the network's public domain; "" withdraws
// it.
func (b *Builder) SetDomain(domain string) (types.AUM, error) {
	return b.finish(types.AUM{Kind: types.KindSetDomain, Domain: &domain})
}

// SetPublicDERP builds a record setting the network's public DERP servers.
func (b *Builder) SetPublicDERP(p types.PublicDERP) (types.AUM, error) {
	return b.finish(types.AUM{Kind: types.KindSetPublicDERP, PublicDERP: &p})
}

// SetPolicy builds a record replacing the network's access policy.
func (b *Builder) SetPolicy(p *types.Policy) (types.AUM, error) {
	return b.finish(types.AUM{Kind: types.KindSetPolicy, Policy: p.Clone()})
}

// SetPublished builds a record replacing the names a member publishes, sorted
// by label and without repeats; none withdraws them all. A label given twice
// otherwise alike is refused.
func (b *Builder) SetPublished(id types.Identity, names []types.PublishedName) (types.AUM, error) {
	grant := &types.PublishGrant{Names: slices.Clone(names)}
	slices.SortFunc(grant.Names, func(x, y types.PublishedName) int { return strings.Compare(x.Label, y.Label) })
	grant.Names = slices.Compact(grant.Names)
	return b.finish(types.AUM{Kind: types.KindSetPublished, Subject: &id, Publish: grant})
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
	// The wrap must be sealed to the new key. The log cannot prove that; the
	// member reports a wrap it cannot open.
	epoch, err := b.seal(sealer, members)
	if err != nil {
		return types.AUM{}, err
	}
	return b.finish(types.AUM{Kind: types.KindRotateNodeKey, Subject: &id, Keys: &keys, Epoch: epoch})
}

// RotateIdentity builds a record replacing a member's identity key, and with
// it its overlay address, with new, whose signing key is signing. The record
// needs signatures by the old key and the new as well as quorum.
func (b *Builder) RotateIdentity(old, new types.Identity, signing types.SigningKey, sealer Sealer) (types.AUM, error) {
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
		Kind: types.KindRotateIdentity, Subject: &old, NewIdentity: &new, NewSigning: &signing, Epoch: epoch,
	})
}

// AddAdminKey builds a record adding an admin signing key, which must name its
// signing key.
func (b *Builder) AddAdminKey(k types.AdminKey) (types.AUM, error) {
	k = *k.Clone()
	if k.Signing == nil {
		return types.AUM{}, fmt.Errorf("log: %v brings no signing key, which the network needs", k.Public.ShortString())
	}
	return b.finish(types.AUM{Kind: types.KindAddAdminKey, Admin: &k})
}

// SetAdminRecipient builds a record giving the admin key id the encryption
// key r. The key must sign it as well as the quorum.
func (b *Builder) SetAdminRecipient(id types.Identity, r types.RecipientKey) (types.AUM, error) {
	return b.finish(types.AUM{Kind: types.KindSetAdminRecipient, Subject: &id, Recipient: &r})
}

// RemoveAdminKey builds a record removing an admin signing key.
func (b *Builder) RemoveAdminKey(id types.Identity) (types.AUM, error) {
	return b.finish(types.AUM{Kind: types.KindRemoveAdminKey, Subject: &id})
}

// SetHolder builds a record setting a holder's votes, and how many of its
// keys must sign for them to count.
func (b *Builder) SetHolder(p types.HolderPolicy) (types.AUM, error) {
	return b.finish(types.AUM{Kind: types.KindSetHolder, Holder: &p})
}

// SetVouchers builds a record changing how many admin devices must vouch.
func (b *Builder) SetVouchers(m uint32) (types.AUM, error) {
	return b.finish(types.AUM{Kind: types.KindSetVouchers, Vouchers: &m})
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

// SchemaUpgrade builds a record raising the network's record schema, up to
// what this build implements, so the network is not stranded.
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

// RenumberNetwork builds a record moving the network to prefix and each
// member to its address in addrs, keeping the ones they leave live until
// until, in Unix seconds.
func (b *Builder) RenumberNetwork(prefix netip.Prefix, addrs []types.MemberV4, until uint64) (types.AUM, error) {
	r := &types.Renumbering{Until: until, Prefix: &prefix, Addrs: slices.Clone(addrs)}
	slices.SortFunc(r.Addrs, func(x, y types.MemberV4) int { return x.Identity.Compare(y.Identity) })
	return b.finish(types.AUM{Kind: types.KindRenumberNetwork, Renumber: r})
}

// RenumberNode builds a record moving one member to v4, keeping the address
// it leaves live until until, in Unix seconds.
func (b *Builder) RenumberNode(id types.Identity, v4 netip.Addr, until uint64) (types.AUM, error) {
	return b.finish(types.AUM{Kind: types.KindRenumberNode, Subject: &id,
		Renumber: &types.Renumbering{Until: until, V4: &v4}})
}

// RetireAddresses builds a record retiring every address and range a
// renumbering left live.
func (b *Builder) RetireAddresses() (types.AUM, error) {
	return b.finish(types.AUM{Kind: types.KindRetireAddresses})
}

// RenameNetwork builds a record giving the network another name.
func (b *Builder) RenameNetwork(name string) (types.AUM, error) {
	return b.finish(types.AUM{Kind: types.KindRenameNetwork, Network: &name})
}

// RenameNode builds a record giving member id another name.
func (b *Builder) RenameNode(id types.Identity, name string) (types.AUM, error) {
	return b.finish(types.AUM{Kind: types.KindRenameNode, Subject: &id, NodeName: &name})
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
// dry run uses a placeholder hash; only genesis depends on its own.
func (b *Builder) finish(aum types.AUM) (types.AUM, error) {
	head := b.state.head
	aum.Prev = &head
	if err := aum.ValidateUnsigned(); err != nil {
		return types.AUM{}, reject(RuleMalformed, fmt.Errorf("log: %w", err))
	}
	if _, err := b.state.apply(&aum, types.Hash{}, applyChain); err != nil {
		return types.AUM{}, err
	}
	return aum, nil
}

// Dry reports whether a record, authorization included, would apply to the
// builder's state, and returns the state it would produce.
func (b *Builder) Dry(aum *types.AUM) (*State, error) {
	if err := verifyAgainst(aum, b.state); err != nil {
		return nil, err
	}
	return b.state.apply(aum, aum.Hash(), applyChain)
}

// Check is [Builder.Dry] for a record still collecting votes: everything but
// the quorum and the self-signatures is checked.
func (b *Builder) Check(aum *types.AUM) (*State, error) {
	if err := verify(aum, b.state, true); err != nil {
		return nil, err
	}
	return b.state.apply(aum, aum.Hash(), applyChain)
}

// Disable builds the record that ends the network by revealing one of its
// break-glass secrets. It is complete as built: it carries no signature.
func (b *Builder) Disable(secret types.DisablementSecret) (types.AUM, error) {
	head := b.state.head
	aum := types.AUM{Kind: types.KindDisable, Prev: &head, Secret: &secret}
	if err := verifyAgainst(&aum, b.state); err != nil {
		return types.AUM{}, err
	}
	return aum, nil
}
