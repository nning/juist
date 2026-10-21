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

// applyMode selects between applying a record to the chain and asking a
// hypothetical question about it.
type applyMode int

const (
	// applyChain is a real application: every rule holds.
	applyChain applyMode = iota

	// applyProbe asks whether a record's substance would be acceptable against
	// a state other than the one it was signed against, for deciding whether a
	// losing branch merely needs reissuing. Reissuing against a new parent
	// fixes the rules about position, so a probe differs from the chain in
	// three ways only:
	//
	//   - it skips the positional rules: the parent, epoch sequencing and wrap
	//     coverage, and that a network renumbering moves exactly the members;
	//   - it allocates afresh the IPv4 addresses an admission or a renumbering
	//     names, which the chosen chain may have given to someone else;
	//   - a record whose effect is in place already changes nothing, rather
	//     than being refused ([inEffect]): a concurrent record doing the same
	//     won.
	applyProbe
)

// kindRules holds, for every kind but genesis, which starts a state rather
// than changing one, what it does to next, a copy of the parent state with
// the record's hash as its head.
var kindRules = map[types.Kind]func(next *State, a *types.AUM, mode applyMode) error{
	types.KindAddNode:           (*State).addNode,
	types.KindRemoveNode:        (*State).removeNode,
	types.KindSetNodeRoutes:     (*State).setNodeRoutes,
	types.KindRotateNodeKey:     (*State).rotateNodeKey,
	types.KindRotateIdentity:    (*State).rotateIdentity,
	types.KindAddAdminKey:       (*State).addAdminKey,
	types.KindRemoveAdminKey:    (*State).removeAdminKey,
	types.KindSetQuorum:         (*State).setQuorum,
	types.KindCheckpoint:        (*State).checkpoint,
	types.KindEpochBump:         func(*State, *types.AUM, applyMode) error { return nil },
	types.KindSchemaUpgrade:     (*State).schemaUpgrade,
	types.KindSetVouchers:       (*State).setVouchers,
	types.KindSetHolder:         (*State).setHolder,
	types.KindRenumberNetwork:   (*State).renumberNetwork,
	types.KindRenumberNode:      (*State).renumberNode,
	types.KindRetireAddresses:   (*State).retireAddresses,
	types.KindRenameNetwork:     (*State).renameNetwork,
	types.KindSetAdminRecipient: (*State).setAdminRecipient,
	types.KindSetNodeNames:      (*State).setNodeNames,
	types.KindSetDomain:         (*State).setDomain,
	types.KindSetPublished:      (*State).setPublished,
	types.KindRenameNode:        (*State).renameNode,
	types.KindSetPolicy:         (*State).setPolicy,
}

// inEffectError is a record refused because what it does is done already,
// which a probe takes as no change instead.
type inEffectError struct{ error }

func inEffect(err error) error { return inEffectError{err} }

func (s *State) clone() *State {
	return &State{
		head:        s.head,
		genesisHash: s.genesisHash,
		network:     s.network,
		quorum:      s.quorum,
		epoch:       s.epoch,
		epochCommit: s.epochCommit,
		schema:      s.schema,
		vouchers:    s.vouchers,
		v4Prefix:    s.v4Prefix,   // replaced, never mutated
		v4Retiring:  s.v4Retiring, // replaced, never mutated
		domain:      s.domain,
		policy:      s.policy,
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
	if mode != applyProbe && a.Kind != types.KindGenesis {
		if a.Prev == nil || *a.Prev != s.head {
			return nil, reject(RuleParent, fmt.Errorf("log: record %v does not chain to head %v", hash, s.head))
		}
	}
	rule, ok := kindRules[a.Kind]
	switch {
	case a.Kind == types.KindGenesis:
		return nil, reject(RuleMalformed, errors.New("log: genesis cannot be applied to an existing state"))
	case a.Kind == types.KindDisable:
		return nil, reject(RuleMalformed, errors.New("log: a disable record ends the network; nothing applies it"))
	case !ok:
		// Unreachable: StaticValidate rejects unknown kinds before this.
		return nil, reject(RuleMalformed, fmt.Errorf("log: unhandled record kind %v", a.Kind))
	}
	next := s.clone()
	next.head = hash
	if err := rule(next, a, mode); err != nil {
		switch {
		case errors.As(err, new(*SchemaTooNewError)):
			return nil, err
		case !errors.As(err, new(inEffectError)) || mode != applyProbe:
			return nil, reject(RuleState, err)
		}
	}
	if a.Epoch != nil {
		if err := next.applyEpoch(s, a.Epoch, mode); err != nil {
			return nil, reject(RuleState, err)
		}
	} else if next.epoch != s.epoch {
		return nil, errors.New("log: internal: epoch changed without an epoch record")
	}
	return next, nil
}

// member returns a member's record, or the error for a record naming a
// non-member.
func (s *State) member(id types.Identity) (*types.NodeRecord, error) {
	n, ok := s.nodes[id]
	if !ok {
		return nil, fmt.Errorf("log: %v is not a member", id.ShortString())
	}
	return n, nil
}

func (next *State) addNode(a *types.AUM, mode applyMode) error {
	n := a.Node
	// A renumbering keeps the ranges it moved from until they retire; an
	// address given out in one would be left behind when they do.
	retiring := n.V4 != nil && next.v4Retiring != nil &&
		!slices.ContainsFunc(types.V4Ranges(next.v4Prefix), func(r netip.Prefix) bool { return r.Contains(*n.V4) })
	if mode == applyProbe && n.V4 != nil &&
		(next.v4Holder(*n.V4) || retiring || types.ValidateV4(*n.V4, next.V4Ranges()) != nil) {
		// Reissued, the admission is allocated a free address.
		n = n.Clone()
		n.V4 = nil
		retiring = false
	}
	if n.Retiring != nil {
		return fmt.Errorf("log: the admission of %v retires an address it never held", n.Identity.ShortString())
	}
	if retiring {
		return fmt.Errorf("log: %v is in a range the network is renumbering away from", *n.V4)
	}
	if _, exists := next.nodes[n.Identity]; exists {
		return fmt.Errorf("log: %v is already a member", n.Identity.ShortString())
	}
	if len(next.nodes) >= types.MaxNodes {
		return fmt.Errorf("log: the member set is at the %d-node limit", types.MaxNodes)
	}
	if err := next.checkNodeAdmissible(n); err != nil {
		return err
	}
	if err := next.checkNodeSigning(n); err != nil {
		return err
	}
	next.nodes[n.Identity] = n.Clone()
	return nil
}

func (next *State) removeNode(a *types.AUM, _ applyMode) error {
	if _, err := next.member(*a.Subject); err != nil {
		return err
	}
	delete(next.nodes, *a.Subject)
	if next.policy != nil {
		next.policy = next.policy.Rekeyed(*a.Subject, nil)
	}
	return nil
}

func (next *State) setNodeRoutes(a *types.AUM, _ applyMode) error {
	cur, err := next.member(*a.Subject)
	if err != nil {
		return err
	}
	updated := cur.Clone()
	updated.Roles = slices.Clone(a.Grant.Roles)
	updated.Routes = slices.Clone(a.Grant.Routes)
	// The grant's routes were checked for form at decode; the overlap rules
	// need the network's own prefix and the other members' routes, which
	// only state knows.
	if err := next.checkNodeAdmissible(updated); err != nil {
		return err
	}
	next.nodes[*a.Subject] = updated
	return nil
}

func (next *State) setNodeNames(a *types.AUM, _ applyMode) error {
	cur, err := next.member(*a.Subject)
	if err != nil {
		return err
	}
	if slices.Equal(cur.Names, a.Names.Names) {
		return inEffect(fmt.Errorf("log: %v answers for those names already", a.Subject.ShortString()))
	}
	updated := cur.Clone()
	updated.Names = slices.Clone(a.Names.Names)
	// Held by no other member, which only state knows.
	if err := next.checkNodeAdmissible(updated); err != nil {
		return err
	}
	next.nodes[*a.Subject] = updated
	return nil
}

func (next *State) setDomain(a *types.AUM, _ applyMode) error {
	if *a.Domain == next.domain {
		return inEffect(fmt.Errorf("log: the network's domain is %q already", next.domain))
	}
	space := next.space()
	space.Domain = *a.Domain
	ix := types.NewMemberIndex(space, len(next.nodes))
	for _, n := range next.Nodes() {
		if len(n.Published) > 0 && *a.Domain == "" {
			return fmt.Errorf("log: %v publishes names; withdraw them before the domain", n.Identity.ShortString())
		}
		// A published name under the new domain may be one pointed at a member.
		if err := ix.Check(&n); err != nil {
			return fmt.Errorf("log: %w", err)
		}
		ix.Add(&n)
	}
	next.domain = *a.Domain
	return nil
}

func (next *State) setPolicy(a *types.AUM, _ applyMode) error {
	if a.Policy.Empty() {
		if next.policy == nil {
			return inEffect(errors.New("log: the network has no policy already"))
		}
		next.policy = nil
		return nil
	}
	if next.policy != nil && bytes.Equal(next.policy.Encode(), a.Policy.Encode()) {
		return inEffect(errors.New("log: the network has this policy already"))
	}
	if err := a.Policy.ValidateMembers(next.Nodes()); err != nil {
		return fmt.Errorf("log: %w", err)
	}
	next.policy = a.Policy.Clone()
	return nil
}

func (next *State) setPublished(a *types.AUM, _ applyMode) error {
	cur, err := next.member(*a.Subject)
	if err != nil {
		return err
	}
	if slices.Equal(cur.Published, a.Publish.Names) {
		return inEffect(fmt.Errorf("log: %v publishes those names already", a.Subject.ShortString()))
	}
	updated := cur.Clone()
	updated.Published = slices.Clone(a.Publish.Names)
	if err := next.checkNodeAdmissible(updated); err != nil {
		return err
	}
	next.nodes[*a.Subject] = updated
	return nil
}

func (next *State) rotateNodeKey(a *types.AUM, _ applyMode) error {
	cur, err := next.member(*a.Subject)
	if err != nil {
		return err
	}
	updated := cur.Clone()
	updated.WireGuard = a.Keys.WireGuard
	updated.X25519 = a.Keys.X25519
	updated.MLKEM = a.Keys.MLKEM
	if err := next.checkNodeAdmissible(updated); err != nil {
		return err
	}
	next.nodes[*a.Subject] = updated
	return nil
}

func (next *State) rotateIdentity(a *types.AUM, _ applyMode) error {
	if next.schema < types.SchemaSignedRotation {
		return fmt.Errorf("log: an identity rotation needs %v; the network is at %v",
			types.SchemaSignedRotation, next.schema)
	}
	cur, err := next.member(*a.Subject)
	if err != nil {
		return err
	}
	if _, taken := next.nodes[*a.NewIdentity]; taken {
		return fmt.Errorf("log: %v is already a member", a.NewIdentity.ShortString())
	}
	updated := cur.Clone()
	updated.Identity = *a.NewIdentity
	updated.Signing = new(*a.NewSigning)
	delete(next.nodes, *a.Subject)
	if err := next.checkNodeAdmissible(updated); err != nil {
		return err
	}
	if err := next.checkNodeSigning(updated); err != nil {
		return err
	}
	next.nodes[*a.NewIdentity] = updated
	if next.policy != nil {
		next.policy = next.policy.Rekeyed(*a.Subject, a.NewIdentity)
	}
	return nil
}

func (next *State) addAdminKey(a *types.AUM, _ applyMode) error {
	if a.Admin.Recipient != nil {
		return fmt.Errorf("log: %v comes with an encryption key, which only the key itself sets",
			a.Admin.Public.ShortString())
	}
	if a.Admin.Signing == nil {
		return fmt.Errorf("log: %v comes with no signing key, which the network needs", a.Admin.Public.ShortString())
	}
	if _, exists := next.admins[a.Admin.Public]; exists {
		return fmt.Errorf("log: %v is already an admin key", a.Admin.Public.ShortString())
	}
	if len(next.admins) >= types.MaxAdmins {
		return fmt.Errorf("log: the admin set is at the %d-key limit", types.MaxAdmins)
	}
	added := *a.Admin.Clone()
	next.admins[added.Public] = added
	if err := types.ValidateAdmins(next.Admins()); err != nil {
		return fmt.Errorf("log: %w", err)
	}
	return next.checkSigningKeys()
}

func (next *State) removeAdminKey(a *types.AUM, _ applyMode) error {
	if _, exists := next.admins[*a.Subject]; !exists {
		return fmt.Errorf("log: %v is not an admin key", a.Subject.ShortString())
	}
	delete(next.admins, *a.Subject)
	// Removing a key that takes the remaining weight below k would leave a
	// network nobody can ever change again — including to undo this.
	if total := next.TotalVotes(); total < next.quorum {
		return fmt.Errorf(
			"log: removing %v would leave %d vote weight against a quorum of %d, "+
				"making the network permanently unmanageable",
			a.Subject.ShortString(), total, next.quorum)
	}
	return nil
}

func (next *State) setAdminRecipient(a *types.AUM, _ applyMode) error {
	k, exists := next.admins[*a.Subject]
	if !exists {
		return fmt.Errorf("log: %v is not an admin key", a.Subject.ShortString())
	}
	if k.Recipient != nil && *k.Recipient == *a.Recipient {
		return inEffect(fmt.Errorf("log: %v has that encryption key already", a.Subject.ShortString()))
	}
	r := *a.Recipient
	k.Recipient = &r
	next.admins[*a.Subject] = k
	return nil
}

func (next *State) setHolder(a *types.AUM, _ applyMode) error {
	h := a.Holder
	keys := 0
	for id, k := range next.admins {
		if k.Holder == h.Name {
			k.Votes, k.Needed = h.Votes, h.Needed
			if k.Needed == 1 {
				k.Needed = 0 // one is written as zero
			}
			next.admins[id] = k
			keys++
		}
	}
	if keys == 0 {
		return fmt.Errorf("log: no admin key belongs to %q", h.Name)
	}
	// A holder that needs more keys than it has casts nothing; where that
	// leaves the rest short of the quorum, nobody could undo it.
	if total := next.TotalVotes(); total < next.quorum {
		return fmt.Errorf("log: that would leave %d vote weight against a quorum of %d, "+
			"making the network permanently unmanageable", total, next.quorum)
	}
	return nil
}

func (next *State) setQuorum(a *types.AUM, _ applyMode) error {
	if *a.Quorum > next.TotalVotes() {
		return fmt.Errorf("log: quorum %d exceeds the total admin vote weight %d",
			*a.Quorum, next.TotalVotes())
	}
	next.quorum = *a.Quorum
	return nil
}

func (next *State) setVouchers(a *types.AUM, _ applyMode) error {
	// Fewer admin devices later is the operator's to notice, and fails
	// closed.
	if err := types.ValidateVouchers(*a.Vouchers, next.Nodes()); err != nil {
		return fmt.Errorf("log: %w", err)
	}
	next.vouchers = *a.Vouchers
	return nil
}

func (next *State) checkpoint(a *types.AUM, mode applyMode) error {
	if mode == applyProbe {
		return nil // one that lost fork choice has nothing to reissue
	}
	if a.State.GenesisHash == nil || *a.State.GenesisHash != next.genesisHash {
		return errors.New("log: checkpoint belongs to a different network")
	}
	// A checkpoint states the state; it must not change it. Where the ancestry
	// is known, the claim is checked against what the chain produces —
	// otherwise a quorum could rewrite membership by asserting a state rather
	// than authoring the changes that reach it.
	if !bytes.Equal(next.Snapshot().Encode(), a.State.Encode()) {
		return errors.New("log: checkpoint state does not match the state its ancestry produces")
	}
	return nil
}

func (next *State) schemaUpgrade(a *types.AUM, _ applyMode) error {
	if *a.Schema <= next.schema {
		return fmt.Errorf("log: schema upgrade to %v, but the network is already at %v",
			*a.Schema, next.schema)
	}
	if *a.Schema > types.CurrentSchema {
		// Not a rejection: the record is authorized and the network has moved.
		// This build cannot read what comes after it, so the chain stops here
		// and the caller raises an alarm. Refusing the record outright would
		// leave a node that only observed sync stopping.
		return &SchemaTooNewError{Version: *a.Schema, Implemented: types.CurrentSchema, At: next.head}
	}
	next.schema = *a.Schema
	return nil
}

// checkSigningKeys refuses a state where two identities name one signing key.
func (s *State) checkSigningKeys() error {
	if err := types.ValidateSigningKeys(s.Admins(), s.Nodes()); err != nil {
		return fmt.Errorf("log: %w", err)
	}
	return nil
}

// checkNodeSigning checks a member's signing key: one no other identity
// names.
func (s *State) checkNodeSigning(n *types.NodeRecord) error {
	if n.Signing == nil {
		return fmt.Errorf("log: %v has no signing key", n.Identity.ShortString())
	}
	for id, other := range s.nodes {
		if id != n.Identity && other.Signing != nil && *other.Signing == *n.Signing {
			return fmt.Errorf("log: %v and %v name one signing key", id.ShortString(), n.Identity.ShortString())
		}
	}
	if k, ok := s.admins[n.Identity]; ok && k.Signing != nil && *k.Signing != *n.Signing {
		return fmt.Errorf("log: %v names two signing keys", n.Identity.ShortString())
	}
	for id, k := range s.admins {
		if id != n.Identity && k.Signing != nil && *k.Signing == *n.Signing {
			return fmt.Errorf("log: %v and %v name one signing key", id.ShortString(), n.Identity.ShortString())
		}
	}
	return nil
}

func (next *State) renameNetwork(a *types.AUM, _ applyMode) error {
	if *a.Network == next.network {
		return inEffect(fmt.Errorf("log: the network is named %q already", next.network))
	}
	next.network = *a.Network
	return nil
}

// renameNode refuses a name another member's folds like, as a holder's: a
// person chose it, and devices are named on the command line by it.
func (next *State) renameNode(a *types.AUM, _ applyMode) error {
	cur, err := next.member(*a.Subject)
	if err != nil {
		return err
	}
	name := *a.NodeName
	if cur.Name == name {
		return inEffect(fmt.Errorf("log: %v is named %q already", a.Subject.ShortString(), name))
	}
	for id, n := range next.nodes {
		if id != *a.Subject && types.FoldName(n.Name) == types.FoldName(name) {
			return fmt.Errorf("log: %v is named %q already", id.ShortString(), n.Name)
		}
	}
	updated := cur.Clone()
	updated.Name = name
	// The share label follows the name.
	if err := next.checkNodeAdmissible(updated); err != nil {
		return err
	}
	next.nodes[*a.Subject] = updated
	return nil
}

func (next *State) retireAddresses(_ *types.AUM, _ applyMode) error {
	retired := next.v4Retiring != nil
	next.v4Retiring = nil
	for id, n := range next.nodes {
		if n.Retiring != nil {
			updated := n.Clone()
			updated.Retiring = nil
			next.nodes[id] = updated
			retired = true
		}
	}
	if !retired {
		return inEffect(errors.New("log: no renumbering has left an address to retire"))
	}
	return nil
}

// renumberNetwork moves the network to r.Prefix and each member to its entry
// in r.Addrs, the address it leaves retiring. The ranges left that hold one of
// those stay reserved; what an earlier renumbering left is dropped.
func (next *State) renumberNetwork(a *types.AUM, mode applyMode) error {
	r := a.Renumber
	if next.v4Prefix != nil && *next.v4Prefix == *r.Prefix {
		return inEffect(fmt.Errorf("log: the network is numbered from %v already", *r.Prefix))
	}
	if mode != applyProbe {
		if err := next.checkRenumbering(r); err != nil {
			return err
		}
	}
	for _, e := range r.Addrs {
		cur, member := next.nodes[e.Identity]
		if !member {
			continue // on the chain, checkRenumbering refused it
		}
		updated := cur.Clone()
		updated.Retiring = nil
		if cur.V4 != nil && *cur.V4 != e.V4 {
			updated.Retiring = &types.RetiringV4{Addr: *cur.V4, Until: r.Until}
		}
		v4 := e.V4
		updated.V4 = &v4
		next.nodes[e.Identity] = updated
	}
	var retiring []netip.Prefix
	for _, p := range types.V4Ranges(next.v4Prefix) {
		for _, n := range next.nodes {
			if n.Retiring != nil && p.Contains(n.Retiring.Addr) && !r.Prefix.Contains(n.Retiring.Addr) {
				retiring = append(retiring, p)
				break
			}
		}
	}
	slices.SortFunc(retiring, types.ComparePrefix)
	prefix := *r.Prefix
	next.v4Prefix = &prefix
	next.v4Retiring = nil
	if len(retiring) > 0 {
		next.v4Retiring = &types.RetiringRanges{Prefixes: retiring, Until: r.Until}
	}
	if mode == applyProbe {
		// Reissued, the renumbering allocates again; only the routes the new
		// prefix would overlap are substance.
		for _, n := range next.nodes {
			for _, pfx := range n.Routes {
				if err := types.ValidateRoute(pfx, next.ULA(), next.V4Ranges(), n.HasRole(types.RoleExit)); err != nil {
					return fmt.Errorf("log: node %v: %w", n.Identity.ShortString(), err)
				}
			}
		}
		return nil
	}
	if err := next.Snapshot().ValidateInNetwork(); err != nil {
		return fmt.Errorf("log: %w", err)
	}
	return nil
}

// checkRenumbering checks what a network renumbering allocates: an address for
// every member and no one else, none of them one another member holds.
func (s *State) checkRenumbering(r *types.Renumbering) error {
	if len(r.Addrs) != len(s.nodes) {
		return fmt.Errorf("log: the renumbering gives %d addresses for %d members; it must move every member "+
			"and no one else", len(r.Addrs), len(s.nodes))
	}
	holders := make(map[netip.Addr]types.Identity, 2*len(s.nodes))
	for id, n := range s.nodes {
		for _, a := range n.V4Addrs() {
			holders[a] = id
		}
	}
	for _, e := range r.Addrs {
		// What another member holds, its retiring address included, stays its
		// own: peers that have not seen this record still route it there.
		if other, held := holders[e.V4]; held && other != e.Identity {
			return fmt.Errorf("log: %v and %v both claim overlay v4 address %v",
				other.ShortString(), e.Identity.ShortString(), e.V4)
		}
	}
	for _, e := range r.Addrs {
		if _, member := s.nodes[e.Identity]; !member {
			return fmt.Errorf("log: the renumbering moves %v, who is not a member", e.Identity.ShortString())
		}
	}
	return nil
}

// renumberNode moves one member to r.V4 in the network's prefix, the address it
// leaves retiring in place of any it retired before.
func (next *State) renumberNode(a *types.AUM, mode applyMode) error {
	id, r := *a.Subject, a.Renumber
	cur, err := next.member(id)
	if err != nil {
		return err
	}
	if mode == applyProbe {
		// Where the member may move to is decided by the chain the move is
		// replayed on: a range or an address the winner took is a move to
		// start again, not a conflict.
		return nil
	}
	v4 := *r.V4
	if err := types.ValidateV4(v4, []netip.Prefix{next.V4Range()}); err != nil {
		return fmt.Errorf("log: %w", err)
	}
	if cur.V4 != nil && *cur.V4 == v4 {
		return fmt.Errorf("log: %v holds %v already", id.ShortString(), v4)
	}
	for _, other := range next.nodes {
		if other.Identity != id && slices.Contains(other.V4Addrs(), v4) {
			return fmt.Errorf("log: %v and %v both claim overlay v4 address %v",
				other.Identity.ShortString(), id.ShortString(), v4)
		}
	}
	updated := cur.Clone()
	updated.Retiring = nil
	if cur.V4 != nil {
		updated.Retiring = &types.RetiringV4{Addr: *cur.V4, Until: r.Until}
	}
	updated.V4 = &v4
	next.nodes[id] = updated
	return nil
}

// applyEpoch installs a new group-secret epoch. prev is the state the record
// was applied to, for the sequencing rule; the member set is read from next,
// since a bump must cover the set as it will be, not as it was.
func (next *State) applyEpoch(prev *State, rec *types.EpochRecord, mode applyMode) error {
	if mode != applyProbe {
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

// v4Holder reports whether a member holds the IPv4 address, as its own or as
// the one it is retiring.
func (s *State) v4Holder(addr netip.Addr) bool {
	for _, n := range s.nodes {
		if slices.Contains(n.V4Addrs(), addr) {
			return true
		}
	}
	return false
}

// checkNodeAdmissible checks n, a member's record as a record leaves it,
// against the network and every other member ([types.NodeRecord.ValidateIn]).
func (s *State) checkNodeAdmissible(n *types.NodeRecord) error {
	others := types.NewMemberIndex(s.space(), len(s.nodes))
	for _, other := range s.nodes {
		if other.Identity != n.Identity {
			others.Add(other)
		}
	}
	if err := n.ValidateIn(others); err != nil {
		return fmt.Errorf("log: %w", err)
	}
	return nil
}

// space returns the network a member is admitted to.
func (s *State) space() types.NetworkSpace {
	return types.NetworkSpace{Genesis: s.genesisHash, Domain: s.domain, V4Prefix: s.v4Prefix, V4Retiring: s.v4Retiring}
}

// applyGenesis builds the initial state from a genesis record.
func applyGenesis(a *types.AUM, hash types.Hash) (*State, error) {
	if a.Kind != types.KindGenesis {
		return nil, reject(RuleMalformed, fmt.Errorf("log: %v is not a genesis record", a.Kind))
	}
	// The genesis record cannot name its own hash, so the applied state takes
	// the record's. The overlay prefix and every derived address follow.
	snap := a.State.Clone()
	snap.GenesisHash = &hash
	return adoptSnapshot(snap, hash, "genesis")
}

// adoptSnapshot builds state from one that arrives whole, on a quorum's word
// rather than record by record: what is a genesis or a checkpoint.
func adoptSnapshot(snap *types.Snapshot, head types.Hash, what string) (*State, error) {
	if err := snap.StaticValidate(false); err != nil {
		return nil, reject(RuleState, fmt.Errorf("log: %s state: %w", what, err))
	}
	if err := snap.ValidateInNetwork(); err != nil {
		return nil, reject(RuleState, fmt.Errorf("log: %s state: %w", what, err))
	}
	return stateFromSnapshot(snap, head)
}
