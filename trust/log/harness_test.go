package log

import (
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// harness builds real networks for the tests: real Ed25519 keys, real HPKE
// fan-out, real chain. Nothing here is stubbed, because the properties under
// test are exactly the ones a stub would define away.
type harness struct {
	t       *testing.T
	admins  []types.PrivateIdentity
	quorum  uint32
	storage *MemStorage
	auth    *Authority

	// secrets records the group secret of each epoch, so tests can check that
	// members can actually open their wraps.
	secrets map[uint64]secrets.Secret

	nodeKeys map[types.Identity]*secrets.PrivateKeys
	nodeIDs  map[types.Identity]types.PrivateIdentity

	disablement [][]byte
}

// newHarness creates a network with numAdmins single-vote admin keys and the
// given quorum, and no members.
func newHarness(t *testing.T, numAdmins int, quorum uint32) *harness {
	t.Helper()
	return newHarnessAt(t, numAdmins, quorum, types.CurrentSchema)
}

// newHarnessAt is [newHarness] for a network created at an older schema.
func newHarnessAt(t *testing.T, numAdmins int, quorum uint32, schema types.SchemaVersion) *harness {
	t.Helper()
	return newHarnessWith(t, numAdmins, quorum, func(s *types.Snapshot) { s.Schema = schema })
}

// newHarnessWith is [newHarness] with the genesis state adjusted before it is
// signed.
func newHarnessWith(t *testing.T, numAdmins int, quorum uint32, mutate func(*types.Snapshot)) *harness {
	t.Helper()
	h := &harness{
		t:        t,
		quorum:   quorum,
		storage:  NewMemStorage(),
		secrets:  map[uint64]secrets.Secret{},
		nodeKeys: map[types.Identity]*secrets.PrivateKeys{},
		nodeIDs:  map[types.Identity]types.PrivateIdentity{},
	}
	var adminKeys []types.AdminKey
	for i := range numAdmins {
		priv, err := types.GenerateIdentity()
		if err != nil {
			t.Fatalf("generating admin key: %v", err)
		}
		h.admins = append(h.admins, priv)
		adminKeys = append(adminKeys, types.AdminKey{
			Public: priv.Public(), Votes: 1, Name: fmt.Sprintf("admin%d", i),
		})
	}
	var commitments []types.Hash
	for range 3 {
		secret := make([]byte, types.DisablementSecretSize)
		if _, err := rand.Read(secret); err != nil {
			t.Fatalf("drawing disablement secret: %v", err)
		}
		h.disablement = append(h.disablement, secret)
		commitments = append(commitments, types.DisablementCommit(secret))
	}

	genesis, err := Genesis("test-net", quorum, adminKeys, commitments, nil, h.sealer())
	if err != nil {
		t.Fatalf("building genesis: %v", err)
	}
	mutate(genesis.State)
	h.signQuorum(&genesis)
	auth, err := Create(h.storage, genesis)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	h.auth = auth
	return h
}

// sealer returns a Sealer that records each epoch's secret.
func (h *harness) sealer() Sealer {
	return func(epoch uint64, members []types.NodeRecord) (*types.EpochRecord, error) {
		secret, rec, err := secrets.NewEpoch(epoch, members)
		if err != nil {
			return nil, err
		}
		h.secrets[epoch] = secret
		return rec, nil
	}
}

// signQuorum signs a record with exactly enough admin keys to reach quorum.
func (h *harness) signQuorum(a *types.AUM) {
	h.t.Helper()
	var votes uint32
	for _, admin := range h.admins {
		if votes >= h.quorum {
			break
		}
		if err := a.Sign(admin); err != nil {
			h.t.Fatalf("signing: %v", err)
		}
		votes++
	}
}

// newNode generates a member record together with its private keys.
func (h *harness) newNode(name string) types.NodeRecord {
	h.t.Helper()
	id, err := types.GenerateIdentity()
	if err != nil {
		h.t.Fatalf("generating node identity: %v", err)
	}
	priv, err := secrets.GenerateKeys()
	if err != nil {
		h.t.Fatalf("generating node keys: %v", err)
	}
	x, m, err := priv.Public()
	if err != nil {
		h.t.Fatalf("node public keys: %v", err)
	}
	var wg types.WGKey
	if _, err := rand.Read(wg[:]); err != nil {
		h.t.Fatalf("drawing WireGuard key: %v", err)
	}
	h.nodeKeys[id.Public()] = priv
	h.nodeIDs[id.Public()] = id
	return types.NodeRecord{
		Identity:  id.Public(),
		Name:      name,
		WireGuard: wg,
		X25519:    x,
		MLKEM:     m,
	}
}

// addNode admits a member and returns its record.
func (h *harness) addNode(name string) types.NodeRecord {
	h.t.Helper()
	n := h.newNode(name)
	aum, err := h.auth.Builder().AddNode(n, h.sealer())
	if err != nil {
		h.t.Fatalf("building AddNode: %v", err)
	}
	h.signQuorum(&aum)
	if err := h.auth.Inform(aum); err != nil {
		h.t.Fatalf("Inform AddNode: %v", err)
	}
	return n
}

// removeNode revokes a member.
func (h *harness) removeNode(id types.Identity) types.AUM {
	h.t.Helper()
	aum, err := h.auth.Builder().RemoveNode(id, h.sealer())
	if err != nil {
		h.t.Fatalf("building RemoveNode: %v", err)
	}
	h.signQuorum(&aum)
	if err := h.auth.Inform(aum); err != nil {
		h.t.Fatalf("Inform RemoveNode: %v", err)
	}
	return aum
}

// copyStorage duplicates the harness's store, so a test can explore an
// alternative future — deliver records in another order, fork the chain —
// without disturbing the original.
func (h *harness) copyStorage() *MemStorage {
	h.t.Helper()
	dup := NewMemStorage()
	stored, err := h.storage.Hashes()
	if err != nil {
		h.t.Fatalf("listing records: %v", err)
	}
	for _, hash := range stored {
		aum, err := h.storage.AUM(hash)
		if err != nil {
			h.t.Fatalf("reading %v: %v", hash, err)
		}
		if err := dup.Add(aum); err != nil {
			h.t.Fatalf("copying %v: %v", hash, err)
		}
	}
	anchor, ok, err := h.storage.Anchor()
	if err != nil || !ok {
		h.t.Fatalf("reading anchor: %v (ok=%v)", err, ok)
	}

	if err := dup.SetAnchor(anchor); err != nil {
		h.t.Fatalf("setting anchor: %v", err)
	}
	floor, err := h.storage.EpochFloor()
	if err != nil {
		h.t.Fatalf("reading epoch floor: %v", err)
	}
	if err := dup.SetEpochFloor(floor); err != nil {
		h.t.Fatalf("setting epoch floor: %v", err)
	}
	return dup
}

// fork returns an independent authority holding the same records as the
// harness, at the same anchor and epoch floor.
func (h *harness) fork() *Authority {
	h.t.Helper()
	auth, err := Open(h.copyStorage())
	if err != nil {
		h.t.Fatalf("opening a copy of the store: %v", err)
	}
	return auth
}

// genesisState returns the state at the genesis record, for building records
// that fork from the very start of the chain.
func (h *harness) genesisState() *State {
	h.t.Helper()
	anchor, _, err := h.storage.Anchor()
	if err != nil {
		h.t.Fatalf("reading anchor: %v", err)
	}
	genesis, err := h.storage.AUM(anchor)
	if err != nil {
		h.t.Fatalf("reading genesis: %v", err)
	}
	st, err := applyGenesis(&genesis, anchor)
	if err != nil {
		h.t.Fatalf("applying genesis: %v", err)
	}
	return st
}

// project returns the state that delivering records to the harness's current
// chain would produce, without delivering them.
func (h *harness) project(records ...types.AUM) *State {
	h.t.Helper()
	auth := h.fork()
	if err := auth.Inform(records...); err != nil {
		h.t.Fatalf("projecting %d record(s): %v", len(records), err)
	}
	return auth.State()
}

// adminKeys returns the network's admin keys, for a ceremony assembled without
// the harness's own genesis.
func (h *harness) adminKeys() []types.AdminKey {
	out := make([]types.AdminKey, 0, len(h.admins))
	for i, priv := range h.admins {
		out = append(out, types.AdminKey{
			Public: priv.Public(), Votes: 1, Name: fmt.Sprintf("admin%d", i),
		})
	}
	return out
}

// commitments returns the network's break-glass commitments.
func (h *harness) commitments() []types.Hash {
	out := make([]types.Hash, 0, len(h.disablement))
	for _, secret := range h.disablement {
		out = append(out, types.DisablementCommit(secret))
	}
	return out
}

// handAssembledCheckpoint builds a quorum-signed checkpoint asserting a member
// set, resealing the epoch so the wrap coverage matches it. It is what a
// quorum that skips the builder can produce.
func (h *harness) handAssembledCheckpoint(members []types.NodeRecord) types.AUM {
	h.t.Helper()
	slices.SortFunc(members, func(a, b types.NodeRecord) int {
		return a.Identity.Compare(b.Identity)
	})
	snap := h.auth.State().Snapshot()
	snap.Nodes = members
	epoch, err := h.sealer()(snap.Epoch, members)
	if err != nil {
		h.t.Fatalf("sealing the epoch: %v", err)
	}
	snap.EpochCommit = epoch.Commit
	snap.EpochWraps = epoch.Wraps
	prev := h.auth.Head()
	aum := types.AUM{Kind: types.KindCheckpoint, Prev: &prev, State: snap}
	h.signQuorum(&aum)
	return aum
}

// handAssembledAddNode builds a signed AddNode record without the builder, the
// way a hostile quorum would: the builder refuses inadmissible nodes before
// signing, so going through it never exercises the receiving node's own
// checks. The epoch is sealed correctly, so a rejection is for the record's
// substance rather than a malformed bump.
func (h *harness) handAssembledAddNode(n types.NodeRecord) types.AUM {
	h.t.Helper()
	members := append(h.auth.State().Nodes(), *n.Clone())
	slices.SortFunc(members, func(a, b types.NodeRecord) int {
		return a.Identity.Compare(b.Identity)
	})
	epoch, err := h.sealer()(h.auth.State().Epoch()+1, members)
	if err != nil {
		h.t.Fatalf("sealing the epoch: %v", err)
	}
	prev := h.auth.Head()
	aum := types.AUM{Kind: types.KindAddNode, Prev: &prev, Node: n.Clone(), Epoch: epoch}
	h.signQuorum(&aum)
	return aum
}

// handAssembledSchemaUpgrade builds a quorum-signed record raising the network
// to a schema this build does not implement. The builder refuses to author one,
// on purpose — a device cannot upgrade a network past what it can read — so
// the only way to have one is to assemble it the way a newer build would.
func (h *harness) handAssembledSchemaUpgrade(v types.SchemaVersion) types.AUM {
	h.t.Helper()
	prev := h.auth.Head()
	aum := types.AUM{Kind: types.KindSchemaUpgrade, Prev: &prev, Schema: &v}
	h.signQuorum(&aum)
	return aum
}

// mustReject asserts that a record is refused under rule, and that refusing it
// left the authority exactly as it was: a rejected record must not move the
// head, and must not be stored where a later resolution would find it.
func (h *harness) mustReject(what string, rule Rule, aum types.AUM) {
	h.t.Helper()
	headBefore := h.auth.Head()
	before, err := h.storage.Hashes()
	if err != nil {
		h.t.Fatalf("listing records: %v", err)
	}
	mustBreak(h.t, what, rule, h.auth.Inform(aum))
	if h.auth.Head() != headBefore {
		h.t.Fatalf("%s: rejected but the head moved", what)
	}
	if after, err := h.storage.Hashes(); err != nil {
		h.t.Fatalf("listing records: %v", err)
	} else if len(after) != len(before) {
		h.t.Fatalf("%s: rejected but %d record(s) were stored anyway", what, len(after)-len(before))
	}
	// A rejected record must also not be adoptable by a fresh open of the
	// same storage, which is where a partially-written batch would surface.
	if _, err := Open(h.storage); err != nil {
		h.t.Fatalf("%s: storage no longer opens after the rejection: %v", what, err)
	}
}

// mustBreak asserts that err is a refusal under rule.
func mustBreak(t testing.TB, what string, rule Rule, err error) {
	t.Helper()
	var re *RejectError
	switch {
	case err == nil:
		t.Fatalf("%s: accepted", what)
	case !errors.As(err, &re):
		t.Fatalf("%s: refused, but not as a rejection: %v", what, err)
	case re.Rule != rule:
		t.Fatalf("%s: refused by the %v rules, want %v: %v", what, re.Rule, rule, err)
	}
}
