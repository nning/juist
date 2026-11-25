package log

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nning/juist/internal/modelspec"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// traceDir holds the behaviours of models/log/Log.tla that make models
// writes for this test: what each validator should hold after each step.
const traceDir = "../../models/log/traces"

// The code resolves as the model does: every trace the model generates,
// replayed against Authorities, leaves each with the head, the alarms, the
// floor, the anchor and the revocations to redo the model says, and refuses
// what the model's validators refuse.
func TestTheCodeFollowsTheModelsTraces(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(traceDir, "*.tla.gz"))
	if err != nil {
		t.Fatal(err)
	}
	// The pair key's traces are internal/pairkey's.
	files = slices.DeleteFunc(files, func(f string) bool { return strings.HasPrefix(filepath.Base(f), "PairKey") })
	if len(files) == 0 {
		t.Fatalf("no traces in %s; make models writes them", traceDir)
	}
	var skipped atomic.Int32
	t.Cleanup(func() {
		if n := int(skipped.Load()); n > len(files)/10 {
			t.Errorf("%d of %d traces skipped: too few replayed to say the code follows the model", n, len(files))
		}
	})
	for _, f := range files {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".tla.gz"), func(t *testing.T) {
			t.Parallel()
			states := readTrace(t, f)
			keys := newReplayKeys(t, states[0]["setup"])
			// Hash order is drawn afresh by each network's name; one that
			// cannot give the model's is drawn again.
			for attempt := range 512 {
				err := replayTrace(t, keys, fmt.Sprintf("model%d", attempt), states)
				if errors.Is(err, errOrder) {
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			skipped.Add(1)
			t.Skip("no network drawn gave the trace's hash order")
		})
	}
}

// errOrder is a record that cannot sort among its siblings as the model's.
var errOrder = errors.New("the model's hash order cannot be drawn")

type tlaValue = any

type modelValue = modelspec.ModelValue

func readTrace(t *testing.T, path string) []map[string]tlaValue {
	t.Helper()
	states, err := modelspec.ReadTrace(path)
	if err != nil {
		t.Fatal(err)
	}
	return states
}

func ints(v tlaValue) []int {
	var out []int
	for _, x := range v.([]tlaValue) {
		out = append(out, int(x.(int64)))
	}
	slices.Sort(out)
	return out
}

func names(v tlaValue) []string {
	var out []string
	for _, x := range v.([]tlaValue) {
		out = append(out, string(x.(modelValue)))
	}
	slices.Sort(out)
	return out
}

func field(v tlaValue, name string) tlaValue { return v.(map[string]tlaValue)[name] }

// replayKeys are a trace's admin keys and members, by the model's names.
type replayKeys struct {
	h         *harness
	setup     tlaValue
	admins    map[string]types.PrivateIdentity
	members   map[string]types.NodeRecord
	adminKeys []types.AdminKey
	genesis   []types.NodeRecord
}

func newReplayKeys(t *testing.T, setup tlaValue) *replayKeys {
	t.Helper()
	k := &replayKeys{
		h: &harness{t: t, quorum: uint32(field(setup, "quorum").(int64)), secrets: map[uint64]secrets.Secret{},
			nodeKeys: map[types.Identity]*secrets.PrivateKeys{}, nodeIDs: map[types.Identity]types.PrivateIdentity{}},
		setup: setup, admins: map[string]types.PrivateIdentity{}, members: map[string]types.NodeRecord{},
	}
	for i, name := range names(field(setup, "keys")) {
		priv, err := types.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		k.admins[name] = priv
		if slices.Contains(names(field(setup, "admins")), name) {
			key := types.AdminKey{Public: priv.Public(), Votes: 1,
				Name: fmt.Sprintf("admin%d", i), Signing: new(priv.SigningKey()), Endorsement: priv.Endorsement()}
			if slices.Contains(names(field(setup, "paired")), name) {
				key.Holder = "pair"
				if n := uint32(field(setup, "pairNeeded").(int64)); n > 1 {
					key.Needed = n
				}
			}
			k.adminKeys = append(k.adminKeys, key)
		}
	}
	for _, name := range names(field(setup, "nodes")) {
		k.members[name] = k.h.newNode(name)
		if slices.Contains(names(field(setup, "members")), name) {
			k.genesis = append(k.genesis, k.members[name])
		}
	}
	return k
}

// replay is a trace's network and validators, and the records written so
// far, model id i at recs[i] with the state after it at after[i].
type replay struct {
	*replayKeys
	auths  map[string]*Authority
	stores map[string]*MemStorage
	recs   []types.AUM
	after  []*State
	model  []tlaValue
}

func replayTrace(t *testing.T, keys *replayKeys, network string, states []map[string]tlaValue) error {
	r := &replay{replayKeys: keys, auths: map[string]*Authority{}, stores: map[string]*MemStorage{}}
	commit := types.DisablementCommit(make([]byte, types.DisablementSecretSize))
	quorum := r.h.quorum
	genesis, err := Genesis(network, quorum, r.adminKeys, []types.Hash{commit}, r.genesis, r.h.sealer())
	if err != nil {
		return err
	}
	for _, k := range r.adminKeys {
		for _, priv := range r.admins {
			if priv.Public() == k.Public {
				if err := genesis.Sign(priv); err != nil {
					return err
				}
			}
		}
	}
	st, err := applyGenesis(&genesis, genesis.Hash())
	if err != nil {
		return err
	}
	r.recs, r.after = []types.AUM{genesis}, []*State{st}
	for _, v := range names(field(r.setup, "validators")) {
		r.stores[v] = NewMemStorage()
		a, err := Create(r.stores[v], genesis)
		if err != nil {
			return err
		}
		r.auths[v] = a
	}

	prev := states[0]
	if err := r.check(0, prev); err != nil {
		return err
	}
	for step, st := range states[1:] {
		if err := r.step(prev, st); err != nil {
			return fmt.Errorf("step %d: %w", step+1, err)
		}
		if err := r.check(step+1, st); err != nil {
			return err
		}
		prev = st
	}
	return nil
}

// step takes what changed from prev to st into the code: a record written,
// one delivered, or a compaction.
func (r *replay) step(prev, st map[string]tlaValue) error {
	if recs := st["rec"].([]tlaValue); len(recs) > len(r.recs)-1 {
		r.model = recs
		return r.write(len(recs))
	}
	for v, a := range r.auths {
		was, now := ints(field(prev["store"], v)), ints(field(st["store"], v))
		if field(prev["anchor"], v) != field(st["anchor"], v) {
			if _, err := a.Compact(); err != nil {
				return fmt.Errorf("%s compacts: %w", v, err)
			}
			return nil
		}
		for _, i := range now {
			if !slices.Contains(was, i) {
				if err := a.Inform(r.recs[i]); err != nil {
					return fmt.Errorf("%s takes record %d in: %w", v, i, err)
				}
				return nil
			}
		}
	}
	return nil
}

// sameContent reports whether model records a and b are copies of one
// record: one content, which an epoch record's fresh secret never shares.
func sameContent(a, b tlaValue) bool {
	kind := field(a, "kind").(string)
	return kind != "AddNode" && kind != "RemoveNode" && kind != "EpochBump" && kind == field(b, "kind") &&
		field(a, "parent") == field(b, "parent") && field(a, "subj") == field(b, "subj") && field(a, "q") == field(b, "q")
}

// write builds model record id, a copy of an earlier one where the model's
// is, drawing its epoch secret until it sorts among its siblings as the
// model's ranks say: by SigHash between contents, by hash between copies.
func (r *replay) write(id int) error {
	m := r.model[id-1]
	parent := int(field(m, "parent").(int64))
	st := r.after[parent]
	original := 0
	for j := 1; j < id; j++ {
		if sameContent(r.model[j-1], m) {
			original = j
		}
	}
	for range 256 {
		var aum types.AUM
		var err error
		if original != 0 {
			aum = r.recs[original]
			aum.Signatures = nil
			err = r.sign(&aum, m)
		} else {
			aum, err = r.build(NewBuilder(st), m)
		}
		if err != nil {
			return fmt.Errorf("building record %d: %w", id, err)
		}
		ordered := true
		for j := 1; j < id; j++ {
			sib := r.model[j-1]
			switch {
			case field(sib, "parent") != field(m, "parent"):
			case sameContent(sib, m):
				lower := field(m, "hrank").(int64) < field(sib, "hrank").(int64)
				ordered = ordered && (aum.Hash().Compare(r.recs[j].Hash()) < 0) == lower
			default:
				lower := field(m, "srank").(int64) < field(sib, "srank").(int64)
				ordered = ordered && (aum.SigHash().Compare(r.recs[j].SigHash()) < 0) == lower
			}
		}
		if ordered {
			next, err := st.apply(&aum, aum.Hash(), applyChain)
			if err != nil {
				return err
			}
			r.recs, r.after = append(r.recs, aum), append(r.after, next)
			return r.refuse(id)
		}
		if aum.Epoch == nil {
			return errOrder
		}
	}
	return errOrder
}

func (r *replay) build(b *Builder, m tlaValue) (types.AUM, error) {
	var aum types.AUM
	var err error
	subj := field(m, "subj")
	switch kind := field(m, "kind").(string); kind {
	case "AddNode":
		aum, err = b.AddNode(r.members[string(subj.(modelValue))], r.h.sealer())
	case "RemoveNode":
		aum, err = b.RemoveNode(r.members[string(subj.(modelValue))].Identity, r.h.sealer())
	case "RemoveAdmin":
		aum, err = b.RemoveAdminKey(r.admins[string(subj.(modelValue))].Public())
	case "SetQuorum":
		aum, err = b.SetQuorum(uint32(field(m, "q").(int64)))
	case "EpochBump":
		aum, err = b.EpochBump(r.h.sealer())
	case "Checkpoint":
		aum, err = b.Checkpoint()
	default:
		return aum, fmt.Errorf("a record of kind %s", kind)
	}
	if err != nil {
		return aum, err
	}
	return aum, r.sign(&aum, m)
}

func (r *replay) sign(aum *types.AUM, m tlaValue) error {
	for _, k := range names(field(m, "signers")) {
		if err := aum.Sign(r.admins[k]); err != nil {
			return err
		}
	}
	return nil
}

// refuse offers record id, if the model's validators may not take it in, to
// each validator holding its parent: the code refuses it too.
func (r *replay) refuse(id int) error {
	m := r.model[id-1]
	parent := int(field(m, "parent").(int64))
	at := tlaValue(map[string]tlaValue{"admins": field(r.setup, "admins"), "quorum": field(r.setup, "quorum")})
	if parent != 0 {
		at = field(r.model[parent-1], "after")
	}
	signers, admins := names(field(m, "signers")), names(field(at, "admins"))
	signed, needed := map[string]int{}, map[string]int{}
	for _, k := range signers {
		h, n := k, 1
		if slices.Contains(names(field(r.setup, "paired")), k) {
			h, n = "pair", int(field(r.setup, "pairNeeded").(int64))
		}
		if slices.Contains(admins, k) {
			signed[h]++
		}
		needed[h] = n
	}
	votes := 0
	for h, n := range signed {
		if n >= needed[h] {
			votes++
		}
	}
	authorized := votes >= int(field(at, "quorum").(int64))
	for _, k := range signers {
		authorized = authorized && slices.Contains(admins, k)
	}
	if authorized {
		return nil
	}
	for v, a := range r.auths {
		if _, err := r.stores[v].AUM(r.recs[parent].Hash()); err != nil {
			continue
		}
		head := a.Head()
		if err := a.Inform(r.recs[id]); err == nil {
			return fmt.Errorf("%s took in record %d, which lacks its quorum", v, id)
		}
		if a.Head() != head {
			return fmt.Errorf("%s moved its head on a refused record", v)
		}
	}
	return nil
}

// check holds each validator to what the model's says after step.
func (r *replay) check(step int, st map[string]tlaValue) error {
	id := map[types.Hash]int{}
	for i, a := range r.recs {
		id[a.Hash()] = i
	}
	for v, a := range r.auths {
		res := field(st["res"], v)
		floor, err := r.stores[v].EpochFloor()
		if err != nil {
			return err
		}
		var unrevoked []int
		for _, o := range a.Orphans() {
			for _, h := range o.Unrevoked {
				unrevoked = append(unrevoked, id[h])
			}
		}
		slices.Sort(unrevoked)
		for _, c := range []struct {
			what       string
			code, want any
		}{
			{"head", id[a.Head()], int(field(res, "head").(int64))},
			{"fork alarm", a.Alarm() != nil, field(res, "alarm").(bool)},
			{"rollback alarm", a.Rollback() != nil, field(st["rollback"], v).(bool)},
			{"epoch floor", int64(floor) - 1, field(st["floor"], v).(int64)},
			{"anchor", id[a.Anchor()], int(field(st["anchor"], v).(int64))},
			{"revocations to redo", fmt.Sprint(unrevoked), fmt.Sprint(ints(field(res, "unrevoked")))},
		} {
			if fmt.Sprint(c.code) != fmt.Sprint(c.want) {
				return fmt.Errorf("after step %d, %s: the code has %s %v, the model %v", step, v, c.what, c.code, c.want)
			}
		}
	}
	return nil
}
