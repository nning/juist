package log

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nning/juist/types"
)

// TestEveryKindHasARule keeps kindRules in step with the record kinds types
// defines: a kind without a rule would be decodable and never appliable.
// Genesis starts a state and a disable record ends one; neither changes one.
func TestEveryKindHasARule(t *testing.T) {
	for k := types.Kind(1); k != 0; k++ {
		if strings.HasPrefix(k.String(), "kind?") {
			continue
		}
		_, ruled := kindRules[k]
		if want := k != types.KindGenesis && k != types.KindDisable; ruled != want {
			t.Errorf("%v: has a rule %v, want %v", k, ruled, want)
		}
	}
	for k := range kindRules {
		if strings.HasPrefix(k.String(), "kind?") {
			t.Errorf("a rule for %v, which types does not define", k)
		}
	}
}

// TestApplyLeavesItsParentUnchanged: a State is immutable, so applying a
// record to it — accepted or refused, on the chain or as a probe — changes
// nothing a holder of it can see. Every generated record is applied to every
// generated state, re-parented so the chain mode reaches the kind's rules.
func TestApplyLeavesItsParentUnchanged(t *testing.T) {
	type outcomes struct{ accepted, refused int }
	seen := map[types.Kind]*outcomes{}
	for seed := uint64(1); seed <= 16; seed++ {
		g := newGenerator(t, seed)
		g.run(40)
		for _, s := range g.states {
			head := s.Head()
			for i := range g.records {
				rec := g.records[i].Clone()
				rec.Prev = &head
				o := seen[rec.Kind]
				if o == nil {
					o = &outcomes{}
					seen[rec.Kind] = o
				}
				for _, mode := range []applyMode{applyChain, applyProbe} {
					if _, err := s.apply(rec, types.Hash{0xaa}, mode); err != nil {
						o.refused++
					} else {
						o.accepted++
					}
				}
			}
		}
		for i, s := range g.states {
			if !bytes.Equal(s.Snapshot().Encode(), g.encoded[i]) {
				t.Fatalf("seed %d: state %d changed after records were applied to it", seed, i)
			}
		}
	}
	for k := range kindRules {
		if k == types.KindSchemaUpgrade {
			continue // the network starts at the current schema
		}
		if o := seen[k]; o == nil || o.accepted == 0 || o.refused == 0 {
			t.Errorf("%v: %+v; want both outcomes exercised", k, o)
		}
	}
}

// TestKindsBeforeTheirSchema: a record of a kind a later schema introduced is
// refused by a network written under an earlier one, whatever it carries.
func TestKindsBeforeTheirSchema(t *testing.T) {
	for k, rule := range kindRules {
		if rule.since == 0 {
			continue
		}
		h := newHarnessAt(t, 1, 1, rule.since-1)
		head := h.auth.Head()
		_, err := h.auth.State().apply(&types.AUM{Kind: k, Prev: &head}, types.Hash{1}, applyChain)
		if err == nil || !strings.Contains(err.Error(), "needs "+rule.since.String()) {
			t.Errorf("%v at %v: %v, want a refusal naming %v", k, rule.since-1, err, rule.since)
		}
	}
}
