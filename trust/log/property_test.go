package log

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"

	"github.com/nning/juist/types"
)

// TestResolutionIsOrderIndependent is the determinism property from
// docs/06-verification.md, over randomly generated record sets that include
// forks: two nodes holding the same records reach byte-identical state, the
// same head, and the same alarm, whatever order the records arrived in.
//
// Seeded rather than randomized: a property test that cannot be replayed is
// not much use when it fails.
func TestResolutionIsOrderIndependent(t *testing.T) {
	for seed := uint64(1); seed <= 24; seed++ {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			g := newGenerator(t, seed)
			g.run(24)
			if len(g.records) < 8 {
				t.Fatalf("generator produced only %d records", len(g.records))
			}

			reference := g.deliverBatch(t, g.topological(rand.New(rand.NewPCG(seed, 1))))
			for attempt := range 6 {
				rng := rand.New(rand.NewPCG(seed, uint64(100+attempt)))
				got := g.deliverBatch(t, g.topological(rng))
				if got.head != reference.head {
					t.Fatalf("attempt %d chose head %v, reference chose %v",
						attempt, got.head, reference.head)
				}
				if string(got.snapshot) != string(reference.snapshot) {
					t.Fatalf("attempt %d reached different state", attempt)
				}
				if got.alarmed != reference.alarmed {
					t.Fatalf("attempt %d alarmed=%v, reference alarmed=%v",
						attempt, got.alarmed, reference.alarmed)
				}
			}
		})
	}
}

// TestIncrementalDeliveryNeverRegresses models gossip: records arrive one at a
// time, in an arbitrary order, possibly out of order. Whatever the sequence,
// the epoch must never go backwards, a rejected record must leave nothing
// behind, and the store must always reopen to the state it is serving.
func TestIncrementalDeliveryNeverRegresses(t *testing.T) {
	for seed := uint64(1); seed <= 16; seed++ {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			g := newGenerator(t, seed)
			g.run(20)
			rng := rand.New(rand.NewPCG(seed, 7))
			order := slices.Clone(g.records)
			rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })

			storage := NewMemStorage()
			auth, err := Create(storage, g.genesis)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			// Keep re-offering deferred records, which is what an
			// anti-entropy round does when it learns a parent it was missing.
			deferred := order
			for round := 0; len(deferred) > 0 && round < 40; round++ {
				var stillDeferred []types.AUM
				for _, rec := range deferred {
					epochBefore := auth.State().Epoch()
					headBefore := auth.Head()
					snapBefore := auth.State().Snapshot().Encode()
					err := auth.Inform(rec)
					if err != nil {
						if auth.Head() != headBefore ||
							string(auth.State().Snapshot().Encode()) != string(snapBefore) {
							t.Fatalf("a rejected record changed state: %v", err)
						}
						stillDeferred = append(stillDeferred, rec)
					}
					if auth.State().Epoch() < epochBefore {
						t.Fatalf("epoch went backwards: %d then %d", epochBefore, auth.State().Epoch())
					}
					reopened, err := Open(storage)
					if err != nil {
						t.Fatalf("store stopped opening: %v", err)
					}
					if reopened.Head() != auth.Head() {
						t.Fatal("the stored chain resolves to a different head than the live authority")
					}
				}
				if len(stillDeferred) == len(deferred) {
					break // no progress; the rest are permanently refused
				}
				deferred = stillDeferred
			}
		})
	}
}

// generator builds random but valid record sets, including forks, by keeping
// every state it has produced and sometimes building against an old one.
type generator struct {
	t       *testing.T
	rng     *rand.Rand
	admin   types.PrivateIdentity
	genesis types.AUM
	states  []*State
	records []types.AUM
	nodeIDs map[types.Identity]types.PrivateIdentity
	counter byte
}

func newGenerator(t *testing.T, seed uint64) *generator {
	t.Helper()
	genesis, admin, err := fixedGenesis()
	if err != nil {
		t.Fatalf("building genesis: %v", err)
	}
	root, err := applyGenesis(&genesis, genesis.Hash())
	if err != nil {
		t.Fatalf("applying genesis: %v", err)
	}
	return &generator{
		t:       t,
		rng:     rand.New(rand.NewPCG(seed, 0)),
		admin:   admin,
		genesis: genesis,
		states:  []*State{root},
		nodeIDs: map[types.Identity]types.PrivateIdentity{},
	}
}

func (g *generator) run(steps int) {
	for range steps {
		// Mostly extend the newest state, sometimes fork from an older one:
		// forks are the interesting case and would almost never appear if
		// every record chained onto the head.
		var base *State
		if g.rng.IntN(4) == 0 && len(g.states) > 1 {
			base = g.states[g.rng.IntN(len(g.states))]
		} else {
			base = g.states[len(g.states)-1]
		}
		if rec, next, ok := g.step(base); ok {
			g.records = append(g.records, rec)
			g.states = append(g.states, next)
		}
	}
}

// step builds one random record against base, returning it and the state it
// produces. It returns false when the drawn operation does not apply, which is
// expected and simply skipped.
func (g *generator) step(base *State) (types.AUM, *State, bool) {
	b := NewBuilder(base)
	members := base.Nodes()
	var aum types.AUM
	var err error
	var selfSign *types.PrivateIdentity

	switch g.rng.IntN(7) {
	case 0, 1: // admit a member
		g.counter++
		node := fixedNode(g.counter)
		g.nodeIDs[node.Identity] = fixedIdentity(100 + g.counter)
		aum, err = b.AddNode(node, testSealer())
	case 2: // revoke a member
		if len(members) == 0 {
			return types.AUM{}, nil, false
		}
		aum, err = b.RemoveNode(members[g.rng.IntN(len(members))].Identity, testSealer())
	case 3: // grant or withdraw roles and routes
		if len(members) == 0 {
			return types.AUM{}, nil, false
		}
		victim := members[g.rng.IntN(len(members))].Identity
		if g.rng.IntN(2) == 0 {
			aum, err = b.SetNodeRoutes(victim,
				[]types.Role{types.RoleExitNode, types.RoleRelayCapable},
				[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("192.168.0.0/16")})
		} else {
			aum, err = b.SetNodeRoutes(victim, nil, nil)
		}
	case 4: // rotate a member's keys
		if len(members) == 0 {
			return types.AUM{}, nil, false
		}
		victim := members[g.rng.IntN(len(members))]
		g.counter++
		fresh := fixedNode(g.counter)
		priv, ok := g.nodeIDs[victim.Identity]
		if !ok {
			return types.AUM{}, nil, false
		}
		selfSign = &priv
		aum, err = b.RotateNodeKey(victim.Identity, types.NodeKeys{
			WireGuard: fresh.WireGuard, X25519: fresh.X25519, MLKEM: fresh.MLKEM,
		}, testSealer())
	case 5: // rotate the group secret
		aum, err = b.EpochBump(testSealer())
	case 6: // settle ordering with a checkpoint
		aum, err = b.Checkpoint()
	}
	if err != nil {
		return types.AUM{}, nil, false
	}
	if err := aum.Sign(g.admin); err != nil {
		g.t.Fatalf("signing: %v", err)
	}
	if selfSign != nil {
		if err := aum.Sign(*selfSign); err != nil {
			g.t.Fatalf("self-signing: %v", err)
		}
	}
	next, err := base.apply(&aum, aum.Hash(), applyChain)
	if err != nil {
		return types.AUM{}, nil, false
	}
	return aum, next, true
}

// topological returns the records in a random order in which every record's
// parent comes first, which is the contract Inform states.
func (g *generator) topological(rng *rand.Rand) []types.AUM {
	remaining := slices.Clone(g.records)
	rng.Shuffle(len(remaining), func(i, j int) { remaining[i], remaining[j] = remaining[j], remaining[i] })
	have := map[types.Hash]bool{g.genesis.Hash(): true}
	out := make([]types.AUM, 0, len(remaining))
	for len(remaining) > 0 {
		progress := false
		var next []types.AUM
		for _, rec := range remaining {
			if rec.Prev != nil && have[*rec.Prev] {
				out = append(out, rec)
				have[rec.Hash()] = true
				progress = true
				continue
			}
			next = append(next, rec)
		}
		remaining = next
		if !progress {
			g.t.Fatalf("%d records have no reachable parent", len(remaining))
		}
	}
	return out
}

type outcome struct {
	head     types.Hash
	snapshot []byte
	alarmed  bool
}

func (g *generator) deliverBatch(t *testing.T, records []types.AUM) outcome {
	t.Helper()
	auth, err := Create(NewMemStorage(), g.genesis)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := auth.Inform(records...); err != nil {
		t.Fatalf("Inform of a generated batch: %v", err)
	}
	return outcome{
		head:     auth.Head(),
		snapshot: auth.State().Snapshot().Encode(),
		alarmed:  auth.Alarm() != nil,
	}
}
