package log

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"

	"github.com/nning/juist/types"
)

// TestResolutionIsOrderIndependent is the determinism property: over generated
// record sets including forks, two nodes holding the same records reach
// byte-identical state, head and alarm whatever order they arrived in. Seeded,
// so a failure can be replayed.
func TestResolutionIsOrderIndependent(t *testing.T) {
	for seed := uint64(1); seed <= 24; seed++ {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			g := newGenerator(t, seed)
			// Enough records whatever path the seed takes, as a step that
			// draws a refused record adds none.
			for range 8 {
				if len(g.records) >= 12 {
					break
				}
				g.run(24)
			}
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

// TestGeneratorIsReproducible: a seed names one record set, hashes included,
// or a failing seed would not replay the fork choices that failed.
func TestGeneratorIsReproducible(t *testing.T) {
	a, b := newGenerator(t, 3), newGenerator(t, 3)
	a.run(24)
	b.run(24)
	if len(a.records) != len(b.records) {
		t.Fatalf("one seed generated %d and %d records", len(a.records), len(b.records))
	}
	for i := range a.records {
		if a.records[i].Hash() != b.records[i].Hash() {
			t.Fatalf("record %d differs between two runs of one seed", i)
		}
	}
}

// TestIncrementalDeliveryNeverRegresses models gossip: records arrive one at a
// time in arbitrary order. The epoch must never go backwards, a rejected
// record must leave nothing behind, and the store must reopen to what it
// serves.
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
// every state it has produced and sometimes building against an old one. It
// draws every kind but genesis and schema upgrades.
type generator struct {
	t        *testing.T
	rng      *rand.Rand
	genesis  types.AUM
	states   []*State
	encoded  [][]byte // each state's snapshot as it was made
	records  []types.AUM
	adminIDs map[types.Identity]types.PrivateIdentity
	nodeIDs  map[types.Identity]types.PrivateIdentity
	counter  byte
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
		t:        t,
		rng:      rand.New(rand.NewPCG(seed, 0)),
		genesis:  genesis,
		states:   []*State{root},
		encoded:  [][]byte{root.Snapshot().Encode()},
		adminIDs: map[types.Identity]types.PrivateIdentity{admin.Public(): admin},
		nodeIDs:  map[types.Identity]types.PrivateIdentity{},
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
			g.encoded = append(g.encoded, next.Snapshot().Encode())
		}
	}
}

func (g *generator) next() byte {
	g.counter++
	return g.counter
}

// freeV4 draws an address in base's range that no member holds.
func (g *generator) freeV4(base *State) (netip.Addr, bool) {
	r := base.V4Range()
	for range 8 {
		a := r.Addr()
		for range 1 + g.rng.IntN(200) {
			a = a.Next()
		}
		if r.Contains(a) && !base.v4Holder(a) {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// step builds one random record against base, returning it and the state it
// produces. It returns false when the drawn operation does not apply, which is
// expected and simply skipped.
func (g *generator) step(base *State) (types.AUM, *State, bool) {
	b := NewBuilder(base)
	members, admins := base.Nodes(), base.Admins()
	var victim types.NodeRecord
	if len(members) > 0 {
		victim = members[g.rng.IntN(len(members))]
	}
	holder := admins[g.rng.IntN(len(admins))]
	var aum types.AUM
	var err error
	var devices []types.PrivateIdentity

	op := g.rng.IntN(23)
	if len(members) == 0 && slices.Contains([]int{2, 3, 4, 5, 14, 18, 20, 21, 22}, op) {
		return types.AUM{}, nil, false
	}
	switch op {
	case 0, 1: // admit a member, sometimes at an address of its own or as an admin device
		n := g.next()
		node := fixedNode(n)
		g.nodeIDs[node.Identity] = fixedIdentity(100 + n)
		if v4, ok := g.freeV4(base); ok && g.rng.IntN(2) == 0 {
			node.V4 = &v4
		}
		if g.rng.IntN(3) == 0 {
			node.Roles = []types.Role{types.RoleAdmin}
		}
		aum, err = b.AddNode(node, fixedSealer())
	case 2: // revoke a member
		aum, err = b.RemoveNode(victim.Identity, fixedSealer())
	case 3: // grant or withdraw roles and routes
		switch g.rng.IntN(3) {
		case 0:
			aum, err = b.SetNodeRoutes(victim.Identity,
				[]types.Role{types.RoleExit, types.RoleRelayCapable},
				[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("192.168.0.0/16")})
		case 1:
			aum, err = b.SetNodeRoutes(victim.Identity, []types.Role{types.RoleAdmin}, nil)
		default:
			aum, err = b.SetNodeRoutes(victim.Identity, nil, nil)
		}
	case 4: // rotate a member's keys
		fresh := fixedNode(g.next())
		devices = []types.PrivateIdentity{g.nodeIDs[victim.Identity]}
		aum, err = b.RotateNodeKey(victim.Identity, types.NodeKeys{
			WireGuard: fresh.WireGuard, X25519: fresh.X25519, MLKEM: fresh.MLKEM,
		}, fixedSealer())
	case 5: // move a member to a new identity
		fresh := fixedIdentity(100 + g.next())
		g.nodeIDs[fresh.Public()] = fresh
		devices = []types.PrivateIdentity{g.nodeIDs[victim.Identity], fresh}
		aum, err = b.RotateIdentity(victim.Identity, fresh.Public(), fresh.SigningKey(), fixedSealer())
	case 6: // rotate the group secret
		aum, err = b.EpochBump(fixedSealer())
	case 7: // settle ordering with a checkpoint
		aum, err = b.Checkpoint()
	case 8: // add an admin key, of its own holder or another's
		n := g.next()
		priv := fixedIdentity(200 + n)
		g.adminIDs[priv.Public()] = priv
		devices = []types.PrivateIdentity{priv}
		k := types.AdminKey{Public: priv.Public(), Signing: new(priv.SigningKey()), Endorsement: priv.Endorsement(), Votes: 1, Holder: fmt.Sprintf("h%d", n)}
		if g.rng.IntN(2) == 0 && holder.Holder != "" {
			k.Holder, k.Votes, k.Needed = holder.Holder, holder.Votes, holder.Needed
		}
		aum, err = b.AddAdminKey(k)
	case 9: // remove an admin key
		aum, err = b.RemoveAdminKey(holder.Public)
	case 10: // move the quorum
		aum, err = b.SetQuorum(1 + uint32(g.rng.IntN(int(max(base.TotalVotes(), 1)))))
	case 11: // change what a holder casts
		if holder.Holder == "" {
			return types.AUM{}, nil, false
		}
		aum, err = b.SetHolder(types.HolderPolicy{Name: holder.Holder,
			Votes: 1 + uint32(g.rng.IntN(3)), Needed: 1 + uint32(g.rng.IntN(2))})
	case 12: // move the vouching threshold, once there is an admin device
		switch admins := len(base.NodesWithRole(types.RoleAdmin)); {
		case admins > 0:
			aum, err = b.SetVouchers(1 + uint32(g.rng.IntN(admins)))
		case len(members) > 0:
			aum, err = b.SetNodeRoutes(victim.Identity, []types.Role{types.RoleAdmin}, nil)
		default:
			return types.AUM{}, nil, false
		}
	case 13: // renumber the network
		prefix := netip.MustParsePrefix([]string{"10.7.0.0/22", "10.9.0.0/22", "10.11.0.0/22"}[g.rng.IntN(3)])
		a := prefix.Addr()
		var addrs []types.MemberV4
		for _, m := range members {
			a = a.Next()
			addrs = append(addrs, types.MemberV4{Identity: m.Identity, V4: a})
		}
		aum, err = b.RenumberNetwork(prefix, addrs, 1000)
	case 14: // move one member
		v4, ok := g.freeV4(base)
		if !ok {
			return types.AUM{}, nil, false
		}
		aum, err = b.RenumberNode(victim.Identity, v4, 1000)
	case 15: // retire what renumberings left
		aum, err = b.RetireAddresses()
	case 16: // rename the network
		aum, err = b.RenameNetwork([]string{"alpha", "bravo", "charlie"}[g.rng.IntN(3)])
	case 17: // give an admin key an encryption key
		keys := fixedNode(g.next())
		aum, err = b.SetAdminRecipient(holder.Public, types.RecipientKey{X25519: keys.X25519, MLKEM: keys.MLKEM})
	case 18: // point names at a member, one another may hold, or withdraw them
		names := [][]string{{"mx.example.org"}, {"imap.example.org", "mx.example.org"}, nil}
		aum, err = b.SetNodeNames(victim.Identity, names[g.rng.IntN(len(names))])
	case 19: // set the domain, to one a name points into, or withdraw it
		aum, err = b.SetDomain([]string{"pub.example.org", "example.org", ""}[g.rng.IntN(3)])
	case 20: // publish names on a member, one another may publish, or withdraw them
		names := [][]types.PublishedName{{{Label: "mx", Port: 443}}, {{Label: "immich", Port: 2283, Proxy: true}}, nil}
		aum, err = b.SetPublished(victim.Identity, names[g.rng.IntN(len(names))])
	case 21: // rename a member, sometimes to a name another holds
		names := []string{"laptop", "Laptop", members[g.rng.IntN(len(members))].Name}
		aum, err = b.RenameNode(victim.Identity, names[g.rng.IntN(len(names))])
	case 22: // let a member reach every other, use it as an exit node, or pass nothing
		policies := []*types.Policy{
			{Rules: []types.PolicyRule{{From: types.PolicyRefs{Nodes: []types.Identity{victim.Identity}},
				To: types.PolicyRefs{Any: true}}}},
			{Tables: []types.PolicyTable{{Name: "exits", Nodes: []types.Identity{victim.Identity}}},
				Rules: []types.PolicyRule{{From: types.PolicyRefs{Any: true},
					To: types.PolicyRefs{Internet: true, ViaTables: []string{"exits"}}}}},
			{},
		}
		aum, err = b.SetPolicy(policies[g.rng.IntN(len(policies))])
	}
	if err != nil || !g.sign(&aum, base, devices) {
		return types.AUM{}, nil, false
	}
	next, err := base.apply(&aum, aum.Hash(), applyChain)
	if err != nil {
		return types.AUM{}, nil, false
	}
	return aum, next, true
}

// sign signs a record with every admin key of base the generator holds, and
// with the device keys it needs, reporting whether that authorizes it.
func (g *generator) sign(aum *types.AUM, base *State, devices []types.PrivateIdentity) bool {
	for _, k := range base.Admins() {
		if priv, ok := g.adminIDs[k.Public]; ok {
			if err := aum.Sign(priv); err != nil {
				g.t.Fatalf("signing: %v", err)
			}
		}
	}
	if err := SignAsDevice(aum, devices...); err != nil {
		g.t.Fatalf("signing as the device: %v", err)
	}
	return verifyAgainst(aum, base) == nil
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
