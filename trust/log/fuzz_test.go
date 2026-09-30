package log

import (
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/nning/juist/types"
)

// FuzzChainValidate offers a record to a real authority — the only way records
// ever arrive — with the fuzzer driving its content and the harness signing
// it: mutated bytes never carry a valid signature, so without re-signing the
// fuzzer would only ever explore authorization. The record is re-parented onto
// the head unless it names a record the network holds, which is how a fork is
// fuzzed. The invariants:
//
//   - no panic, which from a gossiped record would be a denial of service;
//   - a rejected record changes nothing;
//   - the epoch never goes backwards;
//   - reopening the store reproduces whatever state is reached.
func FuzzChainValidate(f *testing.F) {
	fx := theFuzzNetwork(f)
	for _, seed := range fx.seeds {
		f.Add(seed)
	}
	f.Add([]byte{})
	f.Add([]byte{0xa0})

	f.Fuzz(func(t *testing.T, data []byte) {
		aum, err := types.DecodeUnsignedAUM(data)
		if err != nil {
			return
		}
		storage, auth := fx.open(t)
		fx.sign(auth, &aum)
		headBefore := auth.Head()
		epochBefore := auth.State().Epoch()
		stateBefore := auth.State().Snapshot().Encode()

		informErr := auth.Inform(aum)
		if informErr != nil {
			if auth.Head() != headBefore {
				t.Fatal("a rejected record moved the head")
			}
			if string(auth.State().Snapshot().Encode()) != string(stateBefore) {
				t.Fatal("a rejected record changed the state")
			}
		}
		if auth.State().Epoch() < epochBefore {
			t.Fatalf("epoch went backwards: %d then %d", epochBefore, auth.State().Epoch())
		}
		reopened, err := Open(storage)
		if err != nil {
			t.Fatalf("store no longer opens after Inform (err was %v): %v", informErr, err)
		}
		if reopened.Head() != auth.Head() {
			t.Fatal("reopening the store produced a different head")
		}
		if string(reopened.State().Snapshot().Encode()) != string(auth.State().Snapshot().Encode()) {
			t.Fatal("reopening the store produced different state")
		}
	})
}

// TestFuzzSeedsReachTheStateMachine keeps the fuzz harness honest: every seed,
// signed as the harness signs, gets past validation and authorization, so the
// fuzzer starts from inputs that exercise what records do.
func TestFuzzSeedsReachTheStateMachine(t *testing.T) {
	fx := theFuzzNetwork(t)
	accepted := 0
	for _, seed := range fx.seeds {
		aum, err := types.DecodeUnsignedAUM(seed)
		if err != nil {
			t.Fatalf("a seed does not decode: %v", err)
		}
		_, auth := fx.open(t)
		fx.sign(auth, &aum)
		var re *RejectError
		switch err := auth.Inform(aum); {
		case err == nil:
			accepted++
		case !errors.As(err, &re) || re.Rule != RuleState:
			t.Errorf("%v seed refused before its substance was judged: %v", aum.Kind, err)
		}
	}
	if accepted < len(fx.seeds)-2 {
		t.Errorf("only %d of %d seeds apply", accepted, len(fx.seeds))
	}
}

// fuzzNetwork is a fixed network with two members, built once: a fuzz target
// needs the same network on every exec so a failing input reproduces.
type fuzzNetwork struct {
	records []types.AUM // genesis first
	admin   types.PrivateIdentity
	devices []types.PrivateIdentity
	seeds   [][]byte
}

var (
	fuzzOnce sync.Once
	fuzzNet  *fuzzNetwork
	fuzzErr  error
)

func theFuzzNetwork(t testing.TB) *fuzzNetwork {
	fuzzOnce.Do(func() { fuzzNet, fuzzErr = buildFuzzNetwork() })
	if fuzzErr != nil {
		t.Fatalf("building the fuzz network: %v", fuzzErr)
	}
	return fuzzNet
}

// open returns a fresh authority over the fixed network.
func (fx *fuzzNetwork) open(t *testing.T) (*MemStorage, *Authority) {
	st := NewMemStorage()
	auth, err := FromRecords(st, fx.records)
	if err != nil {
		t.Fatalf("FromRecords: %v", err)
	}
	return st, auth
}

// sign replaces a record's signatures with the harness's: the admin's, and
// those of every device key the record needs that the harness holds.
func (fx *fuzzNetwork) sign(auth *Authority, aum *types.AUM) {
	aum.Signatures = nil
	if aum.Prev != nil {
		if _, err := auth.storage.AUM(*aum.Prev); err != nil {
			head := auth.Head()
			aum.Prev = &head
		}
	}
	_ = aum.Sign(fx.admin)
	_ = SignAsDevice(aum, auth.State().Schema(), fx.devices...)
}

func buildFuzzNetwork() (*fuzzNetwork, error) {
	genesis, admin, err := fixedGenesis()
	if err != nil {
		return nil, err
	}
	fx := &fuzzNetwork{records: []types.AUM{genesis}, admin: admin}
	for n := byte(1); n <= 8; n++ {
		fx.devices = append(fx.devices, fixedIdentity(100+n))
	}
	auth, err := Create(NewMemStorage(), genesis)
	if err != nil {
		return nil, err
	}
	seal := fixedSealer()
	v4 := netip.MustParseAddr("198.18.0.2")
	second := fixedNode(2)
	second.V4, second.Roles = &v4, []types.Role{types.RoleAdmin}
	var afterFirst *State
	for _, n := range []types.NodeRecord{fixedNode(1), second} {
		aum, err := auth.Builder().AddNode(n, seal)
		if err != nil {
			return nil, err
		}
		if err := aum.Sign(admin); err != nil {
			return nil, err
		}
		if err := auth.Inform(aum); err != nil {
			return nil, err
		}
		fx.records = append(fx.records, aum)
		if afterFirst == nil {
			afterFirst = auth.State()
		}
	}

	b := auth.Builder()
	first, third := fixedNode(1).Identity, fixedNode(3)
	fourth := fixedNode(4)
	one := uint32(1)
	build := []func() (types.AUM, error){
		func() (types.AUM, error) { return b.AddNode(third, seal) },
		func() (types.AUM, error) { return b.RemoveNode(first, seal) },
		func() (types.AUM, error) {
			return b.SetNodeRoutes(first, []types.Role{types.RoleExit},
				[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
		},
		func() (types.AUM, error) {
			return b.RotateNodeKey(first, types.NodeKeys{WireGuard: fourth.WireGuard,
				X25519: fourth.X25519, MLKEM: fourth.MLKEM}, seal)
		},
		func() (types.AUM, error) { return b.RotateIdentity(first, fixedIdentity(105).Public(), seal) },
		func() (types.AUM, error) {
			return b.AddAdminKey(types.AdminKey{Public: fixedIdentity(10).Public(), Votes: 1, Holder: "other"})
		},
		func() (types.AUM, error) { return b.SetQuorum(1) },
		func() (types.AUM, error) { return b.SetHolder(types.HolderPolicy{Name: "admin", Votes: 2, Needed: 1}) },
		func() (types.AUM, error) { return b.SetVouchers(one) },
		func() (types.AUM, error) { return b.Checkpoint() },
		func() (types.AUM, error) { return b.EpochBump(seal) },
		func() (types.AUM, error) {
			return b.RenumberNetwork(netip.MustParsePrefix("10.7.0.0/22"), []types.MemberV4{
				{Identity: first, V4: netip.MustParseAddr("10.7.0.1")},
				{Identity: second.Identity, V4: netip.MustParseAddr("10.7.0.2")}}, 1000)
		},
		func() (types.AUM, error) { return b.RenumberNode(first, netip.MustParseAddr("198.18.0.9"), 1000) },
		func() (types.AUM, error) { return b.RenameNetwork("renamed") },
		func() (types.AUM, error) { return b.SetNodeNames(first, []string{"mx.example.org"}) },
		func() (types.AUM, error) {
			return b.SetAdminRecipient(admin.Public(), types.RecipientKey{X25519: fourth.X25519, MLKEM: fourth.MLKEM})
		},
		// A fork: an admission off the first member's, beside the second's.
		func() (types.AUM, error) { return NewBuilder(afterFirst).AddNode(third, seal) },
	}
	// Refused on their substance, which is what a seed for these can show.
	head := auth.Head()
	tooNew := types.CurrentSchema + 1
	unsigned := []types.AUM{
		{Kind: types.KindRetireAddresses, Prev: &head},
		{Kind: types.KindSchemaUpgrade, Prev: &head, Schema: &tooNew},
		{Kind: types.KindRemoveAdminKey, Prev: &head, Subject: new(admin.Public())},
	}
	for _, f := range build {
		aum, err := f()
		if err != nil {
			return nil, err
		}
		unsigned = append(unsigned, aum)
	}
	for i := range unsigned {
		b, err := unsigned[i].Encode()
		if err != nil {
			return nil, err
		}
		fx.seeds = append(fx.seeds, b)
	}
	return fx, nil
}
