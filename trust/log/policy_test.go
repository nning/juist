package log

import (
	"reflect"
	"slices"
	"testing"

	"github.com/nning/juist/types"
)

// A policy names members alone, follows a member's identity rotation, loses a
// removed member with every rule and test that named only it, and survives a
// checkpoint bootstrapped from.
func TestThePolicyFollowsItsMembers(t *testing.T) {
	h := newHarness(t, 1, 1)
	nas, laptop, exit := h.addNode("nas"), h.addNode("laptop"), h.addNode("exit")
	policy := &types.Policy{
		Tables: []types.PolicyTable{{Name: "staff", Nodes: sorted(laptop.Identity, nas.Identity)}},
		Rules: []types.PolicyRule{
			{From: types.PolicyRefs{Tables: []string{"staff"}}, To: types.PolicyRefs{Nodes: []types.Identity{nas.Identity}}},
			{From: types.PolicyRefs{Nodes: []types.Identity{laptop.Identity}},
				To: types.PolicyRefs{Internet: true, ViaNodes: []types.Identity{exit.Identity}}},
		},
		Tests: []types.PolicyTest{
			{From: laptop.Identity, To: types.PolicyRefs{Nodes: []types.Identity{nas.Identity}}},
			{From: laptop.Identity, To: types.PolicyRefs{Internet: true, ViaNodes: []types.Identity{exit.Identity}}},
		},
	}
	h.apply(h.auth.Builder().SetPolicy(policy))
	if got := h.auth.State().Policy(); !reflect.DeepEqual(got, policy) {
		t.Fatalf("the state holds %+v, want %+v", got, policy)
	}
	if _, err := h.auth.Builder().SetPolicy(policy); err == nil {
		t.Error("the builder authored the policy the network has")
	}

	stranger := fixedNode(99).Identity
	foreign := policy.Clone()
	foreign.Tables[0].Nodes = sorted(laptop.Identity, nas.Identity, stranger)
	h.mustReject("a policy naming no member", RuleState, h.signed(types.AUM{Kind: types.KindSetPolicy, Policy: foreign}))

	fresh, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rot, err := h.auth.Builder().RotateIdentity(laptop.Identity, fresh.Public(), h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&rot)
	for _, k := range []types.PrivateIdentity{fresh, h.nodeIDs[laptop.Identity]} {
		if err := h.sign(&rot, k); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.auth.Inform(rot); err != nil {
		t.Fatal(err)
	}
	rotated := h.auth.State().Policy()
	if got := rotated.Tables[0].Nodes; !reflect.DeepEqual(got, sorted(nas.Identity, fresh.Public())) {
		t.Errorf("after the rotation the table holds %v", got)
	}
	if rotated.Rules[1].From.Nodes[0] != fresh.Public() || rotated.Tests[0].From != fresh.Public() {
		t.Error("a rule or test still names the identity rotated away")
	}

	h.apply(h.auth.Builder().RemoveNode(exit.Identity, h.sealer()))
	left := h.auth.State().Policy()
	if len(left.Rules) != 1 || len(left.Tests) != 1 {
		t.Fatalf("with its exit node removed, the policy keeps %d rules and %d tests, want 1 and 1",
			len(left.Rules), len(left.Tests))
	}
	h.apply(h.auth.Builder().RemoveNode(nas.Identity, h.sealer()))
	left = h.auth.State().Policy()
	if len(left.Rules) != 0 || len(left.Tests) != 0 || !reflect.DeepEqual(left.Tables[0].Nodes, []types.Identity{fresh.Public()}) {
		t.Fatalf("with nas, the last rule's one destination, removed, the policy is %+v", left)
	}

	cp := h.apply(h.auth.Builder().Checkpoint())
	boot, err := Bootstrap(NewMemStorage(), cp)
	if err != nil {
		t.Fatal(err)
	}
	if got := boot.State().Policy(); !reflect.DeepEqual(got, left) {
		t.Fatalf("bootstrapped from a checkpoint, the policy is %+v", got)
	}

	old := newHarnessAt(t, 1, 1, types.SchemaRelayName)
	old.mustReject("a policy at schema 12", RuleState, old.signed(types.AUM{Kind: types.KindSetPolicy, Policy: &types.Policy{}}))
}

// A removed member that was a rule's only exit node takes the internet out
// of it, rather than leaving it open through every exit node.
func TestARemovedExitNodeLeavesNoOpenInternet(t *testing.T) {
	h := newHarness(t, 1, 1)
	laptop, exit := h.addNode("laptop"), h.addNode("exit")
	h.apply(h.auth.Builder().SetPolicy(&types.Policy{Rules: []types.PolicyRule{{
		From: types.PolicyRefs{Nodes: []types.Identity{laptop.Identity}},
		To:   types.PolicyRefs{Any: true, Internet: true, ViaNodes: []types.Identity{exit.Identity}},
	}}}))
	h.apply(h.auth.Builder().RemoveNode(exit.Identity, h.sealer()))
	to := h.auth.State().Policy().Rules[0].To
	if to.Internet || !to.Any {
		t.Fatalf("the rule's destinations are %+v, want every member and no internet", to)
	}
}

func sorted(ids ...types.Identity) []types.Identity {
	out := slices.Clone(ids)
	slices.SortFunc(out, types.Identity.Compare)
	return out
}

// An empty policy withdraws the one the network has; removals that leave a
// policy empty leave it passing nothing, not withdrawn.
func TestAnEmptyPolicyWithdrawsIt(t *testing.T) {
	h := newHarness(t, 1, 1)
	laptop := h.addNode("laptop")
	h.mustReject("withdrawing no policy", RuleState, h.signed(types.AUM{Kind: types.KindSetPolicy, Policy: &types.Policy{}}))
	h.apply(h.auth.Builder().SetPolicy(&types.Policy{Rules: []types.PolicyRule{{
		From: types.PolicyRefs{Nodes: []types.Identity{laptop.Identity}}, To: types.PolicyRefs{Any: true}}}}))
	h.apply(h.auth.Builder().SetPolicy(&types.Policy{}))
	if p := h.auth.State().Policy(); p != nil {
		t.Fatalf("withdrawn, the network has %+v", p)
	}

	h.apply(h.auth.Builder().SetPolicy(&types.Policy{Rules: []types.PolicyRule{{
		From: types.PolicyRefs{Nodes: []types.Identity{laptop.Identity}}, To: types.PolicyRefs{Any: true}}}}))
	h.apply(h.auth.Builder().RemoveNode(laptop.Identity, h.sealer()))
	if p := h.auth.State().Policy(); p == nil || !p.Empty() {
		t.Fatalf("with its one member removed, the policy is %+v, want one passing nothing", p)
	}
}
