package types

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Validate refuses a policy that cannot mean what it says: a name used
// undefined or defined twice, a table inside itself, a source that is no
// member, exit nodes without the internet, an unsorted set, ports where a
// protocol has none, and a test naming more than one destination.
func TestAPolicyMeansWhatItSays(t *testing.T) {
	a, b := Identity{1}, Identity{2}
	tcp := func(first, last uint16) PortRange { return PortRange{Proto: ProtoTCP, First: first, Last: last} }
	nodes := PolicyRefs{Nodes: []Identity{a}}
	rule := func(r PolicyRule) *Policy { return &Policy{Rules: []PolicyRule{r}} }
	for _, c := range []struct {
		what string
		p    *Policy
		want string
	}{
		{"an undefined table", rule(PolicyRule{From: PolicyRefs{Tables: []string{"staff"}}, To: nodes}), "not defined"},
		{"an undefined service", rule(PolicyRule{From: nodes, To: nodes, Services: []string{"web"}}), "not defined"},
		{"a table defined twice", &Policy{Tables: []PolicyTable{{Name: "x"}, {Name: "x"}}}, "twice"},
		{"a table in itself", &Policy{Tables: []PolicyTable{{Name: "x", Tables: []string{"y"}}, {Name: "y", Tables: []string{"x"}}}},
			"contains itself"},
		{"a name in capitals", &Policy{Tables: []PolicyTable{{Name: "Staff"}}}, "lowercase"},
		{"a name ending in a hyphen", &Policy{Services: []PolicyService{{Name: "web-", Ports: []PortRange{tcp(80, 80)}}}}, "hyphen"},
		{"a service without ports", &Policy{Services: []PolicyService{{Name: "web"}}}, "no ports"},
		{"the internet as a source", rule(PolicyRule{From: PolicyRefs{Internet: true}, To: nodes}), "destinations alone"},
		{"exit nodes without the internet", rule(PolicyRule{From: nodes, To: PolicyRefs{Any: true, ViaNodes: []Identity{b}}}), "no internet"},
		{"an empty source", rule(PolicyRule{To: nodes}), "names nothing"},
		{"unsorted members", rule(PolicyRule{From: PolicyRefs{Nodes: []Identity{b, a}}, To: nodes}), "sorted"},
		{"a prefix with host bits", rule(PolicyRule{From: nodes, To: PolicyRefs{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}}}),
			"network address"},
		{"ports for ICMP", rule(PolicyRule{From: nodes, To: nodes, Ports: []PortRange{{Proto: ProtoICMP, First: 1, Last: 1}}}), "has none"},
		{"a port range backwards", rule(PolicyRule{From: nodes, To: nodes, Ports: []PortRange{tcp(90, 80)}}), "ports 90 to 80"},
		{"ports from zero", rule(PolicyRule{From: nodes, To: nodes, Ports: []PortRange{tcp(0, 80)}}), "ports 0 to 80"},
		{"an unknown protocol", rule(PolicyRule{From: nodes, To: nodes, Ports: []PortRange{{Proto: 47}}}), "protocol 47"},
		{"unsorted ports", rule(PolicyRule{From: nodes, To: nodes, Ports: []PortRange{tcp(443, 443), tcp(80, 80)}}), "sorted"},
		{"a test of a table", &Policy{Tests: []PolicyTest{{From: a, To: PolicyRefs{Any: true}}}}, "one destination"},
		{"a test of two members", &Policy{Tests: []PolicyTest{{From: a, To: PolicyRefs{Nodes: []Identity{a, b}}}}}, "one member"},
		{"a test of a network", &Policy{Tests: []PolicyTest{{From: a, To: PolicyRefs{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}}}},
			"one address"},
		{"a test of a port range", &Policy{Tests: []PolicyTest{{From: a, To: nodes, Port: tcp(80, 81)}}}, "one port"},
	} {
		err := c.p.Validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error saying %q", c.what, err, c.want)
		}
	}
	if err := seedPolicy(a).Validate(); err != nil {
		t.Errorf("the seed policy: %v", err)
	}
	if err := (&Policy{}).Validate(); err != nil {
		t.Errorf("an empty policy, which passes nothing: %v", err)
	}
}

// Rekeyed keeps every set sorted, and a test of a member gone goes with it.
func TestRekeyingKeepsSetsSorted(t *testing.T) {
	a, b, c := Identity{1}, Identity{2}, Identity{3}
	p := &Policy{
		Tables: []PolicyTable{{Name: "x", Nodes: []Identity{a, b}}},
		Rules:  []PolicyRule{{From: PolicyRefs{Nodes: []Identity{a, b}}, To: PolicyRefs{Any: true}}},
		Tests:  []PolicyTest{{From: b, To: PolicyRefs{Nodes: []Identity{a}}}},
	}
	moved := p.Rekeyed(a, &c)
	if err := moved.Validate(); err != nil {
		t.Fatalf("rekeyed: %v", err)
	}
	if got := moved.Tables[0].Nodes; got[0] != b || got[1] != c {
		t.Errorf("the table holds %v, want b then c", got)
	}
	if moved.Tests[0].To.Nodes[0] != c {
		t.Error("the test still names the old identity")
	}
	if p.Tables[0].Nodes[0] != a {
		t.Error("rekeying changed the policy it was asked of")
	}
	if gone := p.Rekeyed(a, nil); len(gone.Tests) != 0 || len(gone.Rules[0].From.Nodes) != 1 {
		t.Errorf("with a gone, the policy is %+v", gone)
	}
}

// Tables nested as densely as the limits allow are checked in time linear in
// their size: a record must not cost every member an exponential walk.
func TestDenselyNestedTablesValidateQuickly(t *testing.T) {
	p := &Policy{}
	for i := range MaxPolicyNames {
		tab := PolicyTable{Name: fmt.Sprintf("t%03d", i)}
		for j := range i {
			tab.Tables = append(tab.Tables, fmt.Sprintf("t%03d", j))
		}
		p.Tables = append(p.Tables, tab)
	}
	start := time.Now()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("validating took %v", took)
	}
}
