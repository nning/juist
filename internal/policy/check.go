package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/nning/juist/types"
)

// A Failure is a test the policy fails: its index among the tests, and its
// line, with the rule that passes what it must block.
type Failure struct {
	Test int
	Text string
}

// Failures are the policy's tests it fails.
func (n *Network) Failures(name Namer) []Failure {
	if n.Policy == nil {
		return nil
	}
	views := map[types.Identity]View{}
	var out []Failure
	for i, t := range n.Policy.Tests {
		v, ok := views[t.From]
		if !ok {
			v = n.View(t.From)
			views[t.From] = v
		}
		if n.passes(func(id types.Identity) Access { return v.Out[id] }, t) != t.Block {
			continue
		}
		line := testLine(t, name)
		if _, by := n.Explain(t); by != nil {
			line += ": " + ruleLine(*by, name) + " passes it"
		}
		out = append(out, Failure{Test: i, Text: line})
	}
	return out
}

// Explain reports whether the policy passes what t asks, as by a test of
// pass, and the first rule that does; that rule is nil without a policy.
func (n *Network) Explain(t types.PolicyTest) (bool, *types.PolicyRule) {
	if n.Policy == nil {
		return true, nil
	}
	c := n.compile()
	if me, ok := c.byID[t.From]; !ok || me.Service {
		return false, nil
	}
	for i := range c.rules {
		r := &c.rules[i]
		if !r.from[t.From] {
			continue
		}
		grant := func(id types.Identity) Access {
			if m, ok := c.byID[id]; ok && id != t.From {
				return r.grant(*m)
			}
			return Access{}
		}
		if n.passes(grant, t) {
			return true, &n.Policy.Rules[i]
		}
	}
	return false, nil
}

func testLine(t types.PolicyTest, name Namer) string {
	return strings.TrimSuffix(Format(&types.Policy{Tests: []types.PolicyTest{t}}, name), "\n")
}

// RuleLine is r as the policy's text says it.
func RuleLine(r types.PolicyRule, name Namer) string { return ruleLine(r, name) }

// PortsLine is a port set as a rule says it, everything where no protocol is
// named.
func PortsLine(ports []types.PortRange) string {
	if len(ports) == 1 && ports[0] == (types.PortRange{}) {
		return "everything"
	}
	return protoPorts(ports)
}

func ruleLine(r types.PolicyRule, name Namer) string {
	return strings.TrimSuffix(Format(&types.Policy{Rules: []types.PolicyRule{r}}, name), "\n")
}

// passes reports whether what out says t's member may open on each other
// passes what t asks, or anything on t's destination where t names no
// protocol.
func (n *Network) passes(out func(types.Identity) Access, t types.PolicyTest) bool {
	open := func(ports []types.PortRange) bool {
		if t.Port == (types.PortRange{}) {
			return len(ports) > 0
		}
		return Allows(ports, t.Port.Proto, t.Port.First)
	}
	switch {
	case len(t.To.Nodes) == 1:
		return open(out(t.To.Nodes[0]).Own)
	case t.To.Internet:
		return open(out(t.To.ViaNodes[0]).Exit)
	}
	addr := t.To.Prefixes[0].Addr()
	for _, m := range n.Members {
		for _, r := range out(m.ID).Routes {
			if r.Prefix.Contains(addr) && open(r.Ports) {
				return true
			}
		}
	}
	return false
}

// Warnings are what the policy names that cannot be meant as written: a
// service member or an ingress as a source, exit nodes and prefixes nothing serves, and
// tables and services no rule uses.
func (n *Network) Warnings(name Namer) []string {
	if n.Policy == nil {
		return nil
	}
	f := formatter{name: name}
	byID := map[types.Identity]Member{}
	for _, m := range n.Members {
		byID[m.ID] = m
	}
	var out []string
	usedTables, usedServices := map[string]bool{}, map[string]bool{}
	for _, t := range n.Policy.Tables {
		for _, inner := range t.Tables {
			usedTables[inner] = true
		}
	}
	for _, r := range n.Policy.Rules {
		for _, set := range [][]string{r.From.Tables, r.To.Tables, r.To.ViaTables} {
			for _, t := range set {
				usedTables[t] = true
			}
		}
		for _, s := range r.Services {
			usedServices[s] = true
		}
		for _, id := range r.From.Nodes {
			switch {
			case byID[id].Service:
				out = append(out, fmt.Sprintf("%s is a service member, which opens nothing", f.node(id)))
			case byID[id].Ingress:
				out = append(out, fmt.Sprintf("%s is an ingress, which opens what is published alone", f.node(id)))
			}
		}
		for _, id := range r.To.ViaNodes {
			if !byID[id].Exit {
				out = append(out, fmt.Sprintf("%s is no exit node: juist grant %s exit", f.node(id), f.node(id)))
			}
		}
		for _, p := range r.To.Prefixes {
			if i := slices.IndexFunc(n.Members, func(m Member) bool { return slices.Contains(m.Addrs, p.Addr()) }); i >= 0 && p.IsSingleIP() {
				out = append(out, fmt.Sprintf("%s is %s's address: name the device", prefix(p), f.node(n.Members[i].ID)))
				continue
			}
			routed := slices.ContainsFunc(n.Members, func(m Member) bool {
				return slices.ContainsFunc(m.Subnets, func(s netip.Prefix) bool { _, ok := intersect(p, s); return ok })
			})
			if !routed {
				out = append(out, fmt.Sprintf("no subnet router routes %s", prefix(p)))
			}
		}
	}
	// What the policy leaves unused: a device in no rule, and an exit node or
	// a subnet router no rule passes anything through.
	served, named := map[types.Identity]bool{}, map[types.Identity]bool{}
	for _, r := range n.compile().rules {
		for _, set := range []map[types.Identity]bool{r.from, r.to, r.via} {
			for id := range set {
				named[id] = true
			}
		}
	}
	for _, m := range n.Members {
		for id, a := range n.View(m.ID).Out {
			if len(a.Exit) > 0 || len(a.Routes) > 0 {
				served[id] = true
			}
		}
	}
	for _, m := range n.Members {
		// A relay or a voucher alone is for the log, not for rules.
		if !named[m.ID] && !served[m.ID] && !m.Ingress && !(m.Carrier && !m.Exit && len(m.Subnets) == 0) {
			out = append(out, fmt.Sprintf("%s is in no rule: it opens nothing, and nothing opens it", f.node(m.ID)))
		}
	}
	for _, m := range n.Members {
		switch {
		case served[m.ID]:
		case m.Exit:
			out = append(out, fmt.Sprintf("%s is an exit node, and no rule passes the internet through it", f.node(m.ID)))
		case len(m.Subnets) > 0:
			out = append(out, fmt.Sprintf("%s routes %s, and no rule passes any of it", f.node(m.ID), prefix(m.Subnets[0])))
		}
	}
	for _, t := range n.Policy.Tables {
		if !usedTables[t.Name] {
			out = append(out, fmt.Sprintf("table <%s> is used by no rule", t.Name))
		}
	}
	for _, s := range n.Policy.Services {
		if !usedServices[s.Name] {
			out = append(out, fmt.Sprintf("service %s is used by no rule", s.Name))
		}
	}
	seen := map[string]bool{}
	return slices.DeleteFunc(out, func(w string) bool {
		dup := seen[w]
		seen[w] = true
		return dup
	})
}
