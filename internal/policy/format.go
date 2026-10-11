package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/nning/juist/types"
)

// A Namer gives a member's name, or "" for a member without one.
type Namer func(types.Identity) string

// Format writes p in its canonical form, naming members by name: tables,
// services, rules and tests, each in the order written, a blank line between
// them, and every list sorted.
func Format(p *types.Policy, name Namer) string {
	f := formatter{name: name}
	var sections [][]string
	var lines []string
	for _, t := range p.Tables {
		members := strings.Join(f.members(t.Nodes, t.Tables), ", ")
		if members == "" {
			lines = append(lines, fmt.Sprintf("table <%s> { }", t.Name))
			continue
		}
		lines = append(lines, fmt.Sprintf("table <%s> { %s }", t.Name, members))
	}
	sections = append(sections, lines)
	lines = nil
	for _, s := range p.Services {
		lines = append(lines, fmt.Sprintf("service %s = %s", s.Name, protoPorts(s.Ports)))
	}
	sections = append(sections, lines)
	lines = nil
	for _, r := range p.Rules {
		line := "pass from " + f.list(f.refs(r.From)) + " to " + f.list(f.refs(r.To))
		if len(r.Ports) > 0 {
			line += " " + protoPorts(r.Ports)
		}
		if len(r.Services) > 0 {
			line += " service " + list(r.Services)
		}
		lines = append(lines, line)
	}
	sections = append(sections, lines)
	lines = nil
	for _, t := range p.Tests {
		verb := "pass"
		if t.Block {
			verb = "block"
		}
		line := fmt.Sprintf("test %s from %s to %s", verb, f.node(t.From), f.list(f.refs(t.To)))
		if t.Port != (types.PortRange{}) {
			line += " " + protoPorts([]types.PortRange{t.Port})
		}
		lines = append(lines, line)
	}
	sections = append(sections, lines)

	var b strings.Builder
	for _, s := range sections {
		if len(s) == 0 {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		for _, l := range s {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

type formatter struct{ name Namer }

// node is a member as the text names it: bare where its name reads as one
// word, quoted where not, and by key where it has none.
func (f formatter) node(id types.Identity) string {
	n := f.name(id)
	switch {
	case n == "":
		return id.String()
	case bare(n):
		return n
	}
	return strconv.Quote(n)
}

// Words is args, each a word of the policy's text, as one line: an argument
// no word reads as, as a device named with a space, in double quotes.
func Words(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = a
		if strings.ContainsFunc(a, func(r rune) bool {
			return r >= 0x80 || r < 0x80 && !isWordByte(byte(r)) && !strings.ContainsRune("{},<>", r)
		}) {
			out[i] = strconv.Quote(a)
		}
	}
	return strings.Join(out, " ")
}

func bare(n string) bool {
	if slices.Contains(keywords, n) || strings.HasPrefix(n, "nid:") {
		return false
	}
	for i := range len(n) {
		if c := n[i]; !isWordByte(c) || c == '.' || c == ':' || c == '/' {
			return false
		}
	}
	return true
}

// members is tables, then devices, each sorted by name, regardless of case;
// devices without one last, by key.
func (f formatter) members(nodes []types.Identity, tables []string) []string {
	var out []string
	for _, t := range slices.Sorted(slices.Values(tables)) {
		out = append(out, "<"+t+">")
	}
	key := func(id types.Identity) string {
		if n := f.name(id); n != "" {
			return strings.ToLower(n) + "\x00" + n
		}
		return "\xff" + id.String()
	}
	sorted := slices.SortedFunc(slices.Values(nodes), func(a, b types.Identity) int {
		return strings.Compare(key(a), key(b))
	})
	for _, id := range sorted {
		out = append(out, f.node(id))
	}
	return out
}

func (f formatter) refs(r types.PolicyRefs) []string {
	var out []string
	if r.Any {
		out = append(out, "any")
	}
	out = append(out, f.members(r.Nodes, r.Tables)...)
	if r.Internet {
		s := "internet"
		if via := f.members(r.ViaNodes, r.ViaTables); len(via) > 0 {
			s += " via " + f.list(via)
		}
		out = append(out, s)
	}
	for _, p := range r.Prefixes {
		out = append(out, prefix(p))
	}
	for _, l := range r.Names {
		out = append(out, nameRef(l))
	}
	return out
}

// nameRef is a published name as the policy's text names it.
func nameRef(label string) string {
	if label == "" {
		return "name @"
	}
	return "name " + label
}

func (f formatter) list(items []string) string { return list(items) }

func list(items []string) string {
	if len(items) == 1 {
		return items[0]
	}
	return "{ " + strings.Join(items, ", ") + " }"
}

func prefix(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// protoPorts is one "proto … [port …]" clause per set of ports the protocols
// share, ICMP's first.
func protoPorts(ports []types.PortRange) string {
	type clause struct {
		protos []string
		ports  []string
	}
	var clauses []clause
	byProto := map[uint8][]string{}
	every := map[uint8]bool{}
	var order []uint8
	for _, p := range ports {
		if _, ok := byProto[p.Proto]; !ok {
			order = append(order, p.Proto)
			byProto[p.Proto] = nil
		}
		if p.First == 0 {
			every[p.Proto] = true
		}
	}
	for _, p := range ports {
		if !every[p.Proto] {
			s := strconv.Itoa(int(p.First))
			if p.Last != p.First {
				s += ":" + strconv.Itoa(int(p.Last))
			}
			byProto[p.Proto] = append(byProto[p.Proto], s)
		}
	}
	for _, proto := range order {
		name := map[uint8]string{types.ProtoICMP: "icmp", types.ProtoTCP: "tcp", types.ProtoUDP: "udp"}[proto]
		i := slices.IndexFunc(clauses, func(c clause) bool { return slices.Equal(c.ports, byProto[proto]) })
		if i < 0 {
			clauses = append(clauses, clause{ports: byProto[proto]})
			i = len(clauses) - 1
		}
		clauses[i].protos = append(clauses[i].protos, name)
	}
	var out []string
	for _, c := range clauses {
		s := "proto " + list(c.protos)
		if len(c.ports) > 0 {
			s += " port " + list(c.ports)
		}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}
