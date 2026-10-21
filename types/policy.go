package types

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
)

// A Policy is what each member may open on which, for [KindSetPolicy]. A
// network without one lets every member open anything on every other.
// Tables, rules and tests keep the order they were written in; every set
// within them is sorted and duplicate-free.
type Policy struct {
	Tables   []PolicyTable   `cbor:"1,keyasint,omitempty"`
	Services []PolicyService `cbor:"2,keyasint,omitempty"`
	Rules    []PolicyRule    `cbor:"3,keyasint,omitempty"`
	Tests    []PolicyTest    `cbor:"4,keyasint,omitempty"`
}

// A PolicyTable names its members and the members of its tables.
type PolicyTable struct {
	Name   string     `cbor:"1,keyasint"`
	Nodes  []Identity `cbor:"2,keyasint,omitempty"`
	Tables []string   `cbor:"3,keyasint,omitempty"`
}

// A PolicyService names ports.
type PolicyService struct {
	Name  string      `cbor:"1,keyasint"`
	Ports []PortRange `cbor:"2,keyasint"`
}

// A PortRange is a protocol and, for TCP and UDP, the ports First to Last;
// both zero is every port. A rule or service names protocols; only a test's
// zero value stands for every protocol.
type PortRange struct {
	Proto uint8  `cbor:"1,keyasint,omitempty"`
	First uint16 `cbor:"2,keyasint,omitempty"`
	Last  uint16 `cbor:"3,keyasint,omitempty"`
}

// The protocols a [PortRange] names; ProtoICMP is ICMP and ICMPv6 alike.
const (
	ProtoAny  uint8 = 0
	ProtoICMP uint8 = 1
	ProtoTCP  uint8 = 6
	ProtoUDP  uint8 = 17
)

// A PolicyRule lets From open connections on To, by Ports and Services, or
// anything where it names neither.
type PolicyRule struct {
	From     PolicyRefs  `cbor:"1,keyasint"`
	To       PolicyRefs  `cbor:"2,keyasint"`
	Ports    []PortRange `cbor:"3,keyasint,omitempty"`
	Services []string    `cbor:"4,keyasint,omitempty"`
}

// PolicyRefs name members: every one, by identity, or by table. As a
// destination they also name the internet through exit nodes, Via's or
// every one where Via names none, and prefixes behind subnet routers.
type PolicyRefs struct {
	Any       bool           `cbor:"1,keyasint,omitempty"`
	Nodes     []Identity     `cbor:"2,keyasint,omitempty"`
	Tables    []string       `cbor:"3,keyasint,omitempty"`
	Internet  bool           `cbor:"4,keyasint,omitempty"`
	ViaNodes  []Identity     `cbor:"5,keyasint,omitempty"`
	ViaTables []string       `cbor:"6,keyasint,omitempty"`
	Prefixes  []netip.Prefix `cbor:"7,keyasint,omitempty"`
	// Names are names published for members alone, by label under the
	// network's domain, "" for the domain itself: a destination alone.
	Names []string `cbor:"8,keyasint,omitempty"`
}

// A PolicyTest is a connection the policy must pass, or not where Block:
// from one member to one member, the internet through one exit node, or one
// address, by one port, or by anything where Port is zero.
type PolicyTest struct {
	Block bool       `cbor:"1,keyasint,omitempty"`
	From  Identity   `cbor:"2,keyasint"`
	To    PolicyRefs `cbor:"3,keyasint"`
	Port  PortRange  `cbor:"4,keyasint"`
}

// Limits on a policy, far above what a network of MaxNodes needs.
const (
	MaxPolicyNames   = 256 // tables, and services
	MaxPolicyRules   = 1024
	MaxPolicyTests   = 256
	MaxPolicyPorts   = 64 // in a rule or a service
	MaxPolicyNameLen = 32
)

// Validate checks a policy's shape: names well-formed and defined once,
// every name it uses defined, no table in itself, sets sorted, and each
// rule and test meaningful. Whether its members exist, and so whether their
// keys are valid, is [Policy.ValidateMembers]'s.
func (p *Policy) Validate() error {
	if len(p.Tables) > MaxPolicyNames || len(p.Services) > MaxPolicyNames {
		return fmt.Errorf("a policy with %d tables and %d services, over the %d limit",
			len(p.Tables), len(p.Services), MaxPolicyNames)
	}
	if len(p.Rules) > MaxPolicyRules || len(p.Tests) > MaxPolicyTests {
		return fmt.Errorf("a policy with %d rules and %d tests, over the %d and %d limits",
			len(p.Rules), len(p.Tests), MaxPolicyRules, MaxPolicyTests)
	}
	tables := map[string][]string{}
	for _, t := range p.Tables {
		if err := ValidatePolicyName(t.Name); err != nil {
			return fmt.Errorf("table: %w", err)
		}
		if _, dup := tables[t.Name]; dup {
			return fmt.Errorf("table <%s> is defined twice", t.Name)
		}
		if err := validateIdentitySet(t.Nodes); err != nil {
			return fmt.Errorf("table <%s>: %w", t.Name, err)
		}
		if !isSortedSet(t.Tables) {
			return fmt.Errorf("table <%s>: tables are not sorted and unique", t.Name)
		}
		tables[t.Name] = t.Tables
	}
	for name, inner := range tables {
		for _, t := range inner {
			if _, ok := tables[t]; !ok {
				return fmt.Errorf("table <%s> names <%s>, which is not defined", name, t)
			}
		}
	}
	if name := cyclic(tables); name != "" {
		return fmt.Errorf("table <%s> contains itself", name)
	}
	services := map[string]bool{}
	for _, s := range p.Services {
		if err := ValidatePolicyName(s.Name); err != nil {
			return fmt.Errorf("service: %w", err)
		}
		if services[s.Name] {
			return fmt.Errorf("service %s is defined twice", s.Name)
		}
		if len(s.Ports) == 0 {
			return fmt.Errorf("service %s names no ports", s.Name)
		}
		if err := validatePorts(s.Ports); err != nil {
			return fmt.Errorf("service %s: %w", s.Name, err)
		}
		services[s.Name] = true
	}
	for i := range p.Rules {
		if err := p.Rules[i].validate(tables, services); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	for i := range p.Tests {
		if err := p.Tests[i].validate(); err != nil {
			return fmt.Errorf("test %d: %w", i+1, err)
		}
	}
	return nil
}

// cyclic is a table that contains itself, or "": a depth-first walk that
// visits each table once.
func cyclic(tables map[string][]string) string {
	const visiting, done = 1, 2
	state := map[string]int{}
	var walk func(string) string
	walk = func(name string) string {
		switch state[name] {
		case visiting:
			return name
		case done:
			return ""
		}
		state[name] = visiting
		for _, t := range tables[name] {
			if c := walk(t); c != "" {
				return c
			}
		}
		state[name] = done
		return ""
	}
	for _, name := range slices.Sorted(maps.Keys(tables)) {
		if c := walk(name); c != "" {
			return c
		}
	}
	return ""
}

func (r *PolicyRule) validate(tables map[string][]string, services map[string]bool) error {
	if err := r.From.validate(tables, false); err != nil {
		return fmt.Errorf("from: %w", err)
	}
	if err := r.To.validate(tables, true); err != nil {
		return fmt.Errorf("to: %w", err)
	}
	if len(r.To.Names) > 0 && (len(r.Ports) > 0 || len(r.Services) > 0) {
		return errors.New("a name is opened on its own port: a rule to names names no port")
	}
	if len(r.Ports) > MaxPolicyPorts {
		return fmt.Errorf("%d ports, over the %d limit", len(r.Ports), MaxPolicyPorts)
	}
	if err := validatePorts(r.Ports); err != nil {
		return err
	}
	if !isSortedSet(r.Services) {
		return errors.New("services are not sorted and unique")
	}
	for _, s := range r.Services {
		if !services[s] {
			return fmt.Errorf("service %s is not defined", s)
		}
	}
	return nil
}

func (r *PolicyRefs) validate(tables map[string][]string, dst bool) error {
	if !dst && (r.Internet || len(r.Prefixes) > 0 || len(r.Names) > 0) {
		return errors.New("the internet, prefixes and names are destinations alone")
	}
	if len(r.Names) > 0 && (r.Any || len(r.Nodes) > 0 || len(r.Tables) > 0 || r.Internet || len(r.Prefixes) > 0) {
		return errors.New("names go with no other destination")
	}
	if len(r.Names) > MaxPolicyRules {
		return fmt.Errorf("%d names, over the %d limit", len(r.Names), MaxPolicyRules)
	}
	if !isSortedSet(r.Names) {
		return errors.New("names are not sorted and unique")
	}
	for _, n := range r.Names {
		if n != "" {
			if err := ValidateLabel(n); err != nil {
				return fmt.Errorf("name %q: %w", n, err)
			}
		}
	}
	if !r.Internet && (len(r.ViaNodes) > 0 || len(r.ViaTables) > 0) {
		return errors.New("exit nodes named for no internet")
	}
	if r.Empty() {
		return errors.New("names nothing")
	}
	for _, set := range [][]Identity{r.Nodes, r.ViaNodes} {
		if err := validateIdentitySet(set); err != nil {
			return err
		}
	}
	for _, set := range [][]string{r.Tables, r.ViaTables} {
		if !isSortedSet(set) {
			return errors.New("tables are not sorted and unique")
		}
		for _, t := range set {
			if _, ok := tables[t]; !ok {
				return fmt.Errorf("table <%s> is not defined", t)
			}
		}
	}
	if len(r.Prefixes) > MaxRoutesPerNode {
		return fmt.Errorf("%d prefixes, over the %d limit", len(r.Prefixes), MaxRoutesPerNode)
	}
	for i, pfx := range r.Prefixes {
		if !pfx.IsValid() || pfx != pfx.Masked() || pfx.Addr().Zone() != "" {
			return fmt.Errorf("prefix %v is not a network address", pfx)
		}
		if i > 0 && ComparePrefix(r.Prefixes[i-1], pfx) >= 0 {
			return fmt.Errorf("prefixes are not sorted and unique at %v", pfx)
		}
	}
	return nil
}

// Empty reports whether p holds nothing: in a record, the policy withdrawn;
// in a state, which removals can leave, a policy passing nothing.
func (p *Policy) Empty() bool {
	return len(p.Tables)+len(p.Services)+len(p.Rules)+len(p.Tests) == 0
}

// Empty reports whether r names nothing.
func (r *PolicyRefs) Empty() bool {
	return !r.Any && len(r.Nodes) == 0 && len(r.Tables) == 0 && !r.Internet && len(r.Prefixes) == 0 && len(r.Names) == 0
}

// NamesNames reports whether a rule or a test of p names a published name.
func (p *Policy) NamesNames() bool {
	return slices.ContainsFunc(p.Rules, func(r PolicyRule) bool { return len(r.To.Names) > 0 }) ||
		slices.ContainsFunc(p.Tests, func(t PolicyTest) bool { return len(t.To.Names) > 0 })
}

func (t *PolicyTest) validate() error {
	to := t.To
	switch {
	case to.Any || len(to.Tables) > 0 || len(to.ViaTables) > 0:
		return errors.New("tests name one destination, not a set")
	case len(to.Names) > 0:
		if len(to.Names) > 1 || len(to.Nodes) > 0 || to.Internet || len(to.ViaNodes) > 0 || len(to.Prefixes) > 0 {
			return errors.New("tests name one member, one exit node, one address, or one name")
		}
		if t.Port != (PortRange{}) {
			return errors.New("a test to a name names no port")
		}
		if to.Names[0] != "" {
			if err := ValidateLabel(to.Names[0]); err != nil {
				return fmt.Errorf("name %q: %w", to.Names[0], err)
			}
		}
	case len(to.Nodes) == 1 && !to.Internet && len(to.Prefixes) == 0:
	case to.Internet && len(to.ViaNodes) == 1 && len(to.Nodes) == 0 && len(to.Prefixes) == 0:
	case len(to.Prefixes) == 1 && to.Prefixes[0].IsSingleIP() && len(to.Nodes) == 0 && !to.Internet:
	default:
		return errors.New("tests name one member, one exit node, one address, or one name")
	}
	if t.Port.First != t.Port.Last {
		return errors.New("tests name one port")
	}
	if t.Port == (PortRange{}) {
		return nil
	}
	return validatePorts([]PortRange{t.Port})
}

func validatePorts(ports []PortRange) error {
	for i, p := range ports {
		switch p.Proto {
		case ProtoICMP:
			if p.First != 0 || p.Last != 0 {
				return errors.New("ports for a protocol that has none")
			}
		case ProtoTCP, ProtoUDP:
			if p.First > p.Last || p.First == 0 && p.Last != 0 {
				return fmt.Errorf("ports %d to %d", p.First, p.Last)
			}
		default:
			return fmt.Errorf("protocol %d", p.Proto)
		}
		if i > 0 && ComparePorts(ports[i-1], p) >= 0 {
			return errors.New("ports are not sorted and unique")
		}
	}
	return nil
}

// ComparePorts orders port ranges by protocol, then first and last port.
func ComparePorts(a, b PortRange) int {
	if a.Proto != b.Proto {
		return int(a.Proto) - int(b.Proto)
	}
	if a.First != b.First {
		return int(a.First) - int(b.First)
	}
	return int(a.Last) - int(b.Last)
}

// ValidatePolicyName checks the name of a table or service.
func ValidatePolicyName(s string) error {
	if s == "" || len(s) > MaxPolicyNameLen {
		return fmt.Errorf("name %q is empty or over %d bytes", s, MaxPolicyNameLen)
	}
	for i := range len(s) {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' && i > 0) {
			return fmt.Errorf("name %q is not lowercase letters, digits and inner hyphens", s)
		}
	}
	if strings.HasSuffix(s, "-") {
		return fmt.Errorf("name %q ends in a hyphen", s)
	}
	return nil
}

func validateIdentitySet(ids []Identity) error {
	if len(ids) > MaxNodes {
		return fmt.Errorf("%d members, over the %d limit", len(ids), MaxNodes)
	}
	for i := range ids {
		if i > 0 && ids[i-1].Compare(ids[i]) >= 0 {
			return errors.New("members are not sorted and unique")
		}
	}
	return nil
}

func isSortedSet(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] >= s[i] {
			return false
		}
	}
	return true
}

// Nodes calls f with every member the policy names, once per mention.
func (p *Policy) Nodes(f func(Identity)) {
	refs := func(r *PolicyRefs) {
		for _, set := range [][]Identity{r.Nodes, r.ViaNodes} {
			for _, id := range set {
				f(id)
			}
		}
	}
	for i := range p.Tables {
		for _, id := range p.Tables[i].Nodes {
			f(id)
		}
	}
	for i := range p.Rules {
		refs(&p.Rules[i].From)
		refs(&p.Rules[i].To)
	}
	for i := range p.Tests {
		f(p.Tests[i].From)
		refs(&p.Tests[i].To)
	}
}

// Rekeyed is p with every reference to from naming to instead, or gone where
// to is nil. A rule left naming no source or destination goes, and so does a
// test naming a member gone.
func (p *Policy) Rekeyed(from Identity, to *Identity) *Policy {
	out := p.Clone()
	swap := func(ids []Identity) []Identity {
		i := slices.Index(ids, from)
		if i < 0 {
			return ids
		}
		ids = slices.Delete(ids, i, i+1)
		if to != nil && !slices.Contains(ids, *to) {
			ids = append(ids, *to)
			slices.SortFunc(ids, Identity.Compare)
		}
		if len(ids) == 0 {
			return nil
		}
		return ids
	}
	refs := func(r *PolicyRefs) {
		hadVia := len(r.ViaNodes)+len(r.ViaTables) > 0
		r.Nodes, r.ViaNodes = swap(r.Nodes), swap(r.ViaNodes)
		if hadVia && len(r.ViaNodes)+len(r.ViaTables) == 0 {
			// Through no exit node left, which is not through every one.
			r.Internet = false
		}
	}
	for i := range out.Tables {
		out.Tables[i].Nodes = swap(out.Tables[i].Nodes)
	}
	var rules []PolicyRule
	for _, r := range out.Rules {
		refs(&r.From)
		refs(&r.To)
		if !r.From.Empty() && !r.To.Empty() {
			rules = append(rules, r)
		}
	}
	out.Rules = rules
	var tests []PolicyTest
	for _, t := range out.Tests {
		named := t.From == from || slices.Contains(t.To.Nodes, from) || slices.Contains(t.To.ViaNodes, from)
		if named && to == nil {
			continue
		}
		if t.From == from {
			t.From = *to
		}
		t.To.Nodes, t.To.ViaNodes = swap(t.To.Nodes), swap(t.To.ViaNodes)
		tests = append(tests, t)
	}
	out.Tests = tests
	return out
}

// Clone returns a deep copy.
func (p *Policy) Clone() *Policy {
	refs := func(r PolicyRefs) PolicyRefs {
		r.Nodes, r.Tables = slices.Clone(r.Nodes), slices.Clone(r.Tables)
		r.ViaNodes, r.ViaTables = slices.Clone(r.ViaNodes), slices.Clone(r.ViaTables)
		r.Prefixes, r.Names = slices.Clone(r.Prefixes), slices.Clone(r.Names)
		return r
	}
	out := &Policy{
		Tables:   slices.Clone(p.Tables),
		Services: slices.Clone(p.Services),
		Rules:    slices.Clone(p.Rules),
		Tests:    slices.Clone(p.Tests),
	}
	for i := range out.Tables {
		out.Tables[i].Nodes = slices.Clone(out.Tables[i].Nodes)
		out.Tables[i].Tables = slices.Clone(out.Tables[i].Tables)
	}
	for i := range out.Services {
		out.Services[i].Ports = slices.Clone(out.Services[i].Ports)
	}
	for i := range out.Rules {
		r := &out.Rules[i]
		r.From, r.To = refs(r.From), refs(r.To)
		r.Ports, r.Services = slices.Clone(r.Ports), slices.Clone(r.Services)
	}
	for i := range out.Tests {
		out.Tests[i].To = refs(out.Tests[i].To)
	}
	return out
}

// ValidateMembers checks that every member the policy names is one of nodes,
// which are sorted by identity.
func (p *Policy) ValidateMembers(nodes []NodeRecord) error {
	var err error
	p.Nodes(func(id Identity) {
		_, found := slices.BinarySearchFunc(nodes, id, func(n NodeRecord, id Identity) int { return n.Identity.Compare(id) })
		if !found && err == nil {
			err = fmt.Errorf("the policy names %v, which is no member", id.ShortString())
		}
	})
	return err
}

// Encode returns the policy's canonical CBOR encoding.
func (p *Policy) Encode() []byte { return mustEncode(p) }
