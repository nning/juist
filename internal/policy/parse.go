// Package policy reads, writes and evaluates a network's access policy: the
// text an admin writes, the [types.Policy] the log holds, and what it lets
// each member open on each other.
package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/nning/juist/types"
)

// A Resolver names the member a policy's text calls name.
type Resolver func(name string) (types.Identity, error)

// Parse reads a policy, naming members by resolve. The policy it returns is
// valid in shape; whether its members exist is the log's to say.
func Parse(src string, resolve Resolver) (*types.Policy, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, resolve: resolve}
	pol, err := p.policy()
	if err != nil {
		return nil, err
	}
	if err := p.check(pol); err != nil {
		return nil, err
	}
	if err := pol.Validate(); err != nil {
		return nil, err
	}
	return pol, nil
}

type tokKind uint8

const (
	tWord  tokKind = iota // keyword, name, number, address or prefix
	tQuote                // a name in double quotes
	tTable                // <name>
	tOpen
	tClose
	tComma
	tEquals
	tNewline
	tEOF
)

type token struct {
	kind tokKind
	text string
	line int
}

func (t token) String() string {
	switch t.kind {
	case tTable:
		return "<" + t.text + ">"
	case tQuote:
		return strconv.Quote(t.text)
	case tNewline:
		return "end of line"
	case tEOF:
		return "end of policy"
	}
	return fmt.Sprintf("%q", t.text)
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '.' || c == '_' || c == ':' || c == '/' || c == '-' || c == '@'
}

func lex(src string) ([]token, error) {
	var toks []token
	line := 1
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '\n':
			toks = append(toks, token{tNewline, "", line})
			line++
			i++
		case c == '#':
			return nil, &Error{Line: line, Msg: "a policy has no comments: the log keeps its rules, not its text; say why in a commit message"}
		case c == '\\' && strings.HasPrefix(src[i+1:], "\n"), c == '\\' && strings.HasPrefix(src[i+1:], "\r\n"):
			// The line goes on, as in pf.
			i += 1 + strings.IndexByte(src[i:], '\n')
			line++
		case c == '{':
			toks = append(toks, token{tOpen, "{", line})
			i++
		case c == '}':
			toks = append(toks, token{tClose, "}", line})
			i++
		case c == ',':
			toks = append(toks, token{tComma, ",", line})
			i++
		case c == '=':
			toks = append(toks, token{tEquals, "=", line})
			i++
		case c == '<':
			end := strings.IndexByte(src[i:], '>')
			if end < 0 || strings.ContainsAny(src[i:i+end], "\n") {
				return nil, &Error{Line: line, Msg: "a table name without its closing >"}
			}
			toks = append(toks, token{tTable, src[i+1 : i+end], line})
			i += end + 1
		case c == '"':
			end := i + 1
			for end < len(src) && src[end] != '"' && src[end] != '\n' {
				if src[end] == '\\' {
					end++
				}
				end++
			}
			if end >= len(src) || src[end] != '"' {
				return nil, &Error{Line: line, Msg: "a quoted name without its closing quote"}
			}
			s, err := strconv.Unquote(src[i : end+1])
			if err != nil {
				return nil, &Error{Line: line, Msg: fmt.Sprintf("%s: %v", src[i:end+1], err)}
			}
			toks = append(toks, token{tQuote, s, line})
			i = end + 1
		case isWordByte(c):
			end := i
			for end < len(src) && isWordByte(src[end]) {
				end++
			}
			toks = append(toks, token{tWord, src[i:end], line})
			i = end
		default:
			r, _ := utf8.DecodeRuneInString(src[i:])
			if c == '\\' {
				return nil, &Error{Line: line, Msg: "a \\ goes on to the next line where it ends one alone"}
			}
			return nil, &Error{Line: line, Msg: fmt.Sprintf("unexpected %q; a name of other characters goes in double quotes", r)}
		}
	}
	return append(toks, token{tEOF, "", line}), nil
}

// CaseLines are the lines src's tests start on, in order; nil where src does
// not read.
func CaseLines(src string) []int {
	toks, err := lex(src)
	if err != nil {
		return nil
	}
	var lines []int
	start, depth := true, 0
	for _, t := range toks {
		switch {
		case t.kind == tOpen:
			depth++
		case t.kind == tClose:
			depth--
		case t.kind == tWord && t.text == "test" && start:
			lines = append(lines, t.line)
		}
		start = t.kind == tNewline && depth == 0
	}
	return lines
}

// keywords may not stand for a device unquoted.
var keywords = []string{"any", "block", "from", "icmp", "internet", "name", "pass", "port", "proto",
	"service", "table", "tcp", "test", "to", "udp", "via"}

type parser struct {
	toks    []token
	pos     int
	depth   int // braces open, inside which lines continue
	resolve Resolver

	// The line each table, service, rule and test starts on.
	tableLines, serviceLines, ruleLines []int
}

func (p *parser) peek() token {
	for p.depth > 0 && p.toks[p.pos].kind == tNewline {
		p.pos++
	}
	return p.toks[p.pos]
}

func (p *parser) next() token {
	t := p.peek()
	if t.kind != tEOF {
		p.pos++
	}
	return t
}

func (p *parser) errorf(t token, format string, args ...any) error {
	return &Error{Line: t.line, Msg: fmt.Sprintf(format, args...)}
}

// An Error is a mistake in a policy's text, on Line.
type Error struct {
	Line int
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Msg) }

func (p *parser) keyword(word string) bool {
	if t := p.peek(); t.kind == tWord && t.text == word {
		p.pos++
		return true
	}
	return false
}

func (p *parser) expect(word string) error {
	if t := p.peek(); !p.keyword(word) {
		return p.errorf(t, "%s where %q belongs", t, word)
	}
	return nil
}

func (p *parser) policy() (*types.Policy, error) {
	pol := &types.Policy{}
	for {
		t := p.next()
		switch {
		case t.kind == tEOF:
			return pol, nil
		case t.kind == tNewline:
			continue
		case t.kind == tWord && t.text == "table":
			tab, err := p.table()
			if err != nil {
				return nil, err
			}
			pol.Tables, p.tableLines = append(pol.Tables, tab), append(p.tableLines, t.line)
		case t.kind == tWord && t.text == "service":
			svc, err := p.service()
			if err != nil {
				return nil, err
			}
			pol.Services, p.serviceLines = append(pol.Services, svc), append(p.serviceLines, t.line)
		case t.kind == tWord && t.text == "pass":
			r, err := p.rule()
			if err != nil {
				return nil, err
			}
			pol.Rules, p.ruleLines = append(pol.Rules, r), append(p.ruleLines, t.line)
		case t.kind == tWord && t.text == "test":
			tst, err := p.test()
			if err != nil {
				return nil, err
			}
			pol.Tests = append(pol.Tests, tst)
		default:
			return nil, p.errorf(t, "%s where a line starts with table, service, pass or test", t)
		}
		if t := p.next(); t.kind != tNewline && t.kind != tEOF {
			switch {
			case t.kind == tComma:
				return nil, p.errorf(t, "a list goes in braces, as { tcp, udp }")
			case t.kind == tWord && (t.text == "proto" || t.text == "port"):
				return nil, p.errorf(t, "proto and port go before service")
			case t.kind == tWord && t.text == "service":
				return nil, p.errorf(t, "a test names proto and port, not a service")
			}
			return nil, p.errorf(t, "%s after the end of a line", t)
		}
	}
}

// list reads one item, or several in braces, separated by commas or space.
func (p *parser) list(item func() error) error { return p.items(item, false) }

// items is list, taking braces with nothing in them where empty.
func (p *parser) items(item func() error, empty bool) error {
	if p.peek().kind != tOpen {
		return item()
	}
	p.next()
	p.depth++
	first := true
	for {
		t := p.peek()
		if t.kind == tClose {
			if first && !empty {
				return p.errorf(t, "an empty list")
			}
			p.depth--
			p.next()
			return nil
		}
		if t.kind == tEOF {
			return p.errorf(t, "a list without its closing }")
		}
		if !first && t.kind == tComma {
			p.next()
		}
		if err := item(); err != nil {
			return err
		}
		first = false
	}
}

func (p *parser) table() (types.PolicyTable, error) {
	t := p.next()
	if t.kind != tTable {
		return types.PolicyTable{}, p.errorf(t, "%s where a table's <name> belongs", t)
	}
	tab := types.PolicyTable{Name: t.text}
	if p.peek().kind != tOpen {
		return tab, p.errorf(p.peek(), "a table's members go in braces")
	}
	var refs types.PolicyRefs
	// Empty where its members' removal left it so.
	err := p.items(func() error { return p.member(&refs.Nodes, &refs.Tables) }, true)
	if err != nil {
		return tab, err
	}
	tab.Nodes, tab.Tables = refs.Nodes, refs.Tables
	return tab, sortRefs(&refs, t)
}

func (p *parser) service() (types.PolicyService, error) {
	t := p.next()
	if t.kind != tWord || slices.Contains(keywords, t.text) {
		return types.PolicyService{}, p.errorf(t, "%s where a service's name belongs", t)
	}
	if e := p.next(); e.kind != tEquals {
		return types.PolicyService{}, p.errorf(e, "%s where = belongs", e)
	}
	ports, err := p.protoPorts(true)
	if err != nil {
		return types.PolicyService{}, err
	}
	return types.PolicyService{Name: t.text, Ports: ports}, nil
}

func (p *parser) rule() (types.PolicyRule, error) {
	var r types.PolicyRule
	at := p.peek()
	if err := p.expect("from"); err != nil {
		return r, err
	}
	if err := p.list(func() error { return p.ref(&r.From, false) }); err != nil {
		return r, err
	}
	if err := p.expect("to"); err != nil {
		return r, err
	}
	if err := p.list(func() error { return p.ref(&r.To, true) }); err != nil {
		return r, err
	}
	ports, err := p.protoPorts(false)
	if err != nil {
		return r, err
	}
	r.Ports = ports
	if p.keyword("service") {
		err := p.list(func() error {
			t := p.next()
			if t.kind != tWord || slices.Contains(keywords, t.text) {
				return p.errorf(t, "%s where a service's name belongs", t)
			}
			r.Services = append(r.Services, t.text)
			return nil
		})
		if err != nil {
			return r, err
		}
		slices.Sort(r.Services)
		if i := dupString(r.Services); i >= 0 {
			return r, p.errorf(at, "service %s named twice", r.Services[i])
		}
	}
	if err := sortRefs(&r.From, at); err != nil {
		return r, err
	}
	return r, sortRefs(&r.To, at)
}

func (p *parser) test() (types.PolicyTest, error) {
	var tst types.PolicyTest
	at := p.peek()
	switch {
	case p.keyword("pass"):
	case p.keyword("block"):
		tst.Block = true
	default:
		return tst, p.errorf(at, "%s where pass or block belongs", at)
	}
	if err := p.expect("from"); err != nil {
		return tst, err
	}
	var from types.PolicyRefs
	if err := p.member(&from.Nodes, nil); err != nil {
		return tst, err
	}
	tst.From = from.Nodes[0]
	if err := p.expect("to"); err != nil {
		return tst, err
	}
	to := p.peek()
	if err := p.ref(&tst.To, true); err != nil {
		return tst, err
	}
	switch r := tst.To; {
	case r.Any || len(r.Tables) > 0:
		return tst, p.errorf(to, "a test names one device, not a set")
	case r.Internet && len(r.ViaNodes)+len(r.ViaTables) == 0:
		return tst, p.errorf(to, "a test of the internet names its exit node: internet via DEVICE")
	case r.Internet && (len(r.ViaNodes) != 1 || len(r.ViaTables) > 0):
		return tst, p.errorf(to, "a test of the internet names one exit node")
	case len(r.Prefixes) == 1 && !r.Prefixes[0].IsSingleIP():
		return tst, p.errorf(to, "a test names one address, not a network")
	}
	ports, err := p.protoPorts(false)
	if err != nil {
		return tst, err
	}
	if len(tst.To.Names) == 1 && len(ports) > 0 {
		return tst, p.errorf(at, "a test to a name names no port: it is opened on its own")
	}
	switch {
	case len(ports) > 1 || len(ports) == 1 && ports[0].First != ports[0].Last:
		return tst, p.errorf(at, "a test names one protocol and one port")
	case len(ports) == 1:
		tst.Port = ports[0]
	}
	return tst, nil
}

// member reads a device, or a table where tables is not nil.
func (p *parser) member(nodes *[]types.Identity, tables *[]string) error {
	t := p.next()
	switch {
	case t.kind == tTable && tables != nil:
		*tables = append(*tables, t.text)
		return nil
	case t.kind == tTable:
		return p.errorf(t, "%s where one device belongs", t)
	case t.kind == tWord && slices.Contains(keywords, t.text):
		if _, err := p.resolve(t.text); err == nil {
			return p.errorf(t, "%s is a word of the policy's; the device goes in double quotes: %q", t, t.text)
		}
	case t.kind == tQuote, t.kind == tWord:
		id, err := p.resolve(t.text)
		if err != nil {
			return p.errorf(t, "%v", err)
		}
		*nodes = append(*nodes, id)
		return nil
	}
	return p.errorf(t, "%s where a device belongs", t)
}

// ref reads one source, or one destination where dst.
func (p *parser) ref(r *types.PolicyRefs, dst bool) error {
	t := p.peek()
	switch {
	case p.keyword("any"):
		if r.Any {
			return p.errorf(t, "any named twice")
		}
		r.Any = true
		return nil
	case dst && p.keyword("name"):
		n := p.next()
		if n.kind != tWord && n.kind != tQuote {
			return p.errorf(n, "%s where a published name belongs", n)
		}
		label := n.text
		if label == "@" {
			label = ""
		} else if err := types.ValidateLabel(label); err != nil {
			return p.errorf(n, "%s is no published name: one label under the domain, or @ for the domain itself", n)
		}
		r.Names = append(r.Names, label)
		return nil
	case dst && p.keyword("internet"):
		if r.Internet {
			return p.errorf(t, "the internet named twice")
		}
		r.Internet = true
		if p.keyword("via") {
			var via types.PolicyRefs
			if err := p.list(func() error { return p.member(&via.Nodes, &via.Tables) }); err != nil {
				return err
			}
			r.ViaNodes, r.ViaTables = via.Nodes, via.Tables
		}
		return nil
	case dst && t.kind == tWord && strings.ContainsAny(t.text, ".:") && !strings.HasPrefix(t.text, "nid:"):
		p.next()
		pfx, err := parsePrefix(t.text)
		if err != nil {
			return p.errorf(t, "%v", err)
		}
		r.Prefixes = append(r.Prefixes, pfx)
		return nil
	}
	return p.member(&r.Nodes, &r.Tables)
}

func parsePrefix(s string) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is no address or prefix; a device named so goes in double quotes", s)
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is no prefix", s)
	}
	if pfx != pfx.Masked() {
		return netip.Prefix{}, fmt.Errorf("%s has host bits set; the network is %s", s, pfx.Masked())
	}
	return pfx, nil
}

// protoPorts reads "proto P [port N]" clauses, at least one where required.
func (p *parser) protoPorts(required bool) ([]types.PortRange, error) {
	var out []types.PortRange
	for {
		t := p.peek()
		if !p.keyword("proto") {
			switch {
			case t.kind == tWord && t.text == "port":
				return nil, p.errorf(t, "a port needs proto tcp or udp before it")
			case required && len(out) == 0:
				return nil, p.errorf(t, "%s where proto belongs", t)
			}
			break
		}
		clause, err := p.protoClause()
		if err != nil {
			return nil, err
		}
		out = append(out, clause...)
	}
	return normalize(out), nil
}

func (p *parser) protoClause() ([]types.PortRange, error) {
	var protos []uint8
	err := p.list(func() error {
		t := p.next()
		proto, ok := map[string]uint8{"tcp": types.ProtoTCP, "udp": types.ProtoUDP, "icmp": types.ProtoICMP}[t.text]
		switch {
		case !ok || t.kind != tWord:
			return p.errorf(t, "%s where tcp, udp or icmp belongs", t)
		case slices.Contains(protos, proto):
			return p.errorf(t, "%s named twice", t.text)
		}
		protos = append(protos, proto)
		return nil
	})
	if err != nil {
		return nil, err
	}
	var ranges [][2]uint16
	if at := p.peek(); p.keyword("port") {
		if slices.Contains(protos, types.ProtoICMP) {
			return nil, p.errorf(at, "icmp has no ports")
		}
		err := p.list(func() error {
			t := p.next()
			r, err := parsePortRange(t.text)
			switch {
			case errors.Is(err, errPortRange):
				return p.errorf(t, "%s: ports run 1 to 65535", t)
			case err != nil || t.kind != tWord:
				return p.errorf(t, "%s where a port or a range like 8000:8080 belongs", t)
			}
			ranges = append(ranges, r)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	var out []types.PortRange
	for _, proto := range protos {
		if len(ranges) == 0 {
			out = append(out, types.PortRange{Proto: proto})
		}
		for _, r := range ranges {
			out = append(out, types.PortRange{Proto: proto, First: r[0], Last: r[1]})
		}
	}
	return out, nil
}

var errPortRange = errors.New("out of range")

func parsePortRange(s string) ([2]uint16, error) {
	first, last, isRange := strings.Cut(s, ":")
	a, err := strconv.ParseUint(first, 10, 32)
	if err != nil {
		return [2]uint16{}, errors.New("no port")
	}
	b := a
	if isRange {
		if b, err = strconv.ParseUint(last, 10, 32); err != nil || b < a {
			return [2]uint16{}, errors.New("no range")
		}
	}
	if a == 0 || b > 65535 {
		return [2]uint16{}, errPortRange
	}
	return [2]uint16{uint16(a), uint16(b)}, nil
}

// sortRefs sorts r's sets as the log keeps them, refusing a name given twice.
func sortRefs(r *types.PolicyRefs, at token) error {
	for _, ids := range [][]types.Identity{r.Nodes, r.ViaNodes} {
		slices.SortFunc(ids, types.Identity.Compare)
		for i := 1; i < len(ids); i++ {
			if ids[i] == ids[i-1] {
				return &Error{Line: at.line, Msg: "a device named twice"}
			}
		}
	}
	for _, names := range [][]string{r.Tables, r.ViaTables} {
		slices.Sort(names)
		if i := dupString(names); i >= 0 {
			return &Error{Line: at.line, Msg: fmt.Sprintf("<%s> named twice", names[i])}
		}
	}
	slices.Sort(r.Names)
	if i := dupString(r.Names); i >= 0 {
		return &Error{Line: at.line, Msg: fmt.Sprintf("%s named twice", nameRef(r.Names[i]))}
	}
	if len(r.Names) > 0 && (r.Any || len(r.Nodes)+len(r.Tables)+len(r.Prefixes) > 0 || r.Internet) {
		return &Error{Line: at.line, Msg: "a rule to names names nothing else"}
	}
	slices.SortFunc(r.Prefixes, types.ComparePrefix)
	for i := 1; i < len(r.Prefixes); i++ {
		if r.Prefixes[i] == r.Prefixes[i-1] {
			return &Error{Line: at.line, Msg: fmt.Sprintf("%s named twice", r.Prefixes[i])}
		}
	}
	if r.Any && len(r.Nodes)+len(r.Tables) > 0 {
		return &Error{Line: at.line, Msg: "any names every device already"}
	}
	return nil
}

// dupString is the index of the first of two equal neighbours in sorted s, or
// -1.
func dupString(s []string) int {
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1] {
			return i
		}
	}
	return -1
}

// check is what [types.Policy.Validate] refuses of names, said by the line:
// a name malformed or defined twice, one used and not defined, and a table
// inside itself.
func (p *parser) check(pol *types.Policy) error {
	tables, services := map[string]int{}, map[string]int{}
	for i, t := range pol.Tables {
		line := p.tableLines[i]
		if err := types.ValidatePolicyName(t.Name); err != nil {
			return &Error{Line: line, Msg: err.Error()}
		}
		if at, dup := tables[t.Name]; dup {
			return &Error{Line: line, Msg: fmt.Sprintf("table <%s> is defined on line %d already", t.Name, at)}
		}
		tables[t.Name] = line
	}
	for i, s := range pol.Services {
		line := p.serviceLines[i]
		if err := types.ValidatePolicyName(s.Name); err != nil {
			return &Error{Line: line, Msg: err.Error()}
		}
		if at, dup := services[s.Name]; dup {
			return &Error{Line: line, Msg: fmt.Sprintf("service %s is defined on line %d already", s.Name, at)}
		}
		services[s.Name] = line
	}
	used := func(line int, names []string) error {
		for _, n := range names {
			if _, ok := tables[n]; !ok {
				return &Error{Line: line, Msg: fmt.Sprintf("no table <%s>", n)}
			}
		}
		return nil
	}
	for i, t := range pol.Tables {
		if err := used(p.tableLines[i], t.Tables); err != nil {
			return err
		}
	}
	for i, r := range pol.Rules {
		for _, set := range [][]string{r.From.Tables, r.To.Tables, r.To.ViaTables} {
			if err := used(p.ruleLines[i], set); err != nil {
				return err
			}
		}
		for _, s := range r.Services {
			if _, ok := services[s]; !ok {
				return &Error{Line: p.ruleLines[i], Msg: fmt.Sprintf("no service %s", s)}
			}
		}
	}
	inner := map[string][]string{}
	for _, t := range pol.Tables {
		inner[t.Name] = t.Tables
	}
	for i, t := range pol.Tables {
		seen := map[string]bool{}
		var reaches func(string) bool
		reaches = func(name string) bool {
			for _, n := range inner[name] {
				if n == t.Name || !seen[n] && func() bool { seen[n] = true; return reaches(n) }() {
					return true
				}
			}
			return false
		}
		if reaches(t.Name) {
			return &Error{Line: p.tableLines[i], Msg: fmt.Sprintf("table <%s> contains itself", t.Name)}
		}
	}
	return nil
}
