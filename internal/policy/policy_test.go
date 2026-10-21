package policy

import (
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/types"
)

// lab is a network of named members with the roles the tests need.
type lab struct {
	ids     map[string]types.Identity
	names   map[types.Identity]string
	members []Member
}

func newLab(members ...Member) *lab {
	l := &lab{ids: map[string]types.Identity{}, names: map[types.Identity]string{}}
	for i, m := range members {
		id := types.Identity{byte(i + 1)}
		l.ids[string(m.ID[:])[:strings.IndexByte(string(m.ID[:]), 0)]] = id
		m.ID = id
		l.members = append(l.members, m)
	}
	for name, id := range l.ids {
		l.names[id] = name
	}
	return l
}

// member is a Member named name, to be numbered by newLab.
func member(name string, m Member) Member {
	copy(m.ID[:], name)
	return m
}

func (l *lab) resolve(name string) (types.Identity, error) {
	if id, ok := l.ids[name]; ok {
		return id, nil
	}
	return types.Identity{}, errNoDevice(name)
}

type errNoDevice string

func (e errNoDevice) Error() string { return "no device " + string(e) }

func (l *lab) name(id types.Identity) string { return l.names[id] }

func (l *lab) network(t *testing.T, src string) *Network {
	t.Helper()
	p, err := Parse(src, l.resolve)
	if err != nil {
		t.Fatalf("parsing:\n%s\n%v", src, err)
	}
	return &Network{Policy: p, Members: l.members}
}

func office() *lab {
	return newLab(
		member("anna", Member{}),
		member("ben", Member{}),
		member("nas", Member{Subnets: []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")}}),
		member("edge01", Member{Exit: true, Carrier: true}),
		member("svc", Member{Service: true}),
		member("vps", Member{Exit: true}),
		member("door", Member{Ingress: true}),
	)
}

const canonical = `table <admins> { anna }
table <staff> { <admins>, ben }

service web = proto tcp port { 80, 443 }

pass from <staff> to nas proto tcp port 445
pass from <admins> to { any, internet via edge01, 192.168.10.0/24 }
pass from ben to { svc, internet } proto icmp proto { tcp, udp } port 53 service web
pass from svc to anna

test pass from ben to nas proto tcp port 445
test block from ben to anna
test pass from anna to internet via edge01
test pass from anna to 192.168.10.7 proto tcp port 22
`

// The canonical text reads back to the record it was read into.
func TestTheCanonicalTextRoundTrips(t *testing.T) {
	l := office()
	p, err := Parse(canonical, l.resolve)
	if err != nil {
		t.Fatal(err)
	}
	if got := Format(p, l.name); got != canonical {
		t.Fatalf("formatted:\n%s\nwant:\n%s", got, canonical)
	}
	again, err := Parse(Format(p, l.name), l.resolve)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again, p) {
		t.Fatalf("read back: %+v\nwant %+v", again, p)
	}
}

// Any text of the same policy formats to the canonical one: lists sorted,
// commas or spaces, lines continued in braces, blank lines and sections in
// their order.
func TestTheTextFormatsCanonically(t *testing.T) {
	l := office()
	messy := `
pass from svc to anna
test pass from ben to nas proto tcp port 445
service web = proto tcp port { 443 80 }
pass from {
  <staff>
} to nas proto tcp port 445
table <staff> { ben <admins> }


table <admins> { anna }
pass from <admins> to { 192.168.10.0/24, internet via edge01 any }
pass from ben to { internet svc } proto { udp tcp } port 53 proto icmp service web
test block from ben to anna
test pass from anna to internet via edge01
test pass from anna to 192.168.10.7 proto tcp port 22
`
	p, err := Parse(messy, l.resolve)
	if err != nil {
		t.Fatal(err)
	}
	want := `table <staff> { <admins>, ben }
table <admins> { anna }

service web = proto tcp port { 80, 443 }

pass from svc to anna
pass from <staff> to nas proto tcp port 445
pass from <admins> to { any, internet via edge01, 192.168.10.0/24 }
pass from ben to { svc, internet } proto icmp proto { tcp, udp } port 53 service web

test pass from ben to nas proto tcp port 445
test block from ben to anna
test pass from anna to internet via edge01
test pass from anna to 192.168.10.7 proto tcp port 22
`
	if got := Format(p, l.name); got != want {
		t.Fatalf("formatted:\n%s\nwant:\n%s", got, want)
	}
}

// Detached names read a policy without the log, and give each name back as
// written, a key as a key.
func TestADetachedPolicyKeepsItsNames(t *testing.T) {
	resolve, name := Detached()
	key := types.Identity{7}.String()
	src := "table <x> { \"Anna's laptop\", Laptop, laptop, " + key + " }\n"
	p, err := Parse(src, resolve)
	if err != nil {
		t.Fatal(err)
	}
	want := "table <x> { \"Anna's laptop\", Laptop, laptop, " + key + " }\n"
	if got := Format(p, name); got != want {
		t.Fatalf("formatted %q, want %q", got, want)
	}
}

// A mistake is said by its line, in words an admin can act on.
func TestParseSaysWhatIsWrong(t *testing.T) {
	l := office()
	for _, c := range []struct{ src, want string }{
		{"# staff\n", "line 1: a policy has no comments"},
		{"pass from ben to nobody\n", "line 1: no device nobody"},
		{"\npass from ben to nas port 22\n", "line 2: a port needs proto tcp or udp before it"},
		{"pass from ben to nas proto icmp port 22\n", "icmp has no ports"},
		{"pass from ben to nas proto tcp port 0\n", "ports run 1 to 65535"},
		{"pass from ben to nas proto tcp port 70000\n", "ports run 1 to 65535"},
		{"pass from ben to nas proto tcp port 80-90\n", "a port or a range like 8000:8080"},
		{"pass from ben to nas service web proto tcp port 22\nservice web = proto tcp port 80\n", "line 1: proto and port go before service"},
		{"pass from ben to nas proto tcp, udp\n", "a list goes in braces, as { tcp, udp }"},
		{"\ntest pass from ben to internet\n", "line 2: a test of the internet names its exit node: internet via DEVICE"},
		{"test pass from ben to any\n", "a test names one device, not a set"},
		{"test pass from ben to 192.168.10.0/24\n", "a test names one address, not a network"},
		{"table <a> { ben }\n\ntable <a> { nas }\n", "line 3: table <a> is defined on line 1 already"},
		{"\ntable <Staff> { ben }\n", "line 2: name \"Staff\""},
		{"table <a> { <b> }\ntable <b> { <a> }\n", "line 1: table <a> contains itself"},
		{"pass from ben to nas\n\npass from <nobody> to nas\n", "line 3: no table <nobody>"},
		{"pass from ben to nas service web\n", "line 1: no service web"},
		{"table <a> { <nobody> }\n", "line 1: no table <nobody>"},
		{"pass from ben to nas proto tcp port 90:80\n", "a port or a range like 8000:8080"},
		{"pass from internet to nas\n", "\"internet\" where a device belongs"},
		{"pass from { ben, ben } to nas\n", "a device named twice"},
		{"pass from { any, ben } to nas\n", "any names every device already"},
		{"pass from ben to 10.0.0.1/8\n", "has host bits set; the network is 10.0.0.0/8"},
		{"pass from ben to nas.local\n", "a device named so goes in double quotes"},
		{"pass from ben to nas\npass\n", "line 2: end of line where \"from\" belongs"},
		{"pass from ben to { nas\n", "a list without its closing }"},
		{"pass from ben to nas extra\n", "\"extra\" after the end of a line"},
		{"block from ben to nas\n", "a line starts with table, service, pass or test"},
		{"service web = port 80\n", "a port needs proto"},
		{"pass from <nobody> to nas\n", "no table <nobody>"},
		{"test pass from <staff> to nas\n", "where one device belongs"},
		{"test pass from ben to nas proto tcp port 80:81\n", "a test names one protocol and one port"},
		{"pass from ben to nas µ\n", "unexpected 'µ'; a name of other characters goes in double quotes"},
		{"pass from ben to nas \\ \n", "a \\ goes on to the next line where it ends one alone"},
		{"test pass from ben to nas service web\n", "a test names proto and port, not a service"},
	} {
		_, err := Parse(c.src, l.resolve)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.src, err, c.want)
		}
	}
}

// A rule lets its sources open what it names on its destinations, not the
// reverse; a service member opens nothing; the internet passes through
// exit nodes alone, via those named; a prefix through the router of it.
func TestWhatARuleLets(t *testing.T) {
	l := office()
	n := l.network(t, canonical)
	ben, anna := n.View(l.ids["ben"]), n.View(l.ids["anna"])
	if got := ben.Out[l.ids["nas"]].Own; !reflect.DeepEqual(got, []types.PortRange{{Proto: types.ProtoTCP, First: 445, Last: 445}}) {
		t.Errorf("ben may open %v on nas", got)
	}
	if _, ok := ben.Out[l.ids["anna"]]; ok {
		t.Error("ben may open something on anna")
	}
	if got := anna.In[l.ids["ben"]]; !got.Empty() {
		t.Errorf("anna takes %+v from ben", got)
	}
	if got := anna.Out[l.ids["ben"]].Own; !reflect.DeepEqual(got, Everything) {
		t.Errorf("anna, an admin, may open %v on ben", got)
	}
	if _, ok := anna.In[l.ids["svc"]]; ok {
		t.Error("a service member's rule lets it open something")
	}
	if got := anna.Out[l.ids["edge01"]].Exit; !reflect.DeepEqual(got, Everything) {
		t.Errorf("anna may use edge01 for %v", got)
	}
	if got := anna.Out[l.ids["vps"]].Exit; got != nil {
		t.Errorf("anna may use vps, which the rule does not name, for %v", got)
	}
	if got := anna.Out[l.ids["nas"]].Routes; len(got) != 1 || got[0].Prefix != netip.MustParsePrefix("192.168.10.0/24") {
		t.Errorf("anna may reach %+v through nas", got)
	}
	web := ben.Out[l.ids["vps"]].Exit
	for _, c := range []struct {
		proto uint8
		port  uint16
		want  bool
	}{{types.ProtoTCP, 443, true}, {types.ProtoUDP, 53, true}, {types.ProtoICMP, 0, true}, {types.ProtoTCP, 22, false}, {types.ProtoUDP, 443, false}} {
		if got := Allows(web, c.proto, c.port); got != c.want {
			t.Errorf("ben through vps, protocol %d port %d: %v", c.proto, c.port, got)
		}
	}
	if got := ben.Out[l.ids["anna"]]; !got.Empty() {
		t.Errorf("ben may open %+v on anna", got)
	}
}

// Members a rule joins either way are peers; a carrier peers every member,
// for juist's own traffic where no rule joins them; two members no rule
// joins are no peers, unless the network has no carrier.
func TestWhoArePeers(t *testing.T) {
	l := office()
	n := l.network(t, "pass from ben to nas\n")
	ben, anna, edge01 := n.View(l.ids["ben"]), n.View(l.ids["anna"]), n.View(l.ids["edge01"])
	if !ben.Peers[l.ids["nas"]] || ben.Control[l.ids["nas"]] {
		t.Error("ben is not a full peer of nas")
	}
	if !n.View(l.ids["nas"]).Peers[l.ids["ben"]] {
		t.Error("nas, which ben may open, does not peer ben")
	}
	if ben.Peers[l.ids["anna"]] || anna.Peers[l.ids["ben"]] {
		t.Error("two members no rule joins are peers")
	}
	if !anna.Peers[l.ids["edge01"]] || !anna.Control[l.ids["edge01"]] {
		t.Error("anna does not peer the carrier edge01 for juist's own traffic")
	}
	if len(edge01.Peers) != len(l.members)-1 {
		t.Errorf("the carrier edge01 peers %d members of %d", len(edge01.Peers), len(l.members)-1)
	}
	none := l.network(t, "pass from ben to nas\n")
	for i := range none.Members {
		none.Members[i].Carrier = false
	}
	if v := none.View(l.ids["anna"]); !v.Peers[l.ids["ben"]] || !v.Control[l.ids["ben"]] {
		t.Error("without a carrier, two members no rule joins do not keep a tunnel for the log")
	}
	open := &Network{Members: l.members}
	if v := open.View(l.ids["anna"]); v.Restricted || len(v.Peers) != len(l.members)-1 {
		t.Errorf("without a policy anna is restricted %v with %d peers", v.Restricted, len(v.Peers))
	}
}

// An ingress peers the members it passes connections to, whatever the
// policy says.
func TestAnIngressPeersItsPublishers(t *testing.T) {
	l := newLab(member("ingress", Member{Ingress: true}), member("blog", Member{Publishes: true}),
		member("laptop", Member{}), member("relay", Member{Carrier: true}))
	n := l.network(t, "pass from laptop to blog proto tcp port 22\n")
	v := n.View(l.ids["ingress"])
	if !v.Peers[l.ids["blog"]] || v.Control[l.ids["blog"]] || v.Peers[l.ids["laptop"]] {
		t.Errorf("the ingress peers %v", v.Peers)
	}
}

// Tests pass or fail as the rules say, and a failure is its line.
func TestTestsAreChecked(t *testing.T) {
	l := office()
	n := l.network(t, canonical)
	if f := n.Failures(l.name); len(f) != 0 {
		t.Fatalf("the canonical policy fails %+v", f)
	}
	n = l.network(t, "pass from ben to nas proto tcp port 22\n"+
		"test pass from ben to nas proto tcp port 22\n"+
		"test pass from ben to nas proto tcp port 445\n"+
		"test block from ben to nas\n"+
		"test pass from ben to 192.168.10.1\n"+
		"test block from anna to internet via edge01\n")
	want := []string{"test pass from ben to nas proto tcp port 445",
		"test block from ben to nas: pass from ben to nas proto tcp port 22 passes it",
		"test pass from ben to 192.168.10.1"}
	var got []string
	for _, f := range n.Failures(l.name) {
		got = append(got, f.Text)
	}
	if !slices.Equal(got, want) {
		t.Errorf("failures %q, want %q", got, want)
	}
}

// Warnings name a service member as a source, an exit node that is none, a
// prefix no router routes, and what no rule uses.
func TestWarnings(t *testing.T) {
	l := office()
	n := l.network(t, "table <idle> { ben }\nservice ssh = proto tcp port 22\n"+
		"pass from { door, svc } to { internet via ben, 10.9.0.0/16 }\n")
	want := []string{"svc is a service member, which opens nothing",
		"door is an ingress, which opens what is published alone", "ben is no exit node: juist grant ben exit",
		"no subnet router routes 10.9.0.0/16", "table <idle> is used by no rule", "service ssh is used by no rule"}
	got := n.Warnings(l.name)
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("warnings %q lack %q", got, w)
		}
	}
}

// Warnings name a device in no rule, an exit node and a subnet router no
// rule passes anything through, and a device's own address in a rule.
func TestWarningsOfWhatIsUnused(t *testing.T) {
	l := office()
	for i := range l.members {
		if l.names[l.members[i].ID] == "nas" {
			l.members[i].Addrs = []netip.Addr{netip.MustParseAddr("198.19.0.3")}
		}
	}
	got := l.network(t, "pass from anna to { nas, 198.19.0.3 }\n").Warnings(l.name)
	for _, w := range []string{"ben is in no rule: it opens nothing, and nothing opens it",
		"edge01 is an exit node, and no rule passes the internet through it",
		"nas routes 192.168.10.0/24, and no rule passes any of it",
		"198.19.0.3 is nas's address: name the device"} {
		if !slices.Contains(got, w) {
			t.Errorf("warnings %q lack %q", got, w)
		}
	}
	for _, w := range got {
		if strings.HasPrefix(w, "anna ") || strings.HasPrefix(w, "nas is in no rule") || strings.HasPrefix(w, "door ") {
			t.Errorf("warned %q", w)
		}
	}
}

func TestNormalize(t *testing.T) {
	tcp := func(a, b uint16) types.PortRange { return types.PortRange{Proto: types.ProtoTCP, First: a, Last: b} }
	for _, c := range []struct{ in, want []types.PortRange }{
		{nil, nil},
		{[]types.PortRange{tcp(80, 80), tcp(81, 90), tcp(100, 100)}, []types.PortRange{tcp(80, 90), tcp(100, 100)}},
		{[]types.PortRange{tcp(80, 80), {Proto: types.ProtoTCP}}, []types.PortRange{{Proto: types.ProtoTCP}}},
		{[]types.PortRange{tcp(80, 80), {}}, Everything},
		{[]types.PortRange{tcp(80, 100), tcp(90, 95)}, []types.PortRange{tcp(80, 100)}},
	} {
		if got := normalize(slices.Clone(c.in)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("normalize(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

// FuzzParse: whatever parses formats to text that parses to the same
// policy, and formats the same again.
func FuzzParse(f *testing.F) {
	f.Add(canonical)
	f.Add("pass from \"a b\" to { 10.0.0.0/8, fd00::/8 } proto udp port 1:65535\n")
	f.Fuzz(func(t *testing.T, src string) {
		resolve, name := Detached()
		p, err := Parse(src, resolve)
		if err != nil {
			return
		}
		text := Format(p, name)
		again, err := Parse(text, resolve)
		if err != nil {
			t.Fatalf("%q formats to %q, which does not parse: %v", src, text, err)
		}
		if !reflect.DeepEqual(again, p) {
			t.Fatalf("%q formats to %q, which reads as another policy", src, text)
		}
		if Format(again, name) != text {
			t.Fatalf("%q does not format stably", src)
		}
	})
}

func TestDiff(t *testing.T) {
	got := Diff("table <a> { x }\npass from x to y\n", "table <a> { x }\npass from x to z\ntest pass from x to z\n")
	want := []string{"  table <a> { x }", "- pass from x to y", "+ pass from x to z", "+ test pass from x to z"}
	if !slices.Equal(got, want) {
		t.Errorf("diff %q, want %q", got, want)
	}
	if got := Diff("table <a> { x }\n\npass from x to y\n", "pass from x to y\n"); !slices.Equal(got,
		[]string{"- table <a> { x }", "-", "  pass from x to y"}) {
		t.Errorf("diff of a blank line %q", got)
	}
	if got := Diff("", "pass from x to y\n"); !slices.Equal(got, []string{"+ pass from x to y"}) {
		t.Errorf("diff from nothing %q", got)
	}
}

// A table its members' removal left empty formats to text that reads back.
func TestAnEmptiedTableReadsBack(t *testing.T) {
	l := office()
	p, err := Parse("table <staff> { ben }\npass from <staff> to nas\n", l.resolve)
	if err != nil {
		t.Fatal(err)
	}
	emptied := p.Rekeyed(l.ids["ben"], nil)
	text := Format(emptied, l.name)
	again, err := Parse(text, l.resolve)
	if err != nil {
		t.Fatalf("%q does not read back: %v", text, err)
	}
	if Format(again, l.name) != text {
		t.Errorf("%q formats otherwise", text)
	}
}

func TestAnEmptyTableSpansLines(t *testing.T) {
	resolve, name := Detached()
	p, err := Parse("table <x> {\n}\n", resolve)
	if err != nil || Format(p, name) != "table <x> { }\n" {
		t.Fatalf("%v %q", err, Format(p, name))
	}
}

// A rule goes on past a line's end after a backslash, as in pf.
func TestALineGoesOnAfterABackslash(t *testing.T) {
	l := office()
	p, err := Parse("pass from ben \\\n  to nas\n", l.resolve)
	if err != nil || Format(p, l.name) != "pass from ben to nas\n" {
		t.Fatalf("%v %q", err, Format(p, l.name))
	}
}

// Tests are checked against the whole policy's view, not rule by rule: a
// policy at its limits is checked in a moment.
func TestTestsAreCheckedQuickly(t *testing.T) {
	var members []Member
	for i := range 100 {
		members = append(members, Member{ID: types.Identity{byte(i), byte(i >> 8), 1}})
	}
	p := &types.Policy{}
	for i := range types.MaxPolicyRules {
		p.Rules = append(p.Rules, types.PolicyRule{From: types.PolicyRefs{Nodes: []types.Identity{members[i%100].ID}},
			To: types.PolicyRefs{Nodes: []types.Identity{members[(i+1)%100].ID}}, Ports: []types.PortRange{{Proto: types.ProtoTCP, First: 22, Last: 22}}})
	}
	for i := range 64 {
		p.Tests = append(p.Tests, types.PolicyTest{Block: true, From: members[i].ID,
			To: types.PolicyRefs{Nodes: []types.Identity{members[(i+50)%100].ID}}})
	}
	n := &Network{Policy: p, Members: members}
	start := time.Now()
	if f := n.Failures(func(types.Identity) string { return "" }); len(f) != 0 {
		t.Fatalf("failures %+v", f)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("checking 64 tests against %d rules took %v", len(p.Rules), took)
	}
}

// Arguments become words of the text: a name that is no word goes in
// quotes, lists and tables as they are.
func TestWords(t *testing.T) {
	got := Words([]string{"from", "My Laptop", "to", "Küche", "port", "{", "22,", "80", "}", "<staff>", "nas.home"})
	want := `from "My Laptop" to "Küche" port { 22, 80 } <staff> nas.home`
	if got != want {
		t.Errorf("%q, want %q", got, want)
	}
}

// A device named like a keyword is named in quotes, refused bare, and
// formats back in quotes.
func TestADeviceNamedLikeAKeyword(t *testing.T) {
	l := newLab(member("test", Member{}), member("nas", Member{}))
	if _, err := Parse("pass from test to nas\n", l.resolve); err == nil ||
		!strings.Contains(err.Error(), `"test" is a word of the policy's; the device goes in double quotes: "test"`) {
		t.Errorf("a keyword as a device: %v", err)
	}
	p, err := Parse("pass from \"test\" to nas\n", l.resolve)
	if err != nil || Format(p, l.name) != "pass from \"test\" to nas\n" {
		t.Errorf("%v %q", err, Format(p, l.name))
	}
}

// A relay or a voucher alone is warned of as in no rule no more, and a
// warning two rules give is said once.
func TestWarningsOfCarriersAndRepeats(t *testing.T) {
	l := office()
	got := l.network(t, "pass from svc to nas\npass from ben to anna\npass from svc to anna\n").Warnings(l.name)
	if n := slices.Index(got, "svc is a service member, which opens nothing"); n < 0 || slices.Contains(got[n+1:], got[n]) {
		t.Errorf("warnings %q", got)
	}
	l.members = append(l.members, Member{ID: types.Identity{99}, Carrier: true})
	for _, w := range l.network(t, "pass from ben to anna\n").Warnings(l.name) {
		if strings.HasPrefix(w, "nid:") {
			t.Errorf("a relay alone is warned of: %q", w)
		}
	}
}

func TestCaseLines(t *testing.T) {
	src := "table <a> { b,\n test }\ntest pass from b to c\npass from b to c\n\ntest block from c to b\n"
	if got := CaseLines(src); !slices.Equal(got, []int{3, 6}) {
		t.Errorf("tests start on %v, want 3 and 6", got)
	}
}

func family() *lab {
	return newLab(
		member("anna", Member{}),
		member("ben", Member{}),
		member("carl", Member{}),
		member("nas", Member{Names: []Name{{Label: "photos", Port: 443, Members: true},
			{Label: "wiki", Port: 8443}, {Label: "blog", Port: 443}}}),
		member("site", Member{Names: []Name{{Label: "", Port: 443, Members: true}}}),
		member("ing", Member{Ingress: true}),
		member("svc", Member{Service: true}),
	)
}

// A rule to a name lets its sources open the name's device on its port,
// and the name alone there; the device knows whom by the name.
func TestARuleToANameLetsItsSourcesOpenIt(t *testing.T) {
	l := family()
	src := "table <family> { anna, ben }\n\npass from <family> to { name @, name photos }\npass from carl to name blog\n\n" +
		"test pass from anna to name photos\ntest block from carl to name photos\ntest pass from ben to name @\n" +
		"test pass from carl to name blog\n"
	n := l.network(t, src)
	if got := Format(n.Policy, l.name); got != src {
		t.Fatalf("formatted:\n%s\nwant:\n%s", got, src)
	}
	if f := n.Failures(l.name); len(f) != 0 {
		t.Fatalf("fails %+v", f)
	}
	anna := n.View(l.ids["anna"]).Out[l.ids["nas"]]
	if !slices.Equal(anna.Names, []string{"photos"}) || !Allows(anna.Own, types.ProtoTCP, 443) ||
		!Allows(anna.Own, types.ProtoUDP, 443) || Allows(anna.Own, types.ProtoTCP, 8443) {
		t.Errorf("anna may open %+v on nas", anna)
	}
	nas := n.View(l.ids["nas"]).In
	if !slices.Equal(nas[l.ids["ben"]].Names, []string{"photos"}) || len(nas[l.ids["carl"]].Names) != 1 {
		t.Errorf("nas takes %+v", nas)
	}
	// A rule opening the device's port is no rule to the name for members.
	n = l.network(t, "pass from carl to nas proto tcp port 443\ntest pass from carl to name blog\ntest block from carl to name photos\n")
	if f := n.Failures(l.name); len(f) != 0 {
		t.Fatalf("fails %+v", f)
	}
	ok, by := n.Explain(types.PolicyTest{From: l.ids["carl"], To: types.PolicyRefs{Names: []string{"photos"}}})
	if ok || by != nil {
		t.Errorf("carl to photos: passes %v by %v", ok, by)
	}
}

// A rule to a public name opens its port; a name for members alone passes
// to no ingress, service member or its own device, as the device takes it,
// with a policy or without.
func TestANameForMembersPassesWhomTheDeviceTakes(t *testing.T) {
	l := family()
	n := l.network(t, "pass from carl to name wiki\ntest pass from carl to name wiki\n")
	if f := n.Failures(l.name); len(f) != 0 {
		t.Fatalf("fails %+v", f)
	}
	if carl := n.View(l.ids["carl"]).Out[l.ids["nas"]]; !Allows(carl.Own, types.ProtoTCP, 8443) || Allows(carl.Own, types.ProtoTCP, 443) {
		t.Errorf("carl may open %+v on nas", carl)
	}
	n = l.network(t, "pass from any to name photos\n")
	none := l.network(t, "")
	none.Policy = nil
	for _, who := range []string{"ing", "svc", "nas"} {
		test := types.PolicyTest{From: l.ids[who], To: types.PolicyRefs{Names: []string{"photos"}}}
		for _, net := range []*Network{n, none} {
			if ok, _ := net.Explain(test); ok {
				t.Errorf("%s passes to photos, policy %v", who, net.Policy != nil)
			}
		}
		n.Policy.Tests = []types.PolicyTest{{From: l.ids[who], To: test.To}}
		if f := n.Failures(l.name); len(f) != 1 {
			t.Errorf("test pass from %s to name photos: %+v", who, f)
		}
	}
	if ok, _ := none.Explain(types.PolicyTest{From: l.ids["anna"], To: types.PolicyRefs{Names: []string{"photos"}}}); !ok {
		t.Error("without a policy, anna does not pass to photos")
	}
}

func TestNamesAreReadAsTheyMayBe(t *testing.T) {
	l := family()
	for _, c := range []struct{ src, want string }{
		{"pass from anna to name photos proto tcp port 443\n", "no port"},
		{"pass from anna to { nas, name photos }\n", "nothing else"},
		{"pass from anna to { name photos, name photos }\n", "named twice"},
		{"pass from name photos to anna\n", "where a device belongs"},
		{"pass from anna to name Photos.x\n", "no published name"},
		{"test pass from anna to name photos proto tcp port 443\n", "no port"},
	} {
		if _, err := Parse(c.src, l.resolve); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.src, err, c.want)
		}
	}
	n := l.network(t, "pass from anna to name gone\n")
	if w := n.Warnings(l.name); !slices.Contains(w, "name gone is published on no device by TLS") {
		t.Errorf("warnings %q", w)
	}
}
