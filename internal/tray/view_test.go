package tray

import (
	"bytes"
	"image/png"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

var (
	self = types.Identity{1}
	fb   = types.Identity{2}
	srv  = types.Identity{3}
	pho  = types.Identity{4}
)

// operated is a connected laptop's status as its operator reads it: fb
// serves as an exit node, srv is granted the role but does not serve.
func operated() *ipc.Status {
	return &ipc.Status{
		Self:  self,
		Addrs: []netip.Prefix{netip.MustParsePrefix("100.70.0.1/32"), netip.MustParsePrefix("fd00::1/128")},
		Derived: ipc.Derived{
			NetworkName: "home", SelfName: "laptop", Members: 4, Peers: 3,
			Devices: []ipc.Device{
				{Identity: self, Name: "laptop", V4: "100.70.0.1"},
				{Identity: srv, Name: "srv", V4: "100.70.0.3", Roles: []types.Role{types.RoleExit}},
				{Identity: fb, Name: "fb", V4: "100.70.0.2", Roles: []types.Role{types.RoleExit}},
				{Identity: pho, Name: "phone", V4: "100.70.0.4"},
			},
			Exit: &ipc.Exit{Offering: []types.Identity{fb}},
		},
		Tunnels: ipc.Tunnels{
			TunnelsChecked: true, TunnelsLive: 2, TunnelsDown: []string{"phone"}, ReachChecked: 1,
			Reach: []ipc.PeerReach{
				{Identity: fb, Live: true, Direct: true},
				{Identity: srv, Live: true, Relay: "fb"},
				{Identity: pho, Absent: true},
			},
		},
		InNetwork: true, CanOperate: true,
	}
}

func find(items []item, prefix string) (item, bool) {
	for _, it := range items {
		if strings.HasPrefix(it.label, prefix) {
			return it, true
		}
	}
	return item{}, false
}

func labels(items []item) []string {
	var out []string
	for _, it := range items {
		if !it.sep {
			out = append(out, it.label)
		}
	}
	return out
}

func TestOperatorGetsTheMenuWhole(t *testing.T) {
	v := render([]network{{st: operated()}})
	if v.icon != (icon{base: baseOn}) || v.title != "juist: connected" {
		t.Fatalf("icon %+v, title %q", v.icon, v.title)
	}
	for _, want := range []item{
		{label: "This device: laptop", act: action{kind: actCopy, arg: "laptop"}},
		{label: "100.70.0.1", act: action{kind: actCopy, arg: "100.70.0.1"}},
		{label: "fd00::1", act: action{kind: actCopy, arg: "fd00::1"}},
	} {
		if got, _ := find(v.menu, want.label); !equalItem(got, want) {
			t.Errorf("menu has %+v, want %+v", got, want)
		}
	}
	devs, _ := find(v.menu, "Devices: ")
	if devs.label != "Devices: 3 others, 1 without a tunnel" {
		t.Errorf("devices item %q", devs.label)
	}
	if got, want := labels(devs.sub), []string{"fb — direct", "phone — offline", "srv — relayed by fb"}; !slices.Equal(got, want) {
		t.Errorf("devices %q, want %q", got, want)
	}
	if devs.sub[0].act != (action{kind: actCopy, arg: "100.70.0.2"}) {
		t.Errorf("clicking fb does %+v", devs.sub[0].act)
	}
	exit, _ := find(v.menu, "Exit node")
	if exit.label != "Exit node: none" {
		t.Errorf("exit item %q", exit.label)
	}
	want := []item{
		{label: "None", checkbox: true, checked: true, act: action{kind: actExitOff}},
		{label: "fb", checkbox: true, act: action{kind: actExitUse, arg: "fb"}},
		{label: "srv (not serving)", checkbox: true},
	}
	if len(exit.sub) != len(want) {
		t.Fatalf("exit choices %+v", exit.sub)
	}
	for k := range want {
		if !equalItem(exit.sub[k], want[k]) {
			t.Errorf("exit choice %d is %+v, want %+v", k, exit.sub[k], want[k])
		}
	}
	if exit.sub[2].enabled() {
		t.Error("an exit node that does not serve can be chosen")
	}
	if _, ok := find(v.menu, "Read-only"); ok {
		t.Error("the operator is told the menu is read-only")
	}
	if last := v.menu[len(v.menu)-1]; last.act.kind != actQuit {
		t.Errorf("last item %+v, not Quit", last)
	}
}

func equalItem(a, b item) bool {
	return a.label == b.label && a.checkbox == b.checkbox && a.checked == b.checked && a.act == b.act && len(a.sub) == len(b.sub)
}

func TestExitInUseShowsInIconTitleAndChoice(t *testing.T) {
	st := operated()
	st.Exit.Node, st.Exit.Name = fb, "fb"
	v := render([]network{{n: 2, st: st}})
	if v.icon.base != baseExit || v.title != "juist: connected, exit node fb" {
		t.Fatalf("icon %+v, title %q", v.icon, v.title)
	}
	exit, _ := find(v.menu, "Exit node")
	if exit.label != "Exit node: fb" || exit.sub[0].checked || !exit.sub[1].checked {
		t.Errorf("exit item %+v", exit)
	}
	if exit.sub[0].act != (action{kind: actExitOff, n: 2}) || exit.sub[1].act != (action{kind: actExitUse, n: 2, arg: "fb"}) {
		t.Errorf("choices act for another instance: %+v", exit.sub)
	}

	st.Exit.Failed = "no route"
	if v := render([]network{{st: st}}); v.icon != (icon{base: baseOn, badge: badgeAlarm}) {
		t.Errorf("a failing exit node shows %+v", v.icon)
	}
}

// A reader's status has neither devices nor reach by name; its menu has the
// state and no switches.
func TestReaderGetsNoMembersAndNoSwitches(t *testing.T) {
	st := operated()
	st.Exit.Node, st.Exit.Name = fb, "fb"
	st.Operator = "anna"
	r := st.ForReader()
	r.CanOperate = false
	v := render([]network{{st: &r}})
	devs, _ := find(v.menu, "Devices: ")
	exit, _ := find(v.menu, "Exit node")
	if len(devs.sub) > 0 || devs.enabled() || len(exit.sub) > 0 || exit.enabled() {
		t.Errorf("a reader gets devices %+v and exit %+v", devs, exit)
	}
	if exit.label != "Exit node: member 1" || v.icon.base != baseExit {
		t.Errorf("a reader sees %q and %+v", exit.label, v.icon)
	}
	if ro, ok := find(v.menu, "Read-only: "); !ok || ro.label != "Read-only: anna manages this device" {
		t.Errorf("read-only line %q", ro.label)
	}
	var walk func([]item)
	walk = func(items []item) {
		for _, it := range items {
			if k := it.act.kind; k == actExitUse || k == actExitOff {
				t.Errorf("a reader can click %q", it.label)
			}
			walk(it.sub)
		}
	}
	walk(v.menu)
}

// Where no other device serves, the exit node item says what this device
// does, and a choice no device backs any longer can still be given up.
func TestExitNodeWithoutOthers(t *testing.T) {
	st := operated()
	st.Devices = st.Devices[:1]
	st.Devices[0].Roles = []types.Role{types.RoleExit}
	st.Exit = &ipc.Exit{Consent: true, Serving: true}
	exit, _ := find(render([]network{{st: st}}).menu, "Exit node")
	if exit.label != "Exit node: this device serves" || len(exit.sub) > 0 {
		t.Errorf("serving alone: %+v", exit)
	}
	st.Exit = &ipc.Exit{Node: fb, Name: "fb", Failed: "no route"}
	exit, _ = find(render([]network{{st: st}}).menu, "Exit node")
	if exit.label != "Exit node: fb, failing" || len(exit.sub) != 1 || exit.sub[0].act.kind != actExitOff || exit.sub[0].checked {
		t.Errorf("a failing choice no device backs: %+v", exit)
	}
	st.Exit = &ipc.Exit{}
	exit, _ = find(render([]network{{st: st}}).menu, "Exit node")
	if exit.label != "Exit node: none in the network" || len(exit.sub) > 0 {
		t.Errorf("none: %+v", exit)
	}
}

func TestNotRunningIsOff(t *testing.T) {
	v := render([]network{{n: 0}})
	if v.icon != (icon{}) || v.title != "juist: juistd not running" || v.tooltip != "juistd not running" {
		t.Errorf("icon %+v, title %q, tooltip %q", v.icon, v.title, v.tooltip)
	}
	if got := labels(v.menu); !slices.Equal(got, []string{"juistd not running", "Quit"}) {
		t.Errorf("menu %q", got)
	}
}

func TestSeveralNetworksGetASubmenuEach(t *testing.T) {
	work := operated()
	work.NetworkName = "work"
	v := render([]network{{n: 0, st: operated(), warnings: []string{"a"}, checked: true}, {n: 1, st: work}, {n: 2}})
	if got, want := labels(v.menu), []string{"home · connected", "work · connected", "juist2 · juistd not running", "Quit"}; !slices.Equal(got, want) {
		t.Fatalf("menu %q, want %q", got, want)
	}
	exit, _ := find(v.menu[1].sub, "Exit node")
	if exit.sub[1].act != (action{kind: actExitUse, n: 1, arg: "fb"}) {
		t.Errorf("work's exit choice does %+v", exit.sub[1].act)
	}
	if v.icon != (icon{base: baseOn, badge: badgeWarning}) || v.title != "juist: home connected; work connected; juist2 juistd not running, 1 warning" {
		t.Errorf("icon %+v, title %q", v.icon, v.title)
	}
	warn, _ := find(v.menu[0].sub, "1 warning")
	if len(warn.sub) != 1 || warn.sub[0].label != "a" {
		t.Errorf("warnings %+v", warn)
	}
}

func TestOutOfNetworkInstancesAreLeftOut(t *testing.T) {
	alone := &ipc.Status{SelfName: "laptop"}
	if got := labels(render([]network{{n: 0, st: alone}, {n: 1, st: operated()}}).menu); slices.Contains(got, "laptop · no network") {
		t.Errorf("menu %q has the instance in no network", got)
	}
	if got := labels(render([]network{{n: 0, st: alone}}).menu); !slices.Equal(got, []string{"laptop · no network", "Quit"}) {
		t.Errorf("menu %q", got)
	}
}

func TestNews(t *testing.T) {
	st := operated()
	first := network{st: st, checked: true, warnings: []string{"old"}}
	if a, w := news(network{st: st}, first); len(a)+len(w) > 0 {
		t.Errorf("a first check is news: %q %q", a, w)
	}
	later := network{st: st, checked: true, warnings: []string{"old", "new"}}
	if a, w := news(first, later); len(a) > 0 || !slices.Equal(w, []string{"new"}) {
		t.Errorf("news %q %q", a, w)
	}
	al := *st
	al.Alarm = "fork"
	if a, _ := news(network{}, network{st: &al}); !slices.Equal(a, []string{"fork"}) {
		t.Errorf("a raised alarm is %q", a)
	}
	if a, _ := news(network{st: &al}, network{st: &al}); len(a) > 0 {
		t.Errorf("an alarm still raised is news: %q", a)
	}
	// Another alarm beside one that stands is news too.
	both := al
	both.Exit = &ipc.Exit{Node: fb, Name: "fb", Failed: "no route"}
	if a, _ := news(network{st: &al}, network{st: &both}); !slices.Equal(a, []string{"internet traffic may leave directly: no route"}) {
		t.Errorf("an alarm beside another is %q", a)
	}
}

// A network without a tunnel is no connection the icon shows, nor an exit
// node it routes through, as juist status says.
func TestNoTunnelIsNotConnected(t *testing.T) {
	down := operated()
	down.Exit.Node, down.Exit.Name = fb, "fb"
	down.TunnelsLive = 0
	if v := render([]network{{st: down}}); v.icon.base != baseOff || v.title != "juist: no tunnel up" {
		t.Errorf("no tunnel up: %+v, %q", v.icon, v.title)
	}
	waiting := operated()
	waiting.Peers = 0
	if v := render([]network{{st: waiting}}); v.icon.base != baseOff || v.title != "juist: waiting for peers" {
		t.Errorf("waiting for peers: %+v, %q", v.icon, v.title)
	}
	limited := operated()
	limited.Stale = true
	if v := render([]network{{st: limited}}); v.icon.base != baseOn {
		t.Errorf("limited: %+v", v.icon)
	}
}

func TestIconsDiffer(t *testing.T) {
	seen := map[string]icon{}
	for _, b := range []base{baseOff, baseOn, baseExit} {
		for _, d := range []badge{badgeNone, badgeWarning, badgeAlarm} {
			ic := icon{b, d}
			raw := iconPNG(ic)
			if _, err := png.Decode(bytes.NewReader(raw)); err != nil {
				t.Fatal(err)
			}
			if other, dup := seen[string(raw)]; dup {
				t.Errorf("%+v draws as %+v", ic, other)
			}
			seen[string(raw)] = ic
		}
	}
}

func TestOutputParsing(t *testing.T) {
	health := "warning: DNS goes around fb\nhint: x\n\nwarning: firewalld blocks udp/41641, which the router maps to this device\n"
	if got := warningsIn(health); !slices.Equal(got, []string{"DNS goes around fb", "firewalld blocks udp/41641, which the router maps to this device"}) {
		t.Errorf("warnings %q", got)
	}
	status := "home · connected\nThis device  laptop  100.70.0.1\nDevices      2 others\n\nhint: y\n"
	if got := firstBlock(status); !slices.Equal(got, []string{"home · connected", "This device laptop 100.70.0.1", "Devices 2 others"}) {
		t.Errorf("summary %q", got)
	}
}
