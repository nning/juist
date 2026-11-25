package tray

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// A network is what the tray knows of one instance's juistd.
type network struct {
	n  int
	st *ipc.Status // nil where juistd does not answer

	// checked says juist health ran since juistd last answered, warnings
	// are its warnings, and summary the first lines of juist status.
	checked  bool
	warnings []string
	summary  []string
}

type base int

const (
	baseOff base = iota
	baseOn
	baseExit
)

type badge int

const (
	badgeNone badge = iota
	badgeWarning
	badgeAlarm
)

type icon struct {
	base  base
	badge badge
}

type actKind int

const (
	actNone actKind = iota
	actCopy
	actExitUse
	actExitOff
	actQuit
)

// An action is what a click on an item does; n is the instance it is for.
type action struct {
	kind actKind
	n    int
	arg  string
}

// An item is one line of the menu: a separator, a submenu where sub is set,
// or an entry that does act, greyed out where act is none.
type item struct {
	label    string
	sep      bool
	checkbox bool
	checked  bool
	act      action
	sub      []item
}

func (i item) enabled() bool { return i.act.kind != actNone || len(i.sub) > 0 }

// A view is everything the tray shows.
type view struct {
	icon    icon
	title   string
	tooltip string
	menu    []item
}

// maxLabel bounds a menu label, which a long warning would make wider than
// the screen.
const maxLabel = 72

func clip(s string) string {
	if r := []rune(s); len(r) > maxLabel {
		return string(r[:maxLabel-1]) + "…"
	}
	return s
}

// shown are the networks the menu has: those in a network or once seen in
// one; else the first, to say why there is none.
func shown(nets []network) []network {
	var out []network
	for _, nw := range nets {
		if nw.st == nil || nw.st.InNetwork {
			out = append(out, nw)
		}
	}
	if len(out) == 0 && len(nets) > 0 {
		out = nets[:1]
	}
	return out
}

func render(nets []network) view {
	nets = shown(nets)
	var v view
	var states, tips []string
	alarms, warnings := 0, 0
	for _, nw := range nets {
		ic := iconOf(nw)
		v.icon.base = max(v.icon.base, ic.base)
		v.icon.badge = max(v.icon.badge, ic.badge)
		if ic.badge == badgeAlarm {
			alarms++
		}
		warnings += len(nw.warnings)
		states = append(states, stateWord(nw, len(nets) > 1))
		tips = append(tips, tipOf(nw, len(nets) > 1)...)
	}
	v.title = "juist: " + strings.Join(states, "; ")
	switch {
	case warnings > 0:
		v.title += ", " + count(warnings, "warning")
	case alarms > 0:
		v.title += ", alarm"
	}
	v.tooltip = strings.Join(tips, "\n")
	if len(nets) == 1 {
		v.menu = networkMenu(nets[0], false)
	} else {
		for _, nw := range nets {
			v.menu = append(v.menu, item{label: clip(headOf(nw, true)), sub: networkMenu(nw, true)})
		}
	}
	v.menu = append(v.menu, item{sep: true}, item{label: "Quit", act: action{kind: actQuit}})
	return v
}

// usable says whether the network carries traffic: status's head says
// "connected", or "limited", which keeps tunnels to admin devices.
func usable(s *ipc.Status) bool {
	switch head(s) {
	case "connected", "limited":
		return true
	}
	return false
}

// exitInUse names the exit node the network's traffic leaves by, "" for none.
// A reader's status names it by pseudonym alone.
func exitInUse(s *ipc.Status) string {
	ex := s.Exit
	if ex == nil || ex.Node.IsZero() && ex.Name == "" || ex.Refused != "" || ex.Failed != "" {
		return ""
	}
	return cmp.Or(ex.Name, ex.Node.ShortString())
}

// alarmed says whether s holds what juist status prints in red.
func alarmed(s *ipc.Status) bool {
	return s.Alarm != "" || s.Disabled != "" || s.NotMember || s.SchemaAlarm != "" || s.Refused || s.Overtaken ||
		s.Exit != nil && s.Exit.Failed != ""
}

func iconOf(nw network) icon {
	s := nw.st
	var ic icon
	switch {
	case !usable(s):
	case exitInUse(s) != "":
		ic.base = baseExit
	default:
		ic.base = baseOn
	}
	switch {
	case s != nil && s.InNetwork && alarmed(s):
		ic.badge = badgeAlarm
	case len(nw.warnings) > 0:
		ic.badge = badgeWarning
	}
	return ic
}

// head is juist status's first word for s.
func head(s *ipc.Status) string {
	switch {
	case s == nil:
		return "juistd not running"
	case s.Joining:
		return "joining a network"
	case !s.InNetwork:
		return "no network"
	case s.Disabled != "":
		return "disabled"
	case s.HostConflict != nil && s.HostConflict.SameNetwork, s.StartError != "":
		return "not connected"
	case s.NotMember:
		return "removed"
	case s.Alarm != "":
		return "disconnected"
	case s.Refused:
		return "refused"
	case s.Overtaken:
		return "behind"
	case s.Stale:
		return "limited"
	case s.Members > 1 && s.Peers == 0:
		return "waiting for peers"
	case s.TunnelsChecked && s.Peers > 0 && s.TunnelsLive == 0:
		return "no tunnel up"
	}
	return "connected"
}

// networkName is the network's name, or where there is none the instance's,
// as juist names it on a host in several.
func networkName(nw network) string {
	if nw.st != nil && nw.st.InNetwork {
		return nw.st.NetworkName
	}
	return instance.Name(nw.n)
}

// headOf is juist status's first line for nw; several names the instance
// whose juistd does not answer.
func headOf(nw network, several bool) string {
	s := nw.st
	switch {
	case s == nil && several:
		return instance.Name(nw.n) + " · " + head(s)
	case s == nil:
		return head(s)
	case !s.InNetwork:
		return cmp.Or(s.SelfName, s.Self.ShortString()) + " · " + head(s)
	}
	return s.NetworkName + " · " + head(s)
}

func stateWord(nw network, several bool) string {
	w := head(nw.st)
	if nw.st != nil && usable(nw.st) {
		if e := exitInUse(nw.st); e != "" {
			w += ", exit node " + e
		}
	}
	if several {
		w = networkName(nw) + " " + w
	}
	return w
}

// tipOf is the tooltip's part for nw: juist status's first lines once it
// ran, the state till then.
func tipOf(nw network, several bool) []string {
	lines := nw.summary
	if nw.st == nil || len(lines) == 0 {
		lines = []string{headOf(nw, several)}
	}
	limit := 6
	if several {
		limit = 3
	}
	return lines[:min(len(lines), limit)]
}

func networkMenu(nw network, several bool) []item {
	s := nw.st
	if s == nil || !s.InNetwork {
		return []item{{label: headOf(nw, several)}}
	}
	var m []item
	if s.SelfName != "" {
		m = append(m, item{label: "This device: " + s.SelfName, act: action{kind: actCopy, arg: s.SelfName}})
	}
	for _, p := range s.Addrs {
		a := p.Addr().String()
		m = append(m, item{label: a, act: action{kind: actCopy, arg: a}})
	}
	m = append(m, item{sep: true}, devicesItem(s), exitItem(nw.n, s))
	if !usable(s) || head(s) != "connected" {
		m = append(m, item{label: "State: " + head(s)})
	}
	if len(nw.warnings) > 0 {
		var sub []item
		for _, w := range nw.warnings {
			sub = append(sub, item{label: clip(w)})
		}
		m = append(m, item{sep: true}, item{label: count(len(nw.warnings), "warning"), sub: sub})
	}
	if !s.CanOperate {
		m = append(m, item{sep: true}, item{label: "Read-only: " + operatorWord(s)})
	}
	return m
}

func operatorWord(s *ipc.Status) string {
	if s.Operator == "" {
		return "root manages this device"
	}
	return s.Operator + " manages this device"
}

// devicesItem is juist status's Devices line, and for an operator the
// devices themselves.
func devicesItem(s *ipc.Status) item {
	label := "no others"
	if others := s.Members - 1 - s.Expired; others > 0 {
		label = count(others, "other")
	}
	if without := s.Unreachable + len(s.TunnelsDown); without > 0 && s.TunnelsChecked {
		label += ", " + strconv.Itoa(without) + " without a tunnel"
	}
	it := item{label: "Devices: " + label}
	if !s.CanOperate {
		return it
	}
	reach := map[types.Identity]ipc.PeerReach{}
	for _, r := range s.Reach {
		reach[r.Identity] = r
	}
	for _, d := range byName(s.Devices) {
		if d.Identity == s.Self {
			continue
		}
		r, installed := reach[d.Identity]
		silent := slices.Contains(s.Silent, d.Name)
		if !installed && !silent && s.ReachChecked != 0 {
			// No tunnel is wanted: the access policy keeps it apart, or it
			// expired.
			continue
		}
		name := cmp.Or(d.Name, d.Identity.ShortString())
		label := name + " — " + reachWord(r, installed, silent, s.ReachChecked == 0)
		act := action{}
		if addr := cmp.Or(d.V4, d.V6); addr != "" {
			act = action{kind: actCopy, arg: addr}
		}
		it.sub = append(it.sub, item{label: clip(label), act: act})
	}
	return it
}

func reachWord(r ipc.PeerReach, installed, silent, unchecked bool) string {
	switch {
	case !installed && silent:
		return "not heard from"
	case !installed && unchecked:
		return "not checked yet"
	case !installed:
		return "not connected"
	case !r.Live && r.Absent:
		return "offline"
	case !r.Live:
		return "no answer"
	case r.Outdated:
		return "outdated"
	case r.Direct:
		return "direct"
	case r.Relay != "":
		return "relayed by " + r.Relay
	}
	return "relayed"
}

// exitItem is the exit node in use, and for an operator the choice.
func exitItem(n int, s *ipc.Status) item {
	ex := cmp.Or(s.Exit, &ipc.Exit{})
	chosen := !ex.Node.IsZero() || ex.Name != "" || ex.Refused != "" || ex.Failed != ""
	now := "none"
	switch {
	case ex.Failed != "":
		now = cmp.Or(ex.Name, "chosen") + ", failing"
	case ex.Refused != "" && ex.Node.IsZero() && ex.Name == "":
		now = "internet refused"
	case ex.Refused != "":
		now = cmp.Or(ex.Name, ex.Node.ShortString()) + ", refused"
	case chosen:
		now = cmp.Or(ex.Name, ex.Node.ShortString())
	case ex.Serving:
		now = "this device serves"
	}
	it := item{label: "Exit node: " + now}
	if !s.CanOperate {
		return it
	}
	var nodes []item
	for _, d := range byName(s.Devices) {
		if d.Identity == s.Self || !slices.Contains(d.Roles, types.RoleExit) {
			continue
		}
		name := cmp.Or(d.Name, d.Identity.ShortString())
		node := item{label: name, checkbox: true, checked: d.Identity == ex.Node}
		if slices.Contains(ex.Offering, d.Identity) {
			node.act = action{kind: actExitUse, n: n, arg: name}
		} else {
			node.label += " (not serving)"
		}
		nodes = append(nodes, node)
	}
	none := item{label: "None", checkbox: true, checked: !chosen, act: action{kind: actExitOff, n: n}}
	switch {
	case len(nodes) > 0:
		it.sub = append([]item{none}, nodes...)
	case chosen:
		// A choice no device granted the role backs: it can only be given up.
		it.sub = []item{none}
	case !ex.Serving:
		it.label = "Exit node: none in the network"
	}
	return it
}

func byName(devs []ipc.Device) []ipc.Device {
	out := slices.Clone(devs)
	slices.SortStableFunc(out, func(a, b ipc.Device) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
