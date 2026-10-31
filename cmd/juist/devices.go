package main

import (
	"cmp"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nning/juist/internal/policy"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

func cmdDevices(a *app, args []string) error {
	s := spec{name: "juist devices", about: `
List the network's devices and how juistd last reached each: directly,
through a relay, or not. outdated means the device runs an older juist and
stays unreachable until updated. SCHEMA is the newest schema each device's
juist implements, yellow if older than this one's. juistd checks every 30s.
On a device in several networks, it lists each network unless NETWORK names
one.`}
	fs := newFlags(s.name)
	long := fs.Bool("keys", false, "show identity keys")
	v6 := fs.Bool("ipv6", false, "show IPv6 addresses")
	all := fs.Bool("all", false, "list the devices the access policy keeps apart from this one too")
	if _, err := a.parse(s, fs, args); err != nil {
		return err
	}
	if listed, err := a.forEachNetwork(func() error { return a.listDevices(*long, *v6, *all) }); listed {
		return err
	}
	return a.listDevices(*long, *v6, *all)
}

// listDevices is "juist devices" for one network.
func (a *app) listDevices(long, v6, all bool) error {
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	self, hasDevice, err := a.selfID()
	if err != nil {
		return err
	}
	// A keystore with the log and no device, as an admin machine's, lists
	// the network as it is.
	if hasDevice && !state.IsMember(self) {
		// What the log says of the others is the old network's business.
		a.warn("not in %q any more", state.Network())
		reset := "juist reset"
		if a.instance != nil && (a.instance.n > 0 || len(a.networkInstances()) > 1) {
			reset += " " + a.instance.name()
		}
		a.hint("rejoin with a new invite, or start over: %s", reset)
		return nil
	}

	// Where no daemon runs there is nothing to say about tunnels.
	var st *ipc.Status
	if n, err := a.openNode(); err == nil {
		if st = liveStatus(n); st != nil && !st.InNetwork {
			st = nil
		}
	}
	devs := ipc.DevicesOf(state, a.now().Unix())
	apart := 0
	if hasDevice && !all {
		view := policy.NetworkOf(state, a.now().Unix()).View(self)
		listed := len(devs)
		devs = slices.DeleteFunc(devs, func(d ipc.Device) bool { return !view.Lists(self, d.Identity) })
		apart = listed - len(devs)
	}
	if err := a.printDevices(devs, self, st, long, v6); err != nil {
		return err
	}
	if apart > 0 {
		a.hint("%s the access policy keeps apart from this one: juist devices --all", count(apart, "more device"))
	}
	if alarm := auth.Alarm(); alarm != nil {
		a.printf("\n")
		a.alarm("%v", alarm)
	}
	return nil
}

// printDevices prints the device table, ROLES last and wrapped where the
// table is wider than the terminal, and a list where even that does not fit.
// st, where a daemon runs, adds how its last check reached each device.
func (a *app) printDevices(devs []ipc.Device, self types.Identity, st *ipc.Status, keys, v6 bool) error {
	reach := map[types.Identity]ipc.PeerReach{}
	builds := map[types.Identity]types.SchemaVersion{}
	if st != nil {
		for _, r := range st.Reach {
			reach[r.Identity] = r
		}
		for _, d := range st.Devices {
			if d.Build != 0 {
				builds[d.Identity] = d.Build
			}
		}
		for _, b := range st.Builds {
			builds[b.Identity] = b.Schema
		}
	}
	showBuilds := len(builds) > 0
	rows := [][]string{{"NAME", "IPV4"}}
	if v6 {
		rows[0] = append(rows[0], "IPV6")
	}
	if keys {
		rows[0] = append(rows[0], "KEY")
	}
	if st != nil {
		rows[0] = append(rows[0], "REACHED")
	}
	if showBuilds {
		rows[0] = append(rows[0], "SCHEMA")
	}
	rows[0] = append(rows[0], "ROLES")
	for _, d := range byAddress(devs) {
		name := cmp.Or(d.Name, d.Identity.ShortString())
		if d.Identity == self {
			name += " (this device)"
		}
		v4 := cmp.Or(d.V4, "-")
		if d.Retiring != "" {
			v4 += " (was " + d.Retiring + ")"
		}
		row := []string{name, v4}
		if v6 {
			row = append(row, cmp.Or(d.V6, "-"))
		}
		if keys {
			row = append(row, d.Identity.String())
		}
		if st != nil {
			row = append(row, a.describeReach(d, d.Identity == self, st, reach))
		}
		if showBuilds {
			row = append(row, a.buildWord(builds[d.Identity]))
		}
		rows = append(rows, append(row, describeGrant(d.Roles, d.Subnets, len(d.Names) > 0, len(d.Published) > 0)))
	}
	if !a.printTable(rows) {
		a.printDeviceList(rows[1:])
	}
	if st != nil && stale(st, time.Now()) {
		a.printf("%s\n", a.paint("33", "checked "+ago(time.Since(time.Unix(st.ReachChecked, 0)))))
	}
	return nil
}

// buildWord is a device's juist by the newest schema it implements, marked
// where older than this one's.
func (a *app) buildWord(b types.SchemaVersion) string {
	switch {
	case b == 0:
		return "-"
	case b < types.CurrentSchema:
		return a.paint("33", strconv.Itoa(int(b)))
	}
	return strconv.Itoa(int(b))
}

// minLastColumn is the narrowest the table's last column wraps to before
// the table gives way to a list.
const minLastColumn = 12

// printTable prints rows as columns two spaces apart, aligned by visible
// width, wrapping the last column to the terminal; false, printing nothing,
// where the last column would be narrower than [minLastColumn] or a word in it.
func (a *app) printTable(rows [][]string) bool {
	last := len(rows[0]) - 1
	widths := make([]int, last+1)
	word := minLastColumn
	for _, row := range rows {
		for i, cell := range row {
			widths[i] = max(widths[i], visibleWidth(cell))
		}
		for _, w := range strings.Fields(row[last]) {
			word = max(word, visibleWidth(w))
		}
	}
	indent := 0
	for _, w := range widths[:last] {
		indent += w + 2
	}
	room := 0
	if a.width > 0 && indent+widths[last] > a.width {
		if room = a.width - indent; room < word {
			return false
		}
	}
	for _, row := range rows {
		var b strings.Builder
		for i, cell := range row[:last] {
			b.WriteString(cell + strings.Repeat(" ", widths[i]-visibleWidth(cell)+2))
		}
		for k, part := range wrap(row[last], room) {
			if k > 0 {
				b.WriteString("\n" + strings.Repeat(" ", indent))
			}
			b.WriteString(part)
		}
		a.printf("%s\n", b.String())
	}
	return true
}

// printDeviceList prints the device table's rows a device to a paragraph:
// name and IPv4, or IPv4 beneath where both do not fit, then the other
// columns but "-" indented beneath, each wrapped to the terminal.
func (a *app) printDeviceList(rows [][]string) {
	for _, row := range rows {
		head, rest := a.bold(row[0]), row[1:]
		if a.width <= 0 || visibleWidth(row[0])+2+visibleWidth(row[1]) <= a.width {
			head, rest = head+"  "+row[1], row[2:]
		}
		a.printf("%s\n", head)
		for _, more := range rest {
			if more == "-" {
				continue
			}
			for k, l := range wrap(more, a.width-4) {
				a.printf("%s%s\n", map[bool]string{true: "  ", false: "    "}[k == 0], l)
			}
		}
	}
}

// byAddress orders devices by IPv4 address, those without one last, and then
// by IPv6 address.
func byAddress(devs []ipc.Device) []ipc.Device {
	key := func(s string) netip.Addr {
		a, _ := netip.ParseAddr(s)
		return a
	}
	out := slices.Clone(devs)
	slices.SortStableFunc(out, func(x, y ipc.Device) int {
		a, b := key(x.V4), key(y.V4)
		switch {
		case a.IsValid() != b.IsValid():
			return cmp.Compare(boolInt(!a.IsValid()), boolInt(!b.IsValid()))
		case a != b:
			return a.Compare(b)
		}
		return key(x.V6).Compare(key(y.V6))
	})
	return out
}

// describeReach says how the last check reached a device.
func (a *app) describeReach(n ipc.Device, self bool, st *ipc.Status,
	reach map[types.Identity]ipc.PeerReach) string {
	r, installed := reach[n.Identity]
	switch {
	case self:
		return "-"
	case !installed && slices.Contains(st.Silent, n.Name):
		return a.dim("not heard from")
	case !installed && st.ReachChecked == 0:
		return a.dim("not checked yet")
	case !installed:
		// Heard from, and still no peer entry: expired, left out for
		// announcing a key another device uses, or not a voucher while this
		// device's view is stale.
		return a.paint("33", "not connected")
	case !r.Live && r.Absent && r.Heard > 0:
		return a.dim("offline, heard " + ago(time.Since(time.Unix(r.Heard, 0))))
	case !r.Live && r.Absent:
		return a.dim("offline")
	default:
		return a.reachWord(r)
	}
}

// reachWord says how the last check reached an installed peer.
func (a *app) reachWord(r ipc.PeerReach) string {
	switch {
	case !r.Live:
		return a.paint("33", "no answer")
	case r.Outdated:
		return a.paint("33", "outdated")
	case r.Direct:
		return "direct"
	default:
		return "relayed"
	}
}
