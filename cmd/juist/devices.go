package main

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nning/juist/ipc"

	"github.com/nning/juist/types"
)

func cmdDevices(a *app, args []string) error {
	s := spec{name: "juist devices", about: `
List the network's devices and how juistd last reached each: directly, or
through a relay. juistd checks every 30s.`}
	fs := newFlags(s.name)
	long := fs.Bool("keys", false, "show identity keys")
	if _, err := a.parse(s, fs, args); err != nil {
		return err
	}
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
		a.hint("rejoin with a new invite, or start over: juist reset")
		return nil
	}

	// Where no daemon runs there is nothing to say about tunnels.
	var st *ipc.Status
	if n, err := a.openNode(); err == nil {
		if st = n.status(); st != nil && !st.InNetwork {
			st = nil
		}
	}
	if err := a.printDevices(ipc.DevicesOf(state, a.now().Unix()), self, st, *long); err != nil {
		return err
	}
	if alarm := auth.Alarm(); alarm != nil {
		a.printf("\n")
		a.alarm("%v", alarm)
	}
	return nil
}

// printDevices prints the device table juist devices and juist status share,
// as a list where the table is wider than the terminal. st, where a daemon
// runs, adds how its last check reached each device.
func (a *app) printDevices(devs []ipc.Device, self types.Identity, st *ipc.Status, long bool) error {
	reach := map[types.Identity]ipc.PeerReach{}
	if st != nil {
		for _, r := range st.Reach {
			reach[r.Identity] = r
		}
	}
	// REACHED last: its colour codes would count as width in any column
	// after it.
	rows := [][]string{{"NAME", "IPV4", "IPV6", "ROLES"}}
	if long {
		rows[0] = append(rows[0], "KEY")
	}
	if st != nil {
		rows[0] = append(rows[0], "REACHED")
	}
	for _, d := range byAddress(devs) {
		name := cmp.Or(d.Name, d.Identity.ShortString())
		if d.Identity == self {
			name += " (this device)"
		}
		v4 := cmp.Or(d.V4, "-")
		if d.Retiring != "" {
			v4 += " (was " + d.Retiring + ")"
		}
		row := []string{name, v4, d.V6, describeRoles(d.Roles)}
		if long {
			row = append(row, d.Identity.String())
		}
		if st != nil {
			row = append(row, a.describeReach(d, d.Identity == self, st, reach))
		}
		rows = append(rows, row)
	}
	if a.width > 0 && tableWidth(rows) > a.width {
		a.printDeviceList(rows[1:], st != nil)
	} else {
		tw := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
		for _, row := range rows {
			fmt.Fprintln(tw, strings.Join(row, "\t"))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if st != nil && stale(st, time.Now()) {
		a.printf("%s\n", a.paint("33", "checked "+ago(time.Since(time.Unix(st.ReachChecked, 0)))))
	}
	return nil
}

// tableWidth is how many columns rows take as a table two spaces apart.
func tableWidth(rows [][]string) int {
	var widths []int
	for _, row := range rows {
		for i, cell := range row {
			if i == len(widths) {
				widths = append(widths, 0)
			}
			widths[i] = max(widths[i], visibleWidth(cell))
		}
	}
	total := 2 * (len(widths) - 1)
	for _, w := range widths {
		total += w
	}
	return total
}

// printDeviceList prints the device table's rows a device to a paragraph:
// name, IPv4 and how it was reached, then the IPv6 address, roles and key
// indented beneath.
func (a *app) printDeviceList(rows [][]string, reached bool) {
	for _, row := range rows {
		head := a.bold(row[0]) + "  " + row[1]
		if reached {
			if r := row[len(row)-1]; r != "-" {
				head += "  " + r
			}
			row = row[:len(row)-1]
		}
		a.printf("%s\n", head)
		for _, more := range row[2:] {
			if more != "-" {
				a.printf("  %s\n", more)
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
	case r.Direct:
		return "direct"
	default:
		return "relayed"
	}
}
