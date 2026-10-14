package main

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"golang.org/x/net/idna"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

func namesFamily() family {
	return family{name: "juist names", intro: "Point public names at devices, which members then reach through the tunnel.",
		subs: []subcommand{
			{name: "list", aliases: []string{"ls"}, run: namesList, forms: [][2]string{{"", "the public names, and how this device resolves them"}}},
			{name: "add", run: namesAdd, forms: [][2]string{{"add DEVICE NAME...", "point NAME at DEVICE"}}},
			{name: "remove", aliases: []string{"rm"}, run: namesRemove,
				forms: [][2]string{{"remove DEVICE NAME...", "take NAME from DEVICE"}}},
			{name: "on", run: namesOn, forms: [][2]string{{"on", "resolve them to their devices on this device"}}},
			{name: "off", run: namesOff, forms: [][2]string{{"off", "resolve them publicly again"}}},
		}, footer: `Every device is DEVICE.NETWORK.juist to the others, where systemd-resolved
runs. A public name, such as mail.example.org, resolves to its device on each
device that turned names on, and publicly elsewhere and while its device is
out of reach.`}
}

func cmdNames(a *app, args []string) error { return namesFamily().run(a, args) }

func namesList(a *app, args []string) error {
	s := spec{name: "juist names", args: "[SUBCOMMAND]", about: namesFamily().about()}
	if _, err := a.parse(s, newFlags(s.name), args); err != nil {
		return err
	}
	if listed, err := a.forEachNetwork(a.listNames); listed {
		return err
	}
	return a.listNames()
}

// listNames is "juist names" for one network.
func (a *app) listNames() error {
	if _, err := a.daemonStatus(); err != nil {
		return err
	}
	// A reader's status says not which device a name points at.
	if err := a.requireOperator(); err != nil {
		return err
	}
	st, err := a.restatus()
	if err != nil {
		return err
	}
	n := cmp.Or(st.Names, &ipc.Names{})
	if len(n.Overrides) == 0 {
		a.ok("no public names")
		a.hint("an admin adds one: juist names add DEVICE mail.example.org")
		return nil
	}
	tw := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tDEVICE\tSTATE")
	for _, o := range n.Overrides {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", o.Name, o.Device, nameState(n, o, a.paint))
	}
	return tw.Flush()
}

// nameState is how this device resolves o, one of n's public names.
func nameState(n *ipc.Names, o ipc.NameOverride, paint func(code, s string) string) string {
	switch {
	case !n.Accepted:
		return "off on this device"
	case !n.Resolved:
		return paint("33", "not resolved here: "+n.Not)
	case o.Not != "":
		return paint("33", "resolved publicly: "+o.Not)
	}
	return paint("32", "resolved to it")
}

func namesAdd(a *app, args []string) error {
	return changeNames(a, args, true, spec{name: "juist names add", args: "DEVICE NAME...", min: 2, max: -1, about: `
Point public names, such as mail.example.org, at a device. Each device that
turned names on resolves them to it: juist names on.`})
}

func namesRemove(a *app, args []string) error {
	return changeNames(a, args, false, spec{name: "juist names remove", args: "DEVICE NAME...", min: 2, max: -1,
		about: `
Take public names from a device.`})
}

func changeNames(a *app, args []string, add bool, s spec) error {
	auth, target, pos, err := a.deviceChange(s, newFlags(s.name), args)
	if err != nil {
		return err
	}
	names := slices.Clone(target.Names)
	for _, arg := range pos {
		host, err := parseHostName(arg)
		if err != nil {
			return err
		}
		if names, err = changeName(auth.State(), target, names, host, add); err != nil {
			return err
		}
	}
	return a.submitNames(auth, target, names)
}

func namesOn(a *app, args []string) error {
	return setAcceptNames(a, args, true, spec{name: "juist names on", about: `
Resolve the public names the network points at devices to them, through the
tunnel, on this device. juist names off undoes it.`})
}

func namesOff(a *app, args []string) error {
	return setAcceptNames(a, args, false, spec{name: "juist names off", about: `
Resolve the network's public names publicly again, as without juist.`})
}

// setAcceptNames has this device resolve the network's public names to their
// devices, or not, and says which it points where.
func setAcceptNames(a *app, args []string, on bool, s spec) error {
	if _, err := a.parse(s, newFlags(s.name), args); err != nil {
		return err
	}
	st, err := a.daemonStatus()
	if err != nil {
		return err
	}
	word := map[bool]string{true: "public names on", false: "public names off"}[on]
	// Sent either way: a status without a running mesh does not say.
	unchanged := st.Names != nil && st.Names.Accepted == on
	if err := a.requireOperator(); err != nil {
		return err
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	st, err = n.exit(ipc.Request{Command: ipc.CmdNames, AcceptNames: &on})
	if err != nil {
		return err
	}
	if unchanged {
		a.ok("unchanged: %s", word)
		return nil
	}
	if t := overridesList(st.Names, a.paint); on && t != "" {
		word += ": " + t
	}
	a.ok("%s", word)
	if n := st.Names; on && n != nil && !n.Resolved {
		a.warn("this host resolves none of them: %s", n.Not)
		if h := dnsHint(n.Not); h != "" {
			a.hint("%s", h)
		}
	}
	return nil
}

// parseHostName reads arg as a public name, in the one form the log takes,
// xn-- for a Unicode name.
func parseHostName(arg string) (string, error) {
	name, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.ToLower(arg), "."))
	switch {
	case err != nil || !strings.Contains(name, "."):
		return "", fmt.Errorf("%q is no public name, such as mail.example.org", arg)
	case strings.HasSuffix(name, "."+types.NamesTLD):
		return "", fmt.Errorf("%s is the network's own; members are DEVICE.NETWORK.%s already", name, types.NamesTLD)
	}
	if err := types.ValidateHostName(name); err != nil {
		return "", err
	}
	return name, nil
}

// changeName is names with name pointed at target or taken from it, where no
// other member holds it.
func changeName(state *log.State, target types.NodeRecord, names []string, name string, grant bool) ([]string, error) {
	dev := displayMember(target)
	if !grant {
		if !slices.Contains(names, name) {
			return nil, fmt.Errorf("%s does not answer for %s\nhint: juist names", dev, name)
		}
		return slices.DeleteFunc(names, func(n string) bool { return n == name }), nil
	}
	for _, n := range state.Nodes() {
		if n.Identity != target.Identity && slices.Contains(n.Names, name) {
			return nil, fmt.Errorf("%s points at %s already\nhint: juist names remove %s %s", name, displayMember(n),
				displayMember(n), name)
		}
	}
	if slices.Contains(names, name) {
		return names, nil
	}
	if len(names) >= types.MaxNamesPerNode {
		return nil, fmt.Errorf("%s answers for %d names, the most a device may", dev, types.MaxNamesPerNode)
	}
	names = append(names, name)
	slices.Sort(names)
	return names, nil
}

// submitNames proposes target's names as next.
func (a *app) submitNames(auth *log.Authority, target types.NodeRecord, next []string) error {
	name := displayMember(target)
	if slices.Equal(next, target.Names) {
		a.ok("%s: unchanged", name)
		return nil
	}
	aum, err := auth.Builder().SetNodeNames(target.Identity, next)
	if err != nil {
		return err
	}
	done := name + ": no names"
	if len(next) > 0 {
		done = name + ": names " + strings.Join(next, ", ")
	}
	if _, err = a.submit(auth, &change{aum: aum, file: "names-" + fileSafe(name) + ".rec", done: done}); err != nil {
		return err
	}
	if len(next) > len(target.Names) && !a.acceptsNames() {
		a.hint("juist names on, on each device that is to resolve it")
	}
	return nil
}

// acceptsNames reports whether this device's juistd resolves public names,
// false where it cannot tell.
func (a *app) acceptsNames() bool {
	n, err := a.openNode()
	if err != nil {
		return false
	}
	st := n.status()
	return st != nil && st.Names != nil && st.Names.Accepted
}

// overridesList is the public names n points at devices, as "NAME at
// DEVICE", each that is resolved publicly for now saying why; paint colours
// those.
func overridesList(n *ipc.Names, paint func(code, s string) string) string {
	if n == nil {
		return ""
	}
	var out []string
	for _, o := range n.Overrides {
		t := o.Name + " at " + o.Device
		if n.Accepted && o.Not != "" {
			t = paint("33", t+" (resolved publicly: "+o.Not+")")
		}
		out = append(out, t)
	}
	return strings.Join(out, ", ")
}

// namesSummary is the status line of how the host resolves the network's
// names, and the hint that would let it where the host could.
func namesSummary(n *ipc.Names, paint func(code, s string) string) (string, string) {
	var text, hint string
	var domains []string
	for _, d := range []string{n.Domain, n.Public} {
		if d != "" {
			domains = append(domains, d)
		}
	}
	switch {
	case n.Resolved:
		text = strings.Join(domains, ", ")
	case n.Cannot:
		text = paint("2", "not resolved here: "+n.Not)
	default:
		text = paint("33", cmp.Or(strings.Join(domains, ", "), "names")+" not resolved: "+n.Not)
		hint = dnsHint(n.Not)
	}
	var more string
	switch {
	case len(n.Overrides) == 0:
	case n.Accepted:
		more = overridesList(n, paint)
	case len(n.Overrides) == 1:
		more = paint("2", "1 public name, off on this device")
	default:
		more = paint("2", fmt.Sprintf("%d public names, off on this device", len(n.Overrides)))
	}
	switch {
	case text == "":
		// A network whose name is no label has public names alone, or its
		// public domain.
		text = cmp.Or(more, "resolved")
	case more != "":
		text += "; " + more
	}
	return text, hint
}
