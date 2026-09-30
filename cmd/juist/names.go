package main

import (
	"fmt"
	"slices"
	"strings"

	"golang.org/x/net/idna"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

const namesAbout = `

A NAME, such as mx.example.org, is a public name the network points at the
device: members that accept names (juist set --accept-names) reach it by
that name through the tunnel, where its TLS certificate still fits.`

// parseHostName reads arg as a public name, where it has a dot and is no
// address: in the one form the log takes, xn-- for a Unicode name.
func parseHostName(arg string) (string, bool, error) {
	if !strings.Contains(arg, ".") || strings.Contains(arg, "/") {
		return "", false, nil
	}
	name, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.ToLower(arg), "."))
	if err != nil {
		return "", true, fmt.Errorf("%q is no DNS name: %v", arg, err)
	}
	if strings.HasSuffix(name, "."+types.NamesTLD) {
		return "", true, fmt.Errorf("%s is the network's own; members are DEVICE.NETWORK.%s already", name, types.NamesTLD)
	}
	if err := types.ValidateHostName(name); err != nil {
		return "", true, err
	}
	return name, true, nil
}

// changeName is names with name pointed at target or taken from it, where no
// other member holds it.
func changeName(state *log.State, target types.NodeRecord, names []string, name string, grant bool) ([]string, error) {
	dev := displayMember(target)
	if !grant {
		if !slices.Contains(names, name) {
			return nil, fmt.Errorf("%s does not answer for %s\nhint: juist status", dev, name)
		}
		return slices.DeleteFunc(names, func(n string) bool { return n == name }), nil
	}
	for _, n := range state.Nodes() {
		if n.Identity != target.Identity && slices.Contains(n.Names, name) {
			return nil, fmt.Errorf("%s points at %s already\nhint: juist revoke %s %s", name, displayMember(n),
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
	if auth.State().Schema() < types.SchemaNames {
		return needsUpgrade("names")
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
		a.hint("juist set --accept-names on each device that is to resolve it")
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
	switch {
	case n.Resolved:
		text = n.Domain
	case n.Cannot:
		text = paint("2", "not resolved here: "+n.Not)
	default:
		text = paint("33", n.Domain+" not resolved: "+n.Not)
		hint = dnsHint(n.Not)
	}
	var more string
	switch {
	case len(n.Overrides) == 0:
	case n.Accepted:
		more = overridesList(n, paint)
	case len(n.Overrides) == 1:
		more = paint("2", "1 public name not accepted")
	default:
		more = paint("2", fmt.Sprintf("%d public names not accepted", len(n.Overrides)))
	}
	switch {
	case text == "":
		// A network whose name is no label has public names alone.
		text = more
	case more != "":
		text += "; " + more
	}
	return text, hint
}
