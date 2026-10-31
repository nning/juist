package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/nning/juist/internal/names"
	"github.com/nning/juist/types"
)

func cmdRename(a *app, args []string) error {
	s := spec{name: "juist rename", args: "DEVICE NAME", min: 2, max: 2, about: `
Rename a device, by name, address or key. DEVICE.NETWORK.juist and its share
name change with it. Keys, addresses, roles and public names stay.`}
	pos, err := a.parse(s, newFlags(s.name), args)
	if err != nil {
		return err
	}
	name := pos[1]
	if err := checkName("device name", name); err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	target, err := resolveDevice(state, pos[0])
	if err != nil {
		return err
	}
	if target.Name == name {
		a.ok("unchanged: named %q", name)
		return nil
	}
	for _, n := range state.Nodes() {
		if n.Identity != target.Identity && foldName(n.Name) == foldName(name) {
			return fmt.Errorf("another device is named %q already", n.Name)
		}
	}
	if target.HasRole(types.RolePublish) {
		renamed := target.Clone()
		renamed.Name = name
		l, ok := renamed.ShareLabel()
		if !ok {
			return fmt.Errorf("%q gives no DNS label for %s to share under\nhint: letters, digits and inner -",
				name, displayMember(target))
		}
		if state.Domain() != "" {
			shared := nameUnder(l, state.Domain())
			if slices.ContainsFunc(target.Published, func(p types.PublishedName) bool { return p.Label == l }) {
				return fmt.Errorf("%s publishes %s already, the name it would share under\nhint: juist publish remove %s %s",
					displayMember(target), shared, displayMember(target), shared)
			}
			if slices.Contains(target.Names, shared) {
				return fmt.Errorf("%s points %s at itself already, the name it would share under\nhint: juist names remove %s %s",
					displayMember(target), shared, displayMember(target), shared)
			}
			if err := labelFree(state, l, target.Identity, a.now().Unix()); err != nil {
				return err
			}
		}
	}
	aum, err := auth.Builder().RenameNode(target.Identity, name)
	if err != nil {
		return fmt.Errorf("%s cannot be named %q: %s", displayMember(target), name, strings.TrimPrefix(err.Error(), "log: "))
	}
	if network := names.Label(state.Network()); network != "" && names.Label(name) == "" {
		a.warn("%q is no DNS label: %s gets no name under %s.%s", name, displayMember(target), network, types.NamesTLD)
	}
	_, err = a.submit(auth, &change{
		aum:  aum,
		file: "rename-" + fileSafe(displayMember(target)) + ".rec",
		done: fmt.Sprintf("renamed %s to %s", displayMember(target), name),
	})
	return err
}
