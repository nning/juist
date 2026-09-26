package main

import "fmt"

func cmdRemove(a *app, args []string) error {
	s := spec{name: "juist remove", args: "DEVICE", min: 1, max: 1, about: `
Remove a device: by name, address, or key ("juist devices --keys"). Rotates
the group secret; every device drops the removed one's tunnel on hearing of
it, and one cut off from the rest at the latest when its freshness expires.`}
	fs := newFlags(s.name)
	yes := fs.Bool("yes", false, "do not ask")
	pos, err := a.parse(s, fs, args)
	if err != nil {
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
	name := displayMember(target)
	self, _, err := a.selfID()
	if err != nil {
		return err
	}
	if self == target.Identity {
		a.warn("that is this device; it leaves the network for good")
	}
	if err := a.checkAdminDeviceLoss(state, target, true); err != nil {
		return err
	}
	if err := a.proceed(*yes, fmt.Sprintf("remove %s (%s) from %q?", name,
		addrList(state, target.Identity), state.Network())); err != nil {
		return err
	}
	aum, err := auth.Builder().RemoveNode(target.Identity, sealer())
	if err != nil {
		return err
	}
	_, err = a.submit(auth, &change{
		aum:  aum,
		file: "remove-" + fileSafe(name) + ".rec",
		done: fmt.Sprintf("removed %s", name),
	})
	return err
}
