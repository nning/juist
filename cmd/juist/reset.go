package main

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/nning/juist/internal/statedir"

	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/internal/keys"
)

func cmdReset(a *app, args []string) error {
	s := spec{name: "juist reset", about: `
Forget the network and this device's keys, log, peers and operator for it,
as on a fresh install. Admin keys are kept. A device the network still lists
needs --force; remove it first where possible. On a device in several
networks only the one named is forgotten, with its juistd unless that is
the default; the others keep their keys.`}
	fs := newFlags(s.name)
	yes := fs.Bool("yes", false, "do not ask")
	force := fs.Bool("force", false, "reset even if the network still lists this device")
	if _, err := a.parse(s, fs, args); err != nil {
		return err
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	st, err := n.standing(*force)
	if err != nil {
		return err
	}
	switch {
	case st.member && !*force:
		return fmt.Errorf("still a member of %q\nhint: juist remove NAME on an admin device, or --force", st.network)
	case st.logOnly && !*force:
		return fmt.Errorf("this keystore holds %q's log and no device; a reset deletes it\nhint: --force",
			st.network)
	}
	if st.member && st.members == 1 {
		a.warn("this device is the only one in %q: the network ends with it", st.network)
	}
	others := a.otherNetworks()
	inst := 0
	if a.instance != nil {
		inst = a.instance.n
	}
	q := "reset this device, with new keys?"
	switch {
	case st.network != "" && inst > 0:
		q = fmt.Sprintf("forget %q, with this device's keys for it and its juistd (%s)?", st.network,
			instance.Name(inst))
	case st.network != "" && len(others) > 0:
		q = fmt.Sprintf("forget %q, with this device's keys for it?", st.network)
	case st.network != "":
		q = fmt.Sprintf("forget %q and reset this device, with new keys?", st.network)
	}
	switch len(others) {
	case 0:
	case 1:
		a.printf("%s\n", a.dim(others[0]+" stays as it is, with its keys"))
	default:
		a.printf("%s\n", a.dim(strings.Join(others, " and ")+" stay as they are, with their keys"))
	}
	if err := a.proceed(*yes, q); err != nil {
		return err
	}
	ds := n.status()
	// Whatever juistd says: a name cleared while relay.sh found no root
	// leaves the grant.
	named := inst == 0 && (ds != nil && ds.HTTPS != nil && ds.HTTPS.Name != "" || a.relayGranted())
	if err := n.reset(*force); err != nil {
		return err
	}
	if named && a.host.relayScript != "" {
		// The relay's name went with the reset; its capability and port go too.
		if err := a.packageScript(a.host.relayScript, "off", "giving the relay's 443 back"); err != nil {
			a.warn("%v", err)
		}
	}
	switch {
	case st.network != "" && (inst > 0 || len(others) > 0):
		a.ok("left %q", st.network)
	default:
		a.ok("reset; new keys, no network")
	}
	if i := a.instance; i != nil && i.n > 0 {
		// A network beside the default one had a juistd of its own, which
		// goes with it.
		if err := a.dropInstance(i.n, *yes); err != nil {
			return err
		}
	}
	if entries, err := os.ReadDir(a.home.join(keys.AdminsDir)); err == nil && len(entries) > 0 {
		a.printf("%s\n", a.dim("admin keys kept in "+a.home.join(keys.AdminsDir)))
	}
	return nil
}

// resetLocalHome deletes what a home run without a daemon holds of a
// network and of this device, and nothing of its admin keys: the log, the node
// keys, and where the home was a stopped daemon's, the state it kept.
func resetLocalHome(h *home) error {
	entries, err := os.ReadDir(h.path)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == logDir || strings.HasPrefix(e.Name(), nodeKeysFile) ||
			slices.Contains(statedir.StateFiles, e.Name()) {
			if err := os.RemoveAll(h.join(e.Name())); err != nil {
				return err
			}
		}
	}
	return keys.SyncDir(h.path)
}

func removeIfPresent(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
