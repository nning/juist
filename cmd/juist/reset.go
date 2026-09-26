package main

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/nning/juist/internal/statedir"

	"github.com/nning/juist/internal/keys"
)

func cmdReset(a *app, args []string) error {
	s := spec{name: "juist reset", about: `
Forget the network and this device's keys, log, peers and operator, as on a
fresh install. Admin keys are kept. A device the network still lists needs
--force; remove it first where possible.`}
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
	q := "reset this device, with new keys?"
	if st.network != "" {
		q = fmt.Sprintf("forget %q and reset this device, with new keys?", st.network)
	}
	if err := a.proceed(*yes, q); err != nil {
		return err
	}
	if err := n.reset(*force); err != nil {
		return err
	}
	a.ok("reset; new keys, no network")
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
