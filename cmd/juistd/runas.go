package main

import (
	"strings"

	"github.com/nning/juist/internal/instance"
)

// defaultUser is the user the default instance's daemon runs as.
const defaultUser = "juist"

// runAs is the user the daemon of args runs as, where juistd starts as root
// and drops to one: juist for the default, juistN for instance N, so that one
// network's daemon reads none of another's keys.
func runAs(args []string) string {
	if v, ok := flagValue(args, "instance"); ok && instance.IsName(v) {
		return v
	}
	return defaultUser
}

// deviceOf is the device the daemon of args makes, as juistd takes it: the
// one --tun names, else its instance's, else the default's. Its helper
// plumbs that one alone, so that no network's daemon touches another's.
func deviceOf(args []string) string {
	if v, ok := flagValue(args, "tun", "t"); ok {
		return v
	}
	if v, ok := flagValue(args, "instance"); ok && instance.IsName(v) {
		return v
	}
	return instance.Name(0)
}

// flagValue is the value args give a flag of one of names, the first.
func flagValue(args []string, names ...string) (string, bool) {
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name, v, set := strings.Cut(strings.TrimLeft(a, "-"), "=")
		found := false
		for _, n := range names {
			found = found || name == n
		}
		if !found {
			continue
		}
		if !set {
			if i+1 >= len(args) {
				return "", false
			}
			v = args[i+1]
		}
		return v, true
	}
	return "", false
}
