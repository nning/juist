package main

import (
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/nning/juist/trust/log"
)

// "juist __complete WORD..." prints the candidates for the last word, one per
// line; nothing lets the shell complete file names. A command run for it
// stops at parse, handing over its spec and flags. It changes nothing and
// asks nothing.

// errCompleting stops a command at its parse, in completion mode.
var errCompleting = errors.New("completing")

// completion is what a command run in completion mode handed over.
type completion struct {
	spec spec
	fs   *flag.FlagSet
}

func (a *app) complete(words []string) error {
	if len(words) == 0 {
		words = []string{""}
	}
	cur, prev := words[len(words)-1], words[:len(words)-1]
	// The value of --network is one of the networks this device is in.
	if n := len(prev); n > 0 && prev[n-1] == "--network" || strings.HasPrefix(cur, "--network=") {
		given := strings.TrimPrefix(cur, "--network=")
		for _, name := range networkNames(a.hostInstances()) {
			if strings.HasPrefix(name, given) && shellSafe(name) {
				fmt.Fprintln(a.out, strings.TrimSuffix(cur, given)+name)
			}
		}
		return nil
	}
	// The value of --home or --socket is a path, which the shell completes.
	for _, g := range []string{"--home", "--socket", "-H", "-s"} {
		if n := len(prev); n > 0 && prev[n-1] == g || strings.HasPrefix(cur, g+"=") {
			return nil
		}
	}
	g, prev, err := extractGlobals(prev)
	if err != nil {
		return nil
	}
	for _, c := range a.candidates(g, cur, prev) {
		if strings.HasPrefix(c, cur) && shellSafe(c) {
			fmt.Fprintln(a.out, c)
		}
	}
	return nil
}

// shellSafe reports whether a candidate can be put on a command line as it
// is. What completion prints is inserted unquoted and then run by the
// person's own shell, and device and admin names come from the log, where
// any member put them: "x$(…)" as a name would be a command the admin runs.
func shellSafe(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			strings.ContainsRune("._-@+=:/", r)) {
			return false
		}
	}
	return s != ""
}

func (a *app) candidates(g globals, cur string, prev []string) []string {
	if len(prev) == 0 {
		if strings.HasPrefix(cur, "-") {
			return []string{"--home", "--socket", "--network", "--help"}
		}
		names := []string{"help", "version"}
		for _, c := range commands {
			names = append(names, c.name)
		}
		return names
	}
	name, rest := prev[0], prev[1:]
	if name == "help" {
		if len(rest) > 0 {
			return nil
		}
		var names []string
		for _, c := range commands {
			names = append(names, c.name)
		}
		return names
	}
	cmd, ok := lookup(name)
	if !ok {
		return nil
	}
	got, ok := a.captureCommand(g, cmd, rest)
	if !ok {
		return nil
	}
	if strings.HasPrefix(cur, "-") {
		out := []string{"--help", "--home", "--socket", "--network"}
		got.fs.VisitAll(func(f *flag.Flag) {
			if len(f.Name) > 1 {
				out = append(out, "--"+f.Name)
			}
		})
		return out
	}
	pos, wantsValue := positionals(got.fs, rest)
	if wantsValue {
		return nil // an option's value: file names, or nothing to offer
	}
	if cmd.family != nil && got.spec.name == cmd.family().name && len(pos) == 0 {
		return cmd.family().names()
	}
	// A subcommand's own word is among the arguments its parent passed on.
	if strings.Count(got.spec.name, " ") == 2 && len(pos) > 0 {
		pos = pos[1:]
	}
	return a.positional(got.spec.name, pos)
}

// captureCommand runs a command in completion mode and returns what its
// parse handed over.
func (a *app) captureCommand(g globals, cmd *command, args []string) (completion, bool) {
	var got completion
	a.capture = func(s spec, fs *flag.FlagSet) { got = completion{spec: s, fs: fs} }
	defer func() { a.capture = nil }()
	h, err := openHome(g.home)
	if err != nil {
		return got, false
	}
	a.home, a.homeExplicit = h, g.homeExplicit
	a.socket, a.socketExplicit = g.socket, g.socket != ""
	a.network = g.network
	if err := cmd.run(a, args); !errors.Is(err, errCompleting) || got.fs == nil {
		return got, false
	}
	return got, true
}

// positionals returns the arguments among args that are not options or
// their values, and whether the last word typed is an option still waiting
// for its value.
func positionals(fs *flag.FlagSet, args []string) (pos []string, wantsValue bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return append(pos, args[i+1:]...), false
		}
		if len(arg) < 2 || arg[0] != '-' {
			pos = append(pos, arg)
			continue
		}
		name, _, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		f := fs.Lookup(name)
		if f == nil || hasValue {
			continue
		}
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			continue
		}
		if i == len(args)-1 {
			return pos, true
		}
		i++
	}
	return pos, false
}

// positional offers what goes in the next positional argument of the
// command whose spec is named.
func (a *app) positional(command string, pos []string) []string {
	switch command {
	case "juist admins remove", "juist admins require":
		if len(pos) == 0 {
			return a.adminNames()
		}
	case "juist rotate":
		if len(pos) == 0 {
			return rotations
		}
	case "juist network renumber":
		if len(pos) == 0 {
			return a.deviceNames()
		}
	case "juist remove":
		if len(pos) == 0 {
			return a.deviceNames()
		}
	case "juist grant", "juist revoke":
		if len(pos) == 0 {
			return a.deviceNames()
		}
		var roles []string
		for _, r := range roleNames {
			if !slices.Contains(pos[1:], r.user) {
				roles = append(roles, r.user)
			}
		}
		return roles
	}
	return nil
}

// deviceNames and adminNames read the log, quietly: completion must neither
// ask anything nor print an error into the command line being typed.
func (a *app) deviceNames() []string {
	auth, err := a.quietLog()
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range auth.State().Nodes() {
		out = append(out, n.Name)
	}
	return out
}

func (a *app) adminNames() []string {
	auth, err := a.quietLog()
	if err != nil {
		return nil
	}
	var out []string
	for _, p := range adminPeople(auth.State().Admins()) {
		out = append(out, p.name)
	}
	return out
}

func (a *app) quietLog() (*log.Authority, error) {
	a.interactive = false
	out := a.out
	a.out = discard{}
	defer func() { a.out = out }()
	return a.networkLog()
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
