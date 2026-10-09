// Command juist creates and runs a juist network from the command line: it
// creates networks, invites and admits devices, removes them, and reports
// how this device is connected. juistd, the daemon, carries the traffic;
// this tool holds the admin keys and never hands them to it.
//
//	juist create home        # a new network, with this device in it
//	juist invite             # prints a code for the next device
//	juist join 42-…          # on that device
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/nning/juist/cmd/internal/defaults"
	"github.com/nning/juist/internal/cliflag"
)

// A command is one verb of the CLI.
type command struct {
	name    string
	aliases []string
	summary string
	group   string
	run     func(a *app, args []string) error
	// family, if set, lists the command's subcommands.
	family func() family
}

// Groups, in the order help lists them.
const (
	groupStart = "Getting started"
	groupDaily = "Devices"
	groupAdmin = "Administration"
)

var commands = []command{
	{name: "create", aliases: []string{"init"}, group: groupStart, summary: "create a network with this device in it",
		run: cmdCreate},
	{name: "invite", group: groupStart, summary: "invite a device", run: cmdInvite},
	{name: "join", group: groupStart, summary: "join a network", run: cmdJoin},

	{name: "status", group: groupDaily, summary: "show this device's connection", run: cmdStatus},
	{name: "devices", aliases: []string{"ls"}, group: groupDaily, summary: "list devices", run: cmdDevices},
	{name: "remove", aliases: []string{"rm"}, group: groupDaily, summary: "remove a device", run: cmdRemove},
	{name: "rename", group: groupDaily, summary: "rename a device", run: cmdRename},
	{name: "rotate", group: groupDaily, summary: "replace keys", run: cmdRotate},
	{name: "exit", group: groupDaily, summary: "route internet traffic through a device", run: cmdExit,
		family: exitFamily},
	{name: "subnet", group: groupDaily, summary: "reach networks behind a device", run: cmdSubnet,
		family: subnetFamily},
	{name: "names", group: groupDaily, summary: "point public names at devices", run: cmdNames,
		family: namesFamily},
	{name: "publish", group: groupDaily, summary: "publish devices' services through an ingress", run: cmdPublish,
		family: publishFamily},
	{name: "share", group: groupDaily, summary: "share a file or directory from the internet", run: cmdShare},
	{name: "ingress", group: groupDaily, summary: "take connections for published names", run: cmdIngress,
		family: ingressFamily},
	{name: "reset", group: groupDaily, summary: "forget the network and keys", run: cmdReset},

	{name: "grant", group: groupAdmin, summary: "give a device a role", run: cmdGrant},
	{name: "revoke", group: groupAdmin, summary: "take a role from a device", run: cmdRevoke},
	{name: "policy", group: groupAdmin, summary: "say which device may open what on which", run: cmdPolicy,
		family: policyFamily},
	{name: "approve", aliases: []string{"apply"}, group: groupAdmin, summary: "sign and apply change files", run: cmdApprove},
	{name: "admins", group: groupAdmin, summary: "manage admin keys and quorum", run: cmdAdmins, family: adminsFamily},
	{name: "set", group: groupAdmin, summary: "change device settings", run: cmdSet},
	{name: "network", group: groupAdmin, summary: "show, rename or renumber the network, set its domain, or end it", run: cmdNetwork, family: networkFamily},
	{name: "log", group: groupAdmin, summary: "inspect the membership log", run: cmdLog, family: logFamily},
}

// A family is a command whose first argument names one of its subcommands.
// The first subcommand runs where none is named.
type family struct {
	name   string // "juist admins"
	intro  string
	subs   []subcommand
	footer string
}

// A subcommand is one verb of a family.
type subcommand struct {
	name    string
	aliases []string
	run     func(a *app, args []string) error
	// forms are the subcommand's synopses after the family's name, each with
	// what it does; a "\n" in one continues it on the next line.
	forms [][2]string
}

func (f family) run(a *app, args []string) error {
	// "juist network home" is the first subcommand, for network home.
	if len(args) == 0 || strings.HasPrefix(args[0], "-") || !f.hasSub(args[0]) && a.namesNetwork(args[0]) {
		return f.subs[0].run(a, args)
	}
	sub, rest := args[0], args[1:]
	for _, s := range f.subs {
		if s.name == sub || slices.Contains(s.aliases, sub) {
			return s.run(a, rest)
		}
	}
	return fmt.Errorf("unknown subcommand %q%s\nhint: %s --help", sub, didYouMean(sub, f.names()...), f.name)
}

func (f family) hasSub(name string) bool {
	return slices.ContainsFunc(f.subs, func(s subcommand) bool { return s.name == name || slices.Contains(s.aliases, name) })
}

func (f family) names() []string {
	out := make([]string, len(f.subs))
	for i, s := range f.subs {
		out[i] = s.name
	}
	return out
}

// about is the family's help: its intro, every form, and its footer.
func (f family) about() string {
	var lines [][2]string
	width := 0
	for i, s := range f.subs {
		for _, form := range s.forms {
			synopsis := f.name
			if i > 0 || form[0] != "" {
				synopsis += " " + form[0]
			}
			lines = append(lines, [2]string{synopsis, form[1]})
			width = max(width, len(synopsis))
		}
	}
	var b strings.Builder
	b.WriteString(f.intro + "\n\n")
	for _, l := range lines {
		for i, text := range strings.Split(l[1], "\n") {
			synopsis := ""
			if i == 0 {
				synopsis = l[0]
			}
			fmt.Fprintf(&b, "  %-*s   %s\n", width, synopsis, text)
		}
	}
	if f.footer != "" {
		b.WriteString("\n" + f.footer)
	}
	return b.String()
}

func lookup(name string) (*command, bool) {
	for i := range commands {
		if commands[i].name == name || slices.Contains(commands[i].aliases, name) {
			return &commands[i], true
		}
	}
	return nil, false
}

func usage(w io.Writer) {
	fmt.Fprint(w, "juist: peer-to-peer mesh VPN, no coordination server\n\n")
	fmt.Fprint(w, "Usage:\n  juist <command> [arguments]\n")
	group := ""
	for _, c := range commands {
		if c.group != group {
			group = c.group
			fmt.Fprintf(w, "\n%s:\n", group)
		}
		fmt.Fprintf(w, "  %-9s %s\n", c.name, c.summary)
	}
	fmt.Fprint(w, `
Other:
  help      show help, or a command's
  version   print the version

On a device in several networks, a command about one takes it first, by its
name or its juistd's (juist1): juist devices home. Listings show them all.

Options for every command:
  -H, --home DIR       keystore (default $JUIST_HOME, or ~/.config/juist)
  -s, --socket PATH    juistd's socket (default $JUIST_SOCKET, or the service's)
      --network NAME   the network, as NETWORK first does ($JUIST_NETWORK)
  -h, --help           show a command's help
`)
}

func main() {
	a := newApp(os.Stdin, os.Stdout, os.Stderr)
	a.ready, a.detach = backgroundShare()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	a.ctx = ctx
	err := a.main(os.Args[1:])
	stop()
	switch {
	case err == nil:
		return
	case errors.Is(err, errSilent):
		os.Exit(1)
	default:
		a.fail(err)
		os.Exit(1)
	}
}

// main runs one invocation. Help that was asked for is a success.
func (a *app) main(args []string) error {
	a.argv = args
	if err := a.dispatch(args); !errors.Is(err, errHelp) {
		return err
	}
	return nil
}

const versionHelp = "Usage: juist version\n\nPrint the version.\n"

func (a *app) dispatch(args []string) error {
	// Completion goes before the globals are taken out, since the word being
	// completed may be the value of one. Globals given ahead of it are kept
	// with the words.
	if i := slices.Index(args, "__complete"); i >= 0 && i%2 == 0 {
		return a.complete(append(slices.Clone(args[:i]), args[i+1:]...))
	}
	g, args, err := extractGlobals(args)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		usage(a.errOut)
		return errSilent
	}
	name, rest := args[0], args[1:]
	switch name {
	case "help", "-h", "--help":
		// "juist help CMD SUB" is "juist CMD SUB --help".
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") && rest[0] != "help" {
			if rest[0] == "version" {
				fmt.Fprint(a.out, versionHelp)
				return nil
			}
			c, ok := lookup(rest[0])
			if !ok {
				return unknownCommand(rest[0])
			}
			return a.runCommand(c, g, append(slices.Clone(rest[1:]), "--help"))
		}
		usage(a.out)
		return nil
	case "version":
		if len(rest) > 0 && (rest[0] == "-h" || rest[0] == "--help") {
			fmt.Fprint(a.out, versionHelp)
			return nil
		}
		fmt.Fprintf(a.out, "juist %s\n", version())
		return nil
	}
	if name == "__manpage" {
		return a.manpage(a.out)
	}
	if name == "__instance" {
		return a.runCommand(&command{name: name, run: cmdInstance}, g, rest)
	}
	if name == "--version" || name == "-v" || name == "-V" {
		return fmt.Errorf("unknown option %s; use: juist version", name)
	}
	if strings.HasPrefix(name, "-") {
		return unknownGlobal(name)
	}
	c, ok := lookup(name)
	if !ok {
		return unknownCommand(name)
	}
	return a.runCommand(c, g, rest)
}

// unknownGlobal explains an option given before the command that is not one
// of the few every command takes.
func unknownGlobal(arg string) error {
	name, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
	if c, ok := lookup(name); ok {
		return fmt.Errorf("unknown option %s; did you mean: juist %s?", arg, c.name)
	}
	for _, g := range []string{"home", "socket", "network"} {
		if cliflag.EditDistance(name, g) <= 2 || strings.HasPrefix(g, name) && name != "" {
			return fmt.Errorf("unknown option %s; did you mean --%s?", arg, g)
		}
	}
	return fmt.Errorf("unknown option %s\nhint: only -H, -s and --network go before the command; its own "+
		"options follow it", arg)
}

func unknownCommand(name string) error {
	msg := fmt.Sprintf("unknown command %q", name)
	if s := suggest(name); s != "" {
		msg += fmt.Sprintf("; did you mean %q?", s)
	}
	return fmt.Errorf("%s\nhint: juist help", msg)
}

func (a *app) runCommand(c *command, g globals, args []string) error {
	h, err := openHome(g.home)
	if err != nil {
		return err
	}
	a.home, a.homeExplicit = h, g.homeExplicit
	a.socket, a.socketExplicit = g.socket, g.socket != ""
	a.network, a.networkFromEnv = g.network, g.networkFromEnv
	return c.run(a, args)
}

// globals are the flags every command takes.
type globals struct {
	home         string
	homeExplicit bool
	socket       string
	network      string
	// networkFromEnv says network is $JUIST_NETWORK's, not --network's.
	networkFromEnv bool
}

// globalShorts spell the global options with one letter.
var globalShorts = map[string]string{"H": "home", "s": "socket"}

// extractGlobals takes --home, --socket and --network out of args wherever
// they appear, so they can be given before or after the command.
func extractGlobals(args []string) (globals, []string, error) {
	g := globals{home: defaults.Home(), socket: os.Getenv("JUIST_SOCKET"), network: os.Getenv("JUIST_NETWORK")}
	g.networkFromEnv = g.network != ""
	_, g.homeExplicit = os.LookupEnv("JUIST_HOME")
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			out = append(out, args[i:]...)
			break
		}
		body, isLong := strings.CutPrefix(arg, "--")
		name, value, hasValue := strings.Cut(body, "=")
		if short, ok := strings.CutPrefix(arg, "-"); ok && !isLong {
			n, v, has := strings.Cut(short, "=")
			if n == "home" || n == "socket" || n == "network" {
				return g, nil, fmt.Errorf("%s: an option's full name takes two dashes, as --%s", arg, n)
			}
			if long, ok := globalShorts[n]; ok {
				isLong, name, value, hasValue = true, long, v, has
			}
		}
		if !isLong || (name != "home" && name != "socket" && name != "network") {
			out = append(out, arg)
			continue
		}
		if !hasValue {
			if i+1 >= len(args) {
				if name == "network" {
					return g, nil, fmt.Errorf("%s needs a network's name", arg)
				}
				return g, nil, fmt.Errorf("%s needs a path", arg)
			}
			i++
			value = args[i]
		}
		switch name {
		case "home":
			g.home, g.homeExplicit = value, true
		case "socket":
			g.socket = value
		default:
			g.network, g.networkFromEnv = value, false
		}
	}
	return g, out, nil
}

// didYouMean is "; did you mean X?" for the word among words closest to a
// mistyped one, or nothing where none is close.
func didYouMean(typed string, words ...string) string {
	best, bestDist := "", 3
	for _, w := range words {
		if d := cliflag.EditDistance(typed, w); d < bestDist {
			best, bestDist = w, d
		}
	}
	if best == "" {
		return ""
	}
	return fmt.Sprintf("; did you mean %q?", best)
}

// suggest returns the command closest to a mistyped one, if any is close: the
// one it begins, where exactly one does, or else the nearest by edit distance.
func suggest(name string) string {
	var prefixed []string
	for _, c := range commands {
		if strings.HasPrefix(c.name, name) {
			prefixed = append(prefixed, c.name)
		}
	}
	if len(prefixed) == 1 {
		return prefixed[0]
	}
	best, bestDist := "", 3
	for _, c := range commands {
		for _, n := range append([]string{c.name}, c.aliases...) {
			if d := cliflag.EditDistance(name, n); d < bestDist {
				best, bestDist = c.name, d
			}
		}
	}
	return best
}
