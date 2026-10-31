package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/nning/juist/discovery/mdns"
	"github.com/nning/juist/internal/cliflag"
	"github.com/nning/juist/internal/rendezvous"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// errSilent reports a failure whose message has already been printed, so the
// exit code is set without repeating it. errHelp reports that help was asked
// for and given, which is a success.
var (
	errSilent = silentError{}
	errHelp   = silentError{help: true}
)

type silentError struct{ help bool }

func (silentError) Error() string { return "" }

// An app is one invocation's environment. Output goes through it rather than
// to os.Stdout, so tests can run two ends of an enrollment concurrently.
type app struct {
	// ctx is cancelled when the operator interrupts the command.
	ctx         context.Context
	in          io.Reader
	out, errOut io.Writer

	// home is the keystore: this user's admin keys, and — where no daemon
	// runs — the device's own state. homeExplicit and socketExplicit record
	// whether --home or --socket named them, which decides where a daemon is
	// looked for; see [app.openNode].
	home           *home
	homeExplicit   bool
	socket         string
	socketExplicit bool
	node           node

	// host is where the host's juistd instances are, one per network;
	// network is --network, naming one; purpose is what the command wants of
	// them, and yes that it may make a new one without asking. instances is
	// what they answered, and instance the one the node is. See instances.go.
	host    *hostLayout
	network string
	// networkFromEnv says network is $JUIST_NETWORK's rather than given.
	networkFromEnv bool
	purpose        purpose
	yes            bool
	instances      *[]hostInstance
	instance       *hostInstance
	asRoot         func() bool
	made           int    // an instance this invocation started, which a failure takes back
	keyName        string // the one admin key to sign with, where one is named
	spec           spec   // the command's, as parsed, for hints that name it
	ownRecordsSaid bool   // see hintOwnRecords
	applied        bool   // a change other than a checkpoint was applied; see checkpointIfDue

	// listing is the instance a listing of every network is at, and
	// listingHeads says the listing heads each network itself.
	listing      string
	listingHeads bool

	// argv is the invocation's arguments, which a background share runs
	// again with. spawn starts that run, in a session of its own; ready is
	// set in it, and says once the share is up, whereupon detach lets go of
	// the terminal.
	argv   []string
	spawn  func(args []string) (ready io.ReadCloser, wait func() error, kill func(), err error)
	ready  io.WriteCloser
	detach func()

	// interactive is set when a person can answer a question on in, read
	// through reader; reading is a read under way.
	interactive bool
	reader      *bufio.Reader
	reading     chan readResult
	color       bool
	width       int  // the terminal's columns, 0 for no limit
	terminal    bool // out is a terminal that can draw block characters

	// inviteAddrs lists where an invite's host can be reached, and findInvite
	// asks the LAN who holds an invite, nil meaning mDNS; tests replace both.
	inviteAddrs func(port uint16, state *log.State) []netip.AddrPort
	findInvite  func(ctx context.Context, nameplate uint16) ([]mdns.InviteHost, error)

	// helpers are the public services an invite meets through where no
	// daemon says which; nil, as in tests, meets through none.
	helpers *rendezvous.Helpers

	// drawV4 picks a new network's IPv4 prefix among those taken leaves;
	// tests make it deterministic.
	drawV4 func(taken func(netip.Prefix) bool) (netip.Prefix, error)

	// genesisSchema, where set, is the schema a new network starts at in
	// place of this build's; tests set an older one.
	genesisSchema types.SchemaVersion

	// admissionHold is how long a copy of an admission waits on the admin
	// devices before its invite renews it; tests shorten it.
	admissionHold time.Duration

	// dir is the working directory pending changes are written to and
	// relative paths are read from, "" meaning the process's; now is the
	// clock. Tests replace both.
	dir string
	now func() time.Time

	// system reads the host's own files, as resolv.conf, and getenv the
	// environment; tests replace both.
	system func(path string) ([]byte, error)
	getenv func(string) string

	// editor edits a file as the operator would in their editor; tests
	// replace it.
	editor func(path string) error

	// capture, when set, receives a command's spec and flags at its parse,
	// which then stops the command: shell completion.
	capture func(spec, *flag.FlagSet)
}

func newApp(in io.Reader, out, errOut io.Writer) *app {
	a := &app{ctx: context.Background(), in: in, out: out, errOut: errOut, inviteAddrs: hostAddrs, now: time.Now, drawV4: drawV4Prefix,
		host: systemLayout(), asRoot: func() bool { return os.Geteuid() == 0 }, admissionHold: admissionHold,
		system: os.ReadFile, getenv: os.Getenv,
		helpers: &rendezvous.Helpers{STUN: rendezvous.DefaultSTUN}, spawn: spawnBackground}
	a.interactive = isTerminal(in)
	a.color = isTerminal(out) && a.getenv("NO_COLOR") == "" && a.getenv("TERM") != "dumb"
	a.width = termWidth(out, a.getenv)
	a.terminal = isTerminal(out) && a.getenv("TERM") != "dumb"
	return a
}

// path resolves a path the person gave against the working directory.
func (a *app) path(p string) string {
	if a.dir == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(a.dir, p)
}

func isTerminal(v any) bool {
	f, ok := v.(*os.File)
	if !ok {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), ioctlGetTermios)
	return err == nil
}

// termWidth is the width of the terminal v is, else $COLUMNS (which watch
// sets for the pipe it reads), else 0.
func termWidth(v any, getenv func(string) string) int {
	f, ok := v.(*os.File)
	if !ok {
		return 0
	}
	if ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ); err == nil && ws.Col > 0 {
		return int(ws.Col)
	}
	if n, err := strconv.Atoi(getenv("COLUMNS")); err == nil && n > 0 {
		return n
	}
	return 0
}

// --- output ----------------------------------------------------------------

func (a *app) printf(format string, args ...any) { fmt.Fprintf(a.out, format, args...) }

func (a *app) paint(code, s string) string {
	if !a.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (a *app) bold(s string) string { return a.paint("1", s) }
func (a *app) dim(s string) string  { return a.paint("2", s) }

// ok reports an outcome in one line; warn reports on stderr what went wrong,
// and alarm, in red, what stops the network until an operator acts.
func (a *app) ok(format string, args ...any) {
	fmt.Fprintf(a.out, "%s\n", fmt.Sprintf(format, args...))
}

func (a *app) warn(format string, args ...any) {
	fmt.Fprintf(a.errOut, "%s %s\n", a.paint("33", "warning:"), fmt.Sprintf(format, args...))
}

func (a *app) alarm(format string, args ...any) {
	fmt.Fprintf(a.errOut, "%s %s\n", a.paint("1;31", "warning:"), fmt.Sprintf(format, args...))
}

// hint suggests on stderr what to do next.
func (a *app) hint(format string, args ...any) {
	fmt.Fprintf(a.errOut, "%s\n", a.dim("hint: "+fmt.Sprintf(format, args...)))
}

// command prints a command for the operator to run.
func (a *app) command(format string, args ...any) {
	a.commands(fmt.Sprintf(format, args...))
}

// commands prints alternatives, one to a line.
func (a *app) commands(lines ...string) {
	for _, l := range lines {
		fmt.Fprintf(a.out, "  %s\n", a.bold(l))
	}
}

// field prints one aligned "label  value" line, the value wrapped to the
// terminal's width.
func (a *app) field(label, format string, args ...any) {
	const indent = 16
	lines := wrap(fmt.Sprintf(format, args...), a.width-indent)
	fmt.Fprintf(a.out, "  %-13s %s\n", label, lines[0])
	for _, l := range lines[1:] {
		fmt.Fprintf(a.out, "%*s%s\n", indent, "", l)
	}
}

// wrap breaks s at spaces into lines of at most width columns, no limit where
// width is not positive; a word wider than width stands on a line alone.
func wrap(s string, width int) []string {
	if width <= 0 {
		return []string{s}
	}
	var lines []string
	for visibleWidth(s) > width {
		cut := 0
		for i := 1; i < len(s); i++ {
			if s[i] != ' ' || s[i-1] == ' ' {
				continue
			}
			if visibleWidth(s[:i]) > width {
				break
			}
			cut = i
		}
		if cut == 0 {
			if cut = strings.IndexByte(s, ' '); cut <= 0 {
				break
			}
		}
		lines = append(lines, s[:cut])
		s = strings.TrimLeft(s[cut:], " ")
	}
	return append(lines, s)
}

// visibleWidth is how many columns s takes on a terminal: its runes, less
// colour codes.
func visibleWidth(s string) int {
	n := 0
	for i := 0; i < len(s); n++ {
		for strings.HasPrefix(s[i:], "\x1b[") {
			end := strings.IndexByte(s[i:], 'm')
			if end < 0 {
				break
			}
			i += end + 1
		}
		if i == len(s) {
			break
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
	}
	return n
}

func (a *app) fail(err error) {
	msg := err.Error()
	first, rest, _ := strings.Cut(msg, "\n")
	fmt.Fprintf(a.errOut, "%s %s\n", a.paint("1;31", "juist:"), first)
	if rest != "" {
		fmt.Fprintln(a.errOut, rest)
	}
}

// --- arguments -------------------------------------------------------------

// A spec describes one command's arguments, for parsing and for its help.
type spec struct {
	name  string // "juist invite"
	args  string // "[NAME]"
	about string // what it does, in a paragraph or two
	min   int
	max   int // -1 for no limit

	// anyNetwork is set on a command about no network the device is in —
	// one it founds or joins, or none — which takes no NETWORK argument.
	anyNetwork bool

	// backwards lets a positional argument be -N, which counts from the end.
	backwards bool
}

// synopsis is the command's arguments as usage shows them: a command about
// one of the device's networks takes it first, where it is in several.
func (s spec) synopsis() string {
	if s.anyNetwork || strings.Contains(s.args, "SUBCOMMAND") {
		return s.args
	}
	return strings.TrimSpace("[NETWORK] " + s.args)
}

// shorts are the one-letter options, by the long option each spells: one
// letter per option in every command that has it. -h, -H and -s are help,
// --home and --socket, which every command takes. A switch that grants
// authority takes a letter no one types by habit, such as -v for verbose.
var shorts = map[string]byte{
	"admin":       'a',
	"admin-key":   'K',
	"admin-name":  'u',
	"admin-votes": 'v',
	"all":         'a',
	"background":  'b',
	"device":      'n',
	"devices":     'd',
	"dns":         'D',
	"expires":     'e',
	"finish":      'f',
	"for":         't',
	"force":       'f',
	"ingress":     'i',
	"ipv4":        '4',
	"ipv6":        '6',
	"isolate":     'i',
	"key":         'k',
	"keys":        'k',
	"list":        'l',
	"members":     'm',
	"name":        'n',
	"no-apply":    'n',
	"no-device":   'N',
	"no-dht":      'd',
	"no-lan":      'l',
	"on":          'o',
	"operator":    'o',
	"port":        'p',
	"http2":       '2',
	"http3":       '3',
	"https-only":  'O',
	"proxy":       'P',
	"public":      'W',
	"quorum":      'q',
	"relay":       'r',
	"relay-name":  'R',
	"secrets":     'g',
	"service":     'S',
	"stop":        'S',
	"tcp":         'T',
	"verbose":     'v',
	"voucher":     'V',
	"votes":       'v',
	"when-ready":  'w',
	"write":       'w',
	"yes":         'y',
}

// addShorts gives every long option of fs its one-letter spelling.
func addShorts(fs *flag.FlagSet) {
	var long []string
	fs.VisitAll(func(f *flag.Flag) {
		if len(f.Name) > 1 {
			long = append(long, f.Name)
		}
	})
	for _, name := range long {
		c, ok := shorts[name]
		switch f := fs.Lookup(string(c)); {
		case !ok:
		case f == nil:
			cliflag.Short(fs, c, name)
		case f.Value != fs.Lookup(name).Value:
			panic(fmt.Sprintf("juist: -%c is --%s's and --%s's in %s", c, name, longFor(fs, f), fs.Name()))
		}
	}
}

func longFor(fs *flag.FlagSet, short *flag.Flag) (name string) {
	fs.VisitAll(func(f *flag.Flag) {
		if len(f.Name) > 1 && f.Value == short.Value {
			name = f.Name
		}
	})
	return name
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parse reads flags wherever they appear among args, as a person expects to
// write them, and returns the positional arguments. "--" ends the flags.
func (a *app) parse(s spec, fs *flag.FlagSet, args []string) ([]string, error) {
	addShorts(fs)
	if a.capture != nil {
		a.capture(s, fs)
		return nil, errCompleting
	}
	if s.backwards {
		args = slices.Clone(args)
		for i, arg := range args {
			if arg == "--" {
				break
			}
			if isBackwards(arg) {
				args[i] = backwardsMark + arg
			}
		}
	}
	args, err := cliflag.Check(fs, args)
	if err != nil {
		return nil, fmt.Errorf("%v\n%s", err, s.usage(fs))
	}
	var pos, tail []string
	if i := slices.Index(args, "--"); i >= 0 {
		args, tail = args[:i], args[i+1:]
	}
	for {
		if err := cliflag.TidyIn(fs, fs.Parse(args)); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				a.help(s, fs, a.out)
				return nil, errHelp
			}
			return nil, fmt.Errorf("%v\n%s", err, s.usage(fs))
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	pos = append(pos, tail...)
	for i := range pos {
		pos[i] = strings.TrimPrefix(pos[i], backwardsMark)
	}
	a.spec = s
	// A first argument that names one of the device's networks is that
	// network, where what follows still makes the command. With one network
	// it may be left out.
	if !s.anyNetwork && (a.network == "" || a.networkFromEnv) && len(pos) > 0 && len(pos)-1 >= s.min &&
		a.namesNetwork(pos[0]) {
		a.network, a.networkFromEnv, pos = pos[0], false, pos[1:]
	}
	switch {
	case len(pos) < s.min:
		// Of several forms, the first; of its arguments, those not given.
		form, _, _ := strings.Cut(s.args, " | ")
		fields := strings.Fields(form)
		missing := slices.DeleteFunc(fields[min(len(pos), len(fields)):], func(f string) bool { return strings.HasPrefix(f, "[") })
		if len(missing) == 0 {
			missing = []string{"an argument"}
		}
		return nil, fmt.Errorf("missing %s\n%s", strings.Join(missing, " "), s.usage(fs))
	case s.max >= 0 && len(pos) > s.max:
		return nil, fmt.Errorf("unexpected argument %q\n%s", pos[s.max], s.usage(fs))
	}
	return pos, nil
}

// backwardsMark hides -N from the flag parser; no argument holds a NUL.
const backwardsMark = "\x00"

func isBackwards(arg string) bool {
	_, err := strconv.ParseUint(strings.TrimPrefix(arg, "-"), 10, 32)
	return strings.HasPrefix(arg, "-") && err == nil
}

// usage is the one-line synopsis errors end with; fs, if any, adds options.
func (s spec) usage(fs *flag.FlagSet) string {
	u := "usage: " + s.name
	if args := s.synopsis(); args != "" {
		u += " " + args
	}
	if fs != nil {
		has := false
		fs.VisitAll(func(*flag.Flag) { has = true })
		if has {
			u += " [options]"
		}
	}
	return u
}

func (a *app) help(s spec, fs *flag.FlagSet, w io.Writer) {
	usage := "Usage: " + s.name
	if args := s.synopsis(); args != "" {
		usage += " " + args
	}
	hasFlags := false
	fs.VisitAll(func(*flag.Flag) { hasFlags = true })
	if hasFlags {
		usage += " [options]"
	}
	fmt.Fprintf(w, "%s\n\n%s\n", usage, strings.TrimSpace(s.about))
	if !hasFlags {
		return
	}
	fmt.Fprintf(w, "\nOptions:\n")
	for _, o := range optionRows(fs) {
		fmt.Fprintf(w, "  %-28s %s\n", o[0], o[1])
	}
}

// optionRows are fs's options as help lists them: each one's spellings with
// its value, and what it does with its default.
func optionRows(fs *flag.FlagSet) [][2]string {
	var rows [][2]string
	fs.VisitAll(func(f *flag.Flag) {
		left, ok := cliflag.Label(fs, f)
		if !ok {
			return
		}
		arg, text := flag.UnquoteUsage(f)
		if p, ok := f.Value.(interface{ Placeholder() string }); ok {
			arg = p.Placeholder()
		}
		switch arg {
		case "uint", "int":
			arg = "N"
		case "duration":
			arg = "DURATION"
		case "string":
			arg = "VALUE"
		}
		switch {
		case strings.HasPrefix(arg, "[="):
			left += arg // an optional value, given as --name=VALUE alone
		case arg != "":
			left += " " + arg
		}
		def := f.DefValue
		if d, err := time.ParseDuration(def); err == nil && strings.HasSuffix(def, "s") {
			def = shortDuration(d)
		}
		if !slices.Contains([]string{"", "false", "0", "0s"}, def) {
			text += fmt.Sprintf(" (default %s)", def)
		}
		rows = append(rows, [2]string{left, text})
	})
	return rows
}

// stringList collects a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// shortDuration prints 1h rather than 1h0m0s.
func shortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "(devel)"
}
