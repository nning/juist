package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/nning/juist/internal/backupline"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// Tags of the lines a secret of the keystore is exported as.
const (
	adminKeyLine   = backupline.AdminKey
	breakGlassLine = backupline.BreakGlass
)

func backupLine(tag string, payload []byte) string { return backupline.Line(tag, payload) }

func parseBackupLine(line, tag string) ([]byte, error) { return backupline.Parse(line, tag) }

// readBackupLine reads an exported line from stdin, without echo on a
// terminal: it is a secret.
func (a *app) readBackupLine() (string, error) { return a.readSecretLine("paste the line: ") }

// readSecretLine reads a line from stdin, asking with prompt and without
// echo on a terminal.
func (a *app) readSecretLine(prompt string) (string, error) {
	if f, ok := a.in.(*os.File); ok && isTerminal(f) {
		fd := int(f.Fd())
		old, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
		if err != nil {
			return "", err
		}
		quiet := *old
		quiet.Lflag &^= unix.ECHO
		if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &quiet); err != nil {
			return "", err
		}
		defer func() {
			_ = unix.IoctlSetTermios(fd, ioctlSetTermios, old)
			fmt.Fprintln(a.errOut)
		}()
		fmt.Fprint(a.errOut, prompt)
	}
	line, err := a.readLine(a.ctx)
	switch {
	case errors.Is(err, context.Canceled):
		return "", errAborted
	case err != nil && !errors.Is(err, io.EOF):
		return "", err
	case strings.TrimSpace(line) == "":
		return "", errNoLine
	}
	return line, nil
}

// --- admin keys ------------------------------------------------------------

func adminsExport(a *app, args []string) error {
	s := spec{name: "juist admins export", args: "NAME", min: 1, max: 1, anyNetwork: true, about: `
Print the admin key NAME, as juist admins lists it under KEY HERE, as one
line for a password manager. The line is the key: keep it secret.

  juist admins export alice@home | bx create --name "juist alice" --password-stdin

juist admins import reads it back.`}
	pos, err := a.parse(s, newFlags(s.name), args)
	if err != nil {
		return err
	}
	files, err := a.adminKeyFiles()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(files, func(k adminKeyFile) bool { return k.name == pos[0] })
	if i < 0 {
		return fmt.Errorf("no admin key %q here\nhint: juist admins lists them under KEY HERE", pos[0])
	}
	a.printf("%s\n", backupLine(adminKeyLine, files[i].priv.Seed()))
	return nil
}

func adminsImport(a *app, args []string) error {
	s := spec{name: "juist admins import", args: "NAME", min: 1, max: 1, anyNetwork: true, about: `
Read a line juist admins export printed from stdin and keep its key here as
NAME, such as alice@home. For a line the Android app sealed, the password is
asked for at the terminal if stdin is a file, else read from the next line
of stdin, or asked for if there is none. An existing key is never replaced.`}
	pos, err := a.parse(s, newFlags(s.name), args)
	if err != nil {
		return err
	}
	name := pos[0]
	person, network, _ := strings.Cut(name, "@")
	if err := checkKeyName(name); err != nil {
		return a.usageErr("%v", err)
	}
	if err := checkName("NAME", person); err != nil {
		return a.usageErr("%v", err)
	}
	if u := a.sudoUser(); u != "" {
		return fmt.Errorf("run as %s, without sudo: the key belongs in your keystore", u)
	}
	files, err := a.home.adminKeyFiles()
	if err != nil {
		return err
	}
	if slices.ContainsFunc(files, func(k adminKeyFile) bool { return k.name == name }) {
		return fmt.Errorf("admin key %q is here already", name)
	}
	line, err := a.readBackupLine()
	if err != nil {
		return err
	}
	seed, err := a.adminSeed(line)
	if err != nil {
		return err
	}
	priv, err := types.NewPrivateIdentity(seed)
	if err != nil {
		return errors.New("the line is damaged or cut short")
	}
	if i := slices.IndexFunc(files, func(k adminKeyFile) bool { return k.priv.Public() == priv.Public() }); i >= 0 {
		return fmt.Errorf("the key is here already, as %q", files[i].name)
	}
	if network != "" && a.network == "" && a.namesNetwork(network) {
		a.network = network
	}
	var state *log.State
	if auth := a.readableLog(); auth != nil {
		state = auth.State()
	}
	// Filed under its network at once, as the next command would.
	k, votes := types.AdminKey{}, false
	if state != nil {
		k, votes = state.Admin(priv.Public())
	}
	if votes && network == "" {
		name = adminKeyName(person, state.Network())
		network = state.Network()
		if slices.ContainsFunc(files, func(k adminKeyFile) bool { return k.name == name }) {
			return fmt.Errorf("admin key %q is here already", name)
		}
	}
	if err := a.home.writeSecret(filepath.Join(adminsDir, name+".key"), adminKeyLines(priv, network == "")); err != nil {
		return err
	}
	a.ok("imported admin key %q", name)
	switch {
	case votes:
		a.ok("it casts %s in %q", count(k.Votes, "vote"), state.Network())
	case state != nil:
		a.warn("the key has no vote in %q: it was removed, or is from another network", state.Network())
	}
	return nil
}

// readableLog is the network's log where this user may read it, else nil: a
// check made in passing, which asks nobody to become the operator.
func (a *app) readableLog() *log.Authority {
	n, err := a.openNode()
	if err != nil {
		return nil
	}
	auth, err := n.log()
	if err != nil {
		return nil
	}
	return auth
}

// --- break-glass secrets ---------------------------------------------------

// readBreakGlass reads the break-glass secrets in a file: the line juist
// create shows, or one secret to a line.
func readBreakGlass(path string) ([][]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text, err := keys.OpenText(path, string(b))
	if err != nil {
		return nil, err
	}
	var out [][]byte
	n := 0
	for line := range strings.Lines(text) {
		n++
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, breakGlassLine+"."):
			payload, err := parseBackupLine(line, breakGlassLine)
			if err != nil {
				return nil, fmt.Errorf("%s: line %d: %w", path, n, err)
			}
			secrets, err := splitSecrets(payload)
			if err != nil {
				return nil, fmt.Errorf("%s: line %d: %w", path, n, err)
			}
			out = append(out, secrets...)
			continue
		}
		s, err := b64.DecodeString(line)
		if err != nil || len(s) != types.DisablementSecretSize {
			return nil, fmt.Errorf("%s: line %d is not a break-glass secret", path, n)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s holds no break-glass secret", path)
	}
	return out, nil
}

// splitSecrets is a line's payload as secrets: one, or as many as a line
// exported from a file of them held.
func splitSecrets(payload []byte) ([][]byte, error) {
	n := len(payload) / types.DisablementSecretSize
	if n == 0 || n > types.MaxDisablementValues || len(payload)%types.DisablementSecretSize != 0 {
		return nil, errors.New("the line is damaged or cut short")
	}
	out := make([][]byte, n)
	for i := range out {
		out[i] = payload[i*types.DisablementSecretSize : (i+1)*types.DisablementSecretSize]
	}
	return out, nil
}

// keystoreBreakGlass reads the break-glass file in the keystore, where one
// holds secrets of state's network: the one named for it, or, after a rename,
// for what it was called. None is no error.
func (a *app) keystoreBreakGlass(state *log.State) ([][]byte, error) {
	entries, err := os.ReadDir(a.home.path)
	if err != nil {
		return nil, err
	}
	named := breakGlassFile(state.Network())
	var paths []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "break-glass-") && strings.HasSuffix(e.Name(), ".secrets") {
			paths = append(paths, e.Name())
		}
	}
	slices.SortStableFunc(paths, func(x, y string) int {
		switch {
		case x == named:
			return -1
		case y == named:
			return 1
		}
		return 0
	})
	for _, p := range paths {
		secrets, err := readBreakGlass(a.home.join(p))
		switch {
		case err != nil && p == named:
			return nil, err
		case err != nil:
			continue // another network's, or damaged; not this one's by its name
		case slices.ContainsFunc(secrets, state.ValidDisablement):
			return secrets, nil
		}
	}
	return nil, nil
}

// --- disabling the network -------------------------------------------------

// breakGlassFrom reads the secrets --secrets names: a file, or - for stdin; or
// where it names none, an older network's file in the keystore, else stdin.
func (a *app) breakGlassFrom(from string, state *log.State) ([][]byte, error) {
	switch from {
	case "":
		if secrets, err := a.keystoreBreakGlass(state); err != nil || secrets != nil {
			return secrets, err
		}
	case "-":
	default:
		return readBreakGlass(a.path(from))
	}
	line, err := a.readBackupLine()
	if err != nil {
		return nil, err
	}
	payload, err := parseBackupLine(line, breakGlassLine)
	if err != nil {
		return nil, err
	}
	return splitSecrets(payload)
}

func networkDisable(a *app, args []string) error {
	s := spec{name: "juist network disable", about: `
End the network for good: a record with its break-glass secret, the line
juist create showed, stops every device it reaches. Nothing undoes it; each
device starts over with juist reset.`}
	fs := newFlags(s.name)
	from := fs.String("secrets", "", "`FILE` with the break-glass secret, - for stdin (default: the keystore's file, else stdin)")
	yes := fs.Bool("yes", false, "do not ask")
	if _, err := a.parse(s, fs, args); err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	if auth.Disabled() != nil {
		return fmt.Errorf("%q is disabled already", state.Network())
	}
	if liveStatus(a.node) == nil {
		return errors.New("no juistd here to hand the record on\nhint: run it on a device of the network")
	}
	secrets, err := a.breakGlassFrom(*from, state)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(secrets, state.ValidDisablement)
	if i < 0 {
		return fmt.Errorf("no break-glass secret of %q found", state.Network())
	}
	if err := a.proceedNow(*yes, fmt.Sprintf("end %q for good? every device stops, and nothing undoes it",
		state.Network())); err != nil {
		return err
	}
	aum, err := auth.Builder().Disable(types.DisablementSecret(secrets[i]))
	if err != nil {
		return err
	}
	if err := a.applyRecords([]types.AUM{aum}); err != nil {
		return err
	}
	a.ok("disabled %q; every device stops as the record reaches it", state.Network())
	return nil
}

// adminSeed is the key a line juist admins export or the app wrote holds,
// asking for the password of one sealed by it.
func (a *app) adminSeed(line string) ([]byte, error) {
	if backupline.Tag(line) != backupline.SealedAdminKey {
		return parseBackupLine(line, adminKeyLine)
	}
	password, err := a.readPassword()
	if err != nil {
		return nil, err
	}
	return backupline.Open(line, strings.TrimRight(password, "\r\n"))
}

// readPassword reads the password of a sealed line by what stdin is, not
// by when the password comes: from a file, as `juist admins import NAME <
// FILE` reads the app's, at the terminal; from a pipe, whose writer gives
// both lines, next on it, and at the terminal where it ends without one;
// at the terminal itself, there.
func (a *app) readPassword() (string, error) {
	f, ok := a.in.(*os.File)
	if !ok || isTerminal(f) {
		return a.readSecretLine("password: ")
	}
	tty, ttyErr := a.tty()
	if ttyErr == nil {
		defer tty.Close()
	}
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		// Typed into the pipe's writer, as with `cat FILE - |`, it echoes:
		// say where it is read, where a person may be there to see.
		if ttyErr == nil {
			fmt.Fprintln(a.errOut, "password: read from the next line of stdin")
		}
		password, err := a.readSecretLine("password: ")
		if !errors.Is(err, errNoLine) {
			return password, err
		}
	}
	if ttyErr != nil {
		return a.readSecretLine("password: ")
	}
	t := &app{ctx: a.ctx, in: tty, out: a.out, errOut: a.errOut}
	return t.readSecretLine("password: ")
}

// errNoLine is readSecretLine's error where stdin holds no further line.
var errNoLine = errors.New("no line on stdin")
