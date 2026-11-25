package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/nning/juist/internal/atomicfile"
	"github.com/nning/juist/internal/cliflag"
	"github.com/nning/juist/internal/tray"
	"golang.org/x/sys/unix"
)

// trayEntry starts juist tray with the person's desktop session.
const trayEntry = `[Desktop Entry]
Type=Application
Name=juist
Comment=juist's state and exit node in the status bar
Exec=juist tray
TryExec=juist
Terminal=false
X-GNOME-Autostart-enabled=true
`

func cmdTray(a *app, args []string) error {
	s := spec{name: "juist tray", anyNetwork: true, about: `
Show this device's state in the desktop's status bar: whether it is
connected, the exit node in use, and what juist health warns of. Its menu
copies the device's name and addresses, lists the devices and switches the
exit node; for another user than the operator, it shows the state alone.
--autostart starts it with your desktop session from then on.`}
	fs := newFlags(s.name)
	autostart := fs.Bool("autostart", false, "start it with your desktop session; =false: no longer")
	if _, err := a.parse(s, fs, args); err != nil {
		return err
	}
	switch {
	case !trayRuns:
		return errors.New("juist tray runs on Linux desktops")
	case a.network != "" && !a.networkFromEnv:
		return a.usageErr("--network cannot be used with juist tray")
	case cliflag.IsSet(fs, "autostart") && a.socketExplicit && !a.socketFromEnv:
		return a.usageErr("--socket cannot be used with --autostart")
	case cliflag.IsSet(fs, "autostart"):
		return a.trayAutostart(*autostart)
	}
	env := os.Environ()
	c, program := a.trayConfig()
	err := trayRun(a.ctx, c)
	if errors.Is(err, tray.ErrReplaced) {
		// The new juist takes the tray over, at the path the old one was
		// started from, which FreeBSD no longer names once it is replaced,
		// with the session's environment as it came.
		return trayExec(program, os.Args, env)
	}
	return err
}

// trayRun and trayExec are tray.Run and execve(2), and executable
// os.Executable; tests replace them.
var (
	trayRun    = tray.Run
	trayExec   = unix.Exec
	executable = os.Executable
)

// trayRuns is whether juist tray runs here.
var trayRuns = tray.Supported

// trayConfig is what juist tray watches. The juist it runs is told the
// network by its arguments alone: the session's JUIST_SOCKET and
// JUIST_NETWORK, which the globals read from the process, are dropped.
func (a *app) trayConfig() (c tray.Config, program string) {
	os.Unsetenv("JUIST_SOCKET")
	os.Unsetenv("JUIST_NETWORK")
	c = tray.Config{SocketOf: a.host.socket, Home: a.host.home, Juist: a.trayJuist, Stderr: a.errOut}
	if a.socketExplicit {
		c.SocketOf, c.Only = func(int) string { return a.socket }, true
	}
	if path, err := executable(); err == nil {
		program = strings.TrimSuffix(path, " (deleted)")
		c.Replaced = replacedSince(program)
	}
	return c, program
}

// replacedSince reports whether path names another file than it does now,
// as after a package's update, one that can be run.
func replacedSince(path string) func() bool {
	before, err := os.Stat(path)
	if err != nil {
		return nil
	}
	return func() bool {
		now, err := os.Stat(path)
		return err == nil && !os.SameFile(before, now) && now.Mode()&0o111 != 0
	}
}

// trayAutostartFile is the person's autostart entry for juist tray.
func (a *app) trayAutostartFile() (string, error) {
	dir := a.getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home := a.getenv("HOME")
		if home == "" {
			return "", errors.New("neither $XDG_CONFIG_HOME nor $HOME is set")
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "autostart", "juist-tray.desktop"), nil
}

func (a *app) trayAutostart(on bool) error {
	path, err := a.trayAutostartFile()
	if err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	has := err == nil && string(b) == trayEntry
	switch {
	case on && has:
		a.ok("unchanged: juist tray starts with your desktop session")
	case on:
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := atomicfile.Write(path, []byte(trayEntry), 0o644); err != nil {
			return err
		}
		a.ok("juist tray starts with your desktop session")
	case errors.Is(err, os.ErrNotExist):
		a.ok("unchanged: juist tray does not start with your desktop session")
	default:
		if err := os.Remove(path); err != nil {
			return err
		}
		a.ok("juist tray no longer starts with your desktop session")
	}
	return nil
}

// runMain is app.main, set at init: the command table names cmdTray, which
// runs it.
var runMain func(*app, []string) error

func init() { runMain = (*app).main }

// trayJuist runs juist in this process for the tray, as the person would
// run it.
func (a *app) trayJuist(ctx context.Context, args []string) (string, string, error) {
	var out, errOut bytes.Buffer
	b := newApp(strings.NewReader(""), &out, &errOut)
	b.ctx, b.host, b.getenv = ctx, a.host, a.getenv
	err := runMain(b, args)
	if err != nil && !errors.Is(err, errSilent) {
		b.fail(err)
	}
	return out.String(), errOut.String(), err
}
