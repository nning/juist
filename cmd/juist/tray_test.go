package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nning/juist/internal/tray"
)

// juist tray --autostart puts the person's autostart entry in place, and
// =false takes it away; each says when nothing changed.
func TestTrayAutostart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	entry := filepath.Join(dir, "autostart", "juist-tray.desktop")
	run := func(args ...string) string {
		var out syncBuffer
		a := newApp(strings.NewReader(""), &out, &out)
		a.getenv = func(k string) string {
			if k == "XDG_CONFIG_HOME" {
				return dir
			}
			return ""
		}
		if err := a.main(append([]string{"tray"}, args...)); err != nil {
			t.Fatalf("juist tray %v: %v\n%s", args, err, out.String())
		}
		return out.String()
	}
	for _, step := range []struct {
		args    []string
		say     string
		entered bool
	}{
		{[]string{"--autostart=false"}, "unchanged: juist tray does not start with your desktop session\n", false},
		{[]string{"--autostart"}, "juist tray starts with your desktop session\n", true},
		{[]string{"--autostart"}, "unchanged: juist tray starts with your desktop session\n", true},
		{[]string{"--autostart=false"}, "juist tray no longer starts with your desktop session\n", false},
	} {
		if got := run(step.args...); got != step.say {
			t.Errorf("juist tray %v says %q, want %q", step.args, got, step.say)
		}
		b, err := os.ReadFile(entry)
		if step.entered != (err == nil) || step.entered && string(b) != trayEntry {
			t.Errorf("after juist tray %v the entry is %q, %v", step.args, b, err)
		}
	}
}

// The entry starts juist tray in every desktop, and their autostart
// settings list it, so that it can be turned off there too.
func TestTrayEntryStartsInEveryDesktop(t *testing.T) {
	t.Parallel()
	keys := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(trayEntry), "\n")[1:] {
		k, v, _ := strings.Cut(l, "=")
		keys[k] = v
	}
	for k, want := range map[string]string{"Type": "Application", "Exec": "juist tray", "TryExec": "juist"} {
		if keys[k] != want {
			t.Errorf("%s=%q, want %q", k, keys[k], want)
		}
	}
	for _, k := range []string{"NoDisplay", "Hidden", "OnlyShowIn", "NotShowIn"} {
		if v, ok := keys[k]; ok {
			t.Errorf("%s=%s keeps it from a desktop or from its autostart settings", k, v)
		}
	}
}

func TestTrayArguments(t *testing.T) {
	t.Parallel()
	for args, want := range map[string]string{
		"tray home":                 "juist: unexpected argument",
		"--network home tray":       "juist: --network cannot be used with juist tray\n",
		"tray --autostart=sometime": "juist: ",
		"-s /x tray --autostart":    "juist: --socket cannot be used with --autostart\n",
		"--network home tray -a":    "juist: --network cannot be used with juist tray\n",
	} {
		var out syncBuffer
		a := newApp(strings.NewReader(""), &out, &out)
		err := a.main(strings.Fields(args))
		if err == nil {
			t.Errorf("juist %s ran", args)
			continue
		}
		a.fail(err)
		if !strings.HasPrefix(out.String(), want) {
			t.Errorf("juist %s says %q, want %q…", args, out.String(), want)
		}
	}
}

// The tray's own juist is told the network by its arguments alone: the
// session's JUIST_SOCKET and JUIST_NETWORK go, its keystore stays.
func TestTrayDropsTheSessionsNetworkAndSocket(t *testing.T) {
	t.Setenv("JUIST_NETWORK", "work")
	t.Setenv("JUIST_SOCKET", "/elsewhere.sock")
	t.Setenv("JUIST_HOME", "/keys")
	a := newApp(strings.NewReader(""), io.Discard, io.Discard)
	a.trayConfig()
	g, _, err := extractGlobals(nil)
	if err != nil || g.network != "" || g.socket != "" || g.home != "/keys" {
		t.Errorf("the tray's juist reads network %q, socket %q, home %q, %v", g.network, g.socket, g.home, err)
	}
}

func TestTrayWatchesTheSocketGiven(t *testing.T) {
	t.Parallel()
	a := newApp(strings.NewReader(""), io.Discard, io.Discard)
	a.socket, a.socketExplicit = "/run/x.sock", true
	if c, _ := a.trayConfig(); !c.Only || c.SocketOf(0) != "/run/x.sock" || c.SocketOf(3) != "/run/x.sock" {
		t.Errorf("with --socket the tray watches %v %q", c.Only, c.SocketOf(0))
	}
}

// Where juist tray does not run, --autostart says so too, rather than
// write an entry nothing reads.
func TestTrayRefusedWhereItDoesNotRun(t *testing.T) {
	was := trayRuns
	trayRuns = false
	defer func() { trayRuns = was }()
	dir := t.TempDir()
	var out syncBuffer
	a := newApp(strings.NewReader(""), &out, &out)
	a.getenv = func(k string) string { return map[string]string{"XDG_CONFIG_HOME": dir}[k] }
	err := a.main([]string{"tray", "--autostart"})
	if err == nil || err.Error() != "juist tray runs on Linux desktops" {
		t.Errorf("juist tray --autostart: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "autostart")); err == nil {
		t.Error("an entry was written")
	}
}

// A tray notices its program replaced, as an update replaces it, and only
// by one that can run.
func TestTrayNoticesJuistReplaced(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "juist")
	os.WriteFile(path, []byte("old"), 0o755)
	replaced := replacedSince(path)
	if replaced() {
		t.Fatal("replaced before anything changed")
	}
	next := filepath.Join(dir, "juist.new")
	os.WriteFile(next, []byte("new"), 0o644)
	os.Rename(next, path)
	if replaced() {
		t.Error("replaced by a file that cannot run")
	}
	os.Chmod(path, 0o755)
	if !replaced() {
		t.Error("not replaced after the update")
	}
}

// juist tray ends with main's context, and a tray whose juist was replaced
// starts the new one at the path it was started from, which FreeBSD no
// longer names then, with the session's environment as it came.
func TestTrayRestartsFromWhereItStarted(t *testing.T) {
	t.Setenv("JUIST_SOCKET", "/run/x.sock")
	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "main's")
	was := []any{trayRun, trayExec, executable}
	defer func() {
		trayRun = was[0].(func(context.Context, tray.Config) error)
		trayExec = was[1].(func(string, []string, []string) error)
		executable = was[2].(func() (string, error))
	}()
	executable = func() (string, error) { return "/usr/bin/juist", nil }
	trayRun = func(c context.Context, _ tray.Config) error {
		if c.Value(key{}) != "main's" {
			t.Error("the tray runs without main's context")
		}
		executable = func() (string, error) { return "", os.ErrNotExist }
		return tray.ErrReplaced
	}
	var path string
	var env []string
	trayExec = func(p string, _ []string, e []string) error {
		path, env = p, e
		return nil
	}
	a := newApp(strings.NewReader(""), io.Discard, io.Discard)
	a.ctx = ctx
	if err := a.main([]string{"tray"}); err != nil {
		t.Fatal(err)
	}
	if path != "/usr/bin/juist" || !slices.Contains(env, "JUIST_SOCKET=/run/x.sock") {
		t.Errorf("restarted %q with %q", path, env)
	}
}

// $JUIST_SOCKET is the session's, which the autostarted tray gets too:
// --autostart takes it, as it does not --socket.
func TestTrayAutostartWithTheSessionsSocket(t *testing.T) {
	t.Setenv("JUIST_SOCKET", "/run/x.sock")
	dir := t.TempDir()
	var out syncBuffer
	a := newApp(strings.NewReader(""), &out, &out)
	a.getenv = func(k string) string { return map[string]string{"XDG_CONFIG_HOME": dir}[k] }
	if err := a.main([]string{"tray", "--autostart"}); err != nil || out.String() != "juist tray starts with your desktop session\n" {
		t.Errorf("with $JUIST_SOCKET: %v, %q", err, out.String())
	}
}

// --socket over the session's JUIST_SOCKET is refused with --autostart
// still: the entry would not name it.
func TestTrayAutostartRefusesSocketOverSessions(t *testing.T) {
	t.Setenv("JUIST_SOCKET", "/run/y.sock")
	dir := t.TempDir()
	var out syncBuffer
	a := newApp(strings.NewReader(""), &out, &out)
	a.getenv = func(k string) string { return map[string]string{"XDG_CONFIG_HOME": dir}[k] }
	err := a.main([]string{"-s", "/x", "tray", "--autostart"})
	if err == nil {
		t.Fatal("--socket with --autostart ran")
	}
	a.fail(err)
	if !strings.HasPrefix(out.String(), "juist: --socket cannot be used with --autostart") {
		t.Errorf("%q", out.String())
	}
}

// The tray's own juist, told the network it runs for, reads health and
// status and switches the exit node as a person does, though the host
// knows another instance down the tray does not show.
func TestTrayJuistBesideAnInstanceDown(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home")
	if err := os.WriteFile(filepath.Join(h.layout.wantsDir, unitOf(1)), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	a := h.cli.app(&syncBuffer{}, "")
	ctx := context.Background()
	run := func(args ...string) (string, string) {
		out, errOut, err := a.trayJuist(ctx, append([]string{"--network", "juist0"}, args...))
		if err != nil {
			t.Fatalf("juist %v: %v\n%s%s", args, err, out, errOut)
		}
		return out, errOut
	}
	if out, _ := run("status"); !strings.HasPrefix(out, "home · ") {
		t.Errorf("status:\n%s", out)
	}
	if out, errOut := run("health"); strings.Contains(out+errOut, "juist1") || strings.Contains(errOut, "juistd not running") {
		t.Errorf("health speaks of the instance down:\n%s%s", out, errOut)
	}
	if out, _ := run("exit", "off"); out != "unchanged: internet direct\n" {
		t.Errorf("exit off: %q", out)
	}
}
