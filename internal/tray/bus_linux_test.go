//go:build linux && !android

package tray

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"
	"github.com/nning/juist/internal/sniprobe"
	"github.com/nning/juist/ipc"
)

func TestMain(m *testing.M) {
	// The tray itself, as juist tray runs it, on the socket and with the
	// fake juist startTray names.
	if sock := os.Getenv("JUIST_TRAY_SOCKET"); sock != "" {
		pollEvery, noBarGrace, replacedEvery = 100*time.Millisecond, 300*time.Millisecond, 100*time.Millisecond
		registerEvery = 100 * time.Millisecond
		c := testConfig(sock, true, os.Getenv("JUIST_TRAY_JUIST"))
		c.Stderr = os.Stderr
		if f := os.Getenv("JUIST_TRAY_REPLACED"); f != "" {
			c.Replaced = func() bool { _, err := os.Stat(f); return err == nil }
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		err := Run(ctx, c)
		stop()
		switch {
		case errors.Is(err, ErrReplaced):
			fmt.Println("replaced")
			os.Exit(3)
		case err != nil:
			fmt.Fprintf(os.Stderr, "juist: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// sessionBus starts a D-Bus daemon of the test's own and connects to it.
func sessionBus(t *testing.T) (*dbus.Conn, string) {
	t.Helper()
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		if os.Getenv("JUIST_REQUIRE_DBUS") != "" {
			t.Fatal("JUIST_REQUIRE_DBUS is set, and dbus-daemon is not installed")
		}
		t.Skip("needs dbus-daemon")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "bus")
	conf := filepath.Join(dir, "bus.conf")
	os.WriteFile(conf, []byte(`<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path=`+sock+`</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
`), 0o644)
	cmd := exec.Command(daemon, "--nofork", "--config-file="+conf)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	addr := "unix:path=" + sock
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := dbus.Connect(addr)
		if err == nil {
			t.Cleanup(func() { conn.Close() })
			return conn, addr
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// fakeWatcher is the part of a status bar items register with.
type fakeWatcher struct {
	mu    sync.Mutex
	items []string
	props *prop.Properties
}

func (w *fakeWatcher) RegisterStatusNotifierItem(sender dbus.Sender, service string) *dbus.Error {
	if strings.HasPrefix(service, "/") {
		service = string(sender) + service
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.items = append(w.items, service)
	w.props.SetMust(watcherName, "RegisteredStatusNotifierItems", slices.Clone(w.items))
	return nil
}

// forget drops every registration, as a watcher that missed one has none.
func (w *fakeWatcher) forget() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.items = nil
	w.props.SetMust(watcherName, "RegisteredStatusNotifierItems", []string{})
}

func serveWatcher(t *testing.T, conn *dbus.Conn) *fakeWatcher {
	t.Helper()
	w := &fakeWatcher{}
	var err error
	w.props, err = prop.Export(conn, "/StatusNotifierWatcher", prop.Map{watcherName: {
		"RegisteredStatusNotifierItems": {Value: []string{}, Emit: prop.EmitTrue},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Export(w, "/StatusNotifierWatcher", watcherName); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.RequestName(watcherName, dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	return w
}

// An item the bar's watcher does not list, as when its registration was
// missed while the bar started, is registered again.
func TestTrayRegistersAgainWhereTheBarMissedIt(t *testing.T) {
	conn, addr := sessionBus(t)
	w := serveWatcher(t, conn)
	dir := t.TempDir()
	fakeJuist(t, dir)
	startTray(t, addr, dir, filepath.Join(dir, "none.sock"))
	found := func() (string, bool) {
		_, err := sniprobe.Find(conn, "juist")
		return fmt.Sprint(err), err == nil
	}
	eventually(t, "the item registered", found)
	w.forget()
	eventually(t, "the item registered again", found)
}

// fakeNotes is a notification daemon that hands each notification on.
type fakeNotes chan string

func (n fakeNotes) Notify(app string, id uint32, icon, summary, body string, actions []string,
	hints map[string]dbus.Variant, timeout int32) (uint32, *dbus.Error) {
	n <- summary + ": " + body
	return 1, nil
}

func serveNotes(t *testing.T, conn *dbus.Conn) fakeNotes {
	t.Helper()
	n := make(fakeNotes, 16)
	if err := conn.Export(n, "/org/freedesktop/Notifications", "org.freedesktop.Notifications"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.RequestName("org.freedesktop.Notifications", dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	return n
}

// syncBuffer is a bytes.Buffer two goroutines may use.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startTray runs this test binary as the tray on the bus at addr, watching
// sock, with the fake juist in dir.
func startTray(t *testing.T, addr, dir, sock string, env ...string) (*exec.Cmd, *syncBuffer, chan error) {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	// fyne.io/systray races itself (refresh against GetLayout): the race
	// detector's reports are judged below, not by the exit status.
	cmd.Env = append(append(os.Environ(), "JUIST_TRAY_SOCKET="+sock, "JUIST_TRAY_JUIST="+filepath.Join(dir, "juist"),
		"DBUS_SESSION_BUS_ADDRESS="+addr, "GORACE=exitcode=0", "GOMAXPROCS=1"), env...)
	out := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done, exited := make(chan error, 1), make(chan struct{})
	go func() { done <- cmd.Wait(); close(exited) }()
	t.Cleanup(func() {
		cmd.Process.Kill()
		<-exited
		for _, r := range strings.Split(out.String(), "WARNING: DATA RACE")[1:] {
			if strings.Contains(r, "nning/juist/internal/tray") {
				t.Error("the tray races")
			}
		}
		if t.Failed() {
			t.Logf("the tray said:\n%s", out)
		}
	})
	return cmd, out, done
}

func eventually(t *testing.T, what string, check func() (string, bool)) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		got, ok := check()
		if ok {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: last saw\n%s", what, got)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func menuOf(it *sniprobe.Item) ([]sniprobe.Entry, string) {
	m, err := it.Menu()
	if err != nil {
		return nil, err.Error()
	}
	return m, sniprobe.Format(m)
}

func TestTrayOnTheBus(t *testing.T) {
	conn, addr := sessionBus(t)
	serveWatcher(t, conn)
	notes := serveNotes(t, conn)
	dir := t.TempDir()
	sock := filepath.Join(dir, "run", "juistd.sock")
	d := newFakeDaemon(t, sock, operated())
	_, calls := fakeJuist(t, dir)
	_, _, done := startTray(t, addr, dir, sock)

	var item *sniprobe.Item
	eventually(t, "the item registered", func() (string, bool) {
		var err error
		item, err = sniprobe.Find(conn, "juist")
		return fmt.Sprint(err), err == nil
	})
	title := func(want string) func() (string, bool) {
		return func() (string, bool) {
			got, err := item.Title()
			return fmt.Sprint(got, err), got == want
		}
	}
	eventually(t, "connected", title("juist: connected"))
	icon := func() []byte {
		b, err := item.Icon()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	eventually(t, "the tooltip", func() (string, bool) {
		got, _ := item.ToolTip()
		return got, got == "home · connected\nThis device laptop 100.70.0.1"
	})
	connected := icon()

	m := eventually(t, "the exit nodes granted", func() (string, bool) {
		_, s := menuOf(item)
		return s, strings.Contains(s, "  [x] None\n  [ ] fb\n  [ ] srv (not serving) (off)\n")
	})
	for _, want := range []string{"This device: laptop\n", "100.70.0.1\n", "Devices: 3 others, 1 without a tunnel\n  fb — direct\n"} {
		if !strings.Contains(m, want) {
			t.Errorf("the menu lacks %q:\n%s", want, m)
		}
	}
	entries, _ := menuOf(item)
	fbEntry, _ := sniprobe.Lookup(entries, "fb")
	if err := item.Click(fbEntry.ID); err != nil {
		t.Fatal(err)
	}
	eventually(t, "juist exit use fb run", func() (string, bool) {
		got := readCalls(t, calls)
		return strings.Join(got, "\n"), slices.Contains(got, "--socket "+sock+" exit use fb")
	})
	eventually(t, "notified of the choice's warning", func() (string, bool) {
		select {
		case n := <-notes:
			return n, n == "internet via fb: warning: fb is offline; internet traffic waits for it"
		default:
			return "", false
		}
	})
	st := operated()
	st.Exit.Node, st.Exit.Name = fb, "fb"
	d.set(st)
	eventually(t, "the icon says the exit node", title("juist: connected, exit node fb"))
	exiting := icon()
	if bytes.Equal(exiting, connected) {
		t.Error("the icon did not change for the exit node")
	}
	eventually(t, "fb checked", func() (string, bool) {
		_, s := menuOf(item)
		return s, strings.Contains(s, "  [ ] None\n  [x] fb\n")
	})

	// A new warning, found as the state changes, is a notification and a
	// badge.
	os.WriteFile(filepath.Join(dir, "warnings"), []byte("warning: DNS goes around fb\n"), 0o644)
	st = operated()
	st.Exit.Node, st.Exit.Name = fb, "fb"
	st.TunnelsLive, st.TunnelsDown, st.Reach[2] = 3, nil, ipc.PeerReach{Identity: pho, Live: true, Direct: true}
	d.set(st)
	eventually(t, "notified of the warning", func() (string, bool) {
		select {
		case n := <-notes:
			return n, n == "juist: warning: DNS goes around fb"
		default:
			return "", false
		}
	})
	eventually(t, "the warning counted", title("juist: connected, exit node fb, 1 warning"))

	// Another user than the operator: the state, no members, no switches.
	r := st.ForReader()
	r.CanOperate = false
	d.set(&r)
	m = eventually(t, "the reader's menu", func() (string, bool) {
		_, s := menuOf(item)
		return s, strings.Contains(s, "Read-only: root manages this device")
	})
	if !strings.Contains(m, "Exit node: member 1 (off)\n") || !strings.Contains(m, "Devices: 3 others (off)\n") ||
		strings.Contains(m, "None") || strings.Contains(m, "direct") {
		t.Errorf("a reader's menu:\n%s", m)
	}

	// juistd stops and starts again: off, and back, the tray running on.
	warned := icon()
	d.stop()
	eventually(t, "off", title("juist: juistd not running"))
	if off := icon(); bytes.Equal(off, warned) || bytes.Equal(off, connected) || bytes.Equal(off, exiting) {
		t.Error("the icon did not turn off")
	}
	d.set(st)
	d.start(t)
	eventually(t, "back", title("juist: connected, exit node fb, 1 warning"))
	eventually(t, "the icon back", func() (string, bool) { return "", bytes.Equal(icon(), warned) })

	// A second tray in the session stops at once.
	_, out2, done2 := startTray(t, addr, dir, sock)
	select {
	case err := <-done2:
		if err == nil || !strings.Contains(out2.String(), "juist: juist tray already runs in this session") {
			t.Errorf("a second tray ended with %v:\n%s", err, out2)
		}
	case <-time.After(15 * time.Second):
		t.Error("a second tray is running")
	}

	entries, _ = menuOf(item)
	quit, _ := sniprobe.Lookup(entries, "Quit")
	// It may be gone before the click is answered.
	item.Click(quit.ID)
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Quit ended it with %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Error("Quit did not end it")
	}
}

// The item is "juist" to the bar whatever the first state it shows, which
// juistd not answering makes come at once.
func TestTheItemIsJuistWhateverTheState(t *testing.T) {
	for range 5 {
		conn, addr := sessionBus(t)
		serveWatcher(t, conn)
		dir := t.TempDir()
		fakeJuist(t, dir)
		cmd, _, _ := startTray(t, addr, dir, filepath.Join(dir, "none.sock"))
		eventually(t, "the item registered as juist", func() (string, bool) {
			_, err := sniprobe.Find(conn, "juist")
			return fmt.Sprint(err), err == nil
		})
		cmd.Process.Kill()
	}
}

// A signal ends the tray, as Ctrl-C or a session's end sends it.
func TestTrayEndsOnASignal(t *testing.T) {
	for _, sig := range []os.Signal{syscall.SIGTERM, os.Interrupt} {
		conn, addr := sessionBus(t)
		serveWatcher(t, conn)
		dir := t.TempDir()
		fakeJuist(t, dir)
		cmd, _, done := startTray(t, addr, dir, filepath.Join(dir, "none.sock"))
		eventually(t, "the item registered", func() (string, bool) {
			_, err := sniprobe.Find(conn, "juist")
			return fmt.Sprint(err), err == nil
		})
		cmd.Process.Signal(sig)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("%v ended it with %v", sig, err)
			}
		case <-time.After(15 * time.Second):
			t.Fatalf("%v did not end it", sig)
		}
	}
}

// A tray whose juist was replaced ends, for the new one to start.
func TestTrayEndsWhenJuistIsReplaced(t *testing.T) {
	conn, addr := sessionBus(t)
	serveWatcher(t, conn)
	dir := t.TempDir()
	fakeJuist(t, dir)
	flag := filepath.Join(dir, "replaced")
	_, out, done := startTray(t, addr, dir, filepath.Join(dir, "none.sock"), "JUIST_TRAY_REPLACED="+flag)
	eventually(t, "the item registered", func() (string, bool) {
		_, err := sniprobe.Find(conn, "juist")
		return fmt.Sprint(err), err == nil
	})
	os.WriteFile(flag, nil, 0o644)
	select {
	case err := <-done:
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 3 || !strings.Contains(out.String(), "replaced") {
			t.Errorf("ended with %v:\n%s", err, out)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("still running once replaced")
	}
}

func TestTraySaysWhereNoStatusBarShowsIt(t *testing.T) {
	conn, addr := sessionBus(t)
	notes := serveNotes(t, conn)
	dir := t.TempDir()
	sock := filepath.Join(dir, "run", "juistd.sock")
	newFakeDaemon(t, sock, operated())
	fakeJuist(t, dir)
	_, out, _ := startTray(t, addr, dir, sock)
	select {
	case n := <-notes:
		if n != "No status bar shows juist's icon: On GNOME, turn on the AppIndicator extension, then log in again." {
			t.Errorf("notified %q", n)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no notification")
	}
	eventually(t, "the warning on stderr", func() (string, bool) {
		s := out.String()
		return s, strings.Contains(s, "warning: no status bar here shows juist's icon\nhint: on GNOME, turn on the AppIndicator extension, then log in again\n")
	})
}

func TestTrayNeedsASession(t *testing.T) {
	dir := t.TempDir()
	fakeJuist(t, dir)
	cmd, out, done := startTray(t, "unix:path="+filepath.Join(dir, "nobus"), dir, filepath.Join(dir, "s"))
	_ = cmd
	select {
	case err := <-done:
		if err == nil || !strings.HasPrefix(out.String(), "juist: no desktop session: ") {
			t.Errorf("without a bus: %v\n%s", err, out)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("still running without a bus")
	}
}

// stuckNotes is a notification daemon that never answers.
type stuckNotes chan struct{}

func (n stuckNotes) Notify(app string, id uint32, icon, summary, body string, actions []string,
	hints map[string]dbus.Variant, timeout int32) (uint32, *dbus.Error) {
	select {
	case n <- struct{}{}:
	default:
	}
	select {}
}

// A notification daemon that does not answer holds up no end of the tray.
func TestTrayEndsThoughNotificationsHang(t *testing.T) {
	conn, addr := sessionBus(t)
	serveWatcher(t, conn)
	n := make(stuckNotes, 1)
	conn.Export(n, "/org/freedesktop/Notifications", "org.freedesktop.Notifications")
	conn.RequestName("org.freedesktop.Notifications", dbus.NameFlagDoNotQueue)
	dir := t.TempDir()
	sock := filepath.Join(dir, "run", "juistd.sock")
	st := operated()
	st.NotMember = true
	newFakeDaemon(t, sock, st)
	fakeJuist(t, dir)
	cmd, _, done := startTray(t, addr, dir, sock)
	waitNotify(t, n)
	cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("SIGTERM did not end the tray while a notification hangs")
	}
}

func waitNotify(t *testing.T, n stuckNotes) {
	t.Helper()
	select {
	case <-n:
	case <-time.After(15 * time.Second):
		t.Fatal("no notification")
	}
}

// A notification daemon that does not answer holds the icon up 5 s at
// most: the next state shows.
func TestTrayShowsOnThoughNotificationsHang(t *testing.T) {
	conn, addr := sessionBus(t)
	serveWatcher(t, conn)
	n := make(stuckNotes, 1)
	conn.Export(n, "/org/freedesktop/Notifications", "org.freedesktop.Notifications")
	conn.RequestName("org.freedesktop.Notifications", dbus.NameFlagDoNotQueue)
	dir := t.TempDir()
	sock := filepath.Join(dir, "run", "juistd.sock")
	st := operated()
	st.NotMember = true
	d := newFakeDaemon(t, sock, st)
	fakeJuist(t, dir)
	startTray(t, addr, dir, sock)
	waitNotify(t, n)
	d.set(operated())
	var item *sniprobe.Item
	eventually(t, "the item registered", func() (string, bool) {
		var err error
		item, err = sniprobe.Find(conn, "juist")
		return fmt.Sprint(err), err == nil
	})
	eventually(t, "connected", func() (string, bool) {
		got, err := item.Title()
		return fmt.Sprint(got, err), got == "juist: connected"
	})
}
