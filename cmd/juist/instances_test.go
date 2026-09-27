package main

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/daemon"
	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/ipc"
)

// testHost is a host as the package sets one up: juistd.service running in a
// state directory of its own, and juistd@.service installed, whose
// instances the CLI starts and stops in-process here.
type testHost struct {
	t      *testing.T
	layout *hostLayout
	cli    *cli

	mu       sync.Mutex
	stops    map[int]func()
	started  []int
	stopped  []int
	firewall func(ctx context.Context, action string, n int) error
	walls    []string // the firewall calls made, as "allow juist1"
}

func newHost(t *testing.T) *testHost {
	t.Helper()
	dir := shortTempDir(t)
	h := &testHost{t: t, stops: map[int]func(){}}
	h.firewall = func(_ context.Context, action string, n int) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.walls = append(h.walls, action+" "+instance.Name(n))
		return nil
	}
	h.layout = &hostLayout{
		runDir:   filepath.Join(dir, "run"),
		stateDir: filepath.Join(dir, "state"),
		wantsDir: filepath.Join(dir, "wants"),
		unitDirs: []string{filepath.Join(dir, "units")},
		start:    h.start,
		stop:     h.stop,
		firewall: h.firewall,
	}
	for _, d := range []string{h.layout.runDir, h.layout.stateDir, h.layout.wantsDir, h.layout.unitDirs[0]} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(h.layout.unitDirs[0], "juistd@.service"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	h.stops[0] = startInstanceService(t, h.layout.home(0), h.layout.socket(0), 0)
	h.cli = newCLI(t)
	h.cli.host, h.cli.root = h.layout, true
	return h
}

// startInstanceService runs instance n's juistd as the unit would.
func startInstanceService(t *testing.T, home, sock string, n int) func() {
	t.Helper()
	s, err := daemon.NewService(daemon.ServiceOptions{
		Home:   home,
		Socket: sock,
		Mesh: daemon.Options{
			Instance:         n,
			TunName:          "",
			Connect:          func(conn.Options) (conn.Manager, error) { return stubManager{}, nil },
			DisableDiscovery: true,
			DisableDHT:       true,
			Logf:             func(string, ...any) {},
		},
		InviteAddrs: func(port uint16) []netip.AddrPort {
			return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
		},
	})
	if err != nil {
		t.Fatalf("starting instance %d: %v", n, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { cancel(); s.Close() }) }
	t.Cleanup(stop)
	return stop
}

func (h *testHost) start(_ context.Context, n int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.started = append(h.started, n)
	h.stops[n] = startInstanceService(h.t, h.layout.home(n), h.layout.socket(n), n)
	return os.WriteFile(filepath.Join(h.layout.wantsDir, unitOf(n)), nil, 0o644)
}

func (h *testHost) stop(_ context.Context, n int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stopped = append(h.stopped, n)
	if stop := h.stops[n]; stop != nil {
		stop()
	}
	delete(h.stops, n)
	return os.Remove(filepath.Join(h.layout.wantsDir, unitOf(n)))
}

func (h *testHost) run(args ...string) (string, error) {
	h.t.Helper()
	return h.cli.run(args...)
}

func (h *testHost) mustRun(args ...string) string {
	h.t.Helper()
	return h.cli.mustRun(args...)
}

func (h *testHost) answer(reply string, args ...string) (string, error) {
	h.t.Helper()
	return h.cli.answer(reply, args...)
}

// A device in a network founds a second one beside it: the new network gets
// an instance of its own, "juist status" shows both, and a command that
// cannot tell which network it is about asks, or says how to name one.
func TestASecondNetworkRunsBesideTheFirst(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	mustContain(t, h.mustRun("create", "home", "--device", "laptop"), `created network "home"`)
	if len(h.started) != 0 {
		t.Fatalf("the first network started instances %v; the default juistd is free", h.started)
	}
	out := h.mustRun("create", "work", "--device", "laptop")
	mustContain(t, out, "juist1", `created network "work"`)
	if len(h.started) != 1 || h.started[0] != 1 {
		t.Fatalf("started instances %v, want juist1", h.started)
	}

	// The second network drew a prefix clear of the first's.
	mustContain(t, h.mustRun("--network", "work", "network"), "198.18.8.0/22")
	if out, err := h.answer("n", "create", "lab", "--ipv4", "198.18.4.0/24"); err == nil ||
		!strings.Contains(out, `overlaps "home" (198.18.4.0/22)`) {
		t.Fatalf("a prefix another network here claims was not questioned (%v):\n%s", err, out)
	}

	out = h.mustRun("status")
	mustContain(t, out, "home · ", "work · ", "juist0", "juist1")
	if strings.Index(out, "home · ") > strings.Index(out, "work · ") {
		t.Errorf("the networks are not listed by instance:\n%s", out)
	}

	// A listing lists every network; a command about one says how to name
	// it, and asks nothing.
	out = h.mustRun("devices")
	mustContain(t, out, "home · juist0", "work · juist1")
	if strings.Count(out, "laptop (this device)") != 2 {
		t.Errorf("devices lists not both networks:\n%s", out)
	}
	_, err := h.run("invite")
	if err == nil || !strings.Contains(err.Error(), "2 networks: home (juist0), work (juist1)") ||
		!strings.Contains(err.Error(), "juist invite home") {
		t.Fatalf("invite with two networks: %v", err)
	}
	if out, err := h.answer("work", "log"); err == nil || strings.Contains(out, "which one") {
		t.Fatalf("log with two networks asked, or chose (%v):\n%s", err, out)
	}
	mustContain(t, h.mustRun("--network", "work", "devices"), "laptop (this device)")
	mustContain(t, h.mustRun("devices", "--network=juist1"), "laptop (this device)")
	mustContain(t, h.mustRun("--network", "HOME", "network"), "home")
	if _, err := h.run("--network", "wrok", "devices"); err == nil || !strings.Contains(err.Error(), `did you mean "work"`) {
		t.Fatalf("a misspelled network: %v", err)
	}
	mustContain(t, h.mustRun("__complete", "--network", ""), "home\n", "work\n", "juist1\n")
	if got := h.mustRun("__complete", "devices", "--network=wo"); got != "--network=work\n" {
		t.Errorf("completing --network=wo: %q", got)
	}

	// A third network takes the next instance, and a reset of one removes
	// its instance, which the next network takes again.
	mustContain(t, h.mustRun("create", "lab", "--device", "laptop"), `created network "lab"`)
	out, err = h.answer("y", "reset", "work", "--force")
	if err != nil {
		t.Fatalf("reset work: %v\n%s", err, out)
	}
	mustContain(t, out, `forget "work", with this device's keys for it and its juistd (juist1)?`,
		`"home" and "lab" stay as they are, with their keys`, `left "work"`, "removed juistd@juist1.service")
	if strings.Contains(out, "reset this device") {
		t.Errorf("leaving one network reads as resetting the device:\n%s", out)
	}
	if len(h.stopped) != 1 || h.stopped[0] != 1 {
		t.Fatalf("stopped instances %v, want juist1", h.stopped)
	}
	if fileExists(h.layout.home(1)) {
		t.Fatal("the removed instance's home is still there")
	}
	out = h.mustRun("status")
	if strings.Contains(out, "work") || !strings.Contains(out, "home · ") || !strings.Contains(out, "lab · ") {
		t.Fatalf("after work's reset:\n%s", out)
	}
	mustContain(t, h.mustRun("create", "work2", "--device", "laptop"), `created network "work2"`)
	if got := h.started; len(got) != 3 || got[2] != 1 {
		t.Fatalf("started instances %v; the freed juist1 was not taken again", got)
	}

	// The default instance is never removed: a reset leaves it in no network.
	mustContain(t, h.mustRun("--network", "home", "reset", "--force", "--yes"),
		`left "home"`, `this device is the only one in "home"`)
	if len(h.stopped) != 1 {
		t.Fatalf("the default instance was stopped: %v", h.stopped)
	}
}

// A device in a network joins another beside it, and a device the network
// removed joins it again in the instance it had.
func TestJoiningASecondNetwork(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")

	office := newDaemonDevice(t, nil)
	office.mustRun("create", "work", "--device", "office")
	inv := office.start("invite", "--no-lan", "--port", "0", "--yes")
	link := inv.waitFor(t, linkRE)[1]
	out := h.mustRun("join", link, "--name", "laptop")
	mustContain(t, out, "juist1", `joined "work" as laptop`)
	if out, err := inv.wait(t); err != nil {
		t.Fatalf("invite: %v\n%s", err, out)
	}
	mustContain(t, h.mustRun("status"), "home · ", "work · ")
	mustContain(t, office.mustRun("devices"), "office (this device)", "laptop")

	// Invited into work again, the host is not in it twice: the new
	// instance refuses the log, says what the admission left, and goes.
	inv = office.start("invite", "--no-lan", "--port", "0", "--yes")
	link = inv.waitFor(t, linkRE)[1]
	_, err := h.run("join", link, "--name", "laptop")
	if err == nil || !strings.Contains(err.Error(), `in "work" already, through another juistd`) ||
		!strings.Contains(err.Error(), "juist remove laptop-2") {
		t.Fatalf("joining work a second time: %v", err)
	}
	_, _ = inv.wait(t)
	if len(h.stopped) != 1 || h.stopped[0] != 2 || fileExists(h.layout.home(2)) {
		t.Fatalf("the instance made for the refused join stays: stopped %v", h.stopped)
	}
	mustContain(t, h.mustRun("status"), "home · ", "work · ")
}

// Without the instance unit a second network cannot be had, and a user who
// is not root is told how to get one rather than left at "already in".
func TestASecondNetworkNeedsTheInstanceUnitAndRoot(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	h.cli.root = false
	if _, err := h.run("create", "work"); err == nil || !strings.Contains(err.Error(), "sudo") {
		t.Fatalf("init as a user, not asked: %v", err)
	}
	h.cli.root = true
	if err := os.Remove(filepath.Join(h.layout.unitDirs[0], "juistd@.service")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.run("create", "work"); err == nil || !strings.Contains(err.Error(), "juistd@.service") {
		t.Fatalf("init without the instance unit: %v", err)
	}
	if len(h.started) != 0 {
		t.Fatalf("started %v", h.started)
	}
}

// Instances are taken lowest first, past one whose home still holds a
// network, which is some network's device. One that is enabled but down is
// not stood in for: it is started first, and until then it is reported,
// and chosen only by name.
func TestANewInstanceTakesAFreeNumber(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home")
	if err := os.MkdirAll(filepath.Join(h.layout.home(1), logDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.layout.home(1), logDir, "anchor"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	mustContain(t, h.mustRun("create", "work"), "juist2")
	if got := h.walls; len(got) != 1 || got[0] != "allow juist2" {
		t.Errorf("firewall calls %v, want juist2 allowed", got)
	}

	if err := os.WriteFile(filepath.Join(h.layout.wantsDir, unitOf(4)), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := h.run("create", "lab"); err == nil || !strings.Contains(err.Error(), "juistd@juist4.service is not running") {
		t.Fatalf("init beside an enabled instance that is down: %v", err)
	}
	out := h.mustRun("status")
	mustContain(t, out, "juist4 · not running", "sudo systemctl start juistd@juist4.service", "home · ", "work · ")
	mustContain(t, h.mustRun("devices"), "juist4 · not running", "home · juist0", "work · juist2")
	if _, err := h.run("remove", "phone"); err == nil || !strings.Contains(err.Error(), "juist4 (not running)") {
		t.Fatalf("a command with an instance down: %v", err)
	}
	if _, err := h.run("--network", "juist4", "devices"); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("a command for an instance that is down: %v", err)
	}
	mustContain(t, h.mustRun("--network", "work", "devices"), "(this device)")
}

// The status of an instance that yields to a lower one says so, naming the
// other network, and how to end it.
func TestAHostConflictReads(t *testing.T) {
	t.Parallel()
	p := netip.MustParsePrefix
	st := &ipc.Status{InNetwork: true, Instance: 1, Derived: ipc.Derived{NetworkName: "work", Members: 1},
		HostConflict: &ipc.HostConflict{Instance: 0, Device: "juist0", Held: p("198.18.4.2/32"), Claim: p("198.18.4.0/22")}}
	v := statusOfOn(st, testNow(), noPaint, func(n int) string { return `"home" (` + instance.Name(n) + ")" }, false)
	notes := render(v.notes)
	mustContain(t, notes, `no IPv4 on this host: "home" (juist0) holds 198.18.4.2, which "work" claims too (198.18.4.0/22)`,
		"juist network renumber juist1 PREFIX")

	st.HostConflict.SameNetwork = true
	st.StartError = "network runs here already"
	v = statusOfOn(st, testNow(), noPaint, instance.Name, false)
	head := render(v.head)
	mustContain(t, head, "not connected", "runs on this host already, as juist0", "juist reset juist1 --force")
	if strings.Contains(head, "CAP_NET_ADMIN") {
		t.Errorf("a same-network refusal reads as a missing capability:\n%s", head)
	}
}

// Hints name the instance's device and ports, not the default's.
func TestHintsNameTheInstancesDeviceAndPorts(t *testing.T) {
	t.Parallel()
	st := &ipc.Status{InNetwork: true, Instance: 2, Device: "juist2", ListenPort: 41663, GossipPort: 41664,
		Derived: ipc.Derived{NetworkName: "work", Members: 3, Peers: 2},
		Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsDown: []string{"a"}, SyncFailing: []string{"b"}, RelayUnreached: true, RelayPort: 41665}}
	notes := render(statusOf(st, testNow(), noPaint).notes)
	mustContain(t, notes, "on juist2", "sudo ufw allow in on juist2", "sudo ufw allow 41663/udp",
		"--add-port=41663/udp", "sudo ufw allow 41665/tcp && sudo ufw allow 41665/udp")
	if strings.Contains(notes, "juist0") || strings.Contains(notes, "--add-service=juist") {
		t.Errorf("the hints name the default instance's device or services:\n%s", notes)
	}
	st.Instance, st.Device, st.ListenPort, st.RelayPort = 0, "juist0", serviceDataPort, serviceRelayPort
	mustContain(t, render(statusOf(st, testNow(), noPaint).notes), "sudo ufw allow juist,", "--add-service=juist-relay")
}

// The CLI's idea of the package's service ports is juistd's.
func TestServicePortsAreJuistdsDefaults(t *testing.T) {
	if serviceDataPort != daemon.DefaultListenPort || serviceRelayPort != daemon.DefaultRelayPort {
		t.Fatalf("service ports %d and %d, juistd's %d and %d", serviceDataPort, serviceRelayPort,
			daemon.DefaultListenPort, daemon.DefaultRelayPort)
	}
}

func testNow() time.Time { return time.Unix(1_000_000, 0) }

// render is lines as text, one to a line.
func render(lines []line) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.text + "\n")
	}
	return b.String()
}

// Where a person names an instance's state directory, the CLI talks to that
// instance, which owns it, and no other.
func TestAnInstancesHomeReachesThatInstance(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home")
	h.mustRun("create", "work")
	out, err := h.cli.run("--home", h.layout.home(1), "network")
	if err != nil || !strings.Contains(out, "work") || strings.Contains(out, "home") {
		t.Fatalf("with --home at juist1's home (%v):\n%s", err, out)
	}
}

// A signing-only network is founded where no juistd runs, and asking for
// one on a device in a network starts nothing.
func TestNoDeviceStartsNoInstance(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home")
	if _, err := h.run("create", "lab", "--no-device", "--yes"); err == nil || !strings.Contains(err.Error(), "juistd runs here") {
		t.Fatalf("--no-device beside a juistd: %v", err)
	}
	if len(h.started) != 0 {
		t.Fatalf("started %v", h.started)
	}
}

// An instance that still holds a network is not removed, whoever asks.
func TestAnInstanceInANetworkIsNotRemoved(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home")
	h.mustRun("create", "work")
	if _, err := h.run("__instance", "remove", "juist1"); err == nil || !strings.Contains(err.Error(), `still holds "work"`) {
		t.Fatalf("removing an instance in a network: %v", err)
	}
	if len(h.stopped) != 0 || !fileExists(h.layout.home(1)) {
		t.Fatalf("the instance went all the same: stopped %v", h.stopped)
	}
	h.cli.root = false
	if _, err := h.run("__instance", "new"); err == nil || !strings.Contains(err.Error(), "needs root") {
		t.Fatalf("__instance as a user: %v", err)
	}
}

// $JUIST_NETWORK chooses among the networks a device is in; a network it
// founds or joins is another, so init and join do not follow it.
func TestJuistNetworkIsForTheNetworksADeviceIsIn(t *testing.T) {
	h := newHost(t)
	h.mustRun("create", "home")
	t.Setenv("JUIST_NETWORK", "home")
	mustContain(t, h.mustRun("create", "work"), `created network "work"`, "juist1")
	mustContain(t, h.mustRun("network"), "home")
	mustContain(t, h.mustRun("--network", "work", "network"), "work")
	// A network named on the command line wins over the variable.
	mustContain(t, h.mustRun("devices", "work"), "198.18.8.1")
	mustContain(t, h.mustRun("network", "work"), "work")
}

// A network founded or joined into a range another here claims is warned of
// after the fact, naming which of the two runs without IPv4: the higher
// instance, whichever that is.
func TestAnOverlapIsWarnedOfAfterTheFact(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home")
	out := h.mustRun("create", "lab", "--ipv4", "198.18.4.0/24", "--yes")
	mustContain(t, out, `"lab"'s IPv4 range overlaps "home"'s (juist0) here; "lab" runs here without IPv4`,
		"juist network renumber juist1 PREFIX")

	// The default freed, a newcomer there takes IPv4 from lab.
	h.mustRun("--network", "home", "reset", "--force", "--yes")
	out = h.mustRun("create", "office", "--ipv4", "198.18.4.0/23", "--yes")
	mustContain(t, out, `"office"'s IPv4 range overlaps "lab"'s (juist1) here; "lab" runs here without IPv4`)
}

// Where the device is in several networks, a command about one takes it
// first, by its name or its juistd's; with one network, it may be given or
// left out.
func TestTheNetworkComesFirst(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	// One network: the argument is optional.
	mustContain(t, h.mustRun("devices", "home"), "laptop (this device)")
	mustContain(t, h.mustRun("network", "home"), "198.18.4.0/22")
	mustContain(t, h.mustRun("network", "renumber", "home", "10.7.0.0/24", "--yes"), "10.7.0.0/24")
	mustContain(t, h.mustRun("network", "renumber", "home", "--finish", "--yes"), "retired")

	h.mustRun("create", "test1", "--device", "laptop")
	mustContain(t, h.mustRun("devices", "test1"), "laptop (this device)")
	mustContain(t, h.mustRun("devices", "juist1"), "laptop (this device)")
	mustContain(t, h.mustRun("log", "test1"), "network creation")
	mustContain(t, h.mustRun("log", "juist1"), "network creation")
	if _, err := h.run("log"); err == nil || !strings.Contains(err.Error(), "name one first: juist log home") {
		t.Fatalf("log with two networks: %v", err)
	}
	mustContain(t, h.mustRun("network"), "home · juist0", "test1 · juist1", "10.7.0.0/24")

	mustContain(t, h.mustRun("network", "rename", "test1", "foo1"), "foo1")
	mustContain(t, h.mustRun("network", "foo1"), "foo1")
	mustContain(t, h.mustRun("network", "renumber", "juist1", "10.11.1.0/24", "--yes"), "10.11.1.0/24")
	mustContain(t, h.mustRun("network", "renumber", "foo1", "laptop", "10.11.1.9", "--yes"), "10.11.1.9")
	mustContain(t, h.mustRun("network", "renumber", "foo1", "--finish", "--yes"), "retired")
	mustContain(t, h.mustRun("devices", "foo1"), "10.11.1.9")
	mustContain(t, h.mustRun("admins", "foo1"), "Quorum")
	mustContain(t, h.mustRun("admins"), "home · juist0", "foo1 · juist1")

	// Usage says so.
	if _, err := h.run("remove"); err == nil || !strings.Contains(err.Error(), "usage: juist remove [NETWORK] DEVICE") {
		t.Fatalf("remove without arguments: %v", err)
	}
}

// An argument that names a network is the network, with one network as with
// several: "juist invite home" invites into home, and names no device home.
func TestAnArgumentNamingANetworkIsTheNetwork(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	parse := func(args ...string) (*app, []string) {
		t.Helper()
		var out syncBuffer
		a := h.cli.app(&out, "")
		hm, err := openHome(h.cli.home)
		if err != nil {
			t.Fatal(err)
		}
		a.home = hm
		pos, err := a.parse(spec{name: "juist invite", args: "[NAME]", max: 1}, newFlags("juist invite"), args)
		if err != nil {
			t.Fatal(err)
		}
		return a, pos
	}
	if a, pos := parse("home"); a.network != "home" || len(pos) != 0 {
		t.Fatalf("juist invite home: network %q, arguments %q", a.network, pos)
	}
	if a, pos := parse("juist0", "phone"); a.network != "juist0" || len(pos) != 1 || pos[0] != "phone" {
		t.Fatalf("juist invite juist0 phone: network %q, arguments %q", a.network, pos)
	}
	if a, pos := parse("phone"); a.network != "" || len(pos) != 1 {
		t.Fatalf("juist invite phone: network %q, arguments %q", a.network, pos)
	}

	h.mustRun("create", "test1", "--device", "laptop")
	if _, err := h.run("invite"); err == nil || !strings.Contains(err.Error(), "name one first: juist invite home [NAME]") {
		t.Fatalf("invite with two networks: %v", err)
	}
}

// A removed device is told how to start over in the instance it is in.
func TestARemovedInstanceSaysHowToStartOver(t *testing.T) {
	t.Parallel()
	st := &ipc.Status{InNetwork: true, Instance: 1, Derived: ipc.Derived{NetworkName: "core", NotMember: true}}
	mustContain(t, render(statusOf(st, testNow(), noPaint).head), "core · removed", "juist reset juist1")
	st.Instance = 0
	if head := render(statusOf(st, testNow(), noPaint).head); strings.Contains(head, "juist0") ||
		!strings.Contains(head, "juist reset") {
		t.Fatalf("the default instance's hint: %s", head)
	}
	// Beside another network, a bare reset would not know which.
	mustContain(t, render(statusOfOn(st, testNow(), noPaint, instance.Name, true).head), "juist reset juist0")
}
