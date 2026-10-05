package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/daemon"
	"github.com/nning/juist/discovery/mdns"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

// cli runs the tool in-process against a home directory. In-process rather
// than through a built binary so that a failure points at a line of code, and
// with its own output so two ends of an enrollment can run at once.
type cli struct {
	t    *testing.T
	home string

	// host, where set, is the host's juistd instances this CLI sees, and
	// root whether it runs as root there; see newHost. Elsewhere it sees
	// none, whatever runs on the machine the tests run on.
	host *hostLayout
	root bool

	// admissionHold, where set, is how long an admission's copy waits.
	admissionHold time.Duration

	// terminal has the output be a colour terminal 80 columns wide.
	terminal bool

	// system is the host's files this CLI reads, by path, and env its
	// environment; none elsewhere, whatever the test's own.
	system map[string]string
	env    map[string]string
}

// noHost is a host with no juistd, and none installed.
var noHost = &hostLayout{
	runDir: "/nonexistent/juist-test/run", stateDir: "/nonexistent/juist-test/state",
	wantsDir: "/nonexistent/juist-test/wants",
	start:    func(context.Context, int) error { return errors.New("no host in this test") },
	stop:     func(context.Context, int) error { return errors.New("no host in this test") },
	firewall: func(context.Context, string, int) error { return nil },
}

func newCLI(t *testing.T) *cli {
	t.Helper()
	return &cli{t: t, home: filepath.Join(shortTempDir(t), "home")}
}

// shortTempDir is t.TempDir() without the test's name in the path: $home
// holds the control socket, and a sockaddr_un path is capped at 104 bytes on
// macOS and the BSDs.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "juist")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// syncBuffer is an output buffer one goroutine writes while another reads.
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

func (c *cli) app(out *syncBuffer, in string) *app {
	a := newApp(strings.NewReader(in), out, out)
	a.interactive = in != ""
	w := worldOf(c.t)
	a.dir, a.now = w.dir, w.now
	// Invites are reached over loopback: the test hosts' interfaces are
	// whatever the CI machine has.
	a.inviteAddrs = func(port uint16, _ *log.State) []netip.AddrPort {
		return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
	}
	// Nothing in a test reaches the public DHT or STUN servers.
	a.helpers = nil
	// A network founded without --ipv4 takes the first free prefix, so that
	// tests can name its addresses.
	a.drawV4 = firstV4Draw
	a.host = noHost
	a.getenv = func(k string) string { return c.env[k] }
	a.system = func(path string) ([]byte, error) {
		if s, ok := c.system[path]; ok {
			return []byte(s), nil
		}
		return nil, os.ErrNotExist
	}
	if c.admissionHold != 0 {
		a.admissionHold = c.admissionHold
	}
	if c.terminal {
		a.terminal, a.color, a.width = true, true, 80
	}
	// A background share runs in-process, writing to out until it is up.
	a.spawn = func(args []string) (io.ReadCloser, func() error, func(), error) {
		r, w := io.Pipe()
		child := c.app(out, "")
		ctx, cancel := context.WithCancel(context.Background())
		child.ctx, child.ready = ctx, w
		done := make(chan struct{})
		var err error
		go func() {
			defer close(done)
			if err = child.main(args); err != nil && !errors.Is(err, errSilent) {
				child.fail(err)
			}
			w.Close()
		}()
		c.t.Cleanup(func() { cancel(); <-done })
		return r, func() error { <-done; return err }, cancel, nil
	}
	if c.host != nil {
		a.host, a.asRoot = c.host, func() bool { return c.root }
	}
	return a
}

// firstV4Draw is [drawV4Prefix] without the chance: the first prefix taken
// leaves.
func firstV4Draw(taken func(netip.Prefix) bool) (netip.Prefix, error) {
	for _, p := range v4DrawCandidates() {
		if !taken(p) {
			return p, nil
		}
	}
	return netip.Prefix{}, errors.New("no prefix free")
}

func (c *cli) run(args ...string) (string, error) {
	c.t.Helper()
	var out syncBuffer
	err := c.app(&out, "").main(append([]string{"--home", c.home}, args...))
	return out.String(), err
}

// answer runs a command that asks a question, answering it.
func (c *cli) answer(reply string, args ...string) (string, error) {
	c.t.Helper()
	var out syncBuffer
	err := c.app(&out, reply+"\n").main(append([]string{"--home", c.home}, args...))
	return out.String(), err
}

func (c *cli) mustRun(args ...string) string {
	c.t.Helper()
	out, err := c.run(args...)
	if err != nil {
		c.t.Fatalf("juist %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// running is a command left running in the background.
type running struct {
	out    *syncBuffer
	done   chan error
	cancel context.CancelFunc
}

func (c *cli) start(args ...string) *running {
	c.t.Helper()
	r := &running{out: &syncBuffer{}, done: make(chan error, 1)}
	a := c.app(r.out, "")
	ctx, cancel := context.WithCancel(context.Background())
	a.ctx, r.cancel = ctx, cancel
	go func() { r.done <- a.main(append([]string{"--home", c.home}, args...)) }()
	c.t.Cleanup(func() {
		cancel()
		<-r.done
	})
	return r
}

// waitFor returns the output once it matches re, failing the test otherwise.
func (r *running) waitFor(t *testing.T, re *regexp.Regexp) []string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(r.out.String()); m != nil {
			return m
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("output never matched %v:\n%s", re, r.out.String())
	return nil
}

func (r *running) wait(t *testing.T) (string, error) {
	t.Helper()
	select {
	case err := <-r.done:
		r.done <- err
		return r.out.String(), err
	case <-time.After(30 * time.Second):
		t.Fatalf("the command did not finish:\n%s", r.out.String())
		return "", nil
	}
}

var linkRE = regexp.MustCompile(`juist join '(juist:[^']+)'`)

// startInvite starts an invite and returns it with its link.
func startInvite(t *testing.T, host *cli, args ...string) (*running, string) {
	t.Helper()
	r := host.start(append([]string{"invite", "--no-lan", "--port", "0", "--yes"}, args...)...)
	return r, r.waitFor(t, linkRE)[1]
}

// startInviteOnTheLAN is startInvite with the code answered for, which a
// guest using the code needs; the LAN search itself is replaced by hostAt.
func startInviteOnTheLAN(t *testing.T, host *cli) (*running, string) {
	t.Helper()
	r := host.start("invite", "--port", "0", "--yes")
	return r, r.waitFor(t, linkRE)[1]
}

// enrollDevice invites a device into host's network and joins it from a fresh home.
func enrollDevice(t *testing.T, host *cli, name string) *cli {
	t.Helper()
	inv, link := startInvite(t, host)
	guest := newCLI(t)
	guest.mustRun("join", link, "--name", name)
	if out, err := inv.wait(t); err != nil {
		t.Fatalf("invite: %v\n%s", err, out)
	}
	return guest
}

// openLog opens a home's log directly, for assertions the tool does not print.
func openLog(t *testing.T, c *cli) *log.Authority {
	t.Helper()
	st, err := store.Open(filepath.Join(c.home, logDir))
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	auth, err := log.Open(st)
	if err != nil {
		t.Fatalf("opening the log: %v", err)
	}
	return auth
}

func nodeKeysOf(t *testing.T, c *cli) *keys.Node {
	t.Helper()
	k, err := keys.LoadNode(filepath.Join(c.home, nodeKeysFile))
	if err != nil {
		t.Fatalf("loading node keys: %v", err)
	}
	return k
}

func mustContain(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Fatalf("output lacks %q:\n%s", w, out)
		}
	}
}

// A world is what the CLIs of one test share: the working directory pending
// changes are written to, and a clock the test can move on.
type world struct {
	dir  string
	skew atomic.Int64
}

func (w *world) now() time.Time { return time.Now().Add(time.Duration(w.skew.Load())) }

var worlds sync.Map // *testing.T to *world

func worldOf(t *testing.T) *world {
	if w, ok := worlds.Load(t); ok {
		return w.(*world)
	}
	w := &world{dir: t.TempDir()}
	worlds.Store(t, w)
	t.Cleanup(func() { worlds.Delete(t) })
	return w
}

// workDir is the directory the test's CLIs write pending changes to.
func workDir(t *testing.T) string { return worldOf(t).dir }

// advance moves the clock of the test's CLIs on by d.
func advance(t *testing.T, d time.Duration) { worldOf(t).skew.Add(int64(d)) }

// hostAt answers a LAN search with the host a link names.
func hostAt(t *testing.T, link string) func(context.Context, uint16) ([]mdns.InviteHost, error) {
	t.Helper()
	l, err := enroll.ParseLink(link)
	if err != nil {
		t.Fatal(err)
	}
	return func(context.Context, uint16) ([]mdns.InviteHost, error) {
		return []mdns.InviteHost{{ID: "host", Addrs: l.Addrs}}, nil
	}
}

func (c *cli) home2() *home {
	c.t.Helper()
	h, err := openHome(c.home)
	if err != nil {
		c.t.Fatal(err)
	}
	return h
}

// copyTree copies a directory, as syncing a log to another machine would.
func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, path)
		dst := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o700)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func corrupt(t *testing.T, c *cli) {
	t.Helper()
	st, err := store.Open(filepath.Join(c.home, logDir))
	if err != nil {
		t.Fatal(err)
	}
	anchor, _, err := st.Anchor()
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(c.home, logDir, "records", anchor.String()+".cbor")
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] ^= 1
	if err := os.WriteFile(name, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// startService runs juistd's service over a state directory, listening on
// sock (or in the directory), with a data plane that records rather than
// connects and LAN discovery replaced by find.
func startService(t *testing.T, home, sock string,
	find func(context.Context, uint16) ([]mdns.InviteHost, error), mgr conn.Manager, mutate ...func(*daemon.ServiceOptions)) func() {
	t.Helper()
	if mgr == nil {
		mgr = stubManager{}
	}
	opts := daemon.ServiceOptions{
		Home:   home,
		Socket: sock,
		Mesh: daemon.Options{
			Connect:          func(conn.Options) (conn.Manager, error) { return mgr, nil },
			DisableDiscovery: true,
			DisableDHT:       true,
			Logf:             func(string, ...any) {},
			// The packaged service's, which exit nodes need.
			EgressUser: func() string { return "" },
		},
		Find: find,
		InviteAddrs: func(port uint16) []netip.AddrPort {
			return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
		},
	}
	for _, m := range mutate {
		m(&opts)
	}
	s, err := daemon.NewService(opts)
	if err != nil {
		t.Fatalf("starting the daemon: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			cancel()
			s.Close()
		}
	}
	t.Cleanup(stop)
	return stop
}

type stubManager struct{}

func (stubManager) SetPeers([]conn.Peer) error { return nil }

func (stubManager) SetRelays([]conn.Relay) error { return nil }

func (stubManager) SetEgress(conn.Egress, bool) error { return nil }

func (stubManager) AnswersThrough() string { return "" }

func (stubManager) SetServe(conn.Serve) error { return nil }

func (stubManager) SetIngressPorts([]uint16) error { return nil }

func (stubManager) HostRoutes() []netip.Prefix { return nil }

func (stubManager) HomeRelay() int { return 0 }

func (stubManager) LocalEndpoints() []netip.AddrPort { return nil }

func (stubManager) LocalPort() uint16 { return 41641 }

func (stubManager) Ping(netip.Addr, func(conn.PingResult)) {}
func (stubManager) Echo(netip.Addr, func(conn.PingResult)) {}

func (stubManager) Tunnels() map[uint64]conn.Tunnel { return nil }

func (stubManager) Probe(_ netip.Addr, _ time.Duration, cb func(bool)) {
	cb(false)
}

func (stubManager) Close() error { return nil }

// daemonDevice is a device as the packaged service runs it: juistd owns the
// state directory and the device's keys, and the person's admin keys are in
// a keystore of their own.
type daemonDevice struct {
	*cli
	state, sock string
	mgr         *peersManager
}

// peersManager is a data plane that keeps the peer set, egress and serving
// it was last given.
type peersManager struct {
	stubManager
	mu      sync.Mutex
	through string // what AnswersThrough says
	peers   []conn.Peer
	egress  conn.Egress
	serve   conn.Serve
	// host is what the host reaches outside juist.
	host []netip.Prefix
}

func (m *peersManager) HostRoutes() []netip.Prefix {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.host)
}

func (m *peersManager) AnswersThrough() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.through
}

func (m *peersManager) SetEgress(e conn.Egress, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.egress = e
	return nil
}

func (*peersManager) SetIngressPorts([]uint16) error { return nil }

func (m *peersManager) SetServe(s conn.Serve) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.serve = s
	return nil
}

// exitState is the egress and serving last set.
func (m *peersManager) exitState() (conn.Egress, conn.Serve) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.egress, m.serve
}

func (m *peersManager) SetPeers(peers []conn.Peer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peers = slices.Clone(peers)
	return nil
}

// allowed is the addresses the data plane accepts from the peer whose
// WireGuard key is wg.
func (m *peersManager) allowed(wg types.WGKey) []netip.Prefix {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.peers {
		if p.NodeKey == conn.NodePublicFromRaw32(wg) {
			return slices.Clone(p.Addrs)
		}
	}
	return nil
}

func newDaemonDevice(t *testing.T, find func(context.Context, uint16) ([]mdns.InviteHost, error)) *daemonDevice {
	t.Helper()
	d := &daemonDevice{cli: newCLI(t), state: filepath.Join(shortTempDir(t), "state"),
		sock: filepath.Join(shortTempDir(t), "juistd.sock")}
	d.mgr = &peersManager{}
	startService(t, d.state, d.sock, find, d.mgr)
	return d
}

func (d *daemonDevice) run(args ...string) (string, error) {
	d.t.Helper()
	return d.cli.run(append([]string{"--socket", d.sock}, args...)...)
}

func (d *daemonDevice) mustRun(args ...string) string {
	d.t.Helper()
	out, err := d.run(args...)
	if err != nil {
		d.t.Fatalf("juist %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (d *daemonDevice) answer(reply string, args ...string) (string, error) {
	d.t.Helper()
	return d.cli.answer(reply, append([]string{"--socket", d.sock}, args...)...)
}

func (d *daemonDevice) start(args ...string) *running {
	d.t.Helper()
	return d.cli.start(append([]string{"--socket", d.sock}, args...)...)
}

// schema0Log returns a network at schema 0 whose one member is self, as it
// is in auth.
func schema0Log(t *testing.T, auth *log.Authority, self types.Identity) *log.Authority {
	t.Helper()
	admin, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := auth.State().Node(self)
	legacy := netip.MustParseAddr("100.64.0.1")
	rec.V4 = &legacy
	genesis, err := log.Genesis("old", 1, []types.AdminKey{{Public: admin.Public(), Votes: 1, Name: "admin"}},
		[]types.Hash{{1}}, []types.NodeRecord{rec}, sealer())
	if err != nil {
		t.Fatal(err)
	}
	genesis.State.Schema = 0
	if err := genesis.Sign(admin); err != nil {
		t.Fatal(err)
	}
	old, err := log.Create(log.NewMemStorage(), genesis)
	if err != nil {
		t.Fatal(err)
	}
	return old
}

// adminKeyOf creates an admin key for person in a keystore of its own, as on
// one of their devices, and returns the keystore and the key.
func adminKeyOf(t *testing.T, person string) (*cli, string) {
	t.Helper()
	c := newCLI(t)
	key := regexp.MustCompile(`juist admins add \S+ (nid:\S+)`).FindStringSubmatch(c.mustRun("admins", "new", person))
	if key == nil {
		t.Fatal("admins new printed no key")
	}
	return c, key[1]
}
