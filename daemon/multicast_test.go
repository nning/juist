package daemon

import (
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/ipc"
)

// connectsSeen records the options each mesh started with.
type connectsSeen struct {
	mu   sync.Mutex
	opts []conn.Options
}

func (c *connectsSeen) wrap(o *Options) {
	next := o.Connect
	o.Connect = func(co conn.Options) (conn.Manager, error) {
		c.mu.Lock()
		c.opts = append(c.opts, co)
		c.mu.Unlock()
		return next(co)
	}
}

// last waits for a mesh started with options ok says are right.
func (c *connectsSeen) last(t *testing.T, what string, ok func(conn.Options) bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := len(c.opts)
		var o conn.Options
		if n > 0 {
			o = c.opts[n-1]
		}
		c.mu.Unlock()
		if n > 0 && ok(o) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no mesh started %s", what)
}

// juist set --multicast and --groups are kept in the device's state, said
// by its status, and taken by the mesh it starts again; a device of its own
// is needed.
func TestMulticastSettingsAreKeptAndTaken(t *testing.T) {
	var seen connectsSeen
	f := newServiceFixtureWith(t, func(o *Options) { o.TunName = "vpn0"; seen.wrap(o) })
	mdns := netip.MustParseAddr("224.0.0.251")
	seen.last(t, "carrying multicast", func(o conn.Options) bool { return o.Multicast && len(o.Groups) == 0 })

	groups, off := []string{"224.0.0.251", "239.255.255.250"}, false
	resp, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdSettings, Groups: &groups})
	if runtime.GOOS != "linux" {
		if err == nil {
			t.Fatal("groups were routed on " + runtime.GOOS)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if m := resp.Status.Multicast; m == nil || m.Off || !slices.Equal(m.Groups, groups) {
		t.Errorf("with groups, the status says %+v", m)
	}
	seen.last(t, "with the groups", func(o conn.Options) bool {
		return o.Multicast && slices.Equal(o.Groups, []netip.Addr{mdns, netip.MustParseAddr("239.255.255.250")})
	})
	if resp, err = ipc.Call(f.sock, ipc.Request{Command: ipc.CmdSettings, Multicast: &off}); err != nil {
		t.Fatal(err)
	}
	if m := resp.Status.Multicast; m == nil || !m.Off {
		t.Errorf("multicast off, the status says %+v", m)
	}
	seen.last(t, "without multicast", func(o conn.Options) bool { return !o.Multicast && len(o.Groups) == 0 })
	for _, name := range []string{statedir.MulticastOffFile, statedir.GroupsFile} {
		if _, err := os.Stat(filepath.Join(f.home, name)); err != nil {
			t.Errorf("%s was not kept: %v", name, err)
		}
	}
	for _, bad := range [][]string{{"10.0.0.1"}, {"ff02::fb"}, {"nonsense"}} {
		if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdSettings, Groups: &bad}); err == nil {
			t.Errorf("groups %v were taken", bad)
		}
	}

	f.s.Close()
	g := startServiceWith(t, f.nw, f.home, func(o *Options) { o.TunName = "vpn0" })
	if resp, err = ipc.Call(g.sock, ipc.Request{Command: ipc.CmdStatus}); err != nil {
		t.Fatal(err)
	}
	if m := resp.Status.Multicast; m == nil || !m.Off || !slices.Equal(m.Groups, groups) {
		t.Errorf("after a restart, the status says %+v", m)
	}
	on, none := true, []string{}
	if _, err := ipc.Call(g.sock, ipc.Request{Command: ipc.CmdSettings, Multicast: &on, Groups: &none}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{statedir.MulticastOffFile, statedir.GroupsFile} {
		if _, err := os.Stat(filepath.Join(f.home, name)); !os.IsNotExist(err) {
			t.Errorf("%s stayed: %v", name, err)
		}
	}

	h := newServiceFixture(t, true)
	if _, err := ipc.Call(h.sock, ipc.Request{Command: ipc.CmdSettings, Multicast: &on}); err == nil {
		t.Error("multicast was set on a device without a device of its own")
	}
	if resp, err = ipc.Call(h.sock, ipc.Request{Command: ipc.CmdStatus}); err != nil || resp.Status.Multicast != nil {
		t.Errorf("without a device, the status says %+v, %v", resp.Status.Multicast, err)
	}
}

// A request whose multicast part is refused sets none of the rest.
func TestARefusedSettingSetsNothing(t *testing.T) {
	f := newServiceFixture(t, true)
	off, on, groups := false, true, []string{"239.255.255.250"}
	for _, req := range []ipc.Request{{DNS: &off, Multicast: &on}, {DNS: &off, Groups: &groups}} {
		req.Command = ipc.CmdSettings
		if _, err := ipc.Call(f.sock, req); err == nil {
			t.Fatalf("%+v was set without a device", req)
		}
	}
	if _, err := os.Stat(filepath.Join(f.home, statedir.DNSOffFile)); !os.IsNotExist(err) {
		t.Errorf("DNS was turned off by a refused request: %v", err)
	}
}

// A groups file edited by hand is read without repeats and at most
// ipc.MaxGroups, which a socket can join.
func TestAGroupsFileIsBounded(t *testing.T) {
	home := t.TempDir()
	var lines []string
	for i := range 2 * ipc.MaxGroups {
		lines = append(lines, netip.AddrFrom4([4]byte{239, 1, 1, byte(i%(ipc.MaxGroups+4) + 1)}).String())
	}
	if err := os.WriteFile(filepath.Join(home, statedir.GroupsFile), []byte(strings.Join(lines, "\n")+"\nnonsense\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := loadGroups(home, t.Logf)
	if len(got) != ipc.MaxGroups || len(slices.Compact(slices.SortedFunc(slices.Values(got), netip.Addr.Compare))) != len(got) {
		t.Errorf("read %v", got)
	}
}

// Groups kept where juistd now runs without a device of its own block no
// other setting, and can be cleared.
func TestGroupsKeptWithoutADeviceBlockNothing(t *testing.T) {
	f := newServiceFixture(t, true)
	f.s.Close()
	if err := os.WriteFile(filepath.Join(f.home, statedir.GroupsFile), []byte("239.255.255.250\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := startServiceWith(t, f.nw, f.home, nil)
	off, none := false, []string{}
	for _, req := range []ipc.Request{{DNS: &off}, {Groups: &none}, {Multicast: &off}} {
		req.Command = ipc.CmdSettings
		if _, err := ipc.Call(g.sock, req); err != nil {
			t.Errorf("%+v: %v", req, err)
		}
	}
	if _, err := os.Stat(filepath.Join(f.home, statedir.GroupsFile)); !os.IsNotExist(err) {
		t.Errorf("the groups stayed: %v", err)
	}
}

// A request whose last file cannot be written puts back those it wrote.
func TestASettingNotWrittenUndoesTheOthers(t *testing.T) {
	f := newServiceFixture(t, true)
	if err := os.MkdirAll(filepath.Join(f.home, statedir.RelayNameFile, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	off, name := false, "relay.example.org"
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdSettings, DNS: &off, RelayName: &name}); err == nil {
		t.Fatal("a relay name was written over a directory")
	}
	if _, err := os.Stat(filepath.Join(f.home, statedir.DNSOffFile)); !os.IsNotExist(err) {
		t.Errorf("DNS stayed off: %v", err)
	}
}

// A setting the mesh does not take, as multicast where juistd has no device
// of its own, restarts nothing.
func TestASettingTheMeshDoesNotTakeRestartsNothing(t *testing.T) {
	var seen connectsSeen
	f := newServiceFixtureWith(t, func(o *Options) { seen.wrap(o) })
	seen.last(t, "at all", func(conn.Options) bool { return true })
	seen.mu.Lock()
	before := len(seen.opts)
	seen.mu.Unlock()
	off := false
	if _, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdSettings, Multicast: &off}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	seen.mu.Lock()
	defer seen.mu.Unlock()
	if n := len(seen.opts) - before; n != 0 {
		t.Errorf("the mesh started %d times again", n)
	}
}
