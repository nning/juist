package main

import (
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

func noPaint(_, s string) string { return s }

// The status's notes are worked out from the report alone, and each warning
// comes with its hint. An alarm already explains the silence a firewall would.
func TestStatusNotesComeFromTheReport(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_000_000, 0)
	tunnels := ipc.Tunnels{Firewalled: "vpn0"}

	v := statusOf(&ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 2, Alarm: "fork"}, Tunnels: tunnels}, now, noPaint)
	if slices.ContainsFunc(v.notes, func(l line) bool { return strings.Contains(l.text, "firewall") }) {
		t.Errorf("a firewall is blamed during an alarm: %v", v.notes)
	}
	if want := (line{kind: lineAlarm, text: "fork; tunnels down until resolved"}); !slices.Contains(v.notes, want) {
		t.Errorf("notes %v lack %v", v.notes, want)
	}
	if v.head[0].text != "home · disconnected" {
		t.Errorf("head %q", v.head[0].text)
	}

	v = statusOf(&ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 2, Peers: 1, LastReconcile: now.Add(-3 * time.Minute).Unix()}, Tunnels: tunnels}, now, noPaint)
	i := slices.Index(v.notes, line{kind: lineWarn, text: "firewalld blocks vpn0, so log sync in the tunnel fails"})
	if i < 0 || i+1 >= len(v.notes) || v.notes[i+1].kind != lineHint || !strings.Contains(v.notes[i+1].text, "--change-interface=vpn0") {
		t.Errorf("a blocked tunnel is not warned of with a hint for its device: %v", v.notes)
	}
	tunnels.FirewallUnsure = true
	v2 := statusOf(&ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 2}, Tunnels: tunnels}, now, noPaint)
	i = slices.IndexFunc(v2.notes, func(l line) bool { return l.kind == lineWarn && strings.HasPrefix(l.text, "firewalld may block vpn0:") })
	if i < 0 || i+1 >= len(v2.notes) || v2.notes[i+1].kind != lineHint {
		t.Errorf("a tunnel firewalld may block is not warned of, hedged, with a hint: %v", v2.notes)
	}
	if !slices.Contains(v.head, line{kind: lineField, label: "Updated", text: "3m ago"}) {
		t.Errorf("the update is not dated from now: %v", v.head)
	}

	v = statusOf(&ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", NotMember: true}}, now, noPaint)
	if len(v.notes) != 0 || v.devices || v.head[0].text != "home · removed" {
		t.Errorf("a removed device's status: %+v", v)
	}
}

func TestLogVerifyReportsCorruption(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("init", "home")
	corrupt(t, c)
	if _, err := c.run("log", "verify"); err == nil {
		t.Fatal("log verify accepted a corrupt log")
	}
}

func TestLogShow(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("init", "home", "--device", "laptop")
	mustContain(t, c.mustRun("log"), "network creation", "approved by")
}

func TestStatusWithoutADaemon(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("init", "home", "--device", "laptop")
	mustContain(t, c.mustRun("status"), "juistd not running", "laptop", "198.18.0.1")
}

func TestStatusShowsFreshness(t *testing.T) {
	t.Parallel()
	d := newDaemonDevice(t, nil)
	d.mustRun("init", "home", "--device", "laptop")
	mustContain(t, d.mustRun("status"), "home · ", "laptop", "Freshness", "vouched")
}

// TestStatusRefusedByPermission: a packaged daemon runs as its own account,
// so a socket the caller may not reach is an ordinary answer, and the message
// names the account to run as.
func TestStatusRefusedByPermission(t *testing.T) {
	t.Parallel()
	if os.Getuid() == 0 {
		t.Skip("root is not subject to the mode bits this test refuses with")
	}
	c := newCLI(t)
	c.mustRun("init", "home")
	sock := ipc.SocketPath(c.home)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := os.Chmod(sock, 0); err != nil {
		t.Fatal(err)
	}
	_, err = c.run("status")
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("status got %v", err)
	}
	if self, uerr := user.Current(); uerr == nil && !strings.Contains(err.Error(), "sudo -u "+self.Username) {
		t.Errorf("error %q does not name the account that owns the state directory", err)
	}
}

func TestLogUpgradeOnANetworkAtTheCurrentSchema(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("init", "home")
	mustContain(t, c.mustRun("log", "upgrade"), "unchanged")
}

// status names the devices it has not heard from.
func TestStatusNamesTheSilentDevices(t *testing.T) {
	t.Parallel()
	var out syncBuffer
	a := newApp(strings.NewReader(""), &out, &out)
	a.node = &daemonNode{sock: "/nonexistent", st: &ipc.Status{InNetwork: true}}
	a.printStatus(&ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 3, Peers: 1, Unreachable: 1, Silent: []string{"phone"}}})
	mustContain(t, out.String(), "2 others, 1 of them heard from", "not heard from: phone")
}

// status says which tunnels are live, and names a device heard from whose
// tunnel does not answer: announcements arriving prove nothing about it.
func TestStatusNamesTheDeadTunnels(t *testing.T) {
	t.Parallel()
	var out syncBuffer
	a := newApp(strings.NewReader(""), &out, &out)
	a.node = &daemonNode{sock: "/nonexistent", st: &ipc.Status{InNetwork: true}}
	a.printStatus(&ipc.Status{InNetwork: true, ListenPort: 41643, Derived: ipc.Derived{NetworkName: "home", Members: 2, Peers: 1}, Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsDown: []string{"homebox1"}}})
	mustContain(t, out.String(), "no tunnel up", "0 of 1 live", "no tunnel traffic from homebox1",
		"udp/41643")

	out = syncBuffer{}
	a.printStatus(&ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 2, Peers: 1}, Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 1}})
	mustContain(t, out.String(), "connected", "1 of 1 live")
	if strings.Contains(out.String(), "No answer") {
		t.Fatalf("all tunnels live, yet one is reported dead:\n%s", out.String())
	}
}

// status says a device every member refuses was most likely removed, and how
// to come back.
func TestStatusSaysTheNetworkRefusesThisDevice(t *testing.T) {
	t.Parallel()
	var out syncBuffer
	a := newApp(strings.NewReader(""), &out, &out)
	a.node = &daemonNode{sock: "/nonexistent", st: &ipc.Status{InNetwork: true}}
	a.printStatus(&ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 2, Refused: true}})
	mustContain(t, out.String(), "home · refused", "warning: the network's devices refuse this one",
		"hint: rejoin with a new invite")
}

// juist devices says per device how the daemon's last check reached it, and
// tells a device never heard from apart from one that stopped answering.
func TestDevicesSayHowEachWasReached(t *testing.T) {
	t.Parallel()
	a := newApp(strings.NewReader(""), &syncBuffer{}, &syncBuffer{})
	ids := make([]types.Identity, 5)
	for i := range ids {
		priv, err := types.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = priv.Public()
	}
	st := &ipc.Status{InNetwork: true, Derived: ipc.Derived{Silent: []string{"quiet"}}, Tunnels: ipc.Tunnels{ReachChecked: 1, Reach: []ipc.PeerReach{
		{Identity: ids[1], Live: true, Direct: true},
		{Identity: ids[2], Live: true},
		{Identity: ids[3]},
	}}}
	reach := map[types.Identity]ipc.PeerReach{}
	for _, r := range st.Reach {
		reach[r.Identity] = r
	}
	ids = append(ids, types.Identity{7}) // heard from, never installed
	for i, want := range []string{"-", "direct", "relayed", "no answer", "not heard from", "not connected"} {
		n := ipc.Device{Identity: ids[i], Name: []string{"self", "a", "b", "c", "quiet", "left out"}[i]}
		if got := a.describeReach(n, i == 0, st, reach); got != want {
			t.Errorf("%s: %q, want %q", n.Name, got, want)
		}
	}
}

// The relay line says which relay this device is connected through, or that
// it reaches none, rather than counting relays in the map. One relay is
// enough, so only a network with none is warned of.
func TestStatusNamesTheRelayInUse(t *testing.T) {
	t.Parallel()
	var out syncBuffer
	a := newApp(strings.NewReader(""), &out, &out)
	a.printStatus(&ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 3, Peers: 2, RelayCapable: 1, Relays: 1}, Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 2, HomeRelay: "vps"}})
	mustContain(t, out.String(), "Relays        1 available, via vps\n")
	if strings.Contains(out.String(), "may relay;") {
		t.Errorf("one relay is warned of as too few:\n%s", out.String())
	}

	out = syncBuffer{}
	a.printStatus(&ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 3, Peers: 2}, Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 2}})
	mustContain(t, out.String(), "warning: no device may relay", "hint: juist grant DEVICE relay")

	out = syncBuffer{}
	a.printStatus(&ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 3, Peers: 2, RelayCapable: 1, Relays: 1}, Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 2}})
	mustContain(t, out.String(), "1 available, no connection")

	// The relay itself is homed at its own, which says nothing.
	out = syncBuffer{}
	a.printStatus(&ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", SelfName: "vps", Members: 3, Peers: 2, RelayCapable: 1, Relays: 1, Relaying: true}, Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 2, HomeRelay: "vps"}})
	mustContain(t, out.String(), "Relays        1 available; this device relays\n")

	// A relay counts whom it serves, and says so when nobody reaches it.
	relay := ipc.Derived{NetworkName: "home", SelfName: "vps", Members: 3, Peers: 2, RelayCapable: 1, Relays: 1, Relaying: true}
	out = syncBuffer{}
	a.printStatus(&ipc.Status{InNetwork: true, Derived: relay, Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 2, RelayedFor: 2, RelayPort: 41645}})
	mustContain(t, out.String(), "Relays        1 available; this device relays for 2 devices\n")
	if strings.Contains(out.String(), "reaches this relay") {
		t.Errorf("a relay in use is warned of:\n%s", out.String())
	}
	out = syncBuffer{}
	a.printStatus(&ipc.Status{InNetwork: true, Derived: relay, Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 2, RelayUnreached: true, RelayPort: 41645}})
	mustContain(t, out.String(), "warning: no device reaches this relay: tcp/41645 or udp/41645 is likely closed",
		"hint: sudo ufw allow juist-relay")
}

// A removed device lists none of the old network's devices: they are that
// network's business, not this device's any more.
func TestARemovedDeviceListsNoDevices(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("init", "home")
	phone := enrollDevice(t, admin, "phone")
	admin.mustRun("remove", "phone", "--yes")
	if err := os.RemoveAll(filepath.Join(phone.home, logDir)); err != nil {
		t.Fatal(err)
	}
	copyTree(t, filepath.Join(admin.home, logDir), filepath.Join(phone.home, logDir))
	out := phone.mustRun("devices")
	mustContain(t, out, "not in", "juist reset")
	if strings.Contains(out, "IPV4") {
		t.Errorf("a removed device listed the old network's devices:\n%s", out)
	}
	phone.mustRun("reset", "--yes")
}

// juist status lists the devices as juist devices does: every member, this
// device marked, with how the last check reached each of the others.
func TestStatusListsTheDevices(t *testing.T) {
	t.Parallel()
	var out syncBuffer
	a := newApp(strings.NewReader(""), &out, &out)
	ids := make([]types.Identity, 3)
	for i := range ids {
		priv, err := types.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = priv.Public()
	}
	a.printStatus(&ipc.Status{InNetwork: true, Self: ids[0], Derived: ipc.Derived{NetworkName: "home", Members: 3, Peers: 2, Devices: []ipc.Device{
		{Identity: ids[0], Name: "desk", V4: "10.11.11.4", V6: "fd89::4"},
		{Identity: ids[1], Name: "laptop", V4: "10.11.11.5", V6: "fd89::5"},
		{Identity: ids[2], Name: "vps", V4: "10.11.11.6", V6: "fd89::6", Roles: []types.Role{types.RoleRelayCapable}},
	}}, Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 1, TunnelsDown: []string{"vps"}, ReachChecked: time.Now().Unix(), Reach: []ipc.PeerReach{{Identity: ids[1], Live: true, Direct: true}, {Identity: ids[2]}}}})
	got := out.String()
	for _, want := range []string{"NAME", "REACHED", "desk (this device)", "laptop", "direct", "vps",
		"relay", "no answer"} {
		if !strings.Contains(got, want) {
			t.Errorf("status lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "checked just now") {
		t.Errorf("a check just now is dated:\n%s", got)
	}
}

// The age of the last tunnel check is said only once juistd has missed
// several, and the ports only where sync is not in the tunnel, the default.
func TestStatusSaysOnlyWhatIsNotTheDefault(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_000_000, 0)
	s := &ipc.Status{InNetwork: true, SyncInTunnel: true, ListenPort: 41643, GossipPort: 41644,
		Derived: ipc.Derived{NetworkName: "home", Members: 2, Peers: 1},
		Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 1, ReachChecked: now.Add(-checkStale).Unix()}}
	v := statusOf(s, now, noPaint)
	for _, want := range []line{{kind: lineField, label: "Tunnels", text: "1 of 1 live"}, {kind: lineField, label: "Ports", text: "udp/41643"}} {
		if !slices.Contains(v.head, want) {
			t.Errorf("head %v lacks %v", v.head, want)
		}
	}

	s.ReachChecked = now.Add(-5 * time.Minute).Unix()
	s.SyncInTunnel = false
	v = statusOf(s, now, noPaint)
	for _, want := range []line{{kind: lineField, label: "Tunnels", text: "1 of 1 live, checked 5m ago"}, {kind: lineField, label: "Ports", text: "udp/41643, tcp/41644 sync"}} {
		if !slices.Contains(v.head, want) {
			t.Errorf("head %v lacks %v", v.head, want)
		}
	}
}

// A relaying device lists its relay port, which has to be open as well.
func TestStatusPortsIncludeTheRelay(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_000_000, 0)
	s := &ipc.Status{InNetwork: true, SyncInTunnel: true, ListenPort: 41643, GossipPort: 41644,
		Derived: ipc.Derived{NetworkName: "home", Members: 2, Peers: 1, Relaying: true, RelayCapable: 1},
		Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 1, ReachChecked: now.Unix(), RelayPort: 41645}}
	want := line{kind: lineField, label: "Ports", text: "udp/41643, tcp/41645 and udp/41645 relay"}
	if v := statusOf(s, now, noPaint); !slices.Contains(v.head, want) {
		t.Errorf("head %v lacks %v", v.head, want)
	}
}

// A live tunnel whose log sync does not come up is named, with what lets the
// sync port through on juist0.
func TestStatusNamesSyncBlockedInTheTunnel(t *testing.T) {
	t.Parallel()
	var out syncBuffer
	a := newApp(strings.NewReader(""), &out, &out)
	a.printStatus(&ipc.Status{InNetwork: true, GossipPort: 41644, Derived: ipc.Derived{NetworkName: "home", Members: 2, Peers: 1}, Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 1, SyncFailing: []string{"vps"}}})
	mustContain(t, out.String(), "log sync to vps fails in the tunnel",
		"tcp/41644 on juist0", "sudo ufw allow in on juist0")
}

// An admin machine's keystore holds a network's log and no device of it. It
// lists the devices as they are, and a reset, which would delete that log,
// wants --force.
func TestAnAdminMachineIsNotTakenForARemovedDevice(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("init", "home", "--no-device")
	out := c.mustRun("devices")
	if strings.Contains(out, "no longer in") {
		t.Fatalf("an admin machine was told it left the network:\n%s", out)
	}
	if _, err := c.run("reset", "--yes"); err == nil || !strings.Contains(err.Error(), "no device") {
		t.Fatalf("reset of an admin machine's log without --force: %v", err)
	}
	if _, err := os.Stat(filepath.Join(c.home, logDir)); err != nil {
		t.Fatalf("the refused reset touched the log: %v", err)
	}
}

// A change that lost fork choice and is not a revocation is named too.
func TestStatusNamesALostChange(t *testing.T) {
	t.Parallel()
	var out syncBuffer
	a := newApp(strings.NewReader(""), &out, &out)
	a.printStatus(&ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 2, Peers: 1, Lost: []string{"the admission of phone"}}})
	mustContain(t, out.String(), "the admission of phone lost to a concurrent change", "redo it")
}

// On a terminal narrower than the device table, as a phone's over ssh, status
// wraps its fields and lists the devices instead, and every line fits.
func TestStatusFitsANarrowTerminal(t *testing.T) {
	t.Parallel()
	self, desktop := types.Identity{1}, types.Identity{2}
	st := &ipc.Status{
		InNetwork: true, Self: self, ListenPort: 41643, CanOperate: true,
		Addrs: []netip.Prefix{netip.MustParsePrefix("10.11.11.254/32"),
			netip.MustParsePrefix("fd12:345:6789:9783:7a4:513e:505f:60a0/128")},
		Derived: ipc.Derived{NetworkName: "lab", SelfName: "edge01", Members: 2, Peers: 1, RelayCapable: 1, Relaying: true,
			Devices: []ipc.Device{
				{Identity: self, Name: "edge01", V4: "10.11.11.254", V6: "fd12:345:6789:9783:7a4:513e:505f:60a0",
					Roles: []types.Role{types.RoleAdmin, types.RoleRelayCapable}},
				{Identity: desktop, Name: "desktop", V4: "10.11.11.10", V6: "fd12:345:6789:27ef:8e2b:1889:2553:4ba2",
					Roles: []types.Role{types.RoleAdmin}},
			}},
		Tunnels: ipc.Tunnels{TunnelsChecked: true, ReachChecked: time.Now().Unix(), TunnelsDown: []string{"desktop"}, RelayedFor: 2,
			Absent: []string{"desktop"},
			Reach:  []ipc.PeerReach{{Identity: desktop, Absent: true, Heard: time.Now().Add(-time.Hour).Unix()}}},
	}
	var out syncBuffer
	a := newApp(strings.NewReader(""), &out, &out)
	a.width = 60
	a.printStatus(st)
	got := out.String()
	for _, l := range strings.Split(got, "\n") {
		if len(l) > a.width {
			t.Errorf("%d columns on a terminal of %d: %q", len(l), a.width, l)
		}
	}
	mustContain(t, got, "  This device   edge01  10.11.11.254\n                fd12:345:6789:9783:7a4:513e:505f:60a0\n",
		"desktop  10.11.11.10  offline, heard 1h ago\n  fd12:345:6789:27ef:8e2b:1889:2553:4ba2\n  voucher\n",
		"edge01 (this device)  10.11.11.254\n  fd12:345:6789:9783:7a4:513e:505f:60a0\n  voucher, relay\n")
	if strings.Contains(got, "NAME") {
		t.Errorf("the table is printed though it does not fit:\n%s", got)
	}

	out = syncBuffer{}
	a.width = 0
	a.printStatus(st)
	mustContain(t, out.String(), "NAME", "desktop ")
}

func TestWrap(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		s     string
		width int
		want  []string
	}{
		{"a b c", 0, []string{"a b c"}},
		{"a b c", 5, []string{"a b c"}},
		{"aa  bb cc", 6, []string{"aa  bb", "cc"}},
		{"toolongword x", 4, []string{"toolongword", "x"}},
		{"\x1b[33mab\x1b[0m cd", 5, []string{"\x1b[33mab\x1b[0m cd"}},
	} {
		if got := wrap(c.s, c.width); !slices.Equal(got, c.want) {
			t.Errorf("wrap(%q, %d) = %q, want %q", c.s, c.width, got, c.want)
		}
	}
}
