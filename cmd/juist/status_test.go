package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

func noPaint(_, s string) string { return s }

// A name the terminator has no certificate for is warned of, with why, while
// it runs.
func TestTheStatusWarnsOfANameWithoutACertificate(t *testing.T) {
	t.Parallel()
	st := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 2}}
	st.Terminator = &ipc.Terminator{Running: true, NoCert: []ipc.NoCert{{Name: "1.juist.dev", Why: "no viable challenge type found"}}}
	want := line{kind: lineWarn, text: "no certificate for 1.juist.dev: no viable challenge type found"}
	if v := statusOf(st, testNow(), noPaint); !slices.Contains(v.notes, want) {
		t.Errorf("notes %v lack %v", v.notes, want)
	}
	st.Terminator.Running = false
	if v := statusOf(st, testNow(), noPaint); slices.Contains(v.notes, want) {
		t.Errorf("a terminator not running is still said to lack a certificate: %v", v.notes)
	}
}

// Another program holding port 80 where names are served is warned of: http://
// to them reaches it, not the terminator's redirect.
func TestTheStatusWarnsOfPort80HeldByAnother(t *testing.T) {
	t.Parallel()
	st := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 2}}
	st.Terminator = &ipc.Terminator{Running: true, Listening: []string{"10.11.11.13:443"},
		Unbound: []string{"10.11.11.13:80", "[fd90::1]:80", "10.11.11.13:8443"}}
	want := line{kind: lineWarn, text: "another program holds port 80 on 10.11.11.13, fd90::1, so http:// to a name " +
		"served here reaches it, not a redirect to https"}
	if v := statusOf(st, testNow(), noPaint); !slices.Contains(v.notes, want) {
		t.Errorf("notes %v lack %v", v.notes, want)
	}
	st.Terminator.Unbound = []string{"10.11.11.13:8443"}
	for _, l := range statusOf(st, testNow(), noPaint).notes {
		if strings.Contains(l.text, "port 80") {
			t.Errorf("warned of port 80 held by none: %v", l)
		}
	}
}

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
	if len(v.notes) != 0 || v.head[0].text != "home · removed" {
		t.Errorf("a removed device's status: %+v", v)
	}
}

func TestLogVerifyReportsCorruption(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home")
	corrupt(t, c)
	if _, err := c.run("log", "verify"); err == nil {
		t.Fatal("log verify accepted a corrupt log")
	}
}

func TestLogShow(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	mustContain(t, c.mustRun("log"), "network creation", "approved by")
}

// One change is said against the state before it, by number or by hash.
func TestLogShowsOneChange(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	c.mustRun("policy", "set", "--yes", writePolicy(t, "p1.conf", "pass from laptop to laptop\n"))
	c.mustRun("policy", "set", "--yes", writePolicy(t, "p2.conf", "pass from laptop to laptop proto tcp port 22\n"))
	out := c.mustRun("log", "show", "2")
	mustContain(t, out, "change of the access policy", "replaces the access policy:",
		"- pass from laptop to laptop\n", "+ pass from laptop to laptop proto tcp port 22", "approved by ", "hash ")
	hash := regexp.MustCompile(`hash (\S+)`).FindStringSubmatch(out)[1]
	if got := c.mustRun("log", "show", strings.ToLower(hash[:6])); got != out {
		t.Errorf("by its hash:\n%s", got)
	}
	mustContain(t, c.mustRun("log", "show", "0"), "creates the network \"home\"", "device laptop")
	if _, err := c.run("log", "show", "3"); err == nil || err.Error() != "no change 3: the log lists 0 to 2" {
		t.Errorf("past the end: %v", err)
	}
}

func TestStatusWithoutADaemon(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	mustContain(t, c.mustRun("status"), "juistd not running", "laptop", "198.18.4.1")
}

func TestStatusShowsFreshness(t *testing.T) {
	t.Parallel()
	d := newDaemonDevice(t, nil)
	d.mustRun("create", "home", "--device", "laptop", "--voucher")
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
	c.mustRun("create", "home")
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
	c.mustRun("create", "home")
	mustContain(t, c.mustRun("log", "upgrade"), "unchanged")
}

func TestLogUpgradesHelpNamesEverySchema(t *testing.T) {
	t.Parallel()
	out := newCLI(t).mustRun("help", "log", "upgrade")
	for v := types.SchemaVersion(1); v <= types.CurrentSchema; v++ {
		if !strings.Contains(out, fmt.Sprintf("\n  %v ", v)) {
			t.Errorf("juist help log upgrade does not say what %v brings", v)
		}
	}
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

// status says by what key each tunnel is post-quantum, and names those that
// are not.
func TestStatusSaysWhichTunnelsArePostQuantum(t *testing.T) {
	t.Parallel()
	base := ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 4, Peers: 3,
		Schema: types.SchemaPQ}}
	for _, c := range []struct {
		pq   ipc.PQ
		want []string
		not  []string
	}{
		{ipc.PQ{Pair: 3}, []string{"Post-quantum  every tunnel: 3 by pair keys"}, []string{"not post-quantum", "no preshared key"}},
		{ipc.PQ{Pair: 1, Group: 2}, []string{"every tunnel: 1 by a pair key, 2 by the group key"}, []string{"not post-quantum", "no preshared key"}},
		{ipc.PQ{Pair: 2, None: []string{"lx"}}, []string{"2 of 3 tunnels: 2 by pair keys",
			"warning: not post-quantum, so juist's own traffic alone: lx, on an older build"}, nil},
		{ipc.PQ{Group: 2, NoKey: []string{"phone"}}, []string{"2 of 3 tunnels: 2 by the group key",
			"warning: no preshared key in common with phone", "hint: it catches up"}, nil},
	} {
		var out syncBuffer
		a := newApp(strings.NewReader(""), &out, &out)
		a.node = &daemonNode{sock: "/nonexistent", st: &ipc.Status{InNetwork: true}}
		s := base
		s.PQ = &c.pq
		a.printStatus(&s)
		mustContain(t, out.String(), c.want...)
		for _, n := range c.not {
			if strings.Contains(out.String(), n) {
				t.Errorf("%+v: says %q:\n%s", c.pq, n, out.String())
			}
		}
	}

	var out syncBuffer
	a := newApp(strings.NewReader(""), &out, &out)
	a.node = &daemonNode{sock: "/nonexistent", st: &ipc.Status{InNetwork: true}}
	s := base
	s.Schema, s.PQ = types.SchemaPQ-1, &ipc.PQ{None: []string{"a", "b", "c"}}
	a.printStatus(&s)
	mustContain(t, out.String(), "Post-quantum  no, the network predates it")
	if strings.Contains(out.String(), "warning: not post-quantum") {
		t.Errorf("a network before post-quantum tunnels names every device:\n%s", out.String())
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
	admin.mustRun("create", "home")
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

// juist status counts the devices and lists none, which juist devices does.
func TestStatusListsNoDevices(t *testing.T) {
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
	a.printStatus(&ipc.Status{InNetwork: true, Self: ids[0], Derived: ipc.Derived{NetworkName: "home", SelfName: "desk", Members: 3, Peers: 2, Devices: []ipc.Device{
		{Identity: ids[0], Name: "desk", V4: "10.11.11.4", V6: "fd89::4"},
		{Identity: ids[1], Name: "laptop", V4: "10.11.11.5", V6: "fd89::5"},
		{Identity: ids[2], Name: "vps", V4: "10.11.11.6", V6: "fd89::6", Roles: []types.Role{types.RoleRelayCapable}},
	}}, Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 2, ReachChecked: time.Now().Unix(), Reach: []ipc.PeerReach{{Identity: ids[1], Live: true, Direct: true}, {Identity: ids[2], Live: true}}}})
	got := out.String()
	mustContain(t, got, "Devices       2 others, all heard from\n")
	for _, absent := range []string{"NAME", "REACHED", "laptop", "10.11.11.6"} {
		if strings.Contains(got, absent) {
			t.Errorf("status lists the devices (%q):\n%s", absent, got)
		}
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
	c.mustRun("create", "home", "--no-device")
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

// On a narrow terminal, as a phone's over ssh, status wraps its fields, and
// every line fits.
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
	mustContain(t, got, "  This device   edge01  10.11.11.254\n                fd12:345:6789:9783:7a4:513e:505f:60a0\n")
}

// juist devices leaves IPv6 out unless asked for it, says that a device
// answers names or publishes some without naming them, and on a terminal too
// narrow for its table wraps the roles beneath their column, and gives way
// to a list only where they would be split within a word, or narrower than
// [minLastColumn].
func TestDevicesTable(t *testing.T) {
	t.Parallel()
	self, desktop := types.Identity{1}, types.Identity{2}
	devs := []ipc.Device{
		{Identity: self, Name: "edge01", V4: "10.11.11.254", V6: "fd12:345:6789:9783:7a4:513e:505f:60a0",
			Roles: []types.Role{types.RoleAdmin, types.RoleRelayCapable}, Names: []string{"mail.example.org"},
			Published: []string{"immich.pub.example.org"}},
		{Identity: desktop, Name: "desktop", V4: "10.11.11.10", V6: "fd12:345:6789:27ef:8e2b:1889:2553:4ba2",
			Roles: []types.Role{types.RoleAdmin}},
	}
	st := &ipc.Status{InNetwork: true, Tunnels: ipc.Tunnels{ReachChecked: time.Now().Unix(),
		Reach: []ipc.PeerReach{{Identity: desktop, Absent: true, Heard: time.Now().Add(-time.Hour).Unix()}}}}
	print := func(width int, v6 bool) string {
		var out syncBuffer
		a := newApp(strings.NewReader(""), &out, &out)
		a.width = width
		if err := a.printDevices(devs, self, st, false, v6); err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(out.String(), "\n") {
			if width > 0 && len(l) > width {
				t.Errorf("%d columns on a terminal of %d: %q", len(l), width, l)
			}
		}
		return out.String()
	}

	got := print(0, false)
	want := "NAME                  IPV4          REACHED                ROLES\n" +
		"desktop               10.11.11.10   offline, heard 1h ago  voucher\n" +
		"edge01 (this device)  10.11.11.254  -                      voucher, relay, names, publishes\n"
	if got != want {
		t.Errorf("devices:\n%s\nwant:\n%s", got, want)
	}
	mustContain(t, print(0, true), "IPV6", "fd12:345:6789:27ef:8e2b:1889:2553:4ba2  offline")

	mustContain(t, print(78, false), "edge01 (this device)  10.11.11.254  -                      voucher, relay,\n"+
		strings.Repeat(" ", 59)+"names, publishes\n")
	mustContain(t, print(72, false), "-                      voucher,\n"+strings.Repeat(" ", 59)+"relay, names,\n"+
		strings.Repeat(" ", 59)+"publishes\n")
	got = print(60, false)
	mustContain(t, got, "desktop  10.11.11.10\n  offline, heard 1h ago\n  voucher\n",
		"edge01 (this device)  10.11.11.254\n  voucher, relay, names, publishes\n")
	if strings.Contains(got, "NAME") {
		t.Errorf("the table is printed though it does not fit:\n%s", got)
	}
}

// juist devices fits a terminal of any width: every line but one word wider
// than the terminal is as wide as it at most, and no device is lost.
func TestDevicesFitEveryWidth(t *testing.T) {
	t.Parallel()
	ids := []types.Identity{{1}, {2}, {3}, {4}}
	devs := []ipc.Device{
		{Identity: ids[0], Name: "edge01", V4: "10.11.11.254", V6: "fd12:345:6789:9783:7a4:513e:505f:60a0",
			Roles: []types.Role{types.RoleAdmin, types.RoleRelayCapable, types.RoleExit}, Names: []string{"mail.example.org"},
			Published: []string{"immich.pub.example.org"}},
		{Identity: ids[1], Name: "desktop", V4: "10.7.0.2", Retiring: "198.18.4.2", V6: "fd12:345:6789:27ef:8e2b:1889:2553:4ba2",
			Roles: []types.Role{types.RoleAdmin}},
		{Identity: ids[2], Name: "nas-im-keller", V4: "10.11.11.3", V6: "fd90::3",
			Subnets: []netip.Prefix{netip.MustParsePrefix("192.168.178.0/24"), netip.MustParsePrefix("10.20.0.0/16")}},
		{Identity: ids[3], Name: "phone", V4: "10.11.11.4", V6: "fd90::4"},
	}
	st := &ipc.Status{InNetwork: true, Tunnels: ipc.Tunnels{ReachChecked: time.Now().Unix(), Reach: []ipc.PeerReach{
		{Identity: ids[1], Absent: true, Heard: time.Now().Add(-time.Hour).Unix()},
		{Identity: ids[2], Live: true, Direct: true}, {Identity: ids[3], Live: true}}}}
	for _, v6 := range []bool{false, true} {
		for _, keys := range []bool{false, true} {
			for width := 20; width <= 160; width++ {
				var out syncBuffer
				a := newApp(strings.NewReader(""), &out, &out)
				a.width = width
				if err := a.printDevices(devs, ids[0], st, keys, v6); err != nil {
					t.Fatal(err)
				}
				got := out.String()
				for _, l := range strings.Split(got, "\n") {
					if len(l) > width && strings.Contains(strings.TrimSpace(l), " ") {
						t.Errorf("-6=%v --keys=%v: %d columns on a terminal of %d: %q", v6, keys, len(l), width, l)
					}
				}
				for _, d := range devs {
					if !strings.Contains(got, d.Name) {
						t.Errorf("-6=%v --keys=%v, %d columns: %s is missing:\n%s", v6, keys, width, d.Name, got)
					}
				}
			}
		}
	}

	var out syncBuffer
	a := newApp(strings.NewReader(""), &out, &out)
	a.width = 32
	if err := a.printDevices(devs, ids[0], st, false, false); err != nil {
		t.Fatal(err)
	}
	want := "desktop\n  10.7.0.2 (was 198.18.4.2)\n  offline, heard 1h ago\n  voucher\n" +
		"nas-im-keller  10.11.11.3\n  direct\n  routes 192.168.178.0/24,\n    10.20.0.0/16\n" +
		"phone  10.11.11.4\n  relayed\n" +
		"edge01 (this device)\n  10.11.11.254\n  voucher, relay, exit, names,\n    publishes\n"
	if got := out.String(); got != want {
		t.Errorf("32 columns:\n%s\nwant:\n%s", got, want)
	}
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

// A status names the devices not yet told of a renumbering while an old
// address works, and once it is retired too, when they reach the moved
// device at no address at all.
func TestStatusNamesTheDevicesNotYetMoved(t *testing.T) {
	st := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 3,
		Unmoved: []string{"tablet"}}}
	st.Devices = []ipc.Device{{Name: "phone", V4: "198.18.4.9", Retiring: "198.18.4.2", RetiringUntil: 2_000_000_000}}
	mustContain(t, render(statusOf(st, testNow(), noPaint).head), "old addresses until", "not told yet: tablet")
	st.Devices[0].Retiring, st.Devices[0].RetiringUntil = "", 0
	mustContain(t, render(statusOf(st, testNow(), noPaint).head), "old addresses held; not told yet: tablet")
	st.Unmoved = nil
	if head := render(statusOf(st, testNow(), noPaint).head); strings.Contains(head, "old addresses") {
		t.Fatalf("a status with nothing to follow speaks of a renumbering:\n%s", head)
	}
}

// An admin's status says the network is below this build's schema, until it
// is upgraded; a keystore without its admin keys is not told.
func TestStatusTellsAnAdminToUpgradeTheLog(t *testing.T) {
	t.Parallel()
	d := &daemonDevice{cli: newCLI(t), state: filepath.Join(shortTempDir(t), "state"),
		sock: filepath.Join(shortTempDir(t), "juistd.sock"), mgr: &peersManager{}}
	stop := startService(t, d.state, d.sock, nil, d.mgr)
	d.mustRun("create", "home", "--device", "laptop")
	if out := d.mustRun("status"); strings.Contains(out, "log upgrade") {
		t.Fatalf("a network at this build's schema is to be upgraded:\n%s", out)
	}
	stop()

	cur := openLog(t, &cli{t: t, home: d.state}).State()
	genesis, err := log.Genesis("home", 1, cur.Admins(), []types.Hash{{1}}, cur.Nodes(), sealer())
	if err != nil {
		t.Fatal(err)
	}
	genesis.State.Schema = types.CurrentSchema - 1
	if p, ok := cur.V4Prefix(); ok {
		genesis.State.V4Prefix = &p
	}
	keys, err := d.home2().adminKeys()
	if err != nil || len(keys) != 1 {
		t.Fatalf("admin keys: %v, %v", keys, err)
	}
	if err := genesis.Sign(keys[0]); err != nil {
		t.Fatal(err)
	}
	// The keystore pins the network it saw; this is another genesis.
	for _, dir := range []string{filepath.Join(d.state, logDir), filepath.Join(d.home, "networks")} {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.Open(filepath.Join(d.state, logDir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Create(st, genesis); err != nil {
		t.Fatal(err)
	}
	startService(t, d.state, d.sock, nil, d.mgr)

	mustContain(t, d.mustRun("status"), fmt.Sprintf("the network is at %v, this version at %v",
		types.CurrentSchema-1, types.CurrentSchema), "hint: once every device runs this version: juist log upgrade")
	other := &daemonDevice{cli: newCLI(t), state: d.state, sock: d.sock}
	if out := other.mustRun("status"); strings.Contains(out, "log upgrade") {
		t.Errorf("a keystore without an admin key is told to upgrade:\n%s", out)
	}
	d.mustRun("log", "upgrade", "--yes")
	if out := d.mustRun("status"); strings.Contains(out, "log upgrade") {
		t.Errorf("the hint outlives the upgrade:\n%s", out)
	}
}

// status warns before freshness ends, not only once it has.
func TestStatusWarnsBeforeFreshnessEnds(t *testing.T) {
	t.Parallel()
	var out syncBuffer
	a := newApp(strings.NewReader(""), &out, &out)
	a.node = &daemonNode{sock: "/nonexistent", st: &ipc.Status{InNetwork: true}}
	now := time.Now().Unix()
	a.printStatus(&ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 3,
		LeaseSigners: 3, Vouchers: 2, Vouching: 2, FreshSince: now - 30*3600, FreshUntil: now + 18*3600}})
	mustContain(t, out.String(), "warning: freshness ends in", "unless 2 vouchers vouch again")
}

// Where nothing vouches and two devices relay, status names them as the
// vouchers that would bound how long a removal takes; with one, it names none.
func TestStatusSuggestsAlwaysOnVouchers(t *testing.T) {
	t.Parallel()
	relay := []types.Role{types.RoleRelayCapable}
	for _, c := range []struct {
		devices []ipc.Device
		want    bool
	}{
		{[]ipc.Device{{Name: "laptop"}, {Name: "vps", Roles: relay}, {Name: "nas", Roles: relay}}, true},
		{[]ipc.Device{{Name: "laptop"}, {Name: "vps", Roles: relay}}, false},
		{[]ipc.Device{{Name: "vps", Roles: relay}, {Name: "nas", Roles: relay},
			{Name: "edge", Roles: []types.Role{types.RoleIngress, types.RoleRelayCapable}}}, true},
		{[]ipc.Device{{Name: "vps", Roles: relay}, {Name: "edge", Roles: []types.Role{types.RoleIngress, types.RoleRelayCapable}}}, false},
	} {
		var out syncBuffer
		a := newApp(strings.NewReader(""), &out, &out)
		a.node = &daemonNode{sock: "/nonexistent", st: &ipc.Status{InNetwork: true}}
		a.printStatus(&ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 3, Devices: c.devices}})
		if got := strings.Contains(out.String(), "juist grant vps voucher, juist grant nas voucher"); got != c.want {
			t.Errorf("suggested=%v, want %v\n%s", got, c.want, out.String())
		}
		if strings.Contains(out.String(), "juist grant edge voucher") {
			t.Errorf("an ingress was suggested as a voucher:\n%s", out.String())
		}
	}
}

// A device on HTTPS alone says so, by which relays and proxy, and warns where
// no relay is on 443; one that does not reach a device blames no UDP port.
// A relay's name has a line of its own, and what keeps it from 443 a warning.
func TestStatusSaysHTTPSAloneAndTheRelaysName(t *testing.T) {
	t.Parallel()
	var out syncBuffer
	a := newApp(strings.NewReader(""), &out, &out)
	base := func() *ipc.Status {
		return &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 3, Peers: 2, RelayCapable: 1,
			Relays: 1}, Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 1, TunnelsDown: []string{"nas"},
			Seeking: []string{"nas"}}}
	}
	st := base()
	st.HTTPS = &ipc.HTTPS{Only: true, Relays: []string{"relay.example.org"}, Proxy: "http://u:xxxxx@proxy:3128"}
	a.printStatus(st)
	mustContain(t, out.String(), "HTTPS         only, by relay.example.org through http://u:xxxxx@proxy:3128\n",
		"no answer from nas: offline, or at no relay on 443")
	if strings.Contains(out.String(), "udp/") {
		t.Errorf("a device on HTTPS alone is told of UDP:\n%s", out.String())
	}

	out = syncBuffer{}
	st.HTTPS.Relays = nil
	a.printStatus(st)
	mustContain(t, out.String(), "only, and no relay on 443", "warning: no relay on 443/tcp",
		"hint: a relay's operator names it there: juist set --relay-name NAME")

	for _, c := range []struct {
		h    ipc.HTTPS
		line string
		want []string
	}{
		{ipc.HTTPS{Name: "relay.example.org", Listening: []string{"192.0.2.7:443"}}, "relay.example.org, on 443\n", nil},
		{ipc.HTTPS{Name: "relay.example.org", Listening: []string{ipc.HandedOn}}, "relay.example.org, on 443 through the ingress\n", nil},
		{ipc.HTTPS{Name: "relay.example.org", NotAnnounced: "the network is at schema 11"}, "relay.example.org, not told to members",
			[]string{"warning: members are not told of relay.example.org: the network is at schema 11", "hint: juist log upgrade"}},
		{ipc.HTTPS{Name: "relay.example.org", ListenError: "listen tcp 192.0.2.7:443: bind: permission denied"}, "relay.example.org, not on 443",
			[]string{"warning: the relay cannot take 443", "hint: sudo juist set --relay-name relay.example.org"}},
		{ipc.HTTPS{Name: "relay.example.org", Listening: []string{"192.0.2.7:443"}, NoCert: "the CA refused"},
			"relay.example.org, no certificate yet", []string{"warning: no certificate for relay.example.org yet: the CA refused",
				"hint: relay.example.org must point at this device in DNS, and every firewall in front of it let 443/tcp in"}},
	} {
		out = syncBuffer{}
		st := base()
		st.Relaying, st.HTTPS, st.CanOperate = true, &c.h, true
		a.printStatus(st)
		mustContain(t, out.String(), append([]string{"Relay name    " + strings.TrimSuffix(c.line, "\n")}, c.want...)...)
	}

	// A reader's status holds none of how the relay takes 443.
	out = syncBuffer{}
	st = base()
	full := ipc.Status{Derived: ipc.Derived{Relaying: true, HTTPS: &ipc.HTTPS{Name: "relay.example.org",
		Listening: []string{ipc.HandedOn}}}}
	st.Relaying, st.HTTPS = true, full.ForReader().HTTPS
	a.printStatus(st)
	mustContain(t, out.String(), "Relay name    relay.example.org\n")
	if strings.Contains(out.String(), "not on 443") {
		t.Errorf("a reader is told the relay is not on 443:\n%s", out.String())
	}
}
