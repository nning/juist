package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/internal/firewalld"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// juist status says how things stand and how many warnings juist health has
// to say; juist health says them, each with its hint.
func TestStatusPointsAtHealth(t *testing.T) {
	t.Parallel()
	st := &ipc.Status{InNetwork: true, GossipPort: 41644, Derived: ipc.Derived{NetworkName: "home", Members: 3,
		Peers: 2, Relays: 1, RelayCapable: 1}, Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 1, SyncFailing: []string{"vps"},
		TunnelsDown: []string{"phone"}}}
	var status, health syncBuffer
	a := newApp(strings.NewReader(""), &status, &status)
	a.printStatusIn(st, "", false)
	a.healthHint(st, "", false)
	got := status.String()
	mustContain(t, got, "home · ", "hint: 2 warnings: juist health\n")
	if strings.Contains(got, "log sync") || strings.Contains(got, "phone") {
		t.Errorf("status says what juist health does:\n%s", got)
	}
	a = newApp(strings.NewReader(""), &health, &health)
	a.health(st, "", false)
	mustContain(t, health.String(), "warning: log sync to vps fails in the tunnel",
		"warning: no tunnel traffic from phone")
	if strings.Contains(health.String(), "This device") {
		t.Errorf("health repeats the status:\n%s", health.String())
	}
}

// Names refused while the host's DNS routing cannot be read are juist
// health's to say, and juist status counts them alone.
func TestHealthSaysTheDNSRoutingIsUnread(t *testing.T) {
	t.Parallel()
	st := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home"}, DNSRoutingUnread: "dbus: call timed out"}
	var status, health syncBuffer
	a := newApp(strings.NewReader(""), &status, &status)
	a.printStatusIn(st, "", false)
	a.healthHint(st, "", false)
	mustContain(t, status.String(), "hint: 1 warning: juist health\n")
	if strings.Contains(status.String(), "dbus") {
		t.Errorf("status says what juist health does:\n%s", status.String())
	}
	a = newApp(strings.NewReader(""), &health, &health)
	a.health(st, "", false)
	mustContain(t, health.String(),
		"warning: cannot read the host's DNS routing, so names routed elsewhere are refused: dbus: call timed out\n")
}

// An overlay the host does not keep to the tunnel is juist health's to say.
func TestHealthSaysTheOverlayIsUnguarded(t *testing.T) {
	t.Parallel()
	st := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home"},
		Tunnels: ipc.Tunnels{Unguarded: "pf's rules call no juist anchor first"}}
	var health syncBuffer
	a := newApp(strings.NewReader(""), &health, &health)
	a.health(st, "", false)
	mustContain(t, health.String(),
		"warning: overlay addresses reachable from outside the tunnel: pf's rules call no juist anchor first\n")
}

// Names refused by how the host routes them are juist health's to say while
// they are recent, and juist status counts them.
func TestHealthSaysRecentRefusals(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	for _, tc := range []struct {
		ago  time.Duration
		want bool
	}{{time.Minute, true}, {time.Hour, false}} {
		var out syncBuffer
		a := c.app(&out, "")
		st := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home"},
			DNSRefused: "the host asks tailscaled alone, whose answers members cannot reach", DNSRefusedAt: a.now().Add(-tc.ago).Unix()}
		n, _ := a.healthWarnings(st, "", false)
		a.health(st, "", false)
		said := strings.Contains(out.String(),
			"warning: names juistd forwards are refused: the host asks tailscaled alone, whose answers members cannot reach\n")
		if said != tc.want || (n == 1) != tc.want {
			t.Errorf("refused %v ago: %d warnings counted:\n%s", tc.ago, n, out.String())
		}
		if hinted := strings.Contains(out.String(), "hint: to let them through: sudo tailscale set --accept-dns=false"); hinted != tc.want && runtime.GOOS != "freebsd" {
			t.Errorf("refused %v ago, hinted %v:\n%s", tc.ago, hinted, out.String())
		}
	}
}

// The warnings juist status counts are the ones juist health prints, alarms
// aside.
func TestStatusCountsTheWarningsHealthPrints(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.system = map[string]string{"/etc/resolv.conf": "nameserver 192.168.1.1\n"}
	for _, st := range []*ipc.Status{
		{InNetwork: true, Derived: ipc.Derived{NetworkName: "home"}},
		{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Alarm: "log: fork alarm"},
			Tunnels: ipc.Tunnels{TunnelsChecked: true, SyncFailing: []string{"vps"}, TunnelsDown: []string{"phone"}}},
		{InNetwork: true, CanOperate: true, Derived: ipc.Derived{NetworkName: "home", Schema: types.CurrentSchema,
			Exit: &ipc.Exit{Node: types.Identity{2}, Name: "vps", DNSNot: "DNS is off on this device"}}},
	} {
		var out syncBuffer
		a := c.app(&out, "")
		a.color = true
		n, _ := a.healthWarnings(st, "", false)
		a.health(st, "", false)
		if printed := strings.Count(out.String(), a.paint("33", "warning:")); printed != n || n == 0 && st.Alarm != "" {
			t.Errorf("%+v: counted %d warnings, health printed %d:\n%s", st, n, printed, out.String())
		}
	}
}

// Where nothing needs attention, juist health says so, and juist status
// points nowhere.
func TestHealthSaysNothingNeedsAttention(t *testing.T) {
	t.Parallel()
	d := newDaemonDevice(t, nil)
	d.mustRun("create", "home", "--device", "laptop")
	mustContain(t, d.mustRun("health"), "nothing needs attention\n")
	if out := d.mustRun("status"); strings.Contains(out, "juist health") {
		t.Errorf("status points at juist health with nothing to say:\n%s", out)
	}
}

// juist devices shows the newest schema each device's juist implements, and
// none where no device says.
func TestDevicesShowEachBuild(t *testing.T) {
	t.Parallel()
	self, desktop, phone := types.Identity{1}, types.Identity{2}, types.Identity{3}
	devs := []ipc.Device{{Identity: self, Name: "edge01", V4: "10.0.0.1"}, {Identity: desktop, Name: "desktop", V4: "10.0.0.2"},
		{Identity: phone, Name: "phone", V4: "10.0.0.3"}}
	st := &ipc.Status{InNetwork: true, Derived: ipc.Derived{Devices: []ipc.Device{{Identity: self, Build: types.CurrentSchema},
		{Identity: desktop, Build: types.CurrentSchema - 2}}}, Tunnels: ipc.Tunnels{ReachChecked: time.Now().Unix()}}
	var out syncBuffer
	a := newApp(strings.NewReader(""), &out, &out)
	if err := a.printDevices(devs, self, st, false, false); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	mustContain(t, got, "SCHEMA")
	for _, l := range strings.Split(got, "\n") {
		switch {
		case strings.HasPrefix(l, "edge01") && !strings.Contains(l, fmt.Sprintf(" %d ", types.CurrentSchema)),
			strings.HasPrefix(l, "desktop") && !strings.Contains(l, fmt.Sprintf(" %d ", types.CurrentSchema-2)),
			strings.HasPrefix(l, "phone") && !strings.Contains(l, " - "):
			t.Errorf("a device's schema is not shown: %q\n%s", l, got)
		}
	}
	st.Devices = nil
	var none syncBuffer
	a = newApp(strings.NewReader(""), &none, &none)
	if err := a.printDevices(devs, self, st, false, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(none.String(), "SCHEMA") {
		t.Errorf("a column of schemas none said:\n%s", none.String())
	}
}

// A member this device's relay says is not there is said so in one line: a
// warning where it runs, as it keeps no connection there, an answer's reason
// where it may be offline, and nothing where it is.
func TestHealthNamesAMemberNotAtTheRelay(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name            string
		seeking, absent []string
		want, not       string
		warnings        int
	}{
		{"runs", nil, nil, "warning: phone is not at edge01, the relay this device uses\n",
			"though it announces itself", 1},
		{"may be offline", []string{"phone"}, nil,
			"no answer from phone: not at edge01, the relay this device uses\n", "udp/", 0},
		{"offline", nil, []string{"phone"}, "", "not at the relay", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 3, Peers: 2, Relays: 2,
				RelayCapable: 2}, Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 1, TunnelsDown: []string{"phone"},
				Seeking: c.seeking, Absent: c.absent, NotAtRelay: []string{"phone"}, HomeRelay: "edge01"}}
			var health syncBuffer
			a := newApp(strings.NewReader(""), &health, &health)
			a.health(st, "", false)
			if !strings.Contains(health.String(), c.want) || strings.Contains(health.String(), c.not) {
				t.Errorf("juist health says:\n%s\nwant %q, not %q", health.String(), c.want, c.not)
			}
			if n, _ := a.healthWarnings(st, "", false); n != c.warnings {
				t.Errorf("%d warnings, want %d", n, c.warnings)
			}
		})
	}
}

// An exit node whose forwarder does not answer says why in juist health, and
// counts it in juist status, which says it serves.
func TestHealthSaysAnExitNodeAnswersNoDNS(t *testing.T) {
	t.Parallel()
	st := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 2, Peers: 1,
		Exit: &ipc.Exit{Consent: true, Serving: true, DNSUnserved: "dnsfwd: listen udp 198.18.0.1:41646: bind: address already in use"}}}
	var status, health syncBuffer
	a := newApp(strings.NewReader(""), &status, &status)
	a.printStatusIn(st, "", false)
	a.healthHint(st, "", false)
	mustContain(t, status.String(), "this device serves\n", "hint: 1 warning: juist health\n")
	if strings.Contains(status.String(), "address already in use") {
		t.Errorf("status says what juist health does:\n%s", status.String())
	}
	a = newApp(strings.NewReader(""), &health, &health)
	a.health(st, "", false)
	mustContain(t, health.String(), "warning: members' DNS is not answered here: dnsfwd: listen udp 198.18.0.1:41646: bind: address already in use\n")
}

// juist health sets each issue off by a blank line on stderr, a hint staying
// with the warning it belongs to and a hint of its own apart.
func TestHealthSetsIssuesApart(t *testing.T) {
	t.Parallel()
	st := &ipc.Status{InNetwork: true, Device: "juist0", GossipPort: 41644, ListenPort: 41643,
		Derived: ipc.Derived{NetworkName: "home", Members: 3, Peers: 2, Relays: 1, RelayCapable: 1},
		Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 1, SyncFailing: []string{"bsdbox01"}, TunnelsDown: []string{"mac-devvm"}, Seeking: []string{"mac-devvm"}},
		HostConflict: &ipc.HostConflict{Instance: 1, Held: netip.MustParsePrefix("10.11.11.0/24"),
			Claim: netip.MustParsePrefix("10.11.11.0/24")}}
	var out, errOut, both syncBuffer
	a := newApp(strings.NewReader(""), io.MultiWriter(&out, &both), io.MultiWriter(&errOut, &both))
	a.health(st, "", false)
	want := `warning: no IPv4 on this host: juist1 holds 10.11.11.0/24, which "home" claims too (10.11.11.0/24)
warning: and IPv6 is off, so this network has no address here
hint: renumber either network: juist network renumber juist0 PREFIX

warning: log sync to bsdbox01 fails in the tunnel: tcp/41644 does not answer there
hint: where it runs Linux: sudo ufw allow in on juist0, or add juist0 to firewalld's trusted zone

no answer from mac-devvm: offline, or udp/41643 blocked

hint: read-only; to manage this device: ` + asRoot("juist set --operator="+currentUser()) + "\n"
	if both.String() != want {
		t.Errorf("health printed\n%s\nwant\n%s", both.String(), want)
	}
	if got := out.String(); got != "no answer from mac-devvm: offline, or udp/41643 blocked\n" {
		t.Errorf("stdout is %q, want its one line alone", got)
	}
}

// A port the router maps is said to be blocked where firewalld keeps UDP to
// juistd out, and the router's mapping then reaches nothing; the hint names
// the zone that does.
func TestHealthSaysFirewalldBlocksTheMappedPort(t *testing.T) {
	t.Parallel()
	st := &ipc.Status{InNetwork: true, Device: "juist0", ListenPort: 41643,
		Derived:  ipc.Derived{NetworkName: "home", Members: 2, Peers: 1},
		Underlay: &ipc.Underlay{UDP: true, IPv4: true, Mapped: "203.0.113.7:41643"}}
	for _, tc := range []struct {
		zone, warning, hint string
		service, unsure     bool
	}{
		{"public", "warning: firewalld blocks udp/41643, which the router maps to this device",
			"hint: sudo firewall-cmd --permanent --zone=public --add-service=juist && sudo firewall-cmd --reload", true, false},
		{"public", "warning: firewalld blocks udp/41643, which the router maps to this device",
			"hint: sudo firewall-cmd --permanent --zone=public --add-port=41643/udp && sudo firewall-cmd --reload", false, false},
		{"home-workstation", "warning: firewalld blocks udp/41643, which the router maps to this device",
			"hint: sudo firewall-cmd --permanent --zone=home-workstation --add-port=41643/udp && sudo firewall-cmd --reload", false, false},
		{"FedoraServer", "hint: firewalld may block udp/41643, which the router maps to this device: juist cannot read the ports of zone FedoraServer",
			"; to check: " + asRoot("juist health"), false, true},
		{"", "", "", false, false},
	} {
		var both syncBuffer
		a := newApp(strings.NewReader(""), &both, &both)
		var asked uint16
		a.host.udpBlocked = func(_ context.Context, port uint16) (string, bool, bool) {
			asked = port
			return tc.zone, tc.service, tc.unsure
		}
		a.health(st, "", false)
		said := strings.Contains(both.String(), "firewalld")
		if said != (tc.zone != "") || asked != 41643 || !strings.Contains(both.String(), tc.warning) || !strings.Contains(both.String(), tc.hint) {
			t.Errorf("zone %q: asked about %d, health printed\n%s", tc.zone, asked, both.String())
		}
	}
	var odd syncBuffer
	a := newApp(strings.NewReader(""), &odd, &odd)
	a.host.udpBlocked = func(context.Context, uint16) (string, bool, bool) { return "my zone;id", false, false }
	a.health(st, "", false)
	if strings.Contains(odd.String(), "firewall-cmd") {
		t.Errorf("a zone not to be pasted, health printed\n%s", odd.String())
	}
	// Beside another issue, the unread zone's hint stands apart from it.
	other := *st
	other.GossipPort = 41644
	other.Tunnels = ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 1, SyncFailing: []string{"bsdbox01"}, Underlay: st.Underlay}
	var apart syncBuffer
	beside := newApp(strings.NewReader(""), &apart, &apart)
	beside.host.udpBlocked = func(context.Context, uint16) (string, bool, bool) { return "FedoraServer", false, true }
	beside.health(&other, "", false)
	if !strings.Contains(apart.String(), "\n\nhint: firewalld may block") {
		t.Errorf("the unread zone's hint joins the issue above it:\n%s", apart.String())
	}
	// Unread, as by a user under firewalld's server policy, it counts as no
	// warning, which the user could never clear.
	unread := newApp(strings.NewReader(""), io.Discard, io.Discard)
	unread.host.udpBlocked = func(context.Context, uint16) (string, bool, bool) { return "FedoraServer", false, true }
	if n, _ := unread.healthWarnings(st, "", false); n != 0 {
		t.Errorf("a zone juist cannot read counts as %d warnings", n)
	}
	unmapped := *st
	unmapped.Underlay = &ipc.Underlay{UDP: true, IPv4: true}
	var both syncBuffer
	a = newApp(strings.NewReader(""), &both, &both)
	a.host.udpBlocked = func(context.Context, uint16) (string, bool, bool) {
		t.Error("asked without a mapping")
		return "public", true, false
	}
	a.health(&unmapped, "", false)
}

// fakeZones answers as firewalld would, by interface and zone; a service
// it does not hold is undefined.
type fakeZones struct {
	ifaces   map[string]string
	def      string
	open     map[string]bool
	services map[string]bool
	refused  bool
	// serviceErr is what asking for a service fails with, where set.
	serviceErr error
}

func (f fakeZones) Zone(iface string) (string, error) {
	if z, ok := f.ifaces[iface]; ok {
		return z, nil
	}
	return f.def, nil
}

func (f fakeZones) Admits(zone string, _ uint16, _ string) (bool, error) {
	if f.refused {
		return false, firewalld.ErrNotAuthorized
	}
	return f.open[zone], nil
}

func (f fakeZones) HasService(zone, service string) (bool, error) {
	if f.serviceErr != nil {
		return false, f.serviceErr
	}
	open, ok := f.services[zone+" "+service]
	if !ok {
		return false, errors.New("INVALID_SERVICE: " + service)
	}
	return open, nil
}

// The zone asked is the uplink's, not the default zone, and a service
// firewalld does not know lets nothing in.
func TestFirewalldUDPAsksTheUplinksZone(t *testing.T) {
	for _, tc := range []struct {
		name    string
		f       fakeZones
		zone    string
		service bool
		unsure  bool
	}{
		{"the uplink's zone closed, the default open",
			fakeZones{ifaces: map[string]string{"wlan0": "public"}, def: "FedoraWorkstation",
				open: map[string]bool{"FedoraWorkstation": true}, services: map[string]bool{"public juist": false}},
			"public", true, false},
		{"the uplink's zone open, the default closed",
			fakeZones{ifaces: map[string]string{"wlan0": "home"}, def: "public",
				open: map[string]bool{"home": true}, services: map[string]bool{"public juist": false}},
			"", false, false},
		{"no service juist defined",
			fakeZones{ifaces: map[string]string{"wlan0": "public"}, def: "public"},
			"public", false, false},
		{"the service juist let in",
			fakeZones{ifaces: map[string]string{"wlan0": "public"}, def: "public", services: map[string]bool{"public juist": true}},
			"", false, false},
		{"the service not to be asked",
			fakeZones{ifaces: map[string]string{"wlan0": "public"}, def: "public", serviceErr: context.DeadlineExceeded},
			"", false, false},
		{"its ports not to be read",
			fakeZones{ifaces: map[string]string{"wlan0": "FedoraServer"}, def: "FedoraServer", refused: true},
			"FedoraServer", false, true},
	} {
		zone, service, unsure := firewalldUDP(tc.f, "wlan0", 41643)
		if zone != tc.zone || service != tc.service || unsure != tc.unsure {
			t.Errorf("%s: zone %q, service %v, unsure %v; want %q, %v, %v", tc.name, zone, service, unsure, tc.zone, tc.service, tc.unsure)
		}
	}
}

// The uplink is the IPv4 default route's interface with the lowest metric.
func TestUplinkIsTheDefaultRoutesInterface(t *testing.T) {
	route := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"juist0\t0000400A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n" +
		"wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	read := func(string) ([]byte, error) { return []byte(route), nil }
	if got := uplink(read); got != "eth0" {
		t.Errorf("uplink %q, want eth0", got)
	}
	if got := uplink(func(string) ([]byte, error) { return nil, errors.New("no /proc") }); got != "" {
		t.Errorf("uplink without /proc: %q", got)
	}
}
