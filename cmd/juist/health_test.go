package main

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

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
		"warning: names the host's DNS routing sends elsewhere are refused, as it cannot be read: dbus: call timed out\n")
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
		"warning: other devices than the tunnel reach this device's overlay addresses: pf's rules call no juist anchor first\n")
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
		if hinted := strings.Contains(out.String(), "hint: sudo tailscale set --accept-dns=false"); hinted != tc.want && runtime.GOOS != "freebsd" {
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
		{"runs", nil, nil, "warning: phone not at the relay on edge01, the one this device reaches it at\n",
			"though it announces itself", 1},
		{"may be offline", []string{"phone"}, nil,
			"no answer from phone: not at the relay on edge01, the one this device reaches it at\n", "udp/", 0},
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
