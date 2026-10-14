package main

import (
	"fmt"
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
	a.printStatus(st)
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
