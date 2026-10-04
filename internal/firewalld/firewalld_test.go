package firewalld

import (
	"errors"
	"os"
	"testing"

	"github.com/godbus/dbus/v5"

	"github.com/nning/juist/internal/firewalld/firewalldtest"
)

func client(t *testing.T, b *firewalldtest.Bus, root bool) (*Client, error) {
	t.Helper()
	conn, err := dbus.Connect(b.Addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := open(conn, root)
	if err == nil {
		t.Cleanup(func() { c.Close() })
	}
	return c, err
}

// firewalld's bus name is activatable, so a question sent while it is not
// running would start it.
func TestAFirewalldNotRunningIsNotStarted(t *testing.T) {
	b := firewalldtest.Start(t)
	b.Polkit(t, firewalldtest.ActionInfo, firewalldtest.ActionConfigInfo)
	if _, err := client(t, b, false); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("open: %v, want ErrNotRunning", err)
	}
	if b.Started() {
		t.Error("firewalld was started")
	}

	f := b.Firewalld(t)
	c, err := client(t, b, false)
	if err != nil {
		t.Fatal(err)
	}
	f.Stop(t)
	if _, err := c.Zone("juist0"); !errors.Is(err, ErrNotRunning) {
		t.Errorf("asking a firewalld that stopped: %v, want ErrNotRunning", err)
	}
	if b.Started() {
		t.Error("firewalld was started")
	}
}

// firewalld has polkit allow interaction, which puts a password dialog before
// whoever is logged in; a question needing one is not sent at all.
func TestAQuestionNeedingAPasswordIsNotAsked(t *testing.T) {
	b := firewalldtest.Start(t)
	p := b.Polkit(t, firewalldtest.ActionInfo)
	f := b.Firewalld(t)
	f.Set(func(f *firewalldtest.Firewalld) { f.Zones["juist0"] = "public" })
	c, err := client(t, b, false)
	if err != nil {
		t.Fatal(err)
	}
	if zone, err := c.Zone("juist0"); err != nil || zone != "public" {
		t.Fatalf("Zone: %q, %v", zone, err)
	}
	for range 2 {
		if _, err := c.Admits("public", 41644, "tcp"); !errors.Is(err, ErrNotAuthorized) {
			t.Fatalf("Admits: %v, want ErrNotAuthorized", err)
		}
	}
	if _, err := c.HasService("public", "juist-invite"); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("HasService: %v, want ErrNotAuthorized", err)
	}
	if got := f.Asked(); len(got) != 1 || got[0] != "getZoneOfInterface" {
		t.Errorf("firewalld was asked %v, want getZoneOfInterface alone", got)
	}
	me := "system-bus-name:" + c.conn.Names()[0]
	want := []firewalldtest.Check{{Subject: me, Action: firewalldtest.ActionInfo}, {Subject: me, Action: firewalldtest.ActionConfigInfo}}
	if got := p.Asked(); len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("polkit was asked %+v, want each action once, for this connection, without interaction: %+v", got, want)
	}
}

// Without polkit on the bus firewalld answers root alone, and only root is
// let past the check.
func TestOnlyRootAsksWithoutPolkit(t *testing.T) {
	b := firewalldtest.Start(t)
	f := b.Firewalld(t)
	f.Set(func(f *firewalldtest.Firewalld) { f.Default = "public" })
	user, err := client(t, b, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := user.Zone(""); !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("a user without polkit: %v, want ErrNotAuthorized", err)
	}
	root, err := client(t, b, true)
	if err != nil {
		t.Fatal(err)
	}
	if zone, err := root.Zone(""); err != nil || zone != "public" {
		t.Errorf("root without polkit: %q, %v", zone, err)
	}
}

// An interface in no zone gets the default zone's treatment.
func TestAnInterfaceInNoZoneIsInTheDefault(t *testing.T) {
	b := firewalldtest.Start(t)
	b.Polkit(t, firewalldtest.ActionInfo)
	f := b.Firewalld(t)
	f.Set(func(f *firewalldtest.Firewalld) { f.Default, f.Zones["juist0"] = "FedoraWorkstation", "trusted" })
	c, err := client(t, b, false)
	if err != nil {
		t.Fatal(err)
	}
	for iface, want := range map[string]string{"juist0": "trusted", "wlan0": "FedoraWorkstation", "": "FedoraWorkstation"} {
		if zone, err := c.Zone(iface); err != nil || zone != want {
			t.Errorf("Zone(%q) = %q, %v; want %q", iface, zone, err, want)
		}
	}
}

// A zone admits a port by accepting everything or by the port itself.
func TestAdmits(t *testing.T) {
	b := firewalldtest.Start(t)
	b.Polkit(t, firewalldtest.ActionInfo, firewalldtest.ActionConfigInfo)
	f := b.Firewalld(t)
	f.Set(func(f *firewalldtest.Firewalld) {
		f.Targets["open"] = "ACCEPT"
		f.Targets["public"] = "default"
		f.Targets["FedoraWorkstation"] = "default"
		f.Ports["FedoraWorkstation 41644/tcp"] = true
		f.Services["public juist-invite"] = true
	})
	c, err := client(t, b, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		zone string
		want bool
	}{{"trusted", true}, {"open", true}, {"FedoraWorkstation", true}, {"public", false}} {
		if got, err := c.Admits(tc.zone, 41644, "tcp"); err != nil || got != tc.want {
			t.Errorf("Admits(%s) = %v, %v; want %v", tc.zone, got, err, tc.want)
		}
	}
	if got, err := c.Admits("FedoraWorkstation", 41644, "udp"); err != nil || got {
		t.Errorf("udp admitted for a tcp port: %v, %v", got, err)
	}
	if got, err := c.HasService("public", "juist-invite"); err != nil || !got {
		t.Errorf("HasService = %v, %v", got, err)
	}
	settings := 0
	for _, m := range f.Asked() {
		if m == "getZoneSettings2" {
			settings++
		}
	}
	if settings != 4 {
		t.Errorf("zone settings were read %d times, want 4: trusted needs none", settings)
	}
}

// firewalld refusing, where polkit's answer changed between the check and the
// call, is told apart from its failing.
func TestARefusalIsNotAuthorized(t *testing.T) {
	b := firewalldtest.Start(t)
	b.Polkit(t, firewalldtest.ActionInfo)
	f := b.Firewalld(t)
	f.Set(func(f *firewalldtest.Firewalld) { f.Refuse = true })
	c, err := client(t, b, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Zone("juist0"); !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("Zone: %v, want ErrNotAuthorized", err)
	}
}

// An interface counts as blocked where its zone lets the port in
// neither by accepting everything nor by the port, or where firewalld names
// a zone other than trusted and will not tell its ports.
func TestBlocksAsksFirewalldOnTheSystemBus(t *testing.T) {
	b := firewalldtest.Start(t)
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", b.Addr)
	if blocked, _ := Blocks(t.Context(), "juist0", 41644); blocked {
		t.Error("with no firewalld, an interface counts as blocked")
	}

	b.Polkit(t, firewalldtest.ActionInfo, firewalldtest.ActionConfigInfo)
	f := b.Firewalld(t)
	f.Set(func(f *firewalldtest.Firewalld) {
		f.Default = "FedoraWorkstation"
		f.Zones["vpn0"] = "trusted"
		f.Zones["public0"] = "public"
		f.Zones["open0"] = "open"
		f.Targets["open"] = "ACCEPT"
		f.Ports["FedoraWorkstation 41644/tcp"] = true
	})
	for iface, want := range map[string]bool{"vpn0": false, "juist0": false, "open0": false, "public0": true} {
		if got, unsure := Blocks(t.Context(), iface, 41644); got != want || unsure {
			t.Errorf("%s: blocked %v, unsure %v; want %v, sure", iface, got, unsure, want)
		}
	}
	if blocked, _ := Blocks(t.Context(), "juist0", 41700); !blocked {
		t.Error("a port the default zone does not open counts as let in")
	}
}

// Where only the zone may be asked, as under firewalld's server policy, a
// zone other than trusted is warned of, unsure, rather than passed over.
func TestAZoneWhosePortsCannotBeAskedCountsAsFirewalled(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is answered without polkit")
	}
	b := firewalldtest.Start(t)
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", b.Addr)
	b.Polkit(t, firewalldtest.ActionInfo)
	f := b.Firewalld(t)
	f.Set(func(f *firewalldtest.Firewalld) { f.Default, f.Zones["vpn0"] = "FedoraServer", "trusted" })
	if blocked, _ := Blocks(t.Context(), "vpn0", 41644); blocked {
		t.Error("the trusted zone counts as blocked")
	}
	if blocked, unsure := Blocks(t.Context(), "juist0", 41644); !blocked || !unsure {
		t.Errorf("an untrusted zone firewalld will not tell about: blocked %v, unsure %v; want both", blocked, unsure)
	}
}
