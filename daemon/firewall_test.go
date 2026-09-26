package daemon

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/nning/juist/ipc"

	"github.com/nning/juist/internal/firewalld/firewalldtest"
)

// The TUN device counts as firewalled where its zone lets the sync port in
// neither by accepting everything nor by the port, or where firewalld names
// a zone other than trusted and will not tell its ports.
func TestFirewalledAsksFirewalldOnTheSystemBus(t *testing.T) {
	b := firewalldtest.Start(t)
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", b.Addr)
	if blocked, _ := firewalled(t.Context(), "juist0", 41644); blocked {
		t.Error("with no firewalld, the tunnel counts as firewalled")
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
		if got, unsure := firewalled(t.Context(), iface, 41644); got != want || unsure {
			t.Errorf("%s: firewalled %v, unsure %v; want %v, sure", iface, got, unsure, want)
		}
	}
	if blocked, _ := firewalled(t.Context(), "juist0", 41700); !blocked {
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
	if blocked, _ := firewalled(t.Context(), "vpn0", 41644); blocked {
		t.Error("the trusted zone counts as firewalled")
	}
	if blocked, unsure := firewalled(t.Context(), "juist0", 41644); !blocked || !unsure {
		t.Errorf("an untrusted zone firewalld will not tell about: blocked %v, unsure %v; want both", blocked, unsure)
	}
}

// A warning of the firewall is gone on the next status after the fix, not
// only after the next tunnel check: reading it asks the firewall again.
func TestAFirewallFixShowsOnTheNextStatus(t *testing.T) {
	b := firewalldtest.Start(t)
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", b.Addr)
	b.Polkit(t, firewalldtest.ActionInfo, firewalldtest.ActionConfigInfo)
	fw := b.Firewalld(t)
	fw.Set(func(f *firewalldtest.Firewalld) { f.Zones["vpn0"] = "public" })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := newServiceFixtureWith(t, func(o *Options) { o.TunName, o.GossipListener = "vpn0", ln })
	status := func() ipc.Status {
		t.Helper()
		resp, err := ipc.Call(f.sock, ipc.Request{Command: ipc.CmdStatus})
		if err != nil {
			t.Fatal(err)
		}
		return *resp.Status
	}
	waitFor := func(what string, done func(ipc.Status) bool, within time.Duration) {
		t.Helper()
		for deadline := time.Now().Add(within); !done(status()); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%s: not within %v", what, within)
			}
		}
	}
	waitFor("the first check warns", func(st ipc.Status) bool { return st.Firewalled == "vpn0" }, 10*time.Second)

	fw.Set(func(f *firewalldtest.Firewalld) { f.Zones["vpn0"] = "trusted" })
	waitFor("the fix shows", func(st ipc.Status) bool { return st.Firewalled == "" }, reachEvery/10)
}
