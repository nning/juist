package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/nning/juist/ipc"

	"github.com/nning/juist/internal/firewalld/firewalldtest"
)

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
