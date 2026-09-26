package main

import (
	"os"
	"testing"

	"github.com/nning/juist/internal/firewalld/firewalldtest"
)

// An invite's port is hinted at unless firewalld's default zone is known to
// let it in: by the zone, by the port, or by the juist-invite service on the
// port that service opens.
func TestInvitePortHintAsksFirewalld(t *testing.T) {
	b := firewalldtest.Start(t)
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", b.Addr)
	b.Polkit(t, firewalldtest.ActionInfo, firewalldtest.ActionConfigInfo)
	fw := b.Firewalld(t)
	fw.Set(func(f *firewalldtest.Firewalld) {
		f.Default = "public"
		f.Services["public juist-invite"] = true
	})
	const other = 40000
	for _, tc := range []struct {
		name string
		set  func(f *firewalldtest.Firewalld)
		port uint16
		want string
	}{
		{"the service on its port", nil, DefaultInvitePort, ""},
		{"the service elsewhere", nil, other, "sudo firewall-cmd --add-port=40000/tcp"},
		{"the port", func(f *firewalldtest.Firewalld) { f.Ports["public 40000/tcp"] = true }, other, ""},
		{"the zone", func(f *firewalldtest.Firewalld) { f.Default = "trusted" }, other, ""},
	} {
		if tc.set != nil {
			fw.Set(tc.set)
		}
		if got := invitePortHint(tc.port); got != tc.want {
			t.Errorf("%s: hint %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Where firewalld will not say, the hint is given: the port may be closed.
func TestInvitePortHintWhereFirewalldWillNotSay(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is answered without polkit")
	}
	b := firewalldtest.Start(t)
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", b.Addr)
	b.Polkit(t, firewalldtest.ActionInfo)
	fw := b.Firewalld(t)
	fw.Set(func(f *firewalldtest.Firewalld) { f.Default, f.Services["public juist-invite"] = "public", true })
	if got, want := invitePortHint(DefaultInvitePort), "sudo firewall-cmd --add-port=41642/tcp"; got != want {
		t.Errorf("hint %q, want %q", got, want)
	}
}
