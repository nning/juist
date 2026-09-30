package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/ipc"
)

// A public name is pointed at a device and taken back, in its one form, on
// its own, and never at two devices at once or into the network's own names.
func TestGrantNames(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "phone")
	mustContain(t, admin.mustRun("grant", "phone", "MX.Example.net."), "phone: names mx.example.net")
	mustContain(t, admin.mustRun("grant", "phone", "mx.example.net"), "unchanged")
	mustContain(t, admin.mustRun("grant", "phone", "münchen.de"), "phone: names mx.example.net, xn--mnchen-3ya.de")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"grant", "laptop", "mx.example.net"}, "points at phone already"},
		{[]string{"grant", "phone", "relay", "www.example.net"}, "hint: juist grant phone www.example.net"},
		{[]string{"revoke", "phone", "relay", "mx.example.net"}, "hint: juist revoke phone mx.example.net"},
		{[]string{"grant", "phone", "mailer.home.juist"}, "the network's own"},
		{[]string{"grant", "phone", "10.1.2.3"}, "as an address does"},
		{[]string{"revoke", "laptop", "mx.example.net"}, "does not answer for mx.example.net"},
	} {
		if out, err := admin.run(tc.args...); err == nil || !strings.Contains(out+err.Error(), tc.want) {
			t.Errorf("juist %q: %v\n%s", tc.args, err, out)
		}
	}
	mustContain(t, admin.mustRun("revoke", "phone", "mx.example.net", "xn--mnchen-3ya.de"), "phone: no names")
}

// An approver reads a change of names as the names it sends into the network
// and those it takes back.
func TestANamesChangeSaysWhatItPoints(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	c.mustRun("grant", "laptop", "mx.example.net")
	auth := openLog(t, c)
	self := nodeKeysOf(t, c).Identity.Public()
	aum, err := auth.Builder().SetNodeNames(self, []string{"imap.example.net"})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(effect(&aum, auth.State(), 0), "\n")
	mustContain(t, got, "points imap.example.net at laptop", "no longer points mx.example.net at laptop")
}

// The status says under which domain the network's names resolve, and why
// they do not, with what would let them where the host could.
func TestStatusSaysHowNamesResolve(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_000_000, 0)
	for _, tc := range []struct {
		names ipc.Names
		want  []line
	}{
		{ipc.Names{Domain: "home.juist", Resolved: true}, []line{{kind: lineField, label: "Names", text: "home.juist"}}},
		{ipc.Names{Domain: "home.juist", Not: "this host's resolver routes no domains", Cannot: true},
			[]line{{kind: lineField, label: "Names", text: "not resolved here: this host's resolver routes no domains"}}},
		{ipc.Names{Domain: "home.juist", Not: "/etc/resolv.conf lists every link's servers, systemd-resolved's uplink mode, not its stub"},
			[]line{{kind: lineField, label: "Names", text: "home.juist not resolved: /etc/resolv.conf lists every link's servers, systemd-resolved's uplink mode, not its stub"},
				{kind: lineHint, text: asRoot("ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf")}}},
	} {
		s := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 1, Names: &tc.names}}
		v := statusOf(s, now, noPaint)
		for _, want := range tc.want {
			if !slices.Contains(v.head, want) {
				t.Errorf("head %v lacks %v", v.head, want)
			}
		}
	}
}

// A device resolves the public names the network points at devices only
// once its owner agreed, says which, and stops when told.
func TestAcceptNames(t *testing.T) {
	t.Parallel()
	laptop, vps := homeAndVPS(t)
	mustContain(t, laptop.mustRun("grant", "vps", "mx.example.net"), "vps: names mx.example.net",
		"hint: juist set --accept-names on each device that is to resolve it")
	eventually(t, "the status names the public name", func() bool {
		return strings.Contains(laptop.mustRun("status"), "1 public name not accepted")
	})
	mustContain(t, laptop.mustRun("set", "--accept-names"), "public names accepted: mx.example.net at vps",
		"warning: this host resolves none of them: juistd runs without a device of its own")
	mustContain(t, laptop.mustRun("set", "-A"), "unchanged: public names accepted")
	mustContain(t, laptop.mustRun("status"), "mx.example.net at vps")
	if out := laptop.mustRun("grant", "vps", "imap.example.net"); strings.Contains(out, "hint:") {
		t.Errorf("a device that accepts names is told to:\n%s", out)
	}
	if st := statusOfDaemon(t, laptop); st.Names == nil || !st.Names.Accepted {
		t.Fatalf("the daemon says %+v", st.Names)
	}
	mustContain(t, laptop.mustRun("set", "--accept-names=false"), "public names not accepted")
	mustContain(t, laptop.mustRun("status"), "2 public names not accepted")
	if _, err := laptop.run("set", "--accept-names=maybe"); err == nil {
		t.Error("took --accept-names=maybe")
	}

	// A device whose status says nothing of names, as one removed, still
	// takes its word back.
	vps.mustRun("set", "--accept-names")
	mustContain(t, laptop.mustRun("remove", "vps", "--yes"), "removed vps")
	eventually(t, "vps knows it was removed", func() bool { return statusOfDaemon(t, vps).NotMember })
	if st := statusOfDaemon(t, vps); st.Names != nil {
		t.Fatalf("removed, vps's status says %+v", st.Names)
	}
	mustContain(t, vps.mustRun("set", "--accept-names=false"), "public names not accepted")
	if _, err := os.Stat(filepath.Join(vps.state, statedir.NamesFile)); !os.IsNotExist(err) {
		t.Errorf("vps kept its word: %v", err)
	}
}

// The status lists the public names in effect, and says of each resolved
// publicly why, or how many were not accepted.
func TestStatusListsPublicNames(t *testing.T) {
	t.Parallel()
	o := []ipc.NameOverride{{Name: "mx.example.net", Device: "mailer"}, {Name: "www.example.net", Device: "nas", Not: "nas is not reachable"}}
	for _, tc := range []struct {
		names ipc.Names
		want  string
	}{
		{ipc.Names{Domain: "home.juist", Resolved: true, Accepted: true, Overrides: o},
			"home.juist; mx.example.net at mailer, www.example.net at nas (resolved publicly: nas is not reachable)"},
		{ipc.Names{Domain: "home.juist", Resolved: true, Overrides: o}, "home.juist; 2 public names not accepted"},
		{ipc.Names{Domain: "home.juist", Resolved: true, Overrides: o[:1]}, "home.juist; 1 public name not accepted"},
		{ipc.Names{Resolved: true, Accepted: true, Overrides: o[:1]}, "mx.example.net at mailer"},
	} {
		s := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 1, Names: &tc.names}}
		want := line{kind: lineField, label: "Names", text: tc.want}
		if v := statusOf(s, time.Unix(1_000_000, 0), noPaint); !slices.Contains(v.head, want) {
			t.Errorf("head %v lacks %v", v.head, want)
		}
	}
}
