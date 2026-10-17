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

// A public name is pointed at a device and taken back, in its one form, and
// never at two devices at once or into the network's own names; grant and
// revoke, which take roles alone, say where one goes.
func TestNamesAddAndRemove(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "phone")
	mustContain(t, admin.mustRun("names", "add", "phone", "MX.Example.net."), "phone: names mx.example.net")
	mustContain(t, admin.mustRun("names", "add", "phone", "mx.example.net"), "unchanged")
	mustContain(t, admin.mustRun("names", "add", "phone", "münchen.de"), "phone: names mx.example.net, xn--mnchen-3ya.de")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"names", "add", "laptop", "mx.example.net"}, "hint: juist names remove phone mx.example.net"},
		{[]string{"names", "add", "phone", "mailer.home.juist"}, "the network's own"},
		{[]string{"names", "add", "phone", "10.1.2.3"}, "as an address does"},
		{[]string{"names", "add", "phone", "mail"}, `"mail" is no public name, such as mail.example.org`},
		{[]string{"names", "remove", "laptop", "mx.example.net"}, "does not answer for mx.example.net"},
		{[]string{"grant", "phone", "relay", "www.example.net"}, "hint: juist names add phone www.example.net"},
		{[]string{"revoke", "phone", "mx.example.net"}, "hint: juist names remove phone mx.example.net"},
	} {
		if out, err := admin.run(tc.args...); err == nil || !strings.Contains(out+err.Error(), tc.want) {
			t.Errorf("juist %q: %v\n%s", tc.args, err, out)
		}
	}
	mustContain(t, admin.mustRun("names", "rm", "phone", "mx.example.net", "xn--mnchen-3ya.de"), "phone: no names")
}

// An approver reads a change of names as the names it sends into the network
// and those it takes back.
func TestANamesChangeSaysWhatItPoints(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	c.mustRun("names", "add", "laptop", "mx.example.net")
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
		{ipc.Names{Domain: "home.juist", Resolved: true}, []line{{kind: lineField, label: "Names", text: "laptop.home.juist"}}},
		{ipc.Names{Domain: "home.juist", Not: "DNS is off on this device", Cannot: true, Off: true},
			[]line{{kind: lineField, label: "Names", text: "laptop.home.juist (DNS off)"},
				{kind: lineInfo, text: "DNS is off on this device: the network's names are not resolved here, and no DNS goes through an exit node; juist set --dns takes it again"}}},
		{ipc.Names{Domain: "home.juist", Not: "this host's resolver routes no domains", Cannot: true},
			[]line{{kind: lineField, label: "Names", text: "laptop.home.juist"},
				{kind: lineInfo, text: "home.juist not resolved here: this host's resolver routes no domains"}}},
		{ipc.Names{Domain: "home.juist", Not: "/etc/resolv.conf lists every link's servers, systemd-resolved's uplink mode, not its stub"},
			[]line{{kind: lineField, label: "Names", text: "laptop.home.juist"},
				{kind: lineWarn, text: "home.juist not resolved here: /etc/resolv.conf lists every link's servers, systemd-resolved's uplink mode, not its stub"},
				{kind: lineHint, text: asRoot("ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf")}}},
		{ipc.Names{Domain: "home.juist", Not: "/etc/resolv.conf is no longer juistd's"},
			[]line{{kind: lineWarn, text: "home.juist not resolved here: /etc/resolv.conf is no longer juistd's"},
				{kind: lineHint, text: "another program wrote it; " + asRoot("systemctl restart juistd") + " hands it back"}}},
		{ipc.Names{Domain: "home.juist", Not: "tailscaled writes /etc/resolv.conf"},
			[]line{{kind: lineWarn, text: "home.juist not resolved here: tailscaled writes /etc/resolv.conf"},
				{kind: lineHint, text: asRoot("tailscale set --accept-dns=false") + " and " + asRoot("systemctl restart juistd") +
					" hand it to juistd, without the tailnet's names"}}},
		{ipc.Names{Domain: "home.juist", Not: "systemd-resolved does not run on this host"},
			[]line{{kind: lineWarn, text: "home.juist not resolved here: systemd-resolved does not run on this host"},
				{kind: lineHint, text: "the package's juistd.service hands juistd /etc/resolv.conf, to answer this host's DNS itself"}}},
		{ipc.Names{Domain: "home.juist", Not: "this host's resolver routes no domains", Cannot: true,
			ForMembers: []string{"photos.pub.example.org", "wiki.pub.example.org"}},
			[]line{{kind: lineWarn, text: "photos.pub.example.org, for members alone, is not reached from here, which resolves the network's names publicly"},
				{kind: lineWarn, text: "wiki.pub.example.org, for members alone, is not reached from here, which resolves the network's names publicly"}}},
	} {
		s := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 1, SelfName: "laptop", Names: &tc.names}}
		v := statusOf(s, now, noPaint)
		for _, want := range tc.want {
			if !slices.Contains(v.head, want) && !slices.Contains(v.notes, want) {
				t.Errorf("status %v %v lacks %v", v.head, v.notes, want)
			}
		}
		// The line names the names, and why not is health's.
		for _, l := range v.head {
			if l.label == "Names" && strings.Contains(l.text, "not resolved") {
				t.Errorf("the Names line says why: %q", l.text)
			}
		}
		// What no host could change is no warning.
		if tc.names.Cannot && len(tc.names.ForMembers) == 0 && slices.ContainsFunc(v.notes, func(l line) bool { return l.kind == lineWarn }) {
			t.Errorf("status warns %v", v.notes)
		}
	}
}

// A device resolves the public names the network points at devices only
// once its owner agreed, says which, and stops when told.
func TestAcceptNames(t *testing.T) {
	t.Parallel()
	laptop, vps := homeAndVPS(t)
	mustContain(t, laptop.mustRun("names"), "*.home.juist", "every member", "hint: an admin points a public name at a device")
	mustContain(t, laptop.mustRun("names", "add", "vps", "mx.example.net"), "vps: names mx.example.net",
		"hint: juist names on, on each device that is to resolve it")
	eventually(t, "health names the public name", func() bool {
		return strings.Contains(laptop.mustRun("health"), "1 public name, off on this device")
	})
	mustContain(t, laptop.mustRun("names"), "NAME", "mx.example.net", "vps", "off on this device")
	mustContain(t, laptop.mustRun("names", "on"), "public names on: mx.example.net at vps",
		"warning: this host resolves none of them: juistd runs without a device of its own")
	mustContain(t, laptop.mustRun("names", "on"), "unchanged: public names on")
	mustContain(t, laptop.mustRun("names", "ls"), "mx.example.net", "not resolved here: juistd runs without a device of its own")
	mustContain(t, laptop.mustRun("names"), "mx.example.net", "vps")
	if out := laptop.mustRun("names", "add", "vps", "imap.example.net"); strings.Contains(out, "hint:") {
		t.Errorf("a device that accepts names is told to:\n%s", out)
	}
	if st := statusOfDaemon(t, laptop); st.Names == nil || !st.Names.Accepted {
		t.Fatalf("the daemon says %+v", st.Names)
	}
	mustContain(t, laptop.mustRun("names", "off"), "public names off")
	mustContain(t, laptop.mustRun("health"), "2 public names, off on this device")
	if _, err := laptop.run("names", "on", "maybe"); err == nil {
		t.Error("juist names on took an argument")
	}

	// A device whose status says nothing of names, as one removed, still
	// takes its word back.
	vps.mustRun("names", "on")
	mustContain(t, laptop.mustRun("remove", "vps", "--yes"), "removed vps")
	eventually(t, "vps knows it was removed", func() bool { return statusOfDaemon(t, vps).NotMember })
	if st := statusOfDaemon(t, vps); st.Names != nil {
		t.Fatalf("removed, vps's status says %+v", st.Names)
	}
	mustContain(t, vps.mustRun("names", "off"), "public names off")
	if _, err := os.Stat(filepath.Join(vps.state, statedir.NamesFile)); !os.IsNotExist(err) {
		t.Errorf("vps kept its word: %v", err)
	}
}

// The status names this device's own names, the public ones pointed at it
// among them, and health says of each public name resolved publicly why, or
// how many are off on this device.
func TestStatusListsPublicNames(t *testing.T) {
	t.Parallel()
	o := []ipc.NameOverride{{Name: "mx.example.net", Device: "mailer"}, {Name: "www.example.net", Device: "nas", Not: "nas is not reachable"}}
	for _, tc := range []struct {
		names ipc.Names
		want  string
		note  string
	}{
		{ipc.Names{Domain: "home.juist", Resolved: true, Accepted: true, Overrides: o},
			"laptop.home.juist", "www.example.net resolved publicly: nas is not reachable"},
		{ipc.Names{Domain: "home.juist", Resolved: true, Overrides: o}, "laptop.home.juist", "2 public names, off on this device"},
		{ipc.Names{Domain: "home.juist", Resolved: true, Overrides: o[:1]}, "laptop.home.juist", "1 public name, off on this device"},
		{ipc.Names{Domain: "home.juist", Resolved: true, Accepted: true, Overrides: []ipc.NameOverride{{Name: "mx.example.net", Device: "laptop"}}},
			"laptop.home.juist, mx.example.net", ""},
	} {
		s := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home", Members: 1, SelfName: "laptop", Names: &tc.names}}
		want := line{kind: lineField, label: "Names", text: tc.want}
		v := statusOf(s, time.Unix(1_000_000, 0), noPaint)
		if !slices.Contains(v.head, want) {
			t.Errorf("head %v lacks %v", v.head, want)
		}
		if tc.note != "" && !slices.Contains(v.notes, line{kind: lineInfo, text: tc.note}) {
			t.Errorf("notes %v lack %q", v.notes, tc.note)
		}
	}
}

// juist names says of each public name how this device resolves it.
func TestNameStates(t *testing.T) {
	t.Parallel()
	o := ipc.NameOverride{Name: "mx.example.net", Device: "mailer"}
	down := ipc.NameOverride{Name: "mx.example.net", Device: "mailer", Not: "mailer is not reachable"}
	for _, tc := range []struct {
		n    ipc.Names
		o    ipc.NameOverride
		want string
	}{
		{ipc.Names{Resolved: true}, o, "off on this device"},
		{ipc.Names{Accepted: true, Not: "this host's resolver routes no domains"}, o,
			"not resolved here: this host's resolver routes no domains"},
		{ipc.Names{Accepted: true, Resolved: true}, down, "resolved publicly: mailer is not reachable"},
		{ipc.Names{Accepted: true, Resolved: true}, o, "resolved to it"},
	} {
		if got := nameState(&tc.n, tc.o, noPaint); got != tc.want {
			t.Errorf("%+v, %+v: %q, want %q", tc.n, tc.o, got, tc.want)
		}
	}
}
