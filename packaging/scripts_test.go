// Package packaging holds no Go code; its tests run the Debian maintainer
// scripts in a sandbox, with their paths moved under a temporary root and the
// commands they call replaced by stubs that record their arguments.
package packaging

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type sandbox struct {
	t    *testing.T
	root string
}

func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	root := t.TempDir()
	sb := &sandbox{t: t, root: root}
	for _, d := range []string{"bin", "var/lib/juist", "run/systemd/system"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Every stub logs how it was called. install creates the directory it
	// is given, as the real one would.
	for _, name := range []string{"systemctl", "systemd-sysusers", "firewall.sh", "install"} {
		body := "#!/bin/sh\necho \"" + name + " $*\" >> " + filepath.Join(root, "calls") + "\n"
		if name == "install" {
			body += "for last; do :; done; mkdir -p \"$last\"\n"
		}
		if err := os.WriteFile(filepath.Join(root, "bin", name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return sb
}

// run runs a maintainer script from packaging/deb with args.
func (sb *sandbox) run(script string, args ...string) {
	sb.t.Helper()
	b, err := os.ReadFile(filepath.Join("deb", script))
	if err != nil {
		sb.t.Fatal(err)
	}
	s := strings.NewReplacer(
		"/usr/lib/juist/firewall.sh", filepath.Join(sb.root, "bin", "firewall.sh"),
		"/var/lib/", sb.root+"/var/lib/",
		"/run/systemd/system", filepath.Join(sb.root, "run/systemd/system"),
	).Replace(string(b))
	path := filepath.Join(sb.root, script)
	if err := os.WriteFile(path, []byte(s), 0o755); err != nil {
		sb.t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", append([]string{path}, args...)...)
	cmd.Env = []string{"PATH=" + filepath.Join(sb.root, "bin") + ":/usr/bin:/bin"}
	if out, err := cmd.CombinedOutput(); err != nil {
		sb.t.Fatalf("%s %v: %v\n%s", script, args, err, out)
	}
}

func (sb *sandbox) calls() string {
	b, _ := os.ReadFile(filepath.Join(sb.root, "calls"))
	os.Remove(filepath.Join(sb.root, "calls"))
	return string(b)
}

// The daemon owns /var/lib/juist. A marker it plants there must not make an
// upgrade look like a fresh install, which would allow the firewall rule and
// enable the service an admin had turned off.
func TestAnUpgradeIgnoresWhatTheDaemonPlants(t *testing.T) {
	sb := newSandbox(t)
	if err := os.WriteFile(filepath.Join(sb.root, "var/lib/juist/.removed"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	sb.run("postinst", "configure", "0.9")
	calls := sb.calls()
	if strings.Contains(calls, "firewall.sh allow") || strings.Contains(calls, "enable") {
		t.Fatalf("an upgrade acted as a fresh install:\n%s", calls)
	}
	if !strings.Contains(calls, "try-restart juistd.service juistd@*.service") {
		t.Fatalf("an upgrade did not restart the daemon and its instances:\n%s", calls)
	}
	// An upgrade can bring new service files, which firewalld reads only on
	// a reload.
	if !strings.Contains(calls, "firewall.sh reload") {
		t.Fatalf("an upgrade did not have firewalld read the new service files:\n%s", calls)
	}
}

// Nor may a link the daemon plants there have root create or truncate a file
// of the daemon's choosing on removal.
func TestARemovalFollowsNoLinkOfTheDaemons(t *testing.T) {
	sb := newSandbox(t)
	target := filepath.Join(sb.root, "nologin")
	if err := os.Symlink(target, filepath.Join(sb.root, "var/lib/juist/.removed")); err != nil {
		t.Fatal(err)
	}
	sb.run("prerm", "remove")
	if _, err := os.Lstat(target); err == nil {
		t.Fatal("prerm created the file the daemon's link points at")
	}
}

// A reinstall after a removal is a fresh install again, and a purge leaves no
// marker behind.
func TestAReinstallIsAFreshInstall(t *testing.T) {
	sb := newSandbox(t)
	sb.run("prerm", "remove")
	calls := sb.calls()
	if !strings.Contains(calls, "firewall.sh revoke\n") || !strings.Contains(calls, "disable --now juistd.service") {
		t.Fatalf("a removal left the service or the rule:\n%s", calls)
	}
	for i := 1; i <= 9; i++ {
		if !strings.Contains(calls, fmt.Sprintf("disable --now juistd@juist%d.service", i)) {
			t.Fatalf("a removal left instance juist%d running:\n%s", i, calls)
		}
	}
	sb.run("postinst", "configure", "0.9")
	calls = sb.calls()
	if !strings.Contains(calls, "firewall.sh allow") || !strings.Contains(calls, "enable --now") {
		t.Fatalf("a reinstall did not act as a fresh install:\n%s", calls)
	}
	sb.run("postinst", "configure", "0.9")
	if calls := sb.calls(); strings.Contains(calls, "enable --now") {
		t.Fatalf("the upgrade after a reinstall acted as a fresh install:\n%s", calls)
	}
	sb.run("prerm", "remove")
	sb.run("postrm", "purge")
	if entries, _ := filepath.Glob(filepath.Join(sb.root, "var/lib/*")); len(entries) != 0 {
		t.Fatalf("a purge left %v", entries)
	}
}

// Every firewalld service file parses: firewalld drops one that does not, and
// "firewall-cmd --add-service" then fails with nothing juist could report. A
// comment may hold no "--", which a firewall-cmd example in one once did.
func TestFirewalldServicesParse(t *testing.T) {
	files, err := filepath.Glob("firewalld/*.xml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no firewalld service files (%v)", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var svc struct {
			Ports []struct {
				Protocol string `xml:"protocol,attr"`
				Port     string `xml:"port,attr"`
			} `xml:"port"`
		}
		if err := xml.Unmarshal(b, &svc); err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if len(svc.Ports) == 0 {
			t.Errorf("%s opens no port", f)
		}
	}
}

// juistd@.service is juistd.service for another instance: every line but
// those naming the instance is the same, so hardening added to one cannot
// be missing from the other.
func TestTheInstanceUnitIsTheDefaultOne(t *testing.T) {
	read := func(name string) []string {
		b, err := os.ReadFile(filepath.Join("systemd", name))
		if err != nil {
			t.Fatal(err)
		}
		_, body, ok := strings.Cut(string(b), "\n[Unit]\n")
		if !ok {
			t.Fatalf("%s has no [Unit]", name)
		}
		return strings.Split(body, "\n")
	}
	def, inst := read("juistd.service"), read("juistd@.service")
	named := strings.NewReplacer(
		"Description=juist node", "Description=juist node %i",
		"After=network-online.target", "After=network-online.target juistd.service",
		"ExecStart=/usr/local/bin/juistd --home /var/lib/juist --socket /run/juist/juistd.sock --tun juist0",
		"ExecStart=/usr/local/bin/juistd --instance %i --home /var/lib/juist/%i --socket /run/juist/%i.sock",
		"/var/lib/juist is created", "/var/lib/juist/%i is created",
		"StateDirectory=juist", "StateDirectory=juist/%i",
		"WorkingDirectory=/var/lib/juist", "WorkingDirectory=/var/lib/juist/%i",
	)
	if len(def) != len(inst) {
		t.Fatalf("juistd.service has %d lines after [Unit], juistd@.service %d", len(def), len(inst))
	}
	for i := range def {
		want := def[i]
		if !strings.HasPrefix(want, "StateDirectoryMode") {
			want = named.Replace(want)
		}
		if inst[i] != want {
			t.Errorf("juistd@.service line %d is %q, want %q", i+1, inst[i], want)
		}
	}
	for _, line := range inst {
		if strings.HasPrefix(line, "RuntimeDirectory=") && line != "RuntimeDirectory=juist" {
			t.Errorf("%s: every instance's socket is in /run/juist", line)
		}
	}
	if !slices.Contains(def, "RuntimeDirectoryPreserve=yes") {
		t.Error("/run/juist is not preserved: the first unit to stop would delete every instance's socket")
	}
}

// firewall.sh acts on the device it is given, only a juist one, and on all of
// them for a revoke that names none.
func TestFirewallScriptTakesADevice(t *testing.T) {
	sb := newSandbox(t)
	for _, name := range []string{"firewall-cmd", "ufw"} {
		body := "#!/bin/sh\necho \"" + name + " $*\" >> " + filepath.Join(sb.root, "calls") + "\n"
		if name == "ufw" {
			body += "[ \"$1\" = status ] && echo 'Status: active'\n"
		}
		if err := os.WriteFile(filepath.Join(sb.root, "bin", name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) (string, error) {
		cmd := exec.Command("/bin/sh", append([]string{"firewall.sh"}, args...)...)
		cmd.Env = []string{"PATH=" + filepath.Join(sb.root, "bin") + ":/usr/bin:/bin"}
		out, err := cmd.CombinedOutput()
		return string(out) + sb.calls(), err
	}
	calls, err := run("allow", "juist3")
	if err != nil || !strings.Contains(calls, "--add-interface=juist3") || !strings.Contains(calls, "allow in on juist3") ||
		strings.Contains(calls, "juist0") {
		t.Fatalf("allow juist3 (%v):\n%s", err, calls)
	}
	calls, err = run("allow")
	if err != nil || !strings.Contains(calls, "--add-interface=juist0") || strings.Contains(calls, "juist1") {
		t.Fatalf("allow (%v):\n%s", err, calls)
	}
	calls, err = run("revoke")
	for i := 0; i <= 9; i++ {
		dev := fmt.Sprintf("juist%d", i)
		if err != nil || !strings.Contains(calls, "--remove-interface="+dev) || !strings.Contains(calls, "delete allow in on "+dev) {
			t.Fatalf("revoke left %s (%v):\n%s", dev, err, calls)
		}
	}
	for _, bad := range []string{"eth0", "juist10", "juist", "juist1;reboot", "-x"} {
		calls, err := run("allow", bad)
		if err == nil || strings.Contains(calls, "firewall-cmd --zone") || strings.Contains(calls, "ufw allow") {
			t.Fatalf("allow %q ran (%v):\n%s", bad, err, calls)
		}
	}
	if calls, err := run("open"); err == nil {
		t.Fatalf("an unknown action succeeded:\n%s", calls)
	}
}
