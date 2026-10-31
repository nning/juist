// Package packaging holds no Go code; its tests run the Debian maintainer
// scripts in a sandbox, with their paths moved under a temporary root and the
// commands they call replaced by stubs that record their arguments.
package packaging

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
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
	// is given, as the real one would, and systemctl has enabled the units
	// the sandbox's enabled file lists. A firewall tool left unstubbed is
	// the host's: firewalld's has polkit ask whoever is logged in for a
	// password.
	for _, name := range []string{"systemctl", "systemd-sysusers", "firewall.sh", "instances.sh", "exit-node.sh", "ingress.sh",
		"serve.sh", "relay.sh", "install", "firewall-cmd", "ufw"} {
		body := "#!/bin/sh\necho \"" + name + " $*\" >> " + filepath.Join(root, "calls") + "\n"
		switch name {
		case "install":
			body += "for last; do :; done; mkdir -p \"$last\"\n"
		case "systemctl":
			body += "if [ \"$1\" = is-enabled ]; then for last; do :; done; grep -qx \"$last\" " +
				filepath.Join(root, "enabled") + " 2>/dev/null; exit; fi\n" +
				"if [ \"$1\" = is-active ]; then for last; do :; done; grep -qx \"$last\" " +
				filepath.Join(root, "active") + " 2>/dev/null; exit; fi\n"
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
	pkla, err := filepath.Abs(filepath.Join("polkit", "juist.pkla"))
	if err != nil {
		sb.t.Fatal(err)
	}
	s := strings.NewReplacer(
		"/usr/lib/juist/firewall.sh", filepath.Join(sb.root, "bin", "firewall.sh"),
		"/usr/lib/juist/instances.sh", filepath.Join(sb.root, "bin", "instances.sh"),
		"/usr/lib/juist/exit-node.sh", filepath.Join(sb.root, "bin", "exit-node.sh"),
		"/usr/lib/juist/ingress.sh", filepath.Join(sb.root, "bin", "ingress.sh"),
		"/usr/lib/juist/serve.sh", filepath.Join(sb.root, "bin", "serve.sh"),
		"/usr/lib/juist/relay.sh", filepath.Join(sb.root, "bin", "relay.sh"),
		"/usr/lib/juist/juist.pkla", pkla,
		"/var/lib/", sb.root+"/var/lib/",
		"/run/systemd/system", filepath.Join(sb.root, "run/systemd/system"),
		"/sys/kernel/security/apparmor", filepath.Join(sb.root, "sys/kernel/security/apparmor"),
		"/etc/apparmor.d/", sb.root+"/etc/apparmor.d/",
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
	if strings.Contains(calls, "firewall.sh allow") || strings.Contains(calls, "systemctl enable") {
		t.Fatalf("an upgrade acted as a fresh install:\n%s", calls)
	}
	if !strings.Contains(calls, "instances.sh move") {
		t.Error("an upgrade did not move the instances' homes out of the default's")
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
	if !strings.Contains(calls, "firewall.sh revoke\n") || !strings.Contains(calls, "disable --now juistd.service") ||
		!strings.Contains(calls, "exit-node.sh off\nexit-node.sh clear\n") {
		t.Fatalf("a removal left the service, the rule or an exit node's forwarding:\n%s", calls)
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

// linuxPackagesOnly skips a test of what only the Linux packages ship, as
// instances.sh, which takes GNU coreutils.
func linuxPackagesOnly(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("instances.sh is the Linux packages'")
	}
}

// What the juist user swaps its instance's home for between the check and
// the move, a link to another's file, is moved, and then neither followed
// nor given on, but removed: root's chmod and chown follow a link.
func TestAHomeSwappedForALinkIsGivenNothing(t *testing.T) {
	linuxPackagesOnly(t)
	sb := newSandbox(t)
	state := filepath.Join(sb.root, "state")
	old := filepath.Join(state, "juist/juist6")
	if err := os.MkdirAll(old, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(sb.root, "sudoers")
	if err := os.WriteFile(victim, nil, 0o440); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(sb.root, "calls")
	for name, body := range map[string]string{
		"chown": "echo \"chown $*\" >> " + calls + "\n",
		// The stop is the window: the juist user swaps the home meanwhile.
		"systemctl": "echo \"systemctl $*\" >> " + calls + "\n" +
			"case $1 in is-active) [ \"$3\" = juistd@juist6.service ];; stop) rm -rf " + old + "; ln -s " + victim + " " + old + ";; esac\n",
	} {
		if err := os.WriteFile(filepath.Join(sb.root, "bin", name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile("instances.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(sb.root, "instances.sh")
	if err := os.WriteFile(script, []byte(strings.ReplaceAll(string(b), "/run/systemd/system", filepath.Join(sb.root, "run/systemd/system"))), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", script, "move")
	cmd.Env = []string{"PATH=" + filepath.Join(sb.root, "bin") + ":/usr/bin:/bin", "JUIST_STATE=" + state}
	out, _ := cmd.CombinedOutput()
	log := string(out) + sb.calls()
	if fi, err := os.Stat(victim); err != nil || fi.Mode().Perm() != 0o440 {
		t.Errorf("the link's target was changed: %v %v\n%s", fi.Mode(), err, log)
	}
	if strings.Contains(log, "chown juist6") || strings.Contains(log, "chown root") {
		t.Errorf("the link was given on:\n%s", log)
	}
	if _, err := os.Lstat(filepath.Join(state, "juist6")); !os.IsNotExist(err) {
		t.Errorf("the link stays as instance 6's home: %v", err)
	}
}

// A purge removes another network's home as the default's: only if empty.
func TestAPurgeKeepsAnInstancesHomeThatHoldsKeys(t *testing.T) {
	sb := newSandbox(t)
	for _, d := range []string{"var/lib/juist1", "var/lib/juist2"} {
		if err := os.MkdirAll(filepath.Join(sb.root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sb.root, "var/lib/juist2/node.keys"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sb.run("postrm", "purge")
	if _, err := os.Stat(filepath.Join(sb.root, "var/lib/juist1")); err == nil {
		t.Error("a purge left juist1's empty home")
	}
	if _, err := os.Stat(filepath.Join(sb.root, "var/lib/juist2/node.keys")); err != nil {
		t.Errorf("a purge took juist2's keys: %v", err)
	}
}

// A removal has an active firewalld forget the service files, asking the
// sandbox's firewall-cmd, not the host's.
func TestARemovalReloadsFirewalld(t *testing.T) {
	sb := newSandbox(t)
	sb.run("postrm", "remove")
	if calls := sb.calls(); !strings.Contains(calls, "firewall-cmd --state\nfirewall-cmd --reload\n") {
		t.Fatalf("postrm did not reload firewalld through the sandbox's firewall-cmd:\n%s", calls)
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
		"ExecStart=/usr/local/bin/juistd --instance %i --home /var/lib/%i --socket /run/%i/juistd.sock",
		"/var/lib/juist is created", "/var/lib/%i is created",
		"StateDirectory=juist", "StateDirectory=%i",
		"WorkingDirectory=/var/lib/juist", "WorkingDirectory=/var/lib/%i",
		"User=juist", "User=%i",
		"Group=juist", "Group=%i",
		"RuntimeDirectory=juist", "RuntimeDirectory=%i",
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
	if !slices.Contains(def, "RuntimeDirectoryPreserve=yes") {
		t.Error("/run/juist is not preserved: a restart would drop the resolv.conf the host points at")
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

// instances.sh move takes each instance's home out of the default's, to one
// of its own, given to its own user; it leaves one that is a link, and one
// whose new home exists already.
func TestInstancesMoveOutOfTheDefaultsHome(t *testing.T) {
	linuxPackagesOnly(t)
	sb := newSandbox(t)
	state := filepath.Join(sb.root, "state")
	for _, d := range []string{"juist/juist2", "juist/juist4", "juist4", "elsewhere"} {
		if err := os.MkdirAll(filepath.Join(state, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"juist/juist2/node.keys", "juist4/node.keys"} {
		if err := os.WriteFile(filepath.Join(state, f), []byte("keys"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(state, "elsewhere"), filepath.Join(state, "juist/juist3")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sb.root, "bin", "chown"),
		[]byte("#!/bin/sh\necho \"chown $*\" >> "+filepath.Join(sb.root, "calls")+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "instances.sh", "move")
	cmd.Env = []string{"PATH=" + filepath.Join(sb.root, "bin") + ":/usr/bin:/bin", "JUIST_STATE=" + state,
		"JUIST_USER=" + me.Username}
	out, err := cmd.CombinedOutput()
	calls := string(out) + sb.calls()
	if err != nil {
		t.Fatalf("move: %v\n%s", err, calls)
	}
	if b, err := os.ReadFile(filepath.Join(state, "juist2/node.keys")); err != nil || string(b) != "keys" {
		t.Errorf("instance 2's keys did not move: %v", err)
	}
	if _, err := os.Stat(filepath.Join(state, "juist/juist2")); !os.IsNotExist(err) {
		t.Errorf("instance 2's old home is still there: %v", err)
	}
	// Shut out of it first, then given what was the default's user's alone:
	// a hard link that user planted to another's file keeps its owner.
	home := filepath.Join(state, "juist2")
	if !strings.Contains(calls, "chown root:root "+home+"\nchown -h juist2:juist2 "+home+"/node.keys\nchown juist2:juist2 "+home+"\n") {
		t.Errorf("instance 2's home was not given to juist2:\n%s", calls)
	}
	if _, err := os.Lstat(filepath.Join(state, "juist3")); !os.IsNotExist(err) || strings.Contains(calls, "juist3") {
		t.Errorf("a link was moved, or acted on:\n%s", calls)
	}
	if _, err := os.Stat(filepath.Join(state, "juist/juist4")); err != nil || !strings.Contains(calls, "both exist") {
		t.Errorf("instance 4's old home was not left beside its new one (%v):\n%s", err, calls)
	}
}

// A running instance's stop already runs the new unit's ExecStopPost, for
// which systemd makes its new, empty StateDirectory: the home replaces that,
// rather than moving into it.
func TestARunningInstanceMovesOverTheHomeItsStopMade(t *testing.T) {
	linuxPackagesOnly(t)
	sb := newSandbox(t)
	state := filepath.Join(sb.root, "state")
	if err := os.MkdirAll(filepath.Join(state, "juist/juist5"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "juist/juist5/node.keys"), []byte("keys"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(sb.root, "calls")
	for name, body := range map[string]string{
		"chown": "echo \"chown $*\" >> " + calls + "\n",
		"systemctl": "echo \"systemctl $*\" >> " + calls + "\n" +
			"case $1 in is-active) [ \"$3\" = juistd@juist5.service ];; stop) mkdir -p " + filepath.Join(state, "juist5") + ";; esac\n",
	} {
		if err := os.WriteFile(filepath.Join(sb.root, "bin", name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile("instances.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(sb.root, "instances.sh")
	if err := os.WriteFile(script, []byte(strings.ReplaceAll(string(b), "/run/systemd/system", filepath.Join(sb.root, "run/systemd/system"))), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", script, "move")
	cmd.Env = []string{"PATH=" + filepath.Join(sb.root, "bin") + ":/usr/bin:/bin", "JUIST_STATE=" + state}
	out, err := cmd.CombinedOutput()
	log := string(out) + sb.calls()
	if err != nil {
		t.Fatalf("move: %v\n%s", err, log)
	}
	if b, err := os.ReadFile(filepath.Join(state, "juist5/node.keys")); err != nil || string(b) != "keys" {
		t.Errorf("instance 5's keys are not in its home: %v\n%s", err, log)
	}
	if _, err := os.Stat(filepath.Join(state, "juist/juist5")); !os.IsNotExist(err) {
		t.Errorf("instance 5's old home is still there: %v", err)
	}
	if !strings.Contains(log, "systemctl stop juistd@juist5.service\n") || !strings.Contains(log, "systemctl start juistd@juist5.service\n") {
		t.Errorf("instance 5 was not stopped and started again:\n%s", log)
	}
}
