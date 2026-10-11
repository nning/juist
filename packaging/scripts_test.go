// Package packaging holds no Go code; its tests run the Debian maintainer
// scripts in a sandbox, with their paths moved under a temporary root and the
// commands they call replaced by stubs that record their arguments.
package packaging

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nning/juist/ipc"
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
	for _, name := range []string{"systemctl", "systemd-sysusers", "firewall.sh", "exit-node.sh", "ingress.sh", "serve.sh",
		"relay.sh", "install", "firewall-cmd", "ufw"} {
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
	s := strings.NewReplacer(
		"/usr/lib/juist/firewall.sh", filepath.Join(sb.root, "bin", "firewall.sh"),
		"/usr/lib/juist/exit-node.sh", filepath.Join(sb.root, "bin", "exit-node.sh"),
		"/usr/lib/juist/ingress.sh", filepath.Join(sb.root, "bin", "ingress.sh"),
		"/usr/lib/juist/serve.sh", filepath.Join(sb.root, "bin", "serve.sh"),
		"/usr/lib/juist/relay.sh", filepath.Join(sb.root, "bin", "relay.sh"),
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
	if strings.Contains(calls, "firewall.sh allow") || strings.Contains(calls, "systemctl enable") {
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

// exitSandbox is a host for exit-node.sh: /proc/sys/net and /etc/sysctl.d
// under the sandbox, and ufw and a Docker host's iptables as stubs.
func exitSandbox(t *testing.T) (sb *sandbox, run func(args ...string) (string, error)) {
	sb = newSandbox(t)
	set := func(rel, v string) {
		p := filepath.Join(sb.root, "proc/sys/net", rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	set("ipv4/ip_forward", "0")
	set("ipv6/conf/all/forwarding", "0")
	set("ipv6/conf/all/accept_ra", "1")
	set("ipv6/conf/default/accept_ra", "1")
	set("ipv6/conf/lo/accept_ra", "1")
	set("ipv6/conf/eth0/accept_ra", "1")
	set("ipv6/conf/eth1/accept_ra", "0")
	set("ipv6/conf/juist0/accept_ra", "1")
	set("ipv6/conf/veth3e0a3e1/accept_ra", "1")
	for _, name := range []string{"ufw", "iptables", "ip6tables"} {
		body := "#!/bin/sh\necho \"" + name + " $*\" >> " + filepath.Join(sb.root, "calls") + "\n"
		if name != "ufw" {
			// DOCKER-USER exists; no rule is there to check or delete.
			body += "case \"$*\" in *-C*|*-D*) exit 1 ;; esac\n"
		}
		if err := os.WriteFile(filepath.Join(sb.root, "bin", name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile("exit-node.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.NewReplacer("/proc/sys/net", filepath.Join(sb.root, "proc/sys/net"),
		"/etc/sysctl.d/", filepath.Join(sb.root, "etc/sysctl.d")+"/").Replace(string(b))
	script := filepath.Join(sb.root, "exit-node.sh")
	if err := os.WriteFile(script, []byte(s), 0o755); err != nil {
		t.Fatal(err)
	}
	return sb, func(args ...string) (string, error) {
		cmd := exec.Command("/bin/sh", append([]string{script}, args...)...)
		cmd.Env = []string{"PATH=" + filepath.Join(sb.root, "bin") + ":/usr/bin:/bin"}
		out, err := cmd.CombinedOutput()
		return string(out) + sb.calls(), err
	}
}

func (sb *sandbox) sysctl(rel string) string {
	b, _ := os.ReadFile(filepath.Join(sb.root, "proc/sys/net", rel))
	return strings.TrimSpace(string(b))
}

// The exit node's setup forwards, keeps the host's router advertisements,
// opens ufw and Docker's chain for the device alone, and its undoing puts
// every one of them back as it was, once the last device is done.
func TestExitNodeScriptUndoesWhatItDid(t *testing.T) {
	sb, run := exitSandbox(t)
	conf := filepath.Join(sb.root, "etc/sysctl.d/60-juist-exit.conf")
	calls, err := run("on", "juist0")
	if err != nil {
		t.Fatalf("on (%v):\n%s", err, calls)
	}
	for rel, want := range map[string]string{"ipv4/ip_forward": "1", "ipv6/conf/all/forwarding": "1",
		"ipv6/conf/eth0/accept_ra": "2", "ipv6/conf/eth1/accept_ra": "0", "ipv6/conf/lo/accept_ra": "1",
		"ipv6/conf/juist0/accept_ra": "1"} {
		if got := sb.sysctl(rel); got != want {
			t.Errorf("after on, %s is %s, want %s", rel, got, want)
		}
	}
	b, _ := os.ReadFile(conf)
	for _, want := range []string{"# for: juist0\n", "net.ipv4.ip_forward = 1", "net.ipv6.conf.all.forwarding = 1",
		"net.ipv6.conf.eth0.accept_ra = 2"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the sysctl file lacks %q:\n%s", want, b)
		}
	}
	// A container's veth takes no router advertisement, and goes with it.
	if strings.Contains(string(b), "veth") {
		t.Errorf("the sysctl file keeps a container's veth:\n%s", b)
	}
	for _, want := range []string{"ufw route allow in on juist0", "iptables -I DOCKER-USER -i juist0 -j ACCEPT",
		"ip6tables -I DOCKER-USER -o juist0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"} {
		if !strings.Contains(calls, want) {
			t.Errorf("on did not run %q:\n%s", want, calls)
		}
	}

	if calls, err := run("on", "juist2"); err != nil || !strings.Contains(calls, "on juist2") {
		t.Fatalf("on juist2 (%v):\n%s", err, calls)
	}
	if calls, err := run("off", "juist0"); err != nil || !strings.Contains(calls, "ufw route delete allow in on juist0") ||
		strings.Contains(calls, "juist2") {
		t.Fatalf("off juist0 (%v):\n%s", err, calls)
	}
	if sb.sysctl("ipv4/ip_forward") != "1" {
		t.Fatal("off for one device stopped forwarding for another")
	}
	if b, _ := os.ReadFile(conf); !strings.Contains(string(b), "# for: juist2\n") {
		t.Fatalf("the sysctl file after off juist0:\n%s", b)
	}
	if calls, err := run("off"); err != nil || !strings.Contains(calls, "delete allow in on juist9") {
		t.Fatalf("off (%v):\n%s", err, calls)
	}
	for rel, want := range map[string]string{"ipv4/ip_forward": "0", "ipv6/conf/all/forwarding": "0",
		"ipv6/conf/eth0/accept_ra": "1", "ipv6/conf/eth1/accept_ra": "0"} {
		if got := sb.sysctl(rel); got != want {
			t.Errorf("after off, %s is %s, want %s", rel, got, want)
		}
	}
	if _, err := os.Stat(conf); !os.IsNotExist(err) {
		t.Error("off left the sysctl file")
	}
	if calls, err := run("off"); err != nil {
		t.Fatalf("a second off (%v):\n%s", err, calls)
	}
}

// Forwarding a host had on before stays on after.
func TestExitNodeScriptKeepsForwardingItFound(t *testing.T) {
	sb, run := exitSandbox(t)
	if err := os.WriteFile(filepath.Join(sb.root, "proc/sys/net/ipv4/ip_forward"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if calls, err := run("on", "juist0"); err != nil {
		t.Fatalf("on (%v):\n%s", err, calls)
	}
	if calls, err := run("off", "juist0"); err != nil {
		t.Fatalf("off (%v):\n%s", err, calls)
	}
	if sb.sysctl("ipv4/ip_forward") != "1" || sb.sysctl("ipv6/conf/all/forwarding") != "0" {
		t.Fatalf("forwarding after off: %s %s", sb.sysctl("ipv4/ip_forward"), sb.sysctl("ipv6/conf/all/forwarding"))
	}
}

// clear takes juist's egress rules, exit tables and masquerade, of every
// instance, and nothing else.
func TestExitNodeScriptClearsWhatAFailedJuistdLeft(t *testing.T) {
	sb, run := exitSandbox(t)
	for _, name := range []string{"ip", "nft"} {
		// Each rule is there once.
		body := "#!/bin/sh\necho \"" + name + " $*\" >> " + filepath.Join(sb.root, "calls") + "\n" +
			"f=" + filepath.Join(sb.root, "gone") + "-$(echo \"$*\" | tr ' ' _)\n" +
			"[ -e \"$f\" ] && exit 2\ntouch \"$f\"\n"
		if err := os.WriteFile(filepath.Join(sb.root, "bin", name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	calls, err := run("clear")
	if err != nil {
		t.Fatalf("clear (%v):\n%s", err, calls)
	}
	for _, want := range []string{"ip -4 rule del pref 5180 table main", "ip -6 rule del pref 5189 table main",
		"ip -4 rule del pref 5200 table 27509", "ip -6 rule del pref 5199 table main", "ip -6 rule del pref 5209 table 27518", "ip -4 route flush table 27509",
		"ip -6 route flush table 27518", "nft delete table ip juist0", "nft delete table ip6 juist9",
		"nft delete table ip juist3guard"} {
		if !strings.Contains(calls, want+"\n") {
			t.Errorf("clear did not run %q:\n%s", want, calls)
		}
	}
	if strings.Contains(calls, "pref 5170") || strings.Contains(calls, "pref 5210") ||
		strings.Contains(calls, "ufw") || regexp.MustCompile(`rule del pref \d+\n`).MatchString(calls) {
		t.Errorf("clear touched what is not an exit node's:\n%s", calls)
	}
}

func TestExitNodeScriptTakesJuistDevicesAlone(t *testing.T) {
	_, run := exitSandbox(t)
	for _, args := range [][]string{{"on"}, {"on", "eth0"}, {"on", "juist10"}, {"on", "juist1;reboot"},
		{"off", "-x"}, {"serve", "juist0"}, {"clear", "juist0"}, {}} {
		if calls, err := run(args...); err == nil || strings.Contains(calls, "ufw") {
			t.Errorf("%q ran (%v):\n%s", args, err, calls)
		}
	}
}

// The polkit rule lets the juist user route resolved's DNS on juist's own
// devices, and nothing else, and nobody else.
func TestThePolkitRuleAllowsJuistsDNSAlone(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node to run polkit's JavaScript with")
	}
	b, err := os.ReadFile(filepath.Join("polkit", "juist.rules"))
	if err != nil {
		t.Fatal(err)
	}
	harness := `
var rule;
var polkit = {Result: {YES: "yes", NO: "no", NOT_HANDLED: "not handled"}, addRule: function(f) { rule = f; }};
` + string(b) + `
var cases = JSON.parse(process.argv[process.argv.length - 1]);
var out = cases.map(function(c) {
	var action = {id: c.action, lookup: function(k) { return c.details[k]; }};
	return rule(action, {user: c.user});
});
console.log(JSON.stringify(out));
`
	type check struct {
		User    string            `json:"user"`
		Action  string            `json:"action"`
		Details map[string]string `json:"details"`
		want    string
	}
	checks := []check{
		{"juist", "org.freedesktop.resolve1.set-dns-servers", map[string]string{"interface": "juist0"}, "yes"},
		{"juist", "org.freedesktop.resolve1.set-domains", map[string]string{"interface": "juist3"}, "yes"},
		{"juist", "org.freedesktop.resolve1.revert", map[string]string{"interface": "juist9"}, "yes"},
		{"juist", "org.freedesktop.resolve1.set-default-route", map[string]string{}, "yes"}, // before systemd 256
		{"juist", "org.freedesktop.resolve1.set-dnssec-negative-trust-anchors", map[string]string{"interface": "juist0"}, "yes"},
		{"juist", "org.freedesktop.resolve1.set-dnssec-negative-trust-anchors", map[string]string{"interface": "eth0"}, "not handled"},
		{"juist", "org.freedesktop.resolve1.set-dns-servers", map[string]string{"interface": "eth0"}, "not handled"},
		{"juist", "org.freedesktop.resolve1.set-dns-servers", map[string]string{"interface": "juist10"}, "not handled"},
		{"juist", "org.freedesktop.resolve1.set-dnssec", map[string]string{"interface": "juist0"}, "not handled"},
		{"juist", "org.freedesktop.systemd1.manage-units", map[string]string{}, "not handled"},
		{"mallory", "org.freedesktop.resolve1.set-dns-servers", map[string]string{"interface": "juist0"}, "not handled"},
	}
	in, err := json.Marshal(checks)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, "-e", harness, string(in)).CombinedOutput()
	if err != nil {
		t.Fatalf("running the rule: %v\n%s", err, out)
	}
	var got []string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for i, c := range checks {
		if got[i] != c.want {
			t.Errorf("%s asking %s on %v: %s, want %s", c.User, c.Action, c.Details, got[i], c.want)
		}
	}
}

// ingress.sh starts the ingress and lets 443 and 80 through an active
// firewall, and takes both back, from a stopped firewalld too.
func TestIngressScriptOpensAndCloses(t *testing.T) {
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
	b, err := os.ReadFile("ingress.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(sb.root, "ingress.sh")
	b = []byte(strings.NewReplacer("/run/juist-ingress-ports.lock", sb.root+"/lock",
		"/var/lib/juist-ingress-ports/", sb.root+"/var/lib/juist-ingress-ports/").Replace(string(b)))
	if err := os.WriteFile(script, b, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		cmd := exec.Command("/bin/sh", append([]string{script}, args...)...)
		cmd.Env = []string{"PATH=" + filepath.Join(sb.root, "bin") + ":/usr/bin:/bin"}
		out, err := cmd.CombinedOutput()
		return string(out) + sb.calls(), err
	}
	calls, err := run("on")
	for _, want := range []string{"systemctl enable --now --quiet juist-ingress.service",
		"systemctl enable --now --quiet juist-ingress-ports.path", "firewall-cmd --add-service=juist-ingress",
		"firewall-cmd --permanent --add-service=juist-ingress", "ufw allow juist-ingress"} {
		if err != nil || !strings.Contains(calls, want) {
			t.Fatalf("on lacks %q (%v):\n%s", want, err, calls)
		}
	}
	calls, err = run("off")
	for _, want := range []string{"systemctl disable --now juist-ingress.service juist-ingress-ports.path",
		"firewall-cmd --remove-service=juist-ingress",
		"firewall-cmd --permanent --remove-service=juist-ingress", "ufw delete allow juist-ingress"} {
		if err != nil || !strings.Contains(calls, want) {
			t.Fatalf("off lacks %q (%v):\n%s", want, err, calls)
		}
	}
	if calls, err := run("open"); err == nil {
		t.Fatalf("an unknown action succeeded:\n%s", calls)
	}

	// A firewall that refuses is said, and the ingress runs all the same.
	refusing := "#!/bin/sh\n[ \"$1\" = --state ] && exit 0\nexit 1\n"
	if err := os.WriteFile(filepath.Join(sb.root, "bin", "firewall-cmd"), []byte(refusing), 0o755); err != nil {
		t.Fatal(err)
	}
	if calls, err := run("on"); err != nil || !strings.Contains(calls, "warning: firewalld did not let juist-ingress in") {
		t.Fatalf("a refusing firewalld (%v):\n%s", err, calls)
	}
}

// ingress.sh has an active firewalld and ufw let exactly the public ports
// juistd lists through while the ingress is enabled, takes back what it let
// through once no longer listed, and leaves the ports others opened alone;
// what juistd's file says is no port, or a port of juist's or the ingress's
// TLS, is let through nowhere, and ufw's rule of someone else's for a port
// stays theirs.
func TestIngressScriptFollowsThePorts(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress.sh is Linux's, with its flock, timeout and dd")
	}
	sb := newSandbox(t)
	fw, ufwRules := filepath.Join(sb.root, "fw-open"), filepath.Join(sb.root, "ufw-rules")
	stubs := map[string]string{
		"firewall-cmd": `case $1 in
--state) exit 0 ;;
--permanent) f=` + fw + `.permanent; shift ;;
*) f=` + fw + ` ;;
esac
case $1 in
--query-port=*) p=${1#--query-port=}; grep -qx "$p" $f 2>/dev/null ;;
--add-port=*) echo "${1#--add-port=}" >> $f ;;
--remove-port=*) grep -vx "${1#--remove-port=}" $f > $f.new; mv $f.new $f ;;
esac`,
		"ufw": `case "$*" in
status) echo 'Status: active' ;;
"show added") echo "Added user rules (see 'ufw status' for running firewall):"; echo "ufw allow 8081/tcp"; while read -r p; do echo "ufw allow $p/tcp comment 'juist-ingress'"; done < ` + ufwRules + ` ;;
"allow "*" comment juist-ingress") echo "${2%/tcp}" >> ` + ufwRules + ` ;;
"delete allow "*/tcp) grep -vx "${3%/tcp}" ` + ufwRules + ` > ` + ufwRules + `.new; mv ` + ufwRules + `.new ` + ufwRules + ` ;;
esac`,
	}
	for name, body := range stubs {
		body = "#!/bin/sh\necho \"" + name + " $*\" >> " + filepath.Join(sb.root, "calls") + "\n" + body + "\n"
		if err := os.WriteFile(filepath.Join(sb.root, "bin", name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{fw, ufwRules} {
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile("ingress.sh")
	if err != nil {
		t.Fatal(err)
	}
	ports := filepath.Join(sb.root, "run/juist/ingress-ports")
	script := filepath.Join(sb.root, "ingress.sh")
	b = []byte(strings.NewReplacer(ipc.IngressPorts, ports,
		"/var/lib/juist-ingress-ports/", sb.root+"/var/lib/juist-ingress-ports/",
		"/run/juist-ingress-ports.lock", sb.root+"/lock").Replace(string(b)))
	if err := os.WriteFile(script, b, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(ports), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(action string) {
		t.Helper()
		cmd := exec.Command("/bin/sh", script, action)
		cmd.Env = []string{"PATH=" + filepath.Join(sb.root, "bin") + ":/usr/bin:/bin"}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ingress.sh %s: %v\n%s", action, err, out)
		}
		sb.calls()
	}
	lines := func(f string) string {
		b, _ := os.ReadFile(f)
		got := strings.Fields(strings.ReplaceAll(string(b), "/tcp", ""))
		slices.Sort(got)
		return strings.Join(got, " ")
	}
	list := func(s string) {
		if err := os.WriteFile(ports, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	check := func(when, firewalld, ufw string) {
		t.Helper()
		if got := lines(fw); got != firewalld {
			t.Errorf("%s, firewalld lets in %q, want %q", when, got, firewalld)
		}
		if got := lines(ufwRules); got != ufw {
			t.Errorf("%s, ufw lets in %q, want %q", when, got, ufw)
		}
	}

	permanent := fw + ".permanent"
	write := func(f, s string) {
		t.Helper()
		if err := os.WriteFile(f, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(permanent, "")
	list("25565\n2222\n80\n443\n41643\nbogus\n0\n70000\n")
	run("ports")
	check("with the ingress not running", "", "")
	write(filepath.Join(sb.root, "active"), "juist-ingress.service\n")
	// Someone else's: open at runtime, and for good.
	write(fw, "8080/tcp\n")
	write(permanent, "8079/tcp\n")
	list("25565\n2222\n8079\n8080\n8081\n80\n443\n41643\nbogus\n0\n70000\n")
	run("ports")
	check("listed", "2222 25565 8080 8081", "2222 25565 8079 8080")
	if got := lines(permanent); got != "2222 25565 8079 8081" {
		t.Errorf("listed, firewalld keeps %q for good", got)
	}
	list("25565\n")
	run("ports")
	check("one withdrawn", "25565 8080", "25565")
	if got := lines(permanent); got != "25565 8079" {
		t.Errorf("one withdrawn, firewalld keeps %q for good", got)
	}
	// A reload takes back what was let in at runtime alone.
	write(fw, "8080/tcp\n")
	run("ports")
	check("after firewalld reloaded", "25565 8080", "25565")
	// Until juistd says, which it does once its view is fresh, as it was.
	if err := os.Remove(ports); err != nil {
		t.Fatal(err)
	}
	run("ports")
	check("juistd's file gone", "25565 8080", "25565")
	write(filepath.Join(sb.root, "elsewhere"), "")
	if err := os.Symlink(filepath.Join(sb.root, "elsewhere"), ports); err != nil {
		t.Fatal(err)
	}
	run("ports")
	check("juistd's file a link", "25565 8080", "25565")
	if err := os.Remove(ports); err != nil {
		t.Fatal(err)
	}
	// A FIFO is no file juistd wrote: nothing waits on it.
	if err := syscall.Mkfifo(ports, 0o644); err != nil {
		t.Fatal(err)
	}
	run("ports")
	check("juistd's file a FIFO", "25565 8080", "25565")
	if err := os.Remove(ports); err != nil {
		t.Fatal(err)
	}
	list("25565\n")
	write(filepath.Join(sb.root, "active"), "")
	run("ports")
	check("the ingress stopped", "8080", "")
	write(filepath.Join(sb.root, "active"), "juist-ingress.service\n")
	run("ports")
	write(filepath.Join(sb.root, "active"), "")
	run("off")
	check("off", "8080", "")
	if got := lines(permanent); got != "8079" {
		t.Errorf("off, firewalld keeps %q for good", got)
	}
	if _, err := os.Stat(filepath.Join(sb.root, "var/lib/juist-ingress-ports")); err == nil {
		t.Error("off left what the script noted")
	}
}

// Two runs at once each let through what they read, and neither takes for
// someone else's what the other let through: they run one after the other.
func TestIngressScriptRunsOneAtATime(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress.sh is Linux's, with its flock, timeout and dd")
	}
	sb := newSandbox(t)
	fw := filepath.Join(sb.root, "fw-open")
	slow := `case $1 in --state) exit 0 ;; --permanent) f=` + fw + `.permanent; shift ;; *) f=` + fw + ` ;; esac
sleep 0.05
case $1 in
--query-port=*) grep -qx "${1#--query-port=}" $f 2>/dev/null ;;
--add-port=*) echo "${1#--add-port=}" >> $f ;;
--remove-port=*) grep -vx "${1#--remove-port=}" $f > $f.new; mv $f.new $f ;;
esac`
	if err := os.WriteFile(filepath.Join(sb.root, "bin", "firewall-cmd"), []byte("#!/bin/sh\n"+slow+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ports := filepath.Join(sb.root, "ingress-ports")
	b, err := os.ReadFile("ingress.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(sb.root, "ingress.sh")
	b = []byte(strings.NewReplacer(ipc.IngressPorts, ports,
		"/var/lib/juist-ingress-ports/", sb.root+"/var/lib/juist-ingress-ports/",
		"/run/juist-ingress-ports.lock", sb.root+"/lock").Replace(string(b)))
	for name, data := range map[string]string{script: string(b), ports: "2222\n25565\n", filepath.Join(sb.root, "active"): "juist-ingress.service\n"} {
		if err := os.WriteFile(name, []byte(data), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Go(func() {
			// The second once the first let a port through, before it noted it.
			time.Sleep(time.Duration(i) * 200 * time.Millisecond)
			cmd := exec.Command("/bin/sh", script, "ports")
			cmd.Env = []string{"PATH=" + filepath.Join(sb.root, "bin") + ":/usr/bin:/bin"}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%v\n%s", err, out)
			}
		})
	}
	wg.Wait()
	if got, _ := os.ReadFile(filepath.Join(sb.root, "var/lib/juist-ingress-ports/opened")); string(got) != "2222\n25565\n" {
		t.Errorf("noted as its own: %q", got)
	}
}

// Removing the package stops an ingress and closes its ports, and takes a
// relay's 443 back.
func TestARemovalStopsTheIngress(t *testing.T) {
	sb := newSandbox(t)
	sb.run("prerm", "remove")
	if calls := sb.calls(); !strings.Contains(calls, "ingress.sh off") || !strings.Contains(calls, "serve.sh off") ||
		!strings.Contains(calls, "relay.sh off") {
		t.Fatalf("prerm left the ingress, the terminator or the relay on 443:\n%s", calls)
	}
}

// relay.sh grants juistd the binding of 443 by a drop-in, which takes a
// restart once and none when it holds already, lets 443/tcp through an
// active firewall, and takes all of it back.
func TestRelayScriptGrantsAndTakesBack443(t *testing.T) {
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
	b, err := os.ReadFile("relay.sh")
	if err != nil {
		t.Fatal(err)
	}
	dropin := filepath.Join(sb.root, "etc/systemd/system/juistd.service.d/juist-relay-443.conf")
	script := filepath.Join(sb.root, "relay.sh")
	b = []byte(strings.ReplaceAll(string(b), "/etc/systemd/", sb.root+"/etc/systemd/"))
	if err := os.WriteFile(script, b, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		cmd := exec.Command("/bin/sh", append([]string{script}, args...)...)
		cmd.Env = []string{"PATH=" + filepath.Join(sb.root, "bin") + ":/usr/bin:/bin"}
		out, err := cmd.CombinedOutput()
		return string(out) + sb.calls(), err
	}
	calls, err := run("on")
	for _, want := range []string{"systemctl daemon-reload", "systemctl try-restart juistd.service",
		"firewall-cmd --add-service=juist-relay-443", "firewall-cmd --permanent --add-service=juist-relay-443",
		"ufw allow juist-relay-443"} {
		if err != nil || !strings.Contains(calls, want) {
			t.Fatalf("on lacks %q (%v):\n%s", want, err, calls)
		}
	}
	grant, err := os.ReadFile(dropin)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n", "\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"} {
		if !strings.Contains(string(grant), want) {
			t.Errorf("the drop-in lacks %q:\n%s", want, grant)
		}
	}
	if calls, err := run("on"); err != nil || strings.Contains(calls, "try-restart") {
		t.Errorf("granting again restarted juistd (%v):\n%s", err, calls)
	}
	calls, err = run("off")
	for _, want := range []string{"systemctl try-restart juistd.service", "firewall-cmd --remove-service=juist-relay-443",
		"firewall-cmd --permanent --remove-service=juist-relay-443", "ufw delete allow juist-relay-443"} {
		if err != nil || !strings.Contains(calls, want) {
			t.Fatalf("off lacks %q (%v):\n%s", want, err, calls)
		}
	}
	if _, err := os.Stat(filepath.Dir(dropin)); !os.IsNotExist(err) {
		t.Errorf("the drop-in's directory stayed: %v", err)
	}
	if calls, err := run("off"); err != nil || strings.Contains(calls, "try-restart") {
		t.Errorf("taking back what was not granted restarted juistd (%v):\n%s", err, calls)
	}
}

// systemd starts the terminator by juistd's file, from a fresh install on;
// an upgrade moves a terminator enabled the old way to it, and enables
// nothing else.
func TestTheTerminatorStartsByItsPath(t *testing.T) {
	b, err := os.ReadFile("systemd/juist-serve.path")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"\nPathExists=" + ipc.TerminatorWanted + "\n", "\nUnit=juist-serve.service\n"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("juist-serve.path lacks %q", strings.TrimSpace(want))
		}
	}
	sb := newSandbox(t)
	sb.run("postinst", "configure")
	if calls := sb.calls(); !strings.Contains(calls, "systemctl enable --now juist-serve.path") {
		t.Fatalf("a fresh install left the terminator's path off:\n%s", calls)
	}
	sb.run("postinst", "configure", "0.9")
	if calls := sb.calls(); strings.Contains(calls, "juist-serve.path") {
		t.Fatalf("an upgrade enabled the terminator's path:\n%s", calls)
	}
	if err := os.WriteFile(filepath.Join(sb.root, "enabled"), []byte("juist-serve.service\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb.run("postinst", "configure", "0.9")
	if calls := sb.calls(); !strings.Contains(calls, "systemctl disable --quiet juist-serve.service\n") ||
		!strings.Contains(calls, "systemctl enable --now juist-serve.path\n") {
		t.Fatalf("an upgrade left the terminator enabled the old way:\n%s", calls)
	}
}

// serve.sh starts the terminator and stops it.
func TestServeScriptStartsAndStops(t *testing.T) {
	sb := newSandbox(t)
	run := func(args ...string) (string, error) {
		cmd := exec.Command("/bin/sh", append([]string{"serve.sh"}, args...)...)
		cmd.Env = []string{"PATH=" + filepath.Join(sb.root, "bin") + ":/usr/bin:/bin"}
		out, err := cmd.CombinedOutput()
		return string(out) + sb.calls(), err
	}
	if calls, err := run("on"); err != nil || !strings.Contains(calls, "systemctl enable --now --quiet juist-serve.path") {
		t.Fatalf("on (%v):\n%s", err, calls)
	}
	if calls, err := run("off"); err != nil || !strings.Contains(calls, "systemctl disable --now juist-serve.path juist-serve.service") {
		t.Fatalf("off (%v):\n%s", err, calls)
	}
	if calls, err := run("open"); err == nil {
		t.Fatalf("an unknown action succeeded:\n%s", calls)
	}
}

// The ingress's firewalld service and ufw profile let in the same ports:
// TLS and QUIC on 443, HTTP on 80; an upgrade has ufw take the profile's
// ports anew, which it holds as they were when allowed.
func TestTheIngressProfilesLetQUICIn(t *testing.T) {
	b, err := os.ReadFile("firewalld/juist-ingress.xml")
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
		t.Fatal(err)
	}
	var got []string
	for _, p := range svc.Ports {
		got = append(got, p.Port+"/"+p.Protocol)
	}
	slices.Sort(got)
	if want := []string{"443/tcp", "443/udp", "80/tcp"}; !slices.Equal(got, want) {
		t.Errorf("firewalld lets in %v, want %v", got, want)
	}
	u, err := os.ReadFile("ufw/juist")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(u), "[juist-ingress]") || !strings.Contains(string(u), "\nports=80,443/tcp|443/udp\n") {
		t.Errorf("ufw's profile:\n%s", u)
	}
	sb := newSandbox(t)
	if err := os.WriteFile(filepath.Join(sb.root, "bin", "ufw"), []byte("#!/bin/sh\necho \"ufw $*\" >> "+
		filepath.Join(sb.root, "calls")+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sb.run("postinst", "configure", "0.9")
	if calls := sb.calls(); !strings.Contains(calls, "ufw app update juist-ingress") {
		t.Errorf("an upgrade left ufw's profile as it was:\n%s", calls)
	}
}

// FreeBSD's relay.sh leaves root's grant the helper binds 443 by, once, and
// takes it back with the directory it made.
func TestFreeBSDRelayScriptGrantsAndTakesBack443(t *testing.T) {
	root := t.TempDir()
	b, err := os.ReadFile("freebsd/libexec/relay.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "relay.sh")
	b = []byte(strings.ReplaceAll(string(b), "/usr/local/etc/juist", root+"/usr/local/etc/juist"))
	if err := os.WriteFile(script, b, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(arg string) {
		t.Helper()
		if out, err := exec.Command("/bin/sh", script, arg).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", arg, err, out)
		}
	}
	grant := filepath.Join(root, "usr/local/etc/juist/relay-443")
	run("on")
	run("on")
	fi, err := os.Stat(grant)
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("the grant is %v, %v", fi, err)
	}
	run("off")
	if _, err := os.Stat(filepath.Dir(grant)); !os.IsNotExist(err) {
		t.Errorf("off left %s: %v", filepath.Dir(grant), err)
	}
	run("off")
	if out, err := exec.Command("/bin/sh", script, "maybe").CombinedOutput(); err == nil {
		t.Errorf("an unknown action was taken:\n%s", out)
	}
}
