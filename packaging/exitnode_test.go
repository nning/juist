package packaging

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

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
