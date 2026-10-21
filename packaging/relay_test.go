package packaging

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
