// Package packaging holds no Go code; its tests run the Debian maintainer
// scripts in a sandbox, with their paths moved under a temporary root and the
// commands they call replaced by stubs that record their arguments.
package packaging

import (
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
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
	if !strings.Contains(calls, "try-restart") {
		t.Fatalf("an upgrade did not restart the daemon:\n%s", calls)
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
	if calls := sb.calls(); !strings.Contains(calls, "firewall.sh revoke") || !strings.Contains(calls, "disable --now") {
		t.Fatalf("a removal left the service or the rule:\n%s", calls)
	}
	sb.run("postinst", "configure", "0.9")
	calls := sb.calls()
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
