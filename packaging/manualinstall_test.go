package packaging

import (
	"cmp"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// make install on a systemd host without a package manager installs the
// RPM's files, the docs beside them and the script that removes them.
func TestTheSystemdStageHoldsTheRPMsFiles(t *testing.T) {
	stage := recipeFiles(t, "stage-systemd")
	rpm := rpmFiles(t)
	if len(stage) < 30 || len(rpm) < 25 {
		t.Fatalf("read %d files of the stage and %d of the RPM; the parsing no longer follows the Makefile or the spec",
			len(stage), len(rpm))
	}
	for _, f := range []string{"/usr/share/doc/juist/README.md", "/usr/share/doc/juist/copyright",
		"/usr/share/doc/juist/THIRD_PARTY_LICENSES", "/usr/lib/juist/manual-install.sh"} {
		rpm[f] = true
	}
	for _, f := range slices.Sorted(maps.Keys(rpm)) {
		if !stage[f] {
			t.Errorf("the RPM installs %s, which the stage does not", f)
		}
	}
	for _, f := range slices.Sorted(maps.Keys(stage)) {
		if !rpm[f] {
			t.Errorf("the stage installs %s, which the RPM does not", f)
		}
	}
}

type manualHost struct {
	t                *testing.T
	root, bin, calls string
}

// newManualHost is a DESTDIR with stubs for what manual-install.sh calls.
// /usr/share and its file are the host's own.
func newManualHost(t *testing.T) *manualHost {
	t.Helper()
	dir := t.TempDir()
	h := &manualHost{t: t, root: filepath.Join(dir, "root"), bin: filepath.Join(dir, "bin"), calls: filepath.Join(dir, "calls")}
	h.write(filepath.Join(h.root, "usr/share/hosts-own"), "", 0o644)
	for _, name := range []string{"systemctl", "systemd-sysusers", "chown", "firewall-cmd"} {
		h.write(filepath.Join(h.bin, name), "#!/bin/sh\necho \""+name+" $*\" >> "+h.calls+"\n", 0o755)
	}
	return h
}

func (h *manualHost) write(path, body string, mode os.FileMode) {
	h.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		h.t.Fatal(err)
	}
}

// stage lays out a tree as make stage-systemd does, its scripts stubs, with
// extra files besides.
func (h *manualHost) stage(extra ...string) string {
	h.t.Helper()
	s := h.t.TempDir()
	h.write(filepath.Join(s, "usr/bin/juistd"), "#!/bin/sh\n", 0o755)
	h.write(filepath.Join(s, "usr/lib/sysusers.d/juist.conf"), "u juist -\n", 0o644)
	for _, sh := range []string{"firewall", "instances", "ingress", "serve", "relay", "exit-node"} {
		h.write(filepath.Join(s, "usr/lib/juist", sh+".sh"),
			"#!/bin/sh\necho \""+sh+".sh $*\" >> "+h.calls+"\n", 0o755)
	}
	for _, f := range extra {
		h.write(filepath.Join(s, f), f, 0o644)
	}
	return s
}

func (h *manualHost) run(args ...string) (string, error) {
	h.t.Helper()
	os.Remove(h.calls)
	cmd := exec.Command("/bin/sh", append([]string{"manual-install.sh"}, args...)...)
	cmd.Env = []string{"PATH=" + h.bin + ":/usr/bin:/bin", "DESTDIR=" + h.root}
	out, err := cmd.CombinedOutput()
	calls, _ := os.ReadFile(h.calls)
	return string(out) + string(calls), err
}

func (h *manualHost) must(args ...string) string {
	h.t.Helper()
	out, err := h.run(args...)
	if err != nil {
		h.t.Fatalf("manual-install.sh %v: %v\n%s", args, err, out)
	}
	return out
}

func (h *manualHost) exists(rel string) bool {
	_, err := os.Lstat(filepath.Join(h.root, rel))
	return err == nil
}

func wants(t *testing.T, what, out string, in, notIn []string) {
	t.Helper()
	for _, w := range in {
		if !strings.Contains(out, w) {
			t.Errorf("%s did not run %q:\n%s", what, w, out)
		}
	}
	for _, w := range notIn {
		if strings.Contains(out, w) {
			t.Errorf("%s ran %q:\n%s", what, w, out)
		}
	}
}

func TestAManualInstallUpgradesAndRemovesCleanly(t *testing.T) {
	linuxPackagesOnly(t)
	h := newManualHost(t)

	out := h.must("install", h.stage("usr/share/doc/juist/old", "usr/share/man/man1/juist.1.gz"))
	wants(t, "a first install", out, []string{
		"systemd-sysusers " + h.root + "/usr/lib/sysusers.d/juist.conf",
		"chown juist:juist " + h.root + "/var/lib/juist",
		"firewall.sh reload", "firewall.sh allow",
		"systemctl enable --now --quiet juistd.service", "systemctl enable --now --quiet juist-serve.path",
		"hint: sudo /usr/lib/juist/manual-install.sh uninstall",
	}, []string{"try-restart"})
	if fi, err := os.Stat(filepath.Join(h.root, "usr/bin/juistd")); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("juistd installed as %v, %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(h.root, "var/lib/juist")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("/var/lib/juist made as %v, %v", fi, err)
	}

	out = h.must("install", h.stage("usr/share/man/man1/juist.1.gz"))
	wants(t, "an upgrade", out, []string{
		"instances.sh move", "systemctl try-restart juistd.service juist-ingress.service juist-serve.service juistd@juist1.service",
		"firewall.sh reload",
	}, []string{"firewall.sh allow", "enable", "hint:"})
	if h.exists("usr/share/doc/juist/old") {
		t.Error("an upgrade left a file the new build does not install")
	}

	h.write(filepath.Join(h.root, "var/lib/juist/node.keys"), "", 0o600)
	h.write(filepath.Join(h.root, "var/lib/juist-serve/account"), "", 0o600)
	if err := os.MkdirAll(filepath.Join(h.root, "var/lib/juist3"), 0o700); err != nil {
		t.Fatal(err)
	}
	out = h.must("uninstall")
	wants(t, "a removal", out, []string{
		"systemctl disable --now --quiet juistd.service", "firewall.sh revoke", "ingress.sh off", "serve.sh off",
		"relay.sh off", "exit-node.sh off", "exit-node.sh clear", "systemctl daemon-reload",
		"kept /var/lib/juist, which still holds this device's keys", "kept /var/lib/juist-serve",
	}, []string{"kept /var/lib/juist3"})

	var left []string
	filepath.WalkDir(h.root, func(p string, d os.DirEntry, err error) error {
		if err == nil {
			left = append(left, cmp.Or(strings.TrimPrefix(p, h.root), "/"))
		}
		return nil
	})
	want := []string{"/", "/usr", "/usr/share", "/usr/share/hosts-own", "/var", "/var/lib",
		"/var/lib/juist", "/var/lib/juist/node.keys", "/var/lib/juist-serve", "/var/lib/juist-serve/account"}
	if !slices.Equal(left, want) {
		t.Errorf("a removal left\n%v\nwant\n%v", left, want)
	}

	// A reinstall after a removal is a first install.
	out = h.must("install", h.stage())
	wants(t, "a reinstall", out, []string{"firewall.sh allow", "enable --now --quiet juistd.service"}, nil)
}

// A juist installed otherwise, by hand or by a package, is not overwritten.
func TestAManualInstallLeavesAnotherJuistBe(t *testing.T) {
	linuxPackagesOnly(t)
	h := newManualHost(t)
	h.write(filepath.Join(h.root, "usr/bin/juistd"), "theirs", 0o755)
	out, err := h.run("install", h.stage())
	if err == nil || !strings.Contains(out, "juist: /usr/bin/juistd is not from make install") {
		t.Fatalf("installed over another juistd: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(filepath.Join(h.root, "usr/bin/juistd")); string(b) != "theirs" {
		t.Error("another juistd was overwritten")
	}
	if out, err := h.run("uninstall"); err == nil || !strings.Contains(out, "juist: juist was not installed by make install") {
		t.Errorf("removed a juist it did not install: %v\n%s", err, out)
	}
	if !h.exists("usr/bin/juistd") {
		t.Error("another juistd was removed")
	}
}
