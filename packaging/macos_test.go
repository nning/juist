package packaging

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type macHost struct {
	t                *testing.T
	root, bin, calls string
}

// newMacHost is a DESTDIR with stubs for what macos/setup.sh calls: dscl
// knows the users and groups named, and no _juist.
func newMacHost(t *testing.T) *macHost {
	t.Helper()
	dir := t.TempDir()
	h := &macHost{t: t, root: filepath.Join(dir, "root"), bin: filepath.Join(dir, "bin"), calls: filepath.Join(dir, "calls")}
	h.write(filepath.Join(h.bin, "dscl"), `#!/bin/sh
echo "dscl $*" >> `+h.calls+`
case "$2" in
-read) exit 1 ;;
-list) [ "$3" = /Users ] && { printf 'root 0\n_www 70\nother 300\n'; sed -n 's/^dscl \. -create \/Users\/\([^ ]*\) UniqueID \(.*\)$/\1 \2/p' `+h.calls+`.all 2>/dev/null; } || printf 'wheel 0\nstaff 20\n' ;;
esac
echo "dscl $*" >> `+h.calls+`.all
`, 0o755)
	h.write(filepath.Join(h.bin, "launchctl"), `#!/bin/sh
echo "launchctl $*" >> `+h.calls+`
[ "$1" = print-disabled ] && [ -f `+filepath.Join(dir, "disabled")+` ] && echo '	"io.nning.juist.juistd" => disabled'
[ "$1" = print ] && { grep -qx "$2" `+filepath.Join(dir, "loaded")+` 2>/dev/null && exit 0; exit 113; }
exit 0
`, 0o755)
	h.write(filepath.Join(h.bin, "chown"), "#!/bin/sh\necho \"chown $*\" >> "+h.calls+"\n", 0o755)
	h.write(filepath.Join(h.bin, "pfctl"), `#!/bin/sh
echo "pfctl $*" >> `+h.calls+`
[ "$*" = "-a com.apple/juist.utun100_in -s Tables" ] && printf 'juist_own\njuist_overlay\n'
[ "$*" = "-a com.apple -s Anchors" ] && printf '  com.apple/200.AirDrop\n  com.apple/juist.daemon_utun100\n  com.apple/juist.utun100_in\n  com.apple/juist.utun100_egress\n'
exit 0
`, 0o755)
	h.write(filepath.Join(h.bin, "scutil"), "#!/bin/sh\nsed 's/^/scutil /' >> "+h.calls+"\n", 0o755)
	return h
}

func (h *macHost) write(path, body string, mode os.FileMode) {
	h.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		h.t.Fatal(err)
	}
}

// kit is an unpacked release as make macos lays it out, its binaries stubs.
func (h *macHost) kit() string {
	h.t.Helper()
	k := h.t.TempDir()
	for _, f := range []string{"juist", "juistd"} {
		h.write(filepath.Join(k, f), "#!/bin/sh\n", 0o755)
	}
	for _, f := range []string{"setup.sh", "juistd-launch", "io.nning.juist.juistd.plist"} {
		b, err := os.ReadFile(filepath.Join("macos", f))
		if err != nil {
			h.t.Fatal(err)
		}
		h.write(filepath.Join(k, f), string(b), 0o644)
	}
	return k
}

func (h *macHost) run(args ...string) (string, error) {
	h.t.Helper()
	os.Remove(h.calls)
	cmd := exec.Command("/bin/sh", append([]string{"macos/setup.sh"}, args...)...)
	cmd.Env = []string{"PATH=" + h.bin + ":/usr/bin:/bin", "DESTDIR=" + h.root}
	out, err := cmd.CombinedOutput()
	calls, _ := os.ReadFile(h.calls)
	return string(out) + string(calls), err
}

func (h *macHost) must(args ...string) string {
	h.t.Helper()
	out, err := h.run(args...)
	if err != nil {
		h.t.Fatalf("setup.sh %v: %v\n%s", args, err, out)
	}
	return out
}

func (h *macHost) exists(path string) bool {
	_, err := os.Lstat(filepath.Join(h.root, path))
	return err == nil
}

// An install makes _juist with an ID no one has, lays the binaries and the
// LaunchDaemon down as root's and loads it; a removal takes all of it but
// the keys and their user, and its own resolver files alone.
func TestMacInstallAndRemoval(t *testing.T) {
	h := newMacHost(t)
	out := h.must("install", h.kit())
	for _, want := range []string{
		"dscl . -create /Users/_juist UniqueID 301",
		"dscl . -create /Groups/_juist PrimaryGroupID 301",
		"dscl . -create /Users/_juist UserShell /usr/bin/false",
		"chown root:wheel " + filepath.Join(h.root, "/Library/juist/juistd.new"),
		"launchctl bootstrap system /Library/LaunchDaemons/io.nning.juist.juistd.plist",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	for _, f := range []string{"/Library/juist/juist", "/Library/juist/juistd", "/Library/juist/juistd-launch", "/Library/juist/setup.sh"} {
		fi, err := os.Stat(filepath.Join(h.root, f))
		if err != nil || fi.Mode().Perm() != 0o755 {
			t.Errorf("%s: %v, %v", f, fi, err)
		}
	}
	if fi, err := os.Stat(filepath.Join(h.root, "/Library/LaunchDaemons/io.nning.juist.juistd.plist")); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("the plist: %v, %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(h.root, "var/log/juistd.log")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("juistd's log, before launchd opens it: %v, %v", fi, err)
	}
	// One launchd makes anew, as after it was deleted, is root's alone too.
	if b, err := os.ReadFile(filepath.Join(h.root, "Library/LaunchDaemons/io.nning.juist.juistd.plist")); err != nil ||
		!strings.Contains(string(b), "<key>Umask</key>\n\t<integer>63</integer>") {
		t.Errorf("the plist leaves launchd's umask: %v\n%s", err, b)
	}
	if l, err := os.Readlink(filepath.Join(h.root, "/usr/local/bin/juist")); err != nil || l != "/Library/juist/juist" {
		t.Errorf("/usr/local/bin/juist links to %q, %v", l, err)
	}
	// An upgrade is an install over it, which leaves a juistd stopped by
	// launchctl disable stopped.
	h.must("install", h.kit())
	h.write(filepath.Join(filepath.Dir(h.calls), "disabled"), "", 0o644)
	if out := h.must("install", h.kit()); strings.Contains(out, "launchctl bootstrap") || !strings.Contains(out, "juistd stays stopped") {
		t.Errorf("an update started a stopped juistd:\n%s", out)
	}
	os.Remove(filepath.Join(filepath.Dir(h.calls), "disabled"))

	h.write(filepath.Join(h.root, "etc/resolver/home.juist"), "# juistd utun100\nnameserver 100.64.0.1\n", 0o644)
	h.write(filepath.Join(h.root, "etc/resolver/corp.example"), "nameserver 10.0.0.53\n", 0o644)
	h.write(filepath.Join(h.root, "var/db/juist/node.keys"), "keys", 0o600)
	h.write(filepath.Join(h.root, "var/run/juistd.utun100.lock"), "", 0o600)
	h.write(filepath.Join(h.root, "var/run/juistd.pf"), "pf utun100_in\ntoken 4242\n", 0o600)
	out = h.must("remove")
	if !strings.Contains(out, "launchctl bootout system/io.nning.juist.juistd") || !strings.Contains(out, "juist: kept /var/db/juist") {
		t.Errorf("remove said:\n%s", out)
	}
	if strings.Contains(out, "-delete /Users/_juist") {
		t.Error("the user owning the kept keys was deleted")
	}
	for _, want := range []string{"pfctl -a com.apple/juist.utun100_in -F rules", "pfctl -a com.apple/juist.utun100_egress -F nat",
		"pfctl -a com.apple/juist.daemon_utun100 -F rules", "pfctl -a com.apple/juist.utun100_in -t juist_own -T kill",
		"pfctl -X 4242", "scutil remove State:/Network/Service/juist-utun100/DNS"} {
		if !strings.Contains(out, want) {
			t.Errorf("removal did not %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "AirDrop") {
		t.Error("removal touched another anchor")
	}
	for _, gone := range []string{"/Library/juist", "/Library/LaunchDaemons/io.nning.juist.juistd.plist", "/usr/local/bin/juist",
		"/etc/resolver/home.juist", "/var/run/juistd.utun100.lock", "/var/run/juistd.pf"} {
		if h.exists(gone) {
			t.Errorf("%s left after the removal", gone)
		}
	}
	for _, kept := range []string{"/etc/resolver/corp.example", "/var/db/juist/node.keys"} {
		if !h.exists(kept) {
			t.Errorf("%s removed", kept)
		}
	}
	out = h.must("remove", "--keys")
	if h.exists("/var/db/juist") || !strings.Contains(out, "dscl . -delete /Users/_juist") {
		t.Errorf("remove --keys left the keys or their user:\n%s", out)
	}
}

// A juist in /usr/local/bin that is not the install's link stops it before
// anything changes.
func TestMacInstallLeavesAnotherJuist(t *testing.T) {
	h := newMacHost(t)
	h.write(filepath.Join(h.root, "usr/local/bin/juist"), "#!/bin/sh\n", 0o755)
	out, err := h.run("install", h.kit())
	if err == nil || !strings.Contains(out, "/usr/local/bin/juist is not juist's") {
		t.Fatalf("install over another juist: %v\n%s", err, out)
	}
	if h.exists("/Library/juist") || strings.Contains(out, "dscl . -create") {
		t.Errorf("install changed the host before stopping:\n%s", out)
	}
}

// install.sh checks a Mac's release against the key packaging/release-signers
// names.
func TestInstallScriptCarriesTheReleaseSigner(t *testing.T) {
	signers, err := os.ReadFile("release-signers")
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	want := "signers='" + strings.TrimSpace(string(signers)) + "'"
	if !strings.Contains(string(script), want) {
		t.Errorf("install.sh's signers are not release-signers'")
	}
}

// On Apple silicon install.sh takes the arm64 release, also from a shell
// under Rosetta, whose uname says x86_64.
func TestInstallScriptTakesAppleSiliconsRelease(t *testing.T) {
	for _, tc := range []struct{ machine, arm64, want string }{
		{"arm64", "1", "juist-macos-arm64.tar.gz"},
		{"x86_64", "1", "juist-macos-arm64.tar.gz"},
		{"x86_64", "", "juist-macos-amd64.tar.gz"},
	} {
		bin := t.TempDir()
		for name, body := range map[string]string{
			"uname":  `[ "${1:-}" = -m ] && echo ` + tc.machine + ` || echo Darwin`,
			"sysctl": `[ -n "` + tc.arm64 + `" ] && echo ` + tc.arm64 + ` || exit 1`,
			"id":     "echo 0",
			"curl":   "exit 22",
		} {
			if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command("/bin/sh", "install.sh")
		cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "JUIST_RELEASE=https://example.org/r"}
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "cannot download https://example.org/r/"+tc.want) {
			t.Errorf("uname -m %s, hw.optional.arm64 %q: %s", tc.machine, tc.arm64, out)
		}
	}
}

// Another network's instance gets its own user and LaunchDaemon, started
// and, stopped, kept stopped; removal takes them too, the user with --keys.
func TestMacInstancesStartAndStop(t *testing.T) {
	h := newMacHost(t)
	h.must("install", h.kit())
	out := h.must("instance", "start", "juist2")
	for _, want := range []string{"dscl . -create /Users/_juist2 UniqueID 302", "launchctl enable system/io.nning.juist.juistd.juist2",
		"launchctl bootstrap system /Library/LaunchDaemons/io.nning.juist.juistd.juist2.plist"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	b, err := os.ReadFile(filepath.Join(h.root, "Library/LaunchDaemons/io.nning.juist.juistd.juist2.plist"))
	if err != nil || !strings.Contains(string(b), "<string>juist2</string>") || !strings.Contains(string(b), "/var/log/juistd.juist2.log") ||
		!strings.Contains(string(b), "<key>Umask</key>\n\t<integer>63</integer>") {
		t.Errorf("the instance's plist: %v\n%s", err, b)
	}
	if fi, err := os.Stat(filepath.Join(h.root, "var/log/juistd.juist2.log")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("the instance's log, before launchd opens it: %v, %v", fi, err)
	}
	if out, err := h.run("instance", "start", "juist0"); err == nil {
		t.Errorf("the default instance was started as another: %s", out)
	}
	out = h.must("instance", "stop", "juist2")
	if !strings.Contains(out, "launchctl disable system/io.nning.juist.juistd.juist2") || h.exists("/Library/LaunchDaemons/io.nning.juist.juistd.juist2.plist") {
		t.Errorf("stop left it to start again:\n%s", out)
	}
	h.must("instance", "start", "juist3")
	h.write(filepath.Join(h.root, "var/db/juist3/node.keys"), "keys", 0o600)
	out = h.must("remove", "--keys")
	if h.exists("/Library/LaunchDaemons/io.nning.juist.juistd.juist3.plist") || h.exists("/var/db/juist3") ||
		!strings.Contains(out, "dscl . -delete /Users/_juist3") {
		t.Errorf("removal left the instance:\n%s", out)
	}
}

// An update restarts the other networks' instances that run, on the new
// juistd, and leaves a stopped one stopped.
func TestMacUpdateRestartsTheInstances(t *testing.T) {
	h := newMacHost(t)
	h.must("install", h.kit())
	h.must("instance", "start", "juist2")
	h.must("instance", "start", "juist3")
	h.write(filepath.Join(filepath.Dir(h.calls), "loaded"), "system/io.nning.juist.juistd.juist2\n", 0o644)
	out := h.must("install", h.kit())
	if !strings.Contains(out, "launchctl kickstart -k system/io.nning.juist.juistd.juist2") {
		t.Errorf("the running instance kept the old juistd:\n%s", out)
	}
	if strings.Contains(out, "kickstart -k system/io.nning.juist.juistd.juist3") {
		t.Errorf("an instance not running was started:\n%s", out)
	}
}
