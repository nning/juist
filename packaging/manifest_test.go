package packaging

import (
	"cmp"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// debOnly are the files the .deb installs and the RPM does not, each for a
// reason of Debian's; rpmNamed the RPM's names of files the .deb installs
// elsewhere.
var (
	debOnly = []string{
		"/etc/ufw/applications.d/juist",
		"/etc/dhcp/dhclient-enter-hooks.d/juist",
		"/etc/apparmor.d/abstractions/nameservice.d/juist",
		"/usr/lib/juist/juist.pkla",
		// The RPM's %doc and %license.
		"/usr/share/doc/juist/README.md",
		"/usr/share/doc/juist/copyright",
		"/usr/share/doc/juist/THIRD_PARTY_LICENSES",
	}
	rpmNamed = map[string]string{
		"/usr/share/zsh/site-functions/_juist": "/usr/share/zsh/vendor-completions/_juist",
	}
)

// The .deb and the RPM install the same files, but for those debOnly names,
// so that a file added to one package is not missing from the other.
func TestTheDebAndTheRPMInstallTheSameFiles(t *testing.T) {
	deb := debFiles(t)
	rpm := rpmFiles(t)
	if len(deb) < 30 || len(rpm) < 25 {
		t.Fatalf("read %d files of the .deb and %d of the RPM; the parsing no longer follows the Makefile or the spec",
			len(deb), len(rpm))
	}
	for _, f := range debOnly {
		if !deb[f] {
			t.Errorf("%s is listed as the .deb's alone, which it does not install", f)
		}
		delete(deb, f)
	}
	for f := range rpm {
		if !deb[cmp.Or(rpmNamed[f], f)] {
			t.Errorf("the RPM installs %s, which the .deb does not", f)
		}
		delete(deb, cmp.Or(rpmNamed[f], f))
	}
	for _, f := range slices.Sorted(maps.Keys(deb)) {
		t.Errorf("the .deb installs %s, which the RPM does not", f)
	}
}

var (
	debPath = regexp.MustCompile(`\$\$root(/[^\s;'"]+)`)
	forLoop = regexp.MustCompile(`for (\w+) in ([^;]+); do`)
	cmdsVar = regexp.MustCompile(`(?m)^CMDS\s+\?=\s+(.+)$`)
)

// debFiles is what `make deb` installs, as its recipe in the Makefile names
// it, man pages without their compression.
func debFiles(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile("../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	mk := string(b)
	cmds := cmdsVar.FindStringSubmatch(mk)
	if cmds == nil {
		t.Fatal("the Makefile sets no CMDS")
	}
	_, recipe, ok := strings.Cut(mk, "\ndeb: ")
	if !ok {
		t.Fatal("the Makefile has no deb target")
	}
	recipe, _, _ = strings.Cut(recipe, "\n\n")
	files := map[string]bool{}
	var loopVar string
	var loopOver []string
	for line := range strings.SplitSeq(recipe, "\n") {
		line = strings.ReplaceAll(line, "$(CMDS)", cmds[1])
		if m := forLoop.FindStringSubmatch(line); m != nil {
			loopVar, loopOver = m[1], strings.Fields(m[2])
		}
		if strings.Contains(line, "install -d ") || strings.Contains(line, "DEBIAN") {
			continue
		}
		for _, m := range debPath.FindAllStringSubmatch(line, -1) {
			p := m[1]
			paths := []string{p}
			if loopVar != "" && strings.Contains(p, "$$"+loopVar) {
				paths = nil
				for _, v := range loopOver {
					paths = append(paths, strings.ReplaceAll(p, "$$"+loopVar, v))
				}
			}
			for _, p := range paths {
				if !strings.Contains(p, "$") {
					files[strings.TrimSuffix(p, ".gz")] = true
				}
			}
		}
		if strings.Contains(line, "done;") {
			loopVar, loopOver = "", nil
		}
	}
	return files
}

// rpmFiles is what the spec's %files lists, its directories aside.
func rpmFiles(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile("rpm/juist.spec")
	if err != nil {
		t.Fatal(err)
	}
	_, list, ok := strings.Cut(string(b), "\n%files\n")
	if !ok {
		t.Fatal("the spec lists no files")
	}
	macros := strings.NewReplacer("%{_bindir}", "/usr/bin", "%{_unitdir}", "/usr/lib/systemd/system",
		"%{_sysusersdir}", "/usr/lib/sysusers.d", "%{_datadir}", "/usr/share", "%{_mandir}", "/usr/share/man",
		"%{_prefix}", "/usr", "%{name}", "juist")
	files := map[string]bool{}
	for line := range strings.SplitSeq(list, "\n") {
		if strings.HasPrefix(line, "%changelog") {
			break
		}
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") || slices.Contains(f, "%dir") ||
			f[0] == "%doc" || f[0] == "%license" {
			continue
		}
		files[strings.TrimSuffix(macros.Replace(f[len(f)-1]), "*")] = true
	}
	return files
}
