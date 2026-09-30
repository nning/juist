package packaging

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGo is a go that logs what it is asked, answers GOOS and GOARCH as
// the test says, builds binaries that write a page, stamped with the VCS
// where FAKE_VCS is set, and writes no package.
const fakeGo = `#!/bin/sh
echo "$*" >> "$FAKE_LOG"
case $1 in
env) [ "$2" = GOOS ] && echo "$FAKE_GOOS" || echo "$FAKE_GOARCH" ;;
build)
	while [ "$1" != -o ]; do shift; done
	mkdir -p "$(dirname "$2")"
	printf '#!/bin/sh\necho page\n' > "$2"; chmod +x "$2" ;;
run) echo page ;;
version) [ -n "$FAKE_VCS" ] && echo "	build	vcs=git" ;;
esac
`

// pkgBuild runs pkg.sh for FreeBSD:14:amd64 as if on goos/goarch, and says
// what it asked of go.
func pkgBuild(t *testing.T, goos, goarch string, env ...string) (log, builddir string) {
	t.Helper()
	dir := t.TempDir()
	goBin := filepath.Join(dir, "go")
	if err := os.WriteFile(goBin, []byte(fakeGo), 0o755); err != nil {
		t.Fatal(err)
	}
	builddir = filepath.Join(dir, "build")
	logFile := filepath.Join(dir, "log")
	cmd := exec.Command("sh", "packaging/freebsd/pkg.sh", goBin, filepath.Join(builddir, "freebsd", "juist.pkg"),
		"1.0", "FreeBSD:14:amd64", builddir)
	cmd.Dir = ".."
	cmd.Env = append(append(os.Environ(), "FAKE_LOG="+logFile, "FAKE_GOOS="+goos, "FAKE_GOARCH="+goarch), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pkg.sh: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(logFile)
	return string(b), builddir
}

// On FreeBSD the package takes the binaries "make build" leaves, which go
// finds up to date, and their own pages: nothing is built twice.
func TestTheFreeBSDPackageTakesWhatMakeBuildLeft(t *testing.T) {
	log, builddir := pkgBuild(t, "freebsd", "amd64")
	for _, c := range []string{"juist", "juistd"} {
		if !strings.Contains(log, "-o "+filepath.Join(builddir, c)+" ./cmd/"+c) {
			t.Errorf("%s is not built where make build leaves it:\n%s", c, log)
		}
	}
	if !strings.Contains(log, "/usr/local/sbin/juistd="+filepath.Join(builddir, "juistd")) {
		t.Errorf("the package does not take build/juistd:\n%s", log)
	}
	if strings.Contains(log, "freebsdman") {
		t.Errorf("the pages are built again:\n%s", log)
	}
}

// Elsewhere the FreeBSD binaries have a directory of their own, beside this
// system's, and the pages are rendered by the freebsdman tag.
func TestTheFreeBSDPackageBuildsElsewhereBeside(t *testing.T) {
	log, builddir := pkgBuild(t, "linux", "amd64")
	if !strings.Contains(log, "-o "+filepath.Join(builddir, "freebsd-amd64", "juistd")+" ./cmd/juistd") {
		t.Errorf("juistd is not built in freebsd-amd64:\n%s", log)
	}
	if !strings.Contains(log, "run -tags freebsdman ./cmd/juist __manpage") {
		t.Errorf("the pages are not FreeBSD's:\n%s", log)
	}
}

// Rendered elsewhere, the pages carry the version stamped into the binaries,
// as they do where the binaries write them, so that both builders agree.
func TestTheFreeBSDPagesCarryTheBinariesVersion(t *testing.T) {
	log, _ := pkgBuild(t, "linux", "amd64", "FAKE_VCS=1")
	if !strings.Contains(log, "run -buildvcs=true -tags freebsdman ./cmd/juistd __manpage") {
		t.Errorf("the pages are not stamped as the binaries are:\n%s", log)
	}
}
