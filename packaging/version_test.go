package packaging

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// version.sh gives each package format the version Go stamps into the
// binaries: the tag on its commit, a pre-release of the next patch after it,
// 0 before any tag, marked where the tree has changes; and every format sorts
// them in the order they were built.
func TestVersionScriptFollowsGosStamp(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go on PATH")
	}
	script, err := filepath.Abs("version.sh")
	if err != nil {
		t.Fatal(err)
	}
	repo, bin := t.TempDir(), filepath.Join(t.TempDir(), "v")
	date := "2026-10-24T07:51:57Z"
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.org"}, args...)...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GIT_COMMITTER_DATE="+date, "GIT_AUTHOR_DATE="+date)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	version := func(format, dirty string) string {
		t.Helper()
		out, err := exec.Command("/bin/sh", "-c", `cd "$1" && sh "$2" "$3" "$4"`, "sh", repo, script, format, dirty).CombinedOutput()
		if err != nil {
			t.Fatalf("version.sh %s: %v\n%s", format, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	stamped := func() string {
		t.Helper()
		cmd := exec.Command(gobin, "build", "-trimpath", "-buildvcs=true", "-o", bin, ".")
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GOFLAGS=", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build: %v\n%s", err, out)
		}
		out, err := exec.Command(bin).Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(repo, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.org/v\n\ngo 1.24\n")
	write("main.go", "package main\n\nimport (\n\t\"fmt\"\n\t\"runtime/debug\"\n)\n\n"+
		"func main() {\n\tbi, _ := debug.ReadBuildInfo()\n\tfmt.Println(bi.Main.Version)\n}\n")
	git("init", "-q")
	git("add", ".")
	git("commit", "-q", "-m", "first")
	git("tag", "public/M21")

	type want struct{ goV, rpmV, rpmR, deb, freebsd string }
	formats := func() want {
		return want{version("go", ""), version("rpm-version", ""), version("rpm-release", ""), version("deb", ""), version("freebsd", "")}
	}
	var built []want
	check := func(name string, w want) {
		t.Helper()
		if got := stamped(); got != w.goV {
			t.Errorf("%s: go stamps %s, want %s", name, got, w.goV)
		}
		if got := formats(); got != w {
			t.Errorf("%s: version.sh gives %+v, want %+v", name, got, w)
		}
		built = append(built, w)
	}
	h := func() string { return git("rev-parse", "--short=12", "HEAD") }
	s := func() string { return git("rev-parse", "--short", "HEAD") }

	check("before a tag", want{"v0.0.0-20261024075157-" + h(), "0", "0.20261024075157git" + s(),
		"0~20261024075157git" + s(), "0.pre20261024075157,1"})
	git("tag", "v0.22.0")
	check("the tag", want{"v0.22.0", "0.22.0", "1", "0.22.0", "0.22.0,1"})
	date = "2026-10-25T08:00:00Z"
	git("commit", "-q", "--allow-empty", "-m", "second")
	check("after it", want{"v0.22.1-0.20261025080000-" + h(), "0.22.1", "0.20261025080000git" + s(),
		"0.22.1~20261025080000git" + s(), "0.22.1.pre20261025080000,1"})
	git("tag", "v0.22.1")
	check("a patch release", want{"v0.22.1", "0.22.1", "1", "0.22.1", "0.22.1,1"})

	write("changed", "")
	if got, want := stamped(), "v0.22.1+dirty"; got != want {
		t.Errorf("with changes: go stamps %s, want %s", got, want)
	}
	for format, want := range map[string]string{"go": "v0.22.1+dirty", "android": "0.22.1+dirty", "rpm-release": "1.dirty20261025090000",
		"deb": "0.22.1+dirty20261025090000", "freebsd": "0.22.1.20261025090000,1", "image": "0.22.1.20261025090000"} {
		if got := version(format, "20261025090000"); got != want {
			t.Errorf("with changes: version.sh %s gives %s, want %s", format, got, want)
		}
	}

	if _, err := exec.LookPath("dpkg"); err != nil {
		return
	}
	prev := "0~20261023120000git345a55f" // as builds before version.sh were
	for _, w := range built {
		if w.deb == prev {
			continue
		}
		if err := exec.Command("dpkg", "--compare-versions", w.deb, "gt", prev).Run(); err != nil {
			t.Errorf("dpkg sorts %s at or below %s, built before it", w.deb, prev)
		}
		prev = w.deb
	}
}

// follow-main's build takes the release tags pushed since its clone, from
// which the package it builds takes its version.
func TestFollowMainBuildFetchesReleaseTags(t *testing.T) {
	script, err := filepath.Abs("follow-main/build")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	origin, home, bin := filepath.Join(dir, "origin"), filepath.Join(dir, "home"), filepath.Join(dir, "bin")
	for _, d := range []string{origin, home, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.org"}, args...)...)
		cmd.Dir = origin
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	// make writes a package named for the release tags it sees.
	fake := "#!/bin/sh\nmkdir -p build/deb build/freebsd\nv=$(git tag -l 'v*' | tr '\\n' _)\n" +
		"touch build/deb/juist_$v.deb build/freebsd/juist-$v.pkg\n"
	for name, body := range map[string]string{"make": fake, "gmake": fake, "pkg": "#!/bin/sh\necho FreeBSD:15:amd64\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, "repo"), []byte(origin+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	build := func() string {
		t.Helper()
		cmd := exec.Command("/bin/sh", script)
		cmd.Env = append(os.Environ(), "HOME="+home, "PATH="+bin+":"+os.Getenv("PATH"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, out)
		}
		out, err := os.ReadDir(filepath.Join(home, "out"))
		if err != nil || len(out) != 1 {
			t.Fatalf("out: %v, %v", out, err)
		}
		return out[0].Name()
	}
	git("init", "-q", "-b", "main")
	git("commit", "-q", "--allow-empty", "-m", "first")
	if got := build(); strings.Contains(got, "v0.22.0") {
		t.Fatalf("built %s before the tag", got)
	}
	git("tag", "v0.22.0")
	if err := os.WriteFile(filepath.Join(origin, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-q", "-m", "second")
	if got := build(); !strings.Contains(got, "v0.22.0") {
		t.Errorf("built %s after v0.22.0 was pushed", got)
	}
}
