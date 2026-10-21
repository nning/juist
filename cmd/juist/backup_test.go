package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	breakGlassLineRE = regexp.MustCompile(`juist-break-glass-1\.\S+`)
	adminKeyLineRE   = regexp.MustCompile(`juist-admin-key-1\.\S+`)
)

// adminKeyHere is the one admin key file in c's keystore, by name.
func adminKeyHere(t *testing.T, c *cli) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(c.home, adminsDir, "*.key"))
	if err != nil || len(files) != 1 {
		t.Fatalf("admin keys here: %v, %v", files, err)
	}
	return strings.TrimSuffix(filepath.Base(files[0]), ".key")
}

// breakGlassOf is the break-glass line juist create showed in out.
func breakGlassOf(t *testing.T, out string) string {
	t.Helper()
	line := breakGlassLineRE.FindString(out)
	if line == "" {
		t.Fatalf("no break-glass line:\n%s", out)
	}
	return line
}

// createDaemonDevice founds home on a device with a juistd, returning the
// device and the break-glass line juist create showed.
func createDaemonDevice(t *testing.T) (*daemonDevice, string) {
	t.Helper()
	laptop := newDaemonDevice(t, nil)
	return laptop, breakGlassOf(t, laptop.mustRun("create", "home", "--device", "laptop"))
}

// writeOldBreakGlass writes the break-glass file juist create wrote into the
// keystore before it showed the secret instead, holding line's secret.
func writeOldBreakGlass(t *testing.T, c *cli, name, line string) {
	t.Helper()
	payload, err := parseBackupLine(line, breakGlassLine)
	if err != nil {
		t.Fatal(err)
	}
	text := "# juist break-glass secrets for network home\n" + b64.EncodeToString(payload) + "\n"
	if err := os.WriteFile(filepath.Join(c.home, name), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// juist create shows the network's one break-glass secret and writes it
// nowhere: not into the keystore, and not into juistd's state directory.
func TestCreateShowsTheBreakGlassSecretAndKeepsItNowhere(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	out := c.mustRun("create", "home")
	line := breakGlassOf(t, out)
	mustContain(t, out, "Break-glass   "+line, "shown only now and kept nowhere",
		"juist network disable ends the network once too few admin keys are left")
	payload, err := parseBackupLine(line, breakGlassLine)
	if err != nil {
		t.Fatal(err)
	}
	state := openLog(t, c).State()
	if len(state.Disablement()) != 1 || !state.ValidDisablement(payload) {
		t.Fatalf("the network commits to %d secrets, and not to the one shown", len(state.Disablement()))
	}
	mustHoldNoSecret(t, c.home, line, payload)

	laptop := newDaemonDevice(t, nil)
	line = breakGlassOf(t, laptop.mustRun("create", "home", "--device", "laptop"))
	if payload, err = parseBackupLine(line, breakGlassLine); err != nil {
		t.Fatal(err)
	}
	mustHoldNoSecret(t, laptop.home, line, payload)
	mustHoldNoSecret(t, laptop.state, line, payload)
}

// mustHoldNoSecret fails where a file under dir holds the secret, as a line
// or as juist create wrote it into a file before.
func mustHoldNoSecret(t *testing.T, dir, line string, secret []byte) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err == nil && (strings.Contains(string(b), b64.EncodeToString(secret)) || strings.Contains(string(b), line)) {
			t.Errorf("%s holds the break-glass secret", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A genesis that waits for other admins' signatures shows the secret it
// commits to, since nothing else will.
func TestACeremonyShowsTheBreakGlassSecret(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	_, bob := adminKeyOf(t, "bob")
	out := c.mustRun("create", "home", "--admin", "bob="+bob, "--quorum", "2")
	mustContain(t, out, "prepared", "shown only now")
	line := breakGlassOf(t, out)
	payload, err := parseBackupLine(line, breakGlassLine)
	if err != nil {
		t.Fatal(err)
	}
	mustHoldNoSecret(t, c.home, line, payload)
	mustHoldNoSecret(t, workDir(t), line, payload)
}

// Once the genesis is handed over the network may exist, whatever the
// founder hears back, so its secret is shown on a failure too.
func TestAFailedCreateShowsTheSecretItHandedOver(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	c := newCLI(t)
	log := filepath.Join(c.home, logDir, "records")
	if err := os.MkdirAll(log, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(log, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(log, 0o700) })
	out, err := c.run("create", "home", "--no-device")
	if err == nil {
		t.Fatal("created a network in a log it cannot write")
	}
	breakGlassOf(t, out)
	mustContain(t, out, "shown only now")
}

func TestDisableEndsTheNetwork(t *testing.T) {
	t.Parallel()
	laptop, line := createDaemonDevice(t)
	if _, err := laptop.run("network", "disable"); err == nil || !strings.Contains(err.Error(), "no line on stdin") {
		t.Fatalf("disabling with no secret: %v", err)
	}
	if _, err := laptop.answer(line, "network", "disable"); err == nil {
		t.Fatal("disabled on no answer")
	}
	if out, err := laptop.answer(line+"\nn", "network", "disable"); err == nil {
		t.Fatalf("disabled on a no:\n%s", out)
	}
	mustContain(t, laptop.mustRun("status"), "connected")

	out, err := laptop.answer(line+"\ny", "network", "disable")
	if err != nil {
		t.Fatalf("disable: %v\n%s", err, out)
	}
	mustContain(t, out, `end "home" for good?`, `disabled "home"`)
	mustContain(t, laptop.mustRun("status"), "disabled", "hint: 1 warning: juist health")
	mustContain(t, laptop.mustRun("health"), "ended with a break-glass secret", "juist reset")
	if _, err := laptop.run("network", "rename", "work"); err == nil || !strings.Contains(err.Error(), "is disabled") {
		t.Fatalf("a change to a disabled network: %v", err)
	}
	if _, err := laptop.answer(line, "network", "disable", "--yes"); err == nil ||
		!strings.Contains(err.Error(), "disabled already") {
		t.Fatalf("disabling twice: %v", err)
	}
	mustContain(t, laptop.mustRun("log"), "ended with a break-glass secret, in record")
	// The device it lists is out of the network all the same.
	mustContain(t, laptop.mustRun("reset", "--yes"), "reset")
}

func TestDisableRefusesALineCutShort(t *testing.T) {
	t.Parallel()
	laptop, line := createDaemonDevice(t)
	if _, err := laptop.answer(line[:len(line)-3], "network", "disable", "--yes"); err == nil ||
		!strings.Contains(err.Error(), "cut short") {
		t.Fatalf("a line cut short: %v", err)
	}
	mustContain(t, laptop.mustRun("status"), "connected")
}

func TestDisableReadsStdinForADash(t *testing.T) {
	t.Parallel()
	laptop, line := createDaemonDevice(t)
	writeOldBreakGlass(t, laptop.cli, breakGlassFile("home"), breakGlassOf(t, newCLI(t).mustRun("create", "home")))
	// The keystore's file is another network's here: - reads stdin all the same.
	mustContain(t, must(laptop.answer(line, "network", "disable", "--secrets", "-", "--yes")), `disabled "home"`)
}

// The line kept in a file is read from it, as is a file of one secret to a
// line.
func TestDisableReadsAFile(t *testing.T) {
	t.Parallel()
	laptop, line := createDaemonDevice(t)
	file := filepath.Join(t.TempDir(), "kept")
	if err := os.WriteFile(file, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustContain(t, laptop.mustRun("network", "disable", "--secrets", file, "--yes"), `disabled "home"`)
}

func TestDisableReadsAnOlderNetworksFile(t *testing.T) {
	t.Parallel()
	laptop, line := createDaemonDevice(t)
	writeOldBreakGlass(t, laptop.cli, breakGlassFile("home"), line)
	// Renamed since, the file keeps the name it was written under.
	laptop.mustRun("network", "rename", "work")
	mustContain(t, laptop.mustRun("network", "disable", "--yes"), `disabled "work"`)
}

// A damaged file of the network's name is said to be damaged, not missing.
func TestDisableNamesADamagedFile(t *testing.T) {
	t.Parallel()
	laptop, line := createDaemonDevice(t)
	writeOldBreakGlass(t, laptop.cli, breakGlassFile("home"), line)
	f, err := os.OpenFile(filepath.Join(laptop.home, breakGlassFile("home")), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("not a secret\n")
	f.Close()
	if _, err := laptop.run("network", "disable", "--yes"); err == nil || !strings.Contains(err.Error(), "is not a break-glass secret") {
		t.Fatalf("a damaged file: %v", err)
	}
}

// The keystore is a directory, not a pattern.
func TestAnOlderFileInAKeystoreWithBrackets(t *testing.T) {
	t.Parallel()
	laptop := newDaemonDevice(t, nil)
	laptop.home = filepath.Join(t.TempDir(), "a[b]")
	line := breakGlassOf(t, laptop.mustRun("create", "home", "--device", "laptop"))
	writeOldBreakGlass(t, laptop.cli, breakGlassFile("home"), line)
	mustContain(t, laptop.mustRun("network", "disable", "--yes"), `disabled "home"`)
}

func TestDisableNeedsThisNetworksSecret(t *testing.T) {
	t.Parallel()
	laptop, _ := createDaemonDevice(t)
	theirs := breakGlassOf(t, newCLI(t).mustRun("create", "home"))
	if _, err := laptop.answer(theirs, "network", "disable", "--yes"); err == nil ||
		!strings.Contains(err.Error(), `no break-glass secret of "home"`) {
		t.Fatalf("another network's secret: %v", err)
	}
	mustContain(t, laptop.mustRun("status"), "connected")
}

// A record has to reach the network, so it is handed to a juistd.
func TestDisableNeedsAJuistd(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	line := breakGlassOf(t, c.mustRun("create", "home"))
	if _, err := c.answer(line, "network", "disable", "--yes"); err == nil || !strings.Contains(err.Error(), "no juistd") {
		t.Fatalf("disabling with no juistd: %v", err)
	}
}

func TestAdminKeyExportAndImport(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home")
	name := adminKeyHere(t, c)
	out := c.mustRun("admins", "export", name)
	line := adminKeyLineRE.FindString(out)
	if line == "" || strings.TrimSpace(out) != line {
		t.Fatalf("export printed more than the line:\n%s", out)
	}
	if _, err := c.answer(line, "admins", "import", name); err == nil || !strings.Contains(err.Error(), "here already") {
		t.Fatalf("importing over a key: %v", err)
	}
	if _, err := c.answer(line, "admins", "import", "copy@home"); err == nil ||
		!strings.Contains(err.Error(), "here already, as") {
		t.Fatalf("importing a key held under another name: %v", err)
	}
	key := filepath.Join(c.home, adminsDir, name+".key")
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if _, err := c.answer(strings.Replace(line, ".", ".A", 1), "admins", "import", name); err == nil ||
		!strings.Contains(err.Error(), "damaged") {
		t.Fatalf("a damaged line: %v", err)
	}
	mustContain(t, must(c.answer(line, "admins", "import", name)), "imported admin key", "casts 1 vote in \"home\"")
	if info, err := os.Stat(key); err != nil || info.Mode().Perm() != keyFileMode {
		t.Fatalf("imported key file: %v, %v", info, err)
	}
	// Signing works with the key as imported.
	mustContain(t, c.mustRun("admins", "quorum", "1", "--yes"), "quorum")
}

func TestImportSaysAKeyHasNoVote(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home")
	other := newCLI(t)
	other.mustRun("create", "work")
	line := adminKeyLineRE.FindString(other.mustRun("admins", "export", adminKeyHere(t, other)))
	mustContain(t, must(c.answer(line, "admins", "import", "work-key")), "imported admin key", `"home" gives it no vote`)
}

func TestImportRefusesTheOtherKindOfLine(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	glass := breakGlassOf(t, c.mustRun("create", "home"))
	if _, err := c.answer(glass, "admins", "import", "x"); err == nil ||
		!strings.Contains(err.Error(), "a break-glass secret\nhint: juist network disable") {
		t.Fatalf("a break-glass line as an admin key: %v", err)
	}
	if _, err := c.run("admins", "import", "x"); err == nil || !strings.Contains(err.Error(), "no line") {
		t.Fatalf("nothing on stdin: %v", err)
	}
}

func must(out string, err error) string {
	if err != nil {
		panic(err)
	}
	return out
}

// A change file made before the network ended is not applied after.
func TestApproveRefusesADisabledNetwork(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	laptop, line := createDaemonDevice(t)
	bobs, bob := adminKeyOf(t, "bob")
	laptop.mustRun("admins", "add", "bob", bob)
	laptop.mustRun("admins", "quorum", "2", "--yes")
	mustContain(t, laptop.mustRun("rotate", "group-secret"), "needs 1 more vote")
	must(laptop.answer(line, "network", "disable", "--yes"))
	change := filepath.Join(dir, "rotate-group-secret.rec")
	// Signed where no log says the network ended, it is applied nowhere.
	bobs.mustRun("approve", "--yes", change)
	if _, err := laptop.run("approve", change); err == nil || !strings.Contains(err.Error(), "is disabled") {
		t.Fatalf("applying to a disabled network: %v", err)
	}
}

// A key imported under its holder's name alone is filed under the network
// that gives it a vote, and named so.
func TestImportFilesAKeyUnderItsNetwork(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home")
	name := adminKeyHere(t, c)
	line := adminKeyLineRE.FindString(c.mustRun("admins", "export", name))
	if err := os.Remove(filepath.Join(c.home, adminsDir, name+".key")); err != nil {
		t.Fatal(err)
	}
	person, _, _ := strings.Cut(name, "@")
	mustContain(t, must(c.answer(line, "admins", "import", person)), fmt.Sprintf("imported admin key %q", name))
	if adminKeyHere(t, c) != name {
		t.Fatalf("filed as %q, want %q", adminKeyHere(t, c), name)
	}
}

// A change proposed after the end is not signed, so no file waits for votes.
func TestNoChangeIsSignedForADisabledNetwork(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	laptop, line := createDaemonDevice(t)
	_, bob := adminKeyOf(t, "bob")
	laptop.mustRun("admins", "add", "bob", bob)
	laptop.mustRun("admins", "quorum", "2", "--yes")
	must(laptop.answer(line, "network", "disable", "--yes"))
	if _, err := laptop.run("rotate", "group-secret"); err == nil || !strings.Contains(err.Error(), "is disabled") {
		t.Fatalf("a change to a disabled network: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "rotate-group-secret.rec")); !os.IsNotExist(err) {
		t.Fatalf("a change file was written: %v", err)
	}
}

func TestAnInterruptedPasteIsAborted(t *testing.T) {
	t.Parallel()
	r, w := io.Pipe()
	defer w.Close()
	a := newApp(r, io.Discard, io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	a.ctx = ctx
	cancel()
	if _, err := a.readBackupLine(); !errors.Is(err, errAborted) {
		t.Fatalf("an interrupted read: %v", err)
	}
}
