package main

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// writePolicy writes a policy file to the test's working directory.
func writePolicy(t *testing.T, name, src string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(workDir(t), name), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

// An admin sets a policy from a file and reads it back in the policy's own
// form, by the devices' names; the same file again changes nothing, and
// diff says how another one differs.
func TestAPolicyIsSetAndShown(t *testing.T) {
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "nas")
	mustContain(t, admin.mustRun("policy"), "no access policy: every device may open anything on every other")

	file := writePolicy(t, "policy.conf", "pass from laptop to nas proto tcp port { 445 22 }\ntest block from nas to laptop\n")
	out := admin.mustRun("policy", "set", "--yes", file)
	mustContain(t, out, "access policy set: 1 rule")
	want := "pass from laptop to nas proto tcp port { 22, 445 }\n\ntest block from nas to laptop\n"
	if got := admin.mustRun("policy"); got != want {
		t.Errorf("the policy reads\n%s\nwant\n%s", got, want)
	}
	mustContain(t, admin.mustRun("policy", "set", "--yes", file), "unchanged: access policy")
	if out, err := admin.run("policy", "diff", file); err != nil || out != "" {
		t.Errorf("diff of the policy set: %v\n%s", err, out)
	}

	other := writePolicy(t, "other.conf", "pass from { laptop, nas } to nas proto tcp port 22\n")
	out, err := admin.run("policy", "diff", other)
	if !errors.Is(err, errSilent) {
		t.Fatalf("diff of another policy: %v", err)
	}
	mustContain(t, out, "- pass from laptop to nas proto tcp port { 22, 445 }",
		"+ pass from { laptop, nas } to nas proto tcp port 22", "- test block from nas to laptop")
}

// A policy that does not read against the network, or fails its tests, is
// refused with the line or the test that says why, and nothing is set.
func TestABadPolicyIsRefused(t *testing.T) {
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	file := writePolicy(t, "bad.conf", "pass from laptop to laptop\n\npass from laptop to nobody\n")
	_, err := admin.run("policy", "set", "--yes", file)
	if err == nil || err.Error() != "bad.conf:3: no device \"nobody\" in \"home\"\nhint: juist log says whether it was renamed or removed" {
		t.Errorf("an unknown device: %v", err)
	}
	failing := writePolicy(t, "failing.conf", "pass from laptop to laptop proto tcp port 22\n"+
		"test pass from laptop to laptop proto tcp port 80\n")
	out, err := admin.run("policy", "check", failing)
	if err == nil || err.Error() != "failing.conf fails 1 test" {
		t.Errorf("a failing test: %v", err)
	}
	mustContain(t, out, "failing.conf:2: fails: test pass from laptop to laptop proto tcp port 80")
	if _, err := admin.run("policy", "set", "--yes", failing); err == nil {
		t.Error("a policy failing its test was set")
	}
	mustContain(t, admin.mustRun("policy"), "no access policy")
	warned := writePolicy(t, "warned.conf", "pass from laptop to internet via laptop\n")
	mustContain(t, admin.mustRun("policy", "check", warned), "warning: laptop is no exit node: juist grant laptop exit",
		"warned.conf: ok, no tests")
}

// Where a change needs another admin's vote, the policy goes as a change
// file, which shows the other admin what it changes.
func TestAPolicyWaitsForVotes(t *testing.T) {
	first, second := newCLI(t), newCLI(t)
	key := regexp.MustCompile(`juist admins add second (nid:\S+)`).
		FindStringSubmatch(second.mustRun("admins", "new", "second"))
	if key == nil {
		t.Fatal("admins new printed no key")
	}
	first.mustRun("create", "home", "--device", "laptop", "--quorum", "2", "--admin", "second="+key[1])
	genesis := filepath.Join(first.home, genesisFileFor("home"))
	second.mustRun("approve", "--yes", genesis)
	first.mustRun("apply", genesis)

	file := writePolicy(t, "policy.conf", "pass from laptop to laptop\n")
	mustContain(t, first.mustRun("policy", "set", "--yes", file), "needs 1 more vote", "juist approve policy.rec")
	pending := filepath.Join(workDir(t), "policy.rec")
	mustContain(t, second.mustRun("approve", "--yes", pending), "sets an access policy", "+ pass from nid:",
		"hint: devices show by key here; juist log verify")
	mustContain(t, first.mustRun("log", "verify", pending), "+ pass from laptop to laptop")
	mustContain(t, first.mustRun("apply", pending), "applied")
	if got := first.mustRun("policy"); got != "pass from laptop to laptop\n" {
		t.Errorf("the policy reads %q", got)
	}
	mustContain(t, first.mustRun("log"), "change of the access policy")
}

// fmt writes the policy's own form without a network, lists files not in it,
// failing, and rewrites them in place.
func TestPolicyFmtNeedsNoNetwork(t *testing.T) {
	c := newCLI(t)
	messy := "pass from { b a } to c proto tcp port 443 proto tcp port 80\n"
	want := "pass from { a, b } to c proto tcp port { 80, 443 }\n"
	out, err := c.answer(strings.TrimSuffix(messy, "\n"), "policy", "fmt")
	if err != nil || out != want {
		t.Fatalf("fmt of standard input: %v\n%q", err, out)
	}
	file := writePolicy(t, "p.conf", messy)
	out, err = c.run("policy", "fmt", "-l", file)
	if !errors.Is(err, errSilent) || out != "p.conf\n" {
		t.Fatalf("fmt -l: %v %q", err, out)
	}
	if out, err := c.run("policy", "fmt", "-w", file); err != nil || out != "" {
		t.Fatalf("fmt -w: %v %q", err, out)
	}
	if b, _ := os.ReadFile(filepath.Join(workDir(t), file)); string(b) != want {
		t.Errorf("rewritten as %q", b)
	}
	if out, err := c.run("policy", "fmt", "-l", file); err != nil || out != "" {
		t.Errorf("fmt -l of a file in form: %v %q", err, out)
	}
	_, err = c.run("policy", "fmt", writePolicy(t, "c.conf", "# note\n"))
	if err == nil || !strings.Contains(err.Error(), "c.conf:1: a policy has no comments") {
		t.Errorf("a comment: %v", err)
	}
}

// edit hands the operator the policy in its own form, and sets what they
// leave, asking again where it does not read.
func TestAPolicyIsEdited(t *testing.T) {
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	edits := []string{"pass from laptop to nobody\n", "pass from laptop to laptop proto icmp\n"}
	var seen []string
	admin.editor = func(path string) error {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		seen = append(seen, string(b))
		next := edits[0]
		edits = edits[1:]
		return os.WriteFile(path, []byte(next), 0o600)
	}
	out, err := admin.answer("y\ny", "policy", "edit")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, `no device "nobody"`, "access policy set: 1 rule")
	if len(seen) != 2 || seen[0] != "" || seen[1] != "pass from laptop to nobody\n" {
		t.Errorf("the editor was handed %q", seen)
	}
	admin.editor = func(path string) error { return nil }
	mustContain(t, admin.mustRun("policy", "edit"), "unchanged: access policy")
}

// A device lists itself and its peers alone, and says how many more the
// policy keeps apart from it.
func TestADeviceListsItsPeersAlone(t *testing.T) {
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "nas")
	enrollDevice(t, admin, "phone")
	admin.mustRun("grant", "nas", "relay")
	mustContain(t, admin.mustRun("devices"), "phone")
	admin.mustRun("policy", "set", "--yes", writePolicy(t, "p.conf", "pass from laptop to nas\n"))
	out := admin.mustRun("devices")
	mustContain(t, out, "laptop (this device)", "nas", "hint: 1 more device the access policy keeps apart from this one: juist devices --all")
	mustContain(t, admin.mustRun("devices", "--all"), "phone")
	if strings.Contains(out, "phone") {
		t.Errorf("a device the policy keeps apart is listed:\n%s", out)
	}
}

// Inviting under a policy says the new device is passed nothing yet.
func TestAnInviteUnderAPolicySaysSo(t *testing.T) {
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	admin.mustRun("policy", "set", "--yes", writePolicy(t, "p.conf", "pass from laptop to laptop\n"))
	inv, link := startInvite(t, admin)
	newCLI(t).mustRun("join", link, "--name", "phone")
	out, err := inv.wait(t)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out, "hint: the access policy passes phone nothing until it names it: juist policy edit")
	if strings.Index(out, "admitted phone") > strings.Index(out, "hint: the access policy") {
		t.Errorf("the hint comes before the outcome:\n%s", out)
	}
}

// off withdraws the policy, once asked; an empty file sets none.
func TestAPolicyIsWithdrawn(t *testing.T) {
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	mustContain(t, admin.mustRun("policy", "off"), "unchanged: no access policy")
	admin.mustRun("policy", "set", "--yes", writePolicy(t, "p.conf", "pass from laptop to laptop\n"))
	_, err := admin.run("policy", "set", "--yes", writePolicy(t, "empty.conf", "\n"))
	if err == nil || !strings.Contains(err.Error(), "empty.conf holds no policy") {
		t.Errorf("an empty file: %v", err)
	}
	if _, err := admin.run("policy", "off"); err == nil {
		t.Error("withdrawn without being asked")
	}
	mustContain(t, admin.mustRun("policy", "off", "--yes"), "access policy withdrawn")
	mustContain(t, admin.mustRun("policy"), "no access policy")
}

// A policy that removals left passing nothing prints as text that reads back,
// and says so on standard error alone.
func TestAnEmptiedPolicyPrintsAsText(t *testing.T) {
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "nas")
	admin.mustRun("policy", "set", "--yes", writePolicy(t, "p.conf", "table <x> { nas }\npass from nas to nas\n"))
	admin.mustRun("remove", "nas", "--yes")
	var out, errOut syncBuffer
	a := admin.app(&out, "")
	a.errOut = &errOut
	if err := a.main([]string{"--home", admin.home, "policy"}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "table <x> { }\n" || !strings.Contains(errOut.String(), "warning: the access policy passes nothing") {
		t.Errorf("printed %q, said %q", out.String(), errOut.String())
	}
}

// Under a policy passing every device something, an invite says nothing of
// it.
func TestAnInviteUnderAnOpenPolicySaysNothing(t *testing.T) {
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	admin.mustRun("policy", "set", "--yes", writePolicy(t, "p.conf", "pass from any to laptop\n"))
	inv, link := startInvite(t, admin)
	newCLI(t).mustRun("join", link, "--name", "phone")
	out, err := inv.wait(t)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "passes phone nothing") {
		t.Errorf("an invite under pass from any says the device is passed nothing:\n%s", out)
	}
}

// fmt -l lists what reads and is not in form past a file that does not
// read, failing; -w and -l together, or -w of standard input, are refused.
func TestPolicyFmtFlags(t *testing.T) {
	c := newCLI(t)
	bad, messy := writePolicy(t, "bad.conf", "# x\n"), writePolicy(t, "messy.conf", "pass from b to a\npass from { b a } to a\n")
	out, err := c.run("policy", "fmt", "-l", bad, messy)
	if !errors.Is(err, errSilent) || !strings.Contains(out, "bad.conf:1:") || !strings.Contains(out, "messy.conf\n") {
		t.Errorf("fmt -l past a bad file: %v\n%s", err, out)
	}
	for _, args := range [][]string{{"-w", "-l", messy}, {"-w", "-"}} {
		if _, err := c.run(append([]string{"policy", "fmt"}, args...)...); err == nil || errors.Is(err, errSilent) {
			t.Errorf("fmt %v: %v", args, err)
		}
	}
}

// test says which rule passes a connection, or that none does and what the
// device may open there instead.
func TestAPolicyIsAsked(t *testing.T) {
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "nas")
	mustContain(t, admin.mustRun("policy", "test", "from", "laptop", "to", "nas"), "passes: the network has no access policy")
	admin.mustRun("policy", "set", "--yes", writePolicy(t, "p.conf", "pass from laptop to nas proto tcp port { 22, 445 }\n"))
	mustContain(t, admin.mustRun("policy", "test", "from", "laptop", "to", "nas", "proto", "tcp", "port", "445"),
		"passes: pass from laptop to nas proto tcp port { 22, 445 }")
	out, err := admin.run("policy", "test", "from", "laptop", "to", "nas", "proto", "tcp", "port", "80")
	if !errors.Is(err, errSilent) {
		t.Fatalf("a refused connection: %v", err)
	}
	mustContain(t, out, "refused: no rule passes it", "hint: laptop may open on nas: proto tcp port { 22, 445 }")
	if _, err := admin.run("policy", "test", "from", "laptop", "to", "internet"); err == nil ||
		!strings.Contains(err.Error(), "internet via DEVICE") {
		t.Errorf("a test of the internet without its exit node: %v", err)
	}
}

// Removing a device the policy names says what the policy loses with it, and
// a file naming it then says where to look.
func TestRemovingADeviceSaysWhatThePolicyLoses(t *testing.T) {
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "phone")
	file := writePolicy(t, "p.conf", "pass from phone to laptop\npass from laptop to laptop\ntest pass from phone to laptop proto tcp port 22\n")
	admin.mustRun("policy", "set", "--yes", file)
	mustContain(t, admin.mustRun("remove", "phone", "--yes"),
		"removed phone; the access policy names it no more, and loses 1 rule and 1 test")
	_, err := admin.run("policy", "diff", file)
	if err == nil || !strings.Contains(err.Error(), "hint: juist log says whether it was renamed or removed") {
		t.Errorf("diff of a file naming a removed device: %v", err)
	}
}

// The first policy is asked about, as it cuts what every device reaches;
// one replacing it is not.
func TestTheFirstPolicyIsAskedAbout(t *testing.T) {
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	first := writePolicy(t, "first.conf", "pass from laptop to laptop\n")
	if _, err := admin.run("policy", "set", first); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("a first policy set unasked: %v", err)
	}
	if out, err := admin.answer("n", "policy", "set", first); err == nil {
		t.Errorf("a first policy declined was set:\n%s", out)
	}
	mustContain(t, admin.mustRun("policy"), "no access policy")
	mustContain(t, func() string {
		out, err := admin.answer("y", "policy", "set", first)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}(), "anything the policy does not pass is then refused; set it? [y/N]", "access policy set: 1 rule")
	mustContain(t, admin.mustRun("policy", "set", writePolicy(t, "next.conf", "pass from laptop to laptop proto icmp\n")),
		"access policy set: 1 rule")
}
