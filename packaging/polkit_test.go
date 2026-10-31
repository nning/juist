package packaging

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The polkit rule lets the juist user route resolved's DNS on juist's own
// devices, and nothing else, and nobody else.
func TestThePolkitRuleAllowsJuistsDNSAlone(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node to run polkit's JavaScript with")
	}
	b, err := os.ReadFile(filepath.Join("polkit", "juist.rules"))
	if err != nil {
		t.Fatal(err)
	}
	harness := `
var rule;
var polkit = {Result: {YES: "yes", NO: "no", NOT_HANDLED: "not handled"}, addRule: function(f) { rule = f; }};
` + string(b) + `
var cases = JSON.parse(process.argv[process.argv.length - 1]);
var out = cases.map(function(c) {
	var action = {id: c.action, lookup: function(k) { return c.details[k]; }};
	return rule(action, {user: c.user});
});
console.log(JSON.stringify(out));
`
	type check struct {
		User    string            `json:"user"`
		Action  string            `json:"action"`
		Details map[string]string `json:"details"`
		want    string
	}
	checks := []check{
		{"juist", "org.freedesktop.resolve1.set-dns-servers", map[string]string{"interface": "juist0"}, "yes"},
		{"juist3", "org.freedesktop.resolve1.set-domains", map[string]string{"interface": "juist3"}, "yes"},
		{"juist9", "org.freedesktop.resolve1.revert", map[string]string{"interface": "juist9"}, "yes"},
		{"juist", "org.freedesktop.resolve1.set-domains", map[string]string{"interface": "juist3"}, "not handled"},
		{"juist3", "org.freedesktop.resolve1.set-dns-servers", map[string]string{"interface": "juist0"}, "not handled"},
		{"juist3", "org.freedesktop.resolve1.set-dns-servers", map[string]string{"interface": "juist4"}, "not handled"},
		{"juist0", "org.freedesktop.resolve1.set-dns-servers", map[string]string{"interface": "juist0"}, "not handled"},
		{"juist10", "org.freedesktop.resolve1.set-dns-servers", map[string]string{"interface": "juist1"}, "not handled"},
		{"juist", "org.freedesktop.resolve1.set-default-route", map[string]string{}, "yes"}, // before systemd 256
		{"juist", "org.freedesktop.resolve1.set-dnssec-negative-trust-anchors", map[string]string{"interface": "juist0"}, "yes"},
		{"juist", "org.freedesktop.resolve1.set-dnssec-negative-trust-anchors", map[string]string{"interface": "eth0"}, "not handled"},
		{"juist", "org.freedesktop.resolve1.set-dns-servers", map[string]string{"interface": "eth0"}, "not handled"},
		{"juist", "org.freedesktop.resolve1.set-dns-servers", map[string]string{"interface": "juist10"}, "not handled"},
		{"juist", "org.freedesktop.resolve1.set-dnssec", map[string]string{"interface": "juist0"}, "not handled"},
		{"juist", "org.freedesktop.systemd1.manage-units", map[string]string{}, "not handled"},
		{"mallory", "org.freedesktop.resolve1.set-dns-servers", map[string]string{"interface": "juist0"}, "not handled"},
	}
	in, err := json.Marshal(checks)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, "-e", harness, string(in)).CombinedOutput()
	if err != nil {
		t.Fatalf("running the rule: %v\n%s", err, out)
	}
	var got []string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for i, c := range checks {
		if got[i] != c.want {
			t.Errorf("%s asking %s on %v: %s, want %s", c.User, c.Action, c.Details, got[i], c.want)
		}
	}
}

// The .pkla allows what the rule does, for a polkit that reads no rules.
func TestThePklaAllowsWhatTheRuleDoes(t *testing.T) {
	actions := regexp.MustCompile(`org\.freedesktop\.[a-z0-9]+\.[a-z-]+`)
	rule, err := os.ReadFile(filepath.Join("polkit", "juist.rules"))
	if err != nil {
		t.Fatal(err)
	}
	pkla, err := os.ReadFile(filepath.Join("polkit", "juist.pkla"))
	if err != nil {
		t.Fatal(err)
	}
	var action string
	for l := range strings.Lines(string(pkla)) {
		if a, ok := strings.CutPrefix(strings.TrimSpace(l), "Action="); ok {
			action = a
		}
	}
	want, got := actions.FindAllString(string(rule), -1), strings.Split(action, ";")
	slices.Sort(want)
	slices.Sort(got)
	if len(want) != 5 || !slices.Equal(got, want) {
		t.Errorf("the .pkla allows %v, the rule %v", got, want)
	}
	if !strings.Contains(string(pkla), "\nIdentity=unix-user:juist;unix-user:juist1;") ||
		!strings.Contains(string(pkla), "\nResultAny=yes\n") {
		t.Errorf("the .pkla is not juistd's, or not for a service:\n%s", pkla)
	}
}

// The .pkla stands in for the rule where polkit is older than 0.106, and is
// nowhere else: a later polkit with polkitd-pkla would read it ahead of the
// rule's check of the device. The trigger brings it as polkit comes or goes.
func TestThePklaIsForAnOldPolkitAlone(t *testing.T) {
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("no dpkg to compare versions with")
	}
	sb := newSandbox(t)
	stub := "#!/bin/sh\nfor last; do :; done; grep \"^$last \" " + filepath.Join(sb.root, "dpkg") +
		" | cut -d' ' -f2- | grep . || exit 1\n"
	if err := os.WriteFile(filepath.Join(sb.root, "bin", "dpkg-query"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	pkla := filepath.Join(sb.root, "var/lib/polkit-1/localauthority/10-vendor.d/60-juist.pkla")
	triggered := []string{"triggered", "/usr/share/polkit-1/actions"}
	for _, c := range []struct {
		dpkg string
		args []string
		want bool
	}{
		{"polkitd installed 0.105-33ubuntu0.2", []string{"configure"}, true}, // Ubuntu 22.04
		{"polkitd installed 122-3", triggered, false},                        // Debian 12
		{"policykit-1 installed 0.105-26ubuntu1", triggered, true},           // Ubuntu 20.04
		{"", []string{"configure", "0.9"}, false},
		{"polkitd unpacked 0.105-33", triggered, true},
		{"polkitd config-files 0.105-33", triggered, false},
		{"polkitd installed 124-2ubuntu1\npolicykit-1 installed 124-2ubuntu1", triggered, false}, // Ubuntu 24.04
	} {
		if err := os.WriteFile(filepath.Join(sb.root, "dpkg"), []byte(c.dpkg+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		sb.run("postinst", c.args...)
		b, err := os.ReadFile(pkla)
		if got := err == nil; got != c.want {
			t.Errorf("%q, postinst %v: .pkla there %v, want %v", c.dpkg, c.args, got, c.want)
		}
		if err == nil && !strings.Contains(string(b), "Identity=unix-user:juist;") {
			t.Errorf("the .pkla installed reads:\n%s", b)
		}
	}
	if err := os.WriteFile(filepath.Join(sb.root, "dpkg"), []byte("polkitd installed 0.105-33\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb.run("postinst", "configure", "0.9")
	sb.run("postrm", "remove")
	if _, err := os.Stat(pkla); err == nil {
		t.Error("a removal kept the .pkla")
	}
}
