package main

import (
	"flag"
	"net/netip"
	"strings"
	"testing"

	"github.com/nning/juist/internal/cliflag"
	"github.com/nning/juist/types"
)

// Every option of every command, subcommands included, has a one-letter
// spelling, and none takes a letter help or the global options have.
func TestEveryOptionHasAOneLetterSpelling(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	a := c.app(&syncBuffer{}, "")
	g := globals{home: c.home, homeExplicit: true}
	h, err := openHome(c.home)
	if err != nil {
		t.Fatal(err)
	}
	a.home = h
	var invocations [][]string
	for _, cmd := range commands {
		invocations = append(invocations, []string{cmd.name})
		if cmd.family == nil {
			continue
		}
		for _, sub := range cmd.family().names() {
			invocations = append(invocations, []string{cmd.name, sub})
		}
	}
	for _, words := range invocations {
		cmd, _ := lookup(words[0])
		got, ok := a.captureCommand(g, cmd, words[1:])
		if !ok {
			t.Fatalf("juist %s did not reach its options", strings.Join(words, " "))
		}
		got.fs.VisitAll(func(f *flag.Flag) {
			if len(f.Name) == 1 {
				if strings.Contains("hHs", f.Name) {
					t.Errorf("%s: -%s is help's or a global option's", got.spec.name, f.Name)
				}
				return
			}
			if label, _ := cliflag.Label(got.fs, f); !strings.HasPrefix(label, "-") {
				t.Errorf("%s: --%s has no one-letter spelling", got.spec.name, f.Name)
			}
		})
	}
}

// One-letter options do what their long ones do, the global ones too, and
// an option that matters only when given counts as given either way.
func TestOneLetterOptions(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "office", "-n", "laptop", "-4", "10.111.0.0/24", "-y")
	state := openLog(t, c).State()
	self, _ := state.Node(nodeKeysOf(t, c).Identity.Public())
	if self.Name != "laptop" || state.V4Range() != netip.MustParsePrefix("10.111.0.0/24") {
		t.Fatalf("init -n laptop -4 10.111.0.0/24 made %q in %v", self.Name, state.V4Range())
	}
	signer := newCLI(t)
	signer.mustRun("create", "office", "-N")
	if n := len(openLog(t, signer).State().Nodes()); n != 0 {
		t.Errorf("init -N made a network of %d devices, not this one's keys alone", n)
	}
	var out syncBuffer
	if err := c.app(&out, "").main([]string{"-H", c.home, "network"}); err != nil ||
		!strings.Contains(out.String(), "office") {
		t.Fatalf("juist -H DIR network: %v\n%s", err, out.String())
	}
	// A switch granting a role says so before anyone joins.
	inv, link := startInvite(t, c, "-V")
	phone := newCLI(t)
	phone.mustRun("join", link, "-n", "phone")
	out2, err := inv.wait(t)
	if err != nil {
		t.Fatalf("invite -V: %v\n%s", err, out2)
	}
	mustContain(t, out2, `invite to "office" as voucher`)
	n, _ := openLog(t, c).State().Node(nodeKeysOf(t, phone).Identity.Public())
	if n.Name != "phone" || !n.HasRole(types.RoleAdmin) {
		t.Fatalf("invite -V and join -n phone admitted %q with %v", n.Name, n.Roles)
	}
	mustContain(t, c.mustRun("network", "renumber", "10.7.0.0/22", "-t", "2d", "-y"), "moving to 10.7.0.0/22")
	mustContain(t, c.mustRun("network", "renumber", "--help"), "-y, --yes", "-t, --for")
	if _, err := c.run("-H"); err == nil || !strings.Contains(err.Error(), "-H needs a path") {
		t.Errorf("juist -H with no path: %v", err)
	}
	for _, words := range [][]string{{"-H", ""}, {"-s", ""}} {
		if got := c.mustRun(append([]string{"__complete"}, words...)...); got != "" {
			t.Errorf("completing the value of %s offered %q, not a path", words[0], got)
		}
	}
}
