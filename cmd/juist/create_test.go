package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nning/juist/types"
)

func TestInitDefaults(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create")
	state := openLog(t, c).State()
	if !regexp.MustCompile(`^[a-z]+-[a-z]+$`).MatchString(state.Network()) {
		t.Fatalf("an unnamed network is called %q, not two words", state.Network())
	}
	self, ok := state.Node(nodeKeysOf(t, c).Identity.Public())
	if !ok {
		t.Fatal("init did not make this device a member")
	}
	if self.V4 == nil || self.V4.String() != "198.18.4.1" {
		t.Fatalf("the first device has IPv4 %v, want 198.18.4.1", self.V4)
	}
	if got := state.V4Range(); got != netip.MustParsePrefix("198.18.4.0/22") {
		t.Fatalf("a network founded without --ipv4 numbers from %v, want a /22 of its own", got)
	}
	if !self.HasRole(types.RoleAdmin) {
		t.Fatal("the first device is not an admin device, so nothing vouches for the network's state")
	}
}

// A network founded without --ipv4 draws a /22 in 198.18/15 at random, other
// than the first and other than one the host's own networks overlap: two
// networks holding all of 198.18/15 could never share a host.
func TestInitDrawsAPrefixOfItsOwn(t *testing.T) {
	t.Parallel()
	candidates := v4DrawCandidates()
	if len(candidates) != 127 {
		t.Fatalf("%d candidates, want the 127 /22s of 198.18/15 after the first", len(candidates))
	}
	seen := map[netip.Prefix]bool{}
	for _, p := range candidates {
		if p.Bits() != 22 || !types.OverlayV4.Contains(p.Addr()) || p.Masked() != p || seen[p] {
			t.Fatalf("candidate %v is not a distinct /22 of %v", p, types.OverlayV4)
		}
		seen[p] = true
	}
	if first := netip.MustParsePrefix("198.18.0.0/22"); seen[first] {
		t.Fatalf("%v is drawn, where networks without a prefix of their own number from", first)
	}
	if last := netip.MustParsePrefix("198.19.252.0/22"); !seen[last] {
		t.Fatalf("%v, the last /22 of the range, is never drawn", last)
	}

	drawn := map[netip.Prefix]bool{}
	for range 64 {
		p, err := drawV4Prefix(func(netip.Prefix) bool { return false })
		if err != nil {
			t.Fatal(err)
		}
		drawn[p] = true
	}
	if len(drawn) < 16 {
		t.Fatalf("64 draws gave %d prefixes; the draw is not random", len(drawn))
	}

	free := candidates[77]
	p, err := drawV4Prefix(func(c netip.Prefix) bool { return c != free })
	if err != nil || p != free {
		t.Fatalf("with one prefix free the draw gave %v, %v; want %v", p, err, free)
	}
	if _, err := drawV4Prefix(func(netip.Prefix) bool { return true }); err == nil ||
		!strings.Contains(err.Error(), "--ipv4") {
		t.Fatalf("with every prefix taken the draw said %v, want a pointer to --ipv4", err)
	}
}

func TestInitRefusesSecondNetwork(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "one")
	if _, err := c.run("create", "two"); err == nil {
		t.Fatal("created a second network in the same home directory")
	}
}

func TestInitRefusesUnreachableQuorum(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	if _, err := c.run("create", "impossible", "--quorum", "5"); err == nil {
		t.Fatal("created a network whose quorum exceeds the admin votes")
	}
}

// One keystore founds several networks, one per daemon, and what belongs to
// one network alone is named for it: its admin key too.
func TestAKeystoreFoundsSeveralNetworks(t *testing.T) {
	t.Parallel()
	a, b := newDaemonDevice(t, nil), newDaemonDevice(t, nil)
	b.cli = a.cli
	a.mustRun("create", "home")
	mustContain(t, b.mustRun("create", "work"), `created network "work"`)
	for _, network := range []string{"home", "work"} {
		if _, err := os.Stat(filepath.Join(a.home, breakGlassFile(network))); err != nil {
			t.Errorf("no break-glass secrets for %s: %v", network, err)
		}
	}
	if keys, err := a.home2().adminKeys(); err != nil || len(keys) != 2 {
		t.Fatalf("%d admin keys, %v", len(keys), err)
	}
	c := newDaemonDevice(t, nil)
	c.cli = a.cli
	if _, err := c.run("create", "home"); err == nil || !strings.Contains(err.Error(), "already prepared") {
		t.Fatalf("a second network called home: %v", err)
	}
}

// TestNamesAreCheckedWhereTheyAreChosen: a name the log will not accept is
// refused by the command that chooses it, before anything is written.
func TestNamesAreCheckedWhereTheyAreChosen(t *testing.T) {
	t.Parallel()
	tooLong := strings.Repeat("a", types.MaxNameLen+1)
	c := newCLI(t)
	if _, err := c.run("create", "home", "--device", tooLong); err == nil {
		t.Fatal("init accepted a device name over the limit")
	}
	for _, name := range []string{nodeKeysFile, breakGlassFile("home"), adminsDir} {
		if _, err := os.Stat(filepath.Join(c.home, name)); !os.IsNotExist(err) {
			t.Errorf("init refused the name but left %s behind", name)
		}
	}
	if _, err := newCLI(t).run("join", "7-acme-adviser-aimless", "--name", tooLong); err == nil {
		t.Fatal("join accepted a device name over the limit")
	}

	// A name in a hand-edited key file reaches the terminal, so it is checked
	// on the way in as well.
	c.mustRun("create", "home", "--device", "laptop")
	path := filepath.Join(c.home, nodeKeysFile)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var edited []string
	for line := range strings.Lines(string(body)) {
		if strings.HasPrefix(line, nameTag+" ") {
			line = nameTag + " " + b64.EncodeToString([]byte("\x1b[2K\rmember")) + "\n"
		}
		edited = append(edited, line)
	}
	if err := os.WriteFile(path, []byte(strings.Join(edited, "")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.run("devices"); err == nil {
		t.Fatal("a key file naming the device with a control sequence loaded without complaint")
	}
}

// A removed device's address is not handed on: members that have not heard
// of the removal still route it to that device.
// A network may choose its own IPv4 prefix at init, and its devices are
// numbered from it.
func TestInitWithItsOwnIPv4Prefix(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	mustContain(t, c.mustRun("create", "home", "--ipv4", "10.111.0.0/24"), "10.111.0.1", "IPv4 range", "10.111.0.0/24")
	phone := enrollDevice(t, c, "phone")
	self, _ := openLog(t, c).State().Node(nodeKeysOf(t, phone).Identity.Public())
	if self.V4 == nil || *self.V4 != netip.MustParseAddr("10.111.0.2") {
		t.Fatalf("the second device got %v, want 10.111.0.2", self.V4)
	}
	for _, bad := range []string{"8.8.8.0/24", "10.111.0.1/24", "10.111.0.0/30", "fd00::/64", "ten"} {
		if _, err := newCLI(t).run("create", "home", "--ipv4", bad); err == nil {
			t.Errorf("init accepted --ipv4 %s", bad)
		}
	}
}

// A network below schema 4 keeps handing out 100.64/10 addresses, the only
// ones its older members accept.
func TestAnOlderNetworkKeepsItsV4Range(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home")
	old := schema0Log(t, openLog(t, c), nodeKeysOf(t, c).Identity.Public())
	if got, err := nextV4(old.State(), nil); err != nil || got != netip.MustParseAddr("100.64.0.2") {
		t.Fatalf("a schema 0 network hands out %v (%v), want 100.64.0.2", got, err)
	}
}

// "juist init", the command's name before it was create, still founds a
// network, and help and usage name it create.
func TestInitIsCreate(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	mustContain(t, c.mustRun("init", "home", "--device", "laptop"), `created network "home"`)
	mustContain(t, c.mustRun("help", "init"), "Usage: juist create")
	if strings.Contains(c.mustRun("help"), "  init ") {
		t.Error("help lists init beside create")
	}
}
