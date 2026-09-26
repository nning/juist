package main

import (
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/nning/juist/ipc"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

// Every device moves into the new prefix at its place in the old range, keeps
// its old address until the deadline, and loses it when the renumbering is
// finished early.
func TestRenumberTheNetwork(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("init", "home", "--device", "laptop")
	phone := enrollDevice(t, c, "phone")
	if _, err := c.run("network", "renumber", "10.7.0.0/22"); err == nil {
		t.Fatal("a renumbering went ahead unconfirmed")
	}
	mustContain(t, c.mustRun("network", "renumber", "10.7.0.0/22", "--for", "2d", "--yes"),
		"moving to 10.7.0.0/22", "old addresses until")

	state := openLog(t, c).State()
	n, _ := state.Node(nodeKeysOf(t, phone).Identity.Public())
	if n.V4 == nil || *n.V4 != netip.MustParseAddr("10.7.0.2") || n.Retiring == nil ||
		n.Retiring.Addr != netip.MustParseAddr("198.18.0.2") {
		t.Fatalf("the phone is at %v retiring %+v, want 10.7.0.2 retiring 198.18.0.2", n.V4, n.Retiring)
	}
	mustContain(t, c.mustRun("devices"), "10.7.0.1 (was 198.18.0.1)", "10.7.0.2 (was 198.18.0.2)")
	out := c.mustRun("network")
	mustContain(t, out, "10.7.0.0/22", "198.18.0.0/15 until", "MOVING")
	if !regexp.MustCompile(`(?m)^laptop +198\.18\.0\.1 +10\.7\.0\.1 .*\n^phone +198\.18\.0\.2 +10\.7\.0\.2 `).MatchString(out) {
		t.Errorf("the devices moving are not one to a line, in address order:\n%s", out)
	}
	mustContain(t, c.mustRun("network", "renumber", "10.7.0.0/22"), "unchanged: numbered from 10.7.0.0/22")

	mustContain(t, c.mustRun("network", "renumber", "--finish", "--yes"), "retired")
	out = c.mustRun("devices")
	if strings.Contains(out, "was 198.18") {
		t.Fatalf("finished, the devices still list their old addresses:\n%s", out)
	}
	mustContain(t, c.mustRun("network", "renumber", "--finish"), "no old addresses to retire")
}

func TestRenumberOneDevice(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("init", "home", "--device", "laptop")
	phone := enrollDevice(t, c, "phone")
	enrollDevice(t, c, "tablet")
	for _, tc := range []struct{ addr, want string }{
		{"198.18.0.1", "taken by laptop"},
		{"10.0.0.5", "outside the network's range"},
		{"198.19.255.255", "first or last"},
		{"fd00::1", "bad IPv4 address"},
	} {
		if out, err := c.run("network", "renumber", "phone", tc.addr, "--yes"); err == nil ||
			!strings.Contains(err.Error(), tc.want) {
			t.Errorf("moving the phone to %s: %v, want an error naming %q\n%s", tc.addr, err, tc.want, out)
		}
	}
	mustContain(t, c.mustRun("network", "renumber", "phone", "198.18.0.2"), "unchanged: phone at 198.18.0.2")

	// The tablet's address is held back once it is removed, and handed on
	// only when asked twice.
	c.mustRun("remove", "tablet", "--yes")
	if _, err := c.run("network", "renumber", "phone", "198.18.0.3"); err == nil {
		t.Fatal("the phone was moved to the removed tablet's address unconfirmed")
	}
	mustContain(t, c.mustRun("network", "renumber", "phone", "198.18.0.3", "--yes"),
		"was tablet's", "phone moving to 198.18.0.3", "198.18.0.2 until")
	n, _ := openLog(t, c).State().Node(nodeKeysOf(t, phone).Identity.Public())
	if *n.V4 != netip.MustParseAddr("198.18.0.3") || n.Retiring.Addr != netip.MustParseAddr("198.18.0.2") {
		t.Fatalf("the phone is at %v retiring %v", *n.V4, n.Retiring.Addr)
	}

	// Moved again, it gives up the address it was retiring, and is warned.
	mustContain(t, c.mustRun("network", "renumber", "phone", "198.18.0.7", "--yes"),
		"retire now, not at their deadline", "phone's 198.18.0.2")
}

// The network renumbering keeps each device at its place in the range where
// that is free, and needs room for all of them.
func TestRenumberedAddresses(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("init", "home", "--device", "laptop")
	enrollDevice(t, c, "phone")
	enrollDevice(t, c, "tablet")
	c.mustRun("remove", "phone", "--yes")
	st, err := store.Open(filepath.Join(c.home, logDir))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := log.Open(st)
	if err != nil {
		t.Fatal(err)
	}
	history, err := auth.Chain()
	if err != nil {
		t.Fatal(err)
	}
	var records []types.AUM
	for _, h := range history {
		a, err := st.AUM(h)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, a)
	}
	state := auth.State()
	// A prefix that holds their addresses keeps them where they are.
	got, err := renumbered(state, netip.MustParsePrefix("198.18.0.0/24"), records)
	if err != nil {
		t.Fatal(err)
	}
	var addrs []string
	for _, m := range got {
		addrs = append(addrs, m.V4.String())
	}
	slices.Sort(addrs)
	if want := []string{"198.18.0.1", "198.18.0.3"}; !slices.Equal(addrs, want) {
		t.Errorf("renumbered into their own range at %v, want %v", addrs, want)
	}
	got, err = renumbered(state, netip.MustParsePrefix("10.7.0.0/30"), records)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].V4 == got[1].V4 {
		t.Errorf("a /30 has room for two, and gave %v", got)
	}
	if _, err := renumbered(state, netip.MustParsePrefix("10.7.0.0/31"), records); err == nil {
		t.Error("a /31 took two devices")
	}
}

// A device already inside the prefix the network shrinks to stays where it is.
func TestRenumberKeepsDevicesInsideTheNewPrefix(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("init", "home", "--device", "laptop")
	phone := enrollDevice(t, c, "phone")
	c.mustRun("network", "renumber", "phone", "198.18.2.5", "--yes")
	c.mustRun("network", "renumber", "198.18.2.0/23", "--yes")
	state := openLog(t, c).State()
	for _, tc := range []struct {
		dev  *cli
		want string
	}{{phone, "198.18.2.5"}, {c, "198.18.2.1"}} {
		n, _ := state.Node(nodeKeysOf(t, tc.dev).Identity.Public())
		if n.V4 == nil || n.V4.String() != tc.want {
			t.Errorf("%s is at %v, want %s", n.Name, n.V4, tc.want)
		}
	}
}

// The device table lists devices by IPv4 address, not by key.
func TestDevicesAreListedByAddress(t *testing.T) {
	t.Parallel()
	devs := []ipc.Device{
		{Name: "c", V4: "198.18.0.10", V6: "fd00::3"},
		{Name: "none", V6: "fd00::1"},
		{Name: "a", V4: "198.18.0.2", V6: "fd00::9"},
		{Name: "b", V4: "198.18.0.9", V6: "fd00::2"},
	}
	var names []string
	for _, d := range byAddress(devs) {
		names = append(names, d.Name)
	}
	if want := []string{"a", "b", "c", "none"}; !slices.Equal(names, want) {
		t.Errorf("listed %v, want %v", names, want)
	}
}

// A rename with a quorum of two waits for the second admin, who is shown the
// new name before approving, and changes nothing but the name.
func TestRenameTheNetwork(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	first, second := newCLI(t), newCLI(t)
	key := regexp.MustCompile(`juist admins add second (nid:\S+)`).
		FindStringSubmatch(second.mustRun("admins", "new", "second"))
	if key == nil {
		t.Fatal("admins new printed no key")
	}
	first.mustRun("init", "home", "--device", "laptop", "--quorum", "2", "--admin", "second="+key[1])
	genesis := filepath.Join(first.home, genesisFileFor("home"))
	second.mustRun("approve", "--yes", genesis)
	first.mustRun("apply", genesis)
	before := openLog(t, first).State()

	for _, bad := range []string{"-office", "off ice", "büro"} {
		if _, err := first.run("network", "rename", bad); err == nil {
			t.Errorf("the network was renamed to %q", bad)
		}
	}
	mustContain(t, first.mustRun("network", "rename", "home"), `unchanged: named "home"`)
	mustContain(t, first.mustRun("network", "rename", "office"), "needs 1 more vote", "juist approve rename.rec")
	pending := filepath.Join(dir, "rename.rec")
	mustContain(t, second.mustRun("approve", "--yes", pending), `renames the network to "office"`)
	mustContain(t, first.mustRun("apply", pending), `renames the network "home" to "office"`, "applied")

	after := openLog(t, first).State()
	if after.Network() != "office" || after.GenesisHash() != before.GenesisHash() || after.ULA() != before.ULA() {
		t.Fatalf("renamed, the network is %q at %v, want office at %v", after.Network(), after.GenesisHash(),
			before.GenesisHash())
	}
	mustContain(t, first.mustRun("network"), "office")
	mustContain(t, first.mustRun("log"), "renaming of the network: office")
	mustContain(t, first.mustRun("__complete", "network", ""), "rename")
}
