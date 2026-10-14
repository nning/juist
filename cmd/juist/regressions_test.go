package main

import (
	"crypto/rand"
	"fmt"
	mrand "math/rand/v2"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/ipc"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

func testNode(t *testing.T, name string) types.NodeRecord {
	t.Helper()
	id, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := secrets.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	x, m, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}
	var wg types.WGKey
	if _, err := rand.Read(wg[:]); err != nil {
		t.Fatal(err)
	}
	return types.NodeRecord{Identity: id.Public(), Name: name, WireGuard: wg, X25519: x, MLKEM: m, Signing: new(id.SigningKey())}
}

// Whatever sequence of admissions, removals, moves and renumberings a network
// goes through, the addresses the CLI hands out are ones the log accepts.
func TestAllocationsTheLogAccepts(t *testing.T) {
	t.Parallel()
	prefixes := []string{"10.7.0.0/24", "10.7.0.0/25", "10.7.0.128/25", "10.7.0.0/23", "10.7.1.0/24",
		"198.18.0.0/24", "198.18.0.0/28", "10.7.0.0/28", "10.7.0.16/28", "192.168.5.0/27"}
	for seed := range 25 {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			t.Parallel()
			r := mrand.New(mrand.NewPCG(uint64(seed), 7))
			admin, _ := types.GenerateIdentity()
			st := log.NewMemStorage()
			first := testNode(t, "n0")
			v4 := netip.MustParseAddr("198.18.0.1")
			first.V4 = &v4
			g, err := log.Genesis("net", 1, []types.AdminKey{{Public: admin.Public(), Signing: new(admin.SigningKey()), Endorsement: admin.Endorsement(), Votes: 1, Name: "a", Holder: "a"}},
				[]types.Hash{{1}}, []types.NodeRecord{first}, sealer())
			if err != nil {
				t.Fatal(err)
			}
			if err := g.Sign(admin); err != nil {
				t.Fatal(err)
			}
			auth, err := log.Create(st, g)
			if err != nil {
				t.Fatal(err)
			}
			history := func() []types.AUM {
				hs, _ := auth.Chain()
				var out []types.AUM
				for _, h := range hs {
					a, _ := st.AUM(h)
					out = append(out, a)
				}
				return out
			}
			apply := func(what string, a types.AUM, err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("seed %d: building %s: %v", seed, what, err)
				}
				if err := a.Sign(admin); err != nil {
					t.Fatal(err)
				}
				if err := auth.Inform(a); err != nil {
					t.Fatalf("seed %d: the log rejects %s: %v", seed, what, err)
				}
			}
			for step := range 40 {
				state := auth.State()
				nodes := state.Nodes()
				switch op := r.IntN(10); {
				case op < 3 && len(nodes) < 12:
					n := testNode(t, fmt.Sprintf("n%d", step+1))
					a, err := nextV4(state, history())
					if err != nil {
						continue
					}
					n.V4 = &a
					b, err := auth.Builder().AddNode(n, sealer())
					apply("admission at "+a.String(), b, err)
				case op < 4 && len(nodes) > 1:
					n := nodes[r.IntN(len(nodes))]
					b, err := auth.Builder().RemoveNode(n.Identity, sealer())
					apply("removal", b, err)
				case op < 6:
					n := nodes[r.IntN(len(nodes))]
					rg := state.V4Range()
					size := usableHosts(rg)
					if size > 60 {
						size = 60
					}
					addr, _ := offsetInto(rg, uint32(1+r.IntN(int(size))))
					bad := n.V4 != nil && *n.V4 == addr
					for _, o := range nodes {
						if o.Identity != n.Identity && slices.Contains(o.V4Addrs(), addr) {
							bad = true
						}
					}
					if bad {
						continue
					}
					b, err := auth.Builder().RenumberNode(n.Identity, addr, 1<<40)
					apply("device renumbering to "+addr.String(), b, err)
				case op < 9:
					p := netip.MustParsePrefix(prefixes[r.IntN(len(prefixes))])
					if p == state.V4Range() || usableHosts(p) < uint64(len(nodes)) {
						continue
					}
					addrs, err := renumbered(state, p, history())
					if err != nil {
						t.Logf("seed %d: renumbered into %v: %v", seed, p, err)
						continue
					}
					b, err := auth.Builder().RenumberNetwork(p, addrs, 1<<40)
					apply(fmt.Sprintf("network renumbering to %v: %v", p, addrs), b, err)
				default:
					if _, ok := state.V4Retiring(); !ok {
						has := false
						for _, n := range nodes {
							has = has || n.Retiring != nil
						}
						if !has {
							continue
						}
					}
					b, err := auth.Builder().RetireAddresses()
					apply("retirement", b, err)
				}
			}
		})
	}
}

// The log and approvals name signers by person, their keys of one person as
// one approval.
func TestSignersAreNamedByPerson(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop", "--admin-name", "alice")
	other := newCLI(t)
	key := regexp.MustCompile(`juist admins add alice (nid:\S+)`).FindStringSubmatch(
		other.mustRun("admins", "new", "alice", "--on", "nas"))[1]
	c.mustRun("admins", "add", "alice", key, "--on", "nas")
	c.mustRun("admins", "require", "alice", "2", "--yes")
	c.mustRun("rotate", "group-secret")
	pending := filepath.Join(dir, "rotate-group-secret.rec")
	other.mustRun("approve", "--yes", pending)
	c.mustRun("apply", pending)
	out := c.mustRun("log")
	if strings.Contains(out, "approved by laptop") || !strings.Contains(out, "approved by alice (2 keys)") {
		t.Errorf("signers are not named by person:\n%s", out)
	}
}

// Taking a key away names the person who loses its vote.
func TestRemovingAKeyNamesThePerson(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop", "--admin-name", "alice")
	bob := newCLI(t)
	key := regexp.MustCompile(`juist admins add bob (nid:\S+)`).FindStringSubmatch(
		bob.mustRun("admins", "new", "bob", "--on", "bobpc"))[1]
	c.mustRun("admins", "add", "bob", key, "--on", "bobpc")
	auth := openLog(t, c)
	k, err := resolveAdmin(auth.State(), "bob")
	if err != nil {
		t.Fatal(err)
	}
	aum, err := auth.Builder().RemoveAdminKey(k.Public)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, strings.Join(effect(&aum, auth.State(), time.Now().Unix()), "\n"), "bob's", "on bobpc")
	mustContain(t, c.mustRun("admins", "remove", "bob"), "removed bob's key")
}

// A renumbering approved after its deadline says so before it applies.
func TestARenumberingApprovedTooLateSaysSo(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	first, second := newCLI(t), newCLI(t)
	key := regexp.MustCompile(`(nid:\S+)`).FindString(second.mustRun("admins", "new", "second"))
	first.mustRun("create", "home", "--device", "laptop", "--admin", "second="+key)
	enrollDevice(t, first, "phone")
	first.mustRun("admins", "quorum", "2", "--yes")
	first.mustRun("network", "renumber", "10.7.0.0/24", "--for", "1s", "--yes")
	advance(t, 2*time.Second)
	mustContain(t, second.mustRun("approve", "--yes", filepath.Join(dir, "renumber.rec")), "deadline has passed")
}

// One approved close to its deadline says how little of the transition is
// left, since the deadline was fixed when it was proposed.
func TestARenumberingApprovedLateSaysHowMuchIsLeft(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	first, second := newCLI(t), newCLI(t)
	key := regexp.MustCompile(`(nid:\S+)`).FindString(second.mustRun("admins", "new", "second"))
	first.mustRun("create", "home", "--device", "laptop", "--admin", "second="+key)
	enrollDevice(t, first, "phone")
	first.mustRun("admins", "quorum", "2", "--yes")
	out := first.mustRun("network", "renumber", "10.7.0.0/24", "--for", "7d", "--yes")
	if strings.Contains(out, "BUT") {
		t.Fatalf("a renumbering with its whole transition ahead warns:\n%s", out)
	}
	advance(t, 6*24*time.Hour)
	mustContain(t, second.mustRun("approve", "--yes", filepath.Join(dir, "renumber.rec")),
		"BUT only 24h of that is left", "--for")
}

// An old address past its deadline still blocks until the renumbering is
// finished, which the refusal says; finishing warns of nothing that stopped.
func TestAnOldAddressPastItsDeadline(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, c, "phone")
	c.mustRun("network", "renumber", "phone", "198.18.4.9", "--for", "1s", "--yes")
	advance(t, 2*time.Second)
	if _, err := c.run("network", "renumber", "laptop", "198.18.4.2", "--yes"); err == nil ||
		!strings.Contains(err.Error(), "--finish") {
		t.Errorf("moving onto an old address past its deadline: %v, want the way to free it", err)
	}
	if out := c.mustRun("network", "renumber", "--finish", "--yes"); strings.Contains(out, "will no longer reach") {
		t.Errorf("finishing warns of an address that stopped working already:\n%s", out)
	}
}

// Moving a device back to the address it is retiring loses nothing, and is
// not warned of.
func TestMovingBackIsNoLoss(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, c, "phone")
	c.mustRun("network", "renumber", "phone", "198.18.4.9", "--yes")
	if out := c.mustRun("network", "renumber", "phone", "198.18.4.2", "--yes"); strings.Contains(out, "stop working now") {
		t.Errorf("moving back warned of a loss:\n%s", out)
	}
}

// A network without a prefix of its own holds no address in 100.64/10,
// tailscaled's range.
func TestAMemberIn100_64IsRefused(t *testing.T) {
	t.Parallel()
	admin, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	n := testNode(t, "old")
	n.V4 = new(netip.MustParseAddr("100.64.0.1"))
	g, err := log.Genesis("net", 1, []types.AdminKey{{Public: admin.Public(), Signing: new(admin.SigningKey()), Endorsement: admin.Endorsement(), Votes: 1, Name: "a", Holder: "a"}},
		[]types.Hash{{1}}, []types.NodeRecord{n}, sealer())
	if err == nil {
		if err = g.Sign(admin); err != nil {
			t.Fatal(err)
		}
		_, err = log.Create(log.NewMemStorage(), g)
	}
	if err == nil || !strings.Contains(err.Error(), "outside 198.18.0.0/15") {
		t.Fatalf("a member at 100.64.0.1 without a prefix of its own: %v", err)
	}
}

var _ = mrand.IntN
var _ = fmt.Sprint

// A device that went offline is counted without a tunnel, but neither blamed
// on a firewall nor named in status; one not decided yet is said to be either.
func TestStatusCallsAnOfflineDeviceOffline(t *testing.T) {
	t.Parallel()
	desktop, laptop := types.Identity{1}, types.Identity{2}
	st := &ipc.Status{
		InNetwork: true, ListenPort: 41643,
		Derived: ipc.Derived{NetworkName: "ionet", Members: 3, Peers: 2,
			Devices: []ipc.Device{{Identity: desktop, Name: "desktop"}, {Identity: laptop, Name: "laptop1"}}},
		Tunnels: ipc.Tunnels{TunnelsChecked: true, TunnelsLive: 0, TunnelsDown: []string{"laptop1", "desktop"},
			Absent: []string{"desktop"}, Seeking: []string{"laptop1"},
			Reach: []ipc.PeerReach{
				{Identity: desktop, Absent: true, Heard: time.Now().Add(-25 * time.Minute).Unix()},
				{Identity: laptop, Seeking: true},
			}},
	}
	var out syncBuffer
	printStatusAndHealth((&cli{t: t, home: t.TempDir()}).app(&out, ""), st)
	got := out.String()
	mustContain(t, got, "2 others, 2 without a tunnel", "no answer from laptop1: offline, or udp/41643 blocked")
	if strings.Contains(got, "desktop") {
		t.Errorf("status names an offline device:\n%s", got)
	}
	if strings.Contains(got, "ufw") || strings.Contains(got, "firewall-cmd") {
		t.Errorf("an offline device, or one not decided yet, is blamed on a firewall:\n%s", got)
	}
}

// Renumbering says every risk it sees, and asks once.
func TestRenumberingAsksOnce(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, c, "phone")
	enrollDevice(t, c, "tablet")
	c.mustRun("remove", "tablet", "--yes")
	c.mustRun("network", "renumber", "phone", "198.18.4.9", "--yes")
	// Onto the removed tablet's address, cutting the phone's old one short:
	// two warnings, one question.
	out, err := c.answer("y", "network", "renumber", "phone", "198.18.4.3")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "was tablet's", "retire now")
	if n := strings.Count(out, "[y/N]"); n != 1 {
		t.Errorf("asked %d times:\n%s", n, out)
	}
}

// A range every address of which went to a device once is full, however few
// members are left in it: none is handed out twice. The error says how to
// make room rather than only that there is none.
func TestARangeFullByHistorySaysHowToGrow(t *testing.T) {
	t.Parallel()
	admin, _ := types.GenerateIdentity()
	st := log.NewMemStorage()
	first := testNode(t, "n0")
	v4 := netip.MustParseAddr("10.7.0.1")
	first.V4 = &v4
	prefix := netip.MustParsePrefix("10.7.0.0/28")
	g, err := log.Genesis("net", 1, []types.AdminKey{{Public: admin.Public(), Signing: new(admin.SigningKey()), Endorsement: admin.Endorsement(), Votes: 1, Name: "a", Holder: "a"}},
		[]types.Hash{{1}}, []types.NodeRecord{first}, sealer())
	if err != nil {
		t.Fatal(err)
	}
	g.State.V4Prefix = &prefix
	if err := g.Sign(admin); err != nil {
		t.Fatal(err)
	}
	auth, err := log.Create(st, g)
	if err != nil {
		t.Fatal(err)
	}
	history := func() []types.AUM {
		hs, _ := auth.Chain()
		var out []types.AUM
		for _, h := range hs {
			a, _ := st.AUM(h)
			out = append(out, a)
		}
		return out
	}
	inform := func(a types.AUM, err error) {
		t.Helper()
		if err == nil {
			err = a.Sign(admin)
		}
		if err == nil {
			err = auth.Inform(a)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := range 20 {
		a, err := nextV4(auth.State(), history())
		if err != nil {
			if !strings.Contains(err.Error(), "juist network renumber") || len(auth.State().Nodes()) != 1 {
				t.Fatalf("after %d admissions, with %d members: %v", i, len(auth.State().Nodes()), err)
			}
			return
		}
		n := testNode(t, fmt.Sprintf("n%d", i+1))
		n.V4 = &a
		inform(auth.Builder().AddNode(n, sealer()))
		inform(auth.Builder().RemoveNode(n.Identity, sealer()))
	}
	t.Fatal("a /28 took twenty admissions")
}

// A move at once reads as one to the admin who approves it, however late.
func TestAMoveAtOnceReadsAsOne(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	first, second := newCLI(t), newCLI(t)
	key := regexp.MustCompile(`(nid:\S+)`).FindString(second.mustRun("admins", "new", "second"))
	first.mustRun("create", "home", "--device", "laptop", "--admin", "second="+key)
	enrollDevice(t, first, "phone")
	first.mustRun("admins", "quorum", "2", "--yes")
	mustContain(t, first.mustRun("network", "renumber", "phone", "198.18.4.9", "--finish", "--yes"),
		"needs 1 more vote")
	advance(t, 3*24*time.Hour)
	out := second.mustRun("approve", "--yes", filepath.Join(dir, "renumber-phone.rec"))
	mustContain(t, out, "to 198.18.4.9 at once", "retires its old address now")
	out = first.mustRun("approve", filepath.Join(dir, "renumber-phone.rec"))
	mustContain(t, out, "moves phone", "to 198.18.4.9 at once",
		"retires 198.18.4.2 now: devices not told yet reach the device over IPv6 only", "applied")
	if strings.Contains(out, "BUT") || strings.Contains(out, "1970") || strings.Contains(out, "until") {
		t.Fatalf("a move at once reads as a transition that ran out:\n%s", out)
	}
}
