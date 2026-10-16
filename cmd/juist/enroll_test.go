package main

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

// TestInviteAndJoin walks the loop a new user runs: create a network, invite
// a device, join it, see it, remove it. Every step goes through the real log
// and the real enrollment protocol over TCP.
func TestInviteAndJoin(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	out := admin.mustRun("create", "home", "--device", "laptop", "--voucher")
	mustContain(t, out, `created network "home"`, "laptop", "198.18.4.1")

	inv, link := startInvite(t, admin)
	guest := newCLI(t)
	out = guest.mustRun("join", link, "--name", "phone")
	mustContain(t, out, `joined "home" as phone`, "198.18.4.2", "juistd")
	hostOut, err := inv.wait(t)
	if err != nil {
		t.Fatalf("invite: %v\n%s", err, hostOut)
	}
	mustContain(t, hostOut, "admitted phone at 198.18.4.2", "phone joined")

	// The guest verified and stored the same log the admin holds.
	if a, g := openLog(t, admin).Head(), openLog(t, guest).Head(); a != g {
		t.Fatalf("the guest's head %v differs from the admin's %v", g, a)
	}
	mustContain(t, guest.mustRun("log", "verify"), "group secret: ok")
	out = admin.mustRun("devices")
	mustContain(t, out, "laptop (this device)", "phone", "198.18.4.2", "voucher")

	epoch := openLog(t, admin).State().Epoch()
	admin.mustRun("remove", "phone", "--yes")
	state := openLog(t, admin).State()
	if state.Epoch() == epoch {
		t.Fatal("removing a device did not rotate the group secret")
	}
	if strings.Contains(admin.mustRun("devices"), "phone") {
		t.Fatal("the removed device is still listed")
	}
}

// TestJoinWithTheCode runs the typed code rather than the link. The LAN search
// is replaced by the host's address, since CI has no multicast; what is under
// test is that the code is the password the host checks.
func TestJoinWithTheCode(t *testing.T) {
	admin := newCLI(t)
	admin.mustRun("create", "home")
	inv, link := startInviteOnTheLAN(t, admin)
	code := inv.waitFor(t, regexp.MustCompile(`juist join (\d+-[a-z]+-[a-z]+-[a-z]+)`))[1]
	guest := newCLI(t)
	var out syncBuffer
	a := guest.app(&out, "")
	a.findInvite = hostAt(t, link)
	if err := a.main([]string{"--home", guest.home, "join", code}); err != nil {
		t.Fatalf("join: %v\n%s", err, out.String())
	}
	if _, err := inv.wait(t); err != nil {
		t.Fatal(err)
	}
	if !openLog(t, guest).State().IsMember(nodeKeysOf(t, guest).Identity.Public()) {
		t.Fatal("joining with the code did not admit the device")
	}
}

// TestAWrongCodeVoidsTheInvite is the first exit criterion at the level a
// person sees it: one wrong try, reported on both sides, and the invite is
// gone, so the right code no longer works either.
func TestAWrongCodeVoidsTheInvite(t *testing.T) {
	admin := newCLI(t)
	admin.mustRun("create", "home")
	inv, link := startInviteOnTheLAN(t, admin)
	code := inv.waitFor(t, regexp.MustCompile(`juist join (\d+-[a-z]+-[a-z]+-[a-z]+)`))[1]
	c, err := enroll.ParseCode(code)
	if err != nil {
		t.Fatal(err)
	}
	c.Words[2]++
	attacker := newCLI(t)
	var out syncBuffer
	a := attacker.app(&out, "")
	a.findInvite = hostAt(t, link)
	err = a.main([]string{"--home", attacker.home, "join", c.String()})
	if err == nil || !strings.Contains(err.Error(), "code is wrong") {
		t.Fatalf("a wrong code got %v", err)
	}
	inv.waitFor(t, regexp.MustCompile(`code voided: wrong guess`))

	// The right code no longer works; the link, a secret of its own, does.
	var out2 syncBuffer
	b := newCLI(t).app(&out2, "")
	b.findInvite = hostAt(t, link)
	if err := b.main([]string{"--home", t.TempDir(), "join", code}); err == nil {
		t.Fatal("the right code worked after a wrong guess")
	}
	guest := newCLI(t)
	guest.mustRun("join", link)
	if _, err := inv.wait(t); err != nil {
		t.Fatalf("the invite, after a wrong code and then the link: %v", err)
	}
	if openLog(t, admin).State().IsMember(nodeKeysOf(t, attacker).Identity.Public()) {
		t.Fatal("the wrong guess admitted a device")
	}
}

// A wrong link, unlike a wrong code, leaves the invite to the right one.
func TestAWrongLinkLeavesTheInviteOpen(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home")
	inv, link := startInvite(t, admin)
	body, addr, _ := strings.Cut(strings.TrimPrefix(link, enroll.LinkPrefix), "@")
	secret, adminKey, _ := strings.Cut(body, ".")
	wrong := enroll.LinkPrefix + strings.Repeat("A", len(secret)) + "." + adminKey + "@" + addr
	if _, err := newCLI(t).run("join", wrong); err == nil || !strings.Contains(err.Error(), "link does not match") {
		t.Fatalf("a wrong link got %v", err)
	}
	guest := newCLI(t)
	guest.mustRun("join", link)
	if _, err := inv.wait(t); err != nil {
		t.Fatal(err)
	}
}

// TestAnInviteAdmitsOneDevice: the invite is spent by the device that uses
// it, so a copy of the code that leaked afterwards admits nobody.
func TestAnInviteAdmitsOneDevice(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home")
	inv, link := startInvite(t, admin)
	newCLI(t).mustRun("join", link)
	if _, err := inv.wait(t); err != nil {
		t.Fatal(err)
	}
	if _, err := newCLI(t).run("join", link); err == nil {
		t.Fatal("a second device joined with a spent invite")
	}
}

func TestInviteExpires(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home")
	r := admin.start("invite", "--no-lan", "--port", "0", "--expires", "300ms", "--yes")
	out, err := r.wait(t)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("an expired invite returned %v\n%s", err, out)
	}
}

// TestInviteWaitsForTheOtherAdmins is the third exit criterion: a quorum of
// two, with the second admin key on a machine that holds nothing else, admits
// a device through an invite, and no machine ever holds both keys.
func TestInviteWaitsForTheOtherAdmins(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	first, second := newCLI(t), newCLI(t)
	key := regexp.MustCompile(`juist admins add second (nid:\S+)`).
		FindStringSubmatch(second.mustRun("admins", "new", "second"))
	if key == nil {
		t.Fatal("admins new printed no key")
	}
	out := first.mustRun("create", "home", "--quorum", "2", "--admin", "second="+key[1])
	mustContain(t, out, "needs 1 more vote", "juist approve")
	genesis := filepath.Join(first.home, genesisFileFor("home"))
	if _, err := first.run("apply", genesis); err == nil {
		t.Fatal("one of two admins created the network alone")
	}
	mustContain(t, second.mustRun("approve", "--yes", genesis), "the founder runs")
	first.mustRun("apply", genesis)

	inv, link := startInvite(t, first)
	guest := newCLI(t)
	joined := guest.start("join", link, "--name", "phone")
	inv.waitFor(t, regexp.MustCompile(`juist approve add-phone\.rec`))
	joined.waitFor(t, regexp.MustCompile(`1 of 2 votes`))
	pending := filepath.Join(dir, "add-phone.rec")

	// The device being admitted has no part in approving itself, and must not
	// spoil the record by trying.
	before, err := os.ReadFile(pending)
	if err != nil {
		t.Fatal(err)
	}
	guest.run("approve", "--yes", pending)
	if after, _ := os.ReadFile(pending); !bytes.Equal(before, after) {
		t.Fatal("approving on the device being admitted changed the record")
	}

	// The second admin approves on a machine with no network, and the record
	// comes back to be applied: the invite notices and finishes.
	second.mustRun("approve", "--yes", pending)
	first.mustRun("apply", pending)
	if out, err := inv.wait(t); err != nil {
		t.Fatalf("invite: %v\n%s", err, out)
	}
	if out, err := joined.wait(t); err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}
	if !openLog(t, guest).State().IsMember(nodeKeysOf(t, guest).Identity.Public()) {
		t.Fatal("the two-admin invite did not admit the device")
	}
}

func TestInviteNamesDevicesUniquely(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	enrollDevice(t, admin, "laptop")
	mustContain(t, admin.mustRun("devices"), "laptop-2")
}

// TestARemovedDeviceCanRejoin: a removed device keeps its own log, which the
// rejoin extends rather than replaces, so its ratchets survive the round trip.
func TestARemovedDeviceCanRejoin(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home")
	phone := enrollDevice(t, admin, "phone")
	admin.mustRun("remove", "phone", "--yes")

	inv, link := startInvite(t, admin)
	mustContain(t, phone.mustRun("join", link), `joined "home"`)
	if _, err := inv.wait(t); err != nil {
		t.Fatal(err)
	}
	if !openLog(t, phone).State().IsMember(nodeKeysOf(t, phone).Identity.Public()) {
		t.Fatal("the rejoined device is not a member in its own log")
	}

	// A device holding another network's log is not silently moved over.
	other := newCLI(t)
	other.mustRun("create", "elsewhere")
	inv, link = startInvite(t, other)
	if _, err := phone.run("join", link); err == nil {
		t.Fatal("a device in one network joined another without being asked to leave it")
	}
	inv.cancel()
}

// A device whose log starts below what the inviting device keeps is invited
// again, and its log moves to the chain the invite brings.
func TestADeviceBehindWhatItsPeersKeepIsInvitedAgain(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home")
	phone := enrollDevice(t, admin, "phone")
	compact := func() {
		t.Helper()
		admin.mustRun("log", "checkpoint")
		if _, err := openLog(t, admin).Compact(); err != nil {
			t.Fatal(err)
		}
	}
	admin.mustRun("rotate", "group-secret")
	compact()
	admin.mustRun("network", "rename", "house")
	compact()

	inv, link := startInvite(t, admin)
	mustContain(t, phone.mustRun("join", link), `joined "house"`)
	if _, err := inv.wait(t); err != nil {
		t.Fatal(err)
	}
	if got, want := openLog(t, phone), openLog(t, admin); got.Head() != want.Head() || got.Anchor() != want.Anchor() {
		t.Fatal("the device invited again does not follow the inviting device's chain")
	}
}

// TestUniqueNameFitsTheLimit: a name at the length limit that is already
// taken must still yield a valid unused name, and not loop.
func TestUniqueNameFitsTheLimit(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	long := strings.Repeat("a", types.MaxNameLen)
	c.mustRun("create", "home", "--device", long)
	state := openLog(t, c).State()
	got := uniqueName(state, long)
	if got == long || types.ValidateName(got) != nil || len(got) > types.MaxNameLen {
		t.Fatalf("uniqueName(%q) = %q", long, got)
	}
}

func TestJoinThroughTheDaemonWithTheCode(t *testing.T) {
	laptop := newDaemonDevice(t, nil)
	laptop.mustRun("create", "home")
	inv := laptop.start("invite", "--port", "0", "--yes")
	link := inv.waitFor(t, linkRE)[1]
	code := inv.waitFor(t, regexp.MustCompile(`juist join (\d+-[a-z]+-[a-z]+-[a-z]+)`))[1]
	phone := newDaemonDevice(t, hostAt(t, link))
	mustContain(t, phone.mustRun("join", code), "looking for the inviting device", "joined")
	if _, err := inv.wait(t); err != nil {
		t.Fatal(err)
	}
}

// A daemon running an invite gets one admission out of the CLI, and only
// after it offered the invite: a compromised juistd asking again would
// otherwise admit devices of its choosing, one signature each.
func TestAnInviteThroughTheDaemonAdmitsOneDevice(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home")
	var out syncBuffer
	a := c.app(&out, "")
	a.home, _ = openHome(c.home)
	auth := openLog(t, c)
	key, err := a.admittingKey(auth)
	if err != nil {
		t.Fatal(err)
	}
	a.node = &localNode{h: a.home}
	d := &daemonInvite{a: a, auth: auth, adm: &admitter{a: a, key: key}, o: inviteOptions{expires: time.Minute}}
	join := func() *ipc.Event {
		g, err := keys.GenerateNode()
		if err != nil {
			t.Fatal(err)
		}
		return &ipc.Event{Kind: ipc.EventInviteAdmit,
			Join: &enroll.JoinRequest{Name: "evil", Identity: g.Identity.Public(), Keys: g.Public,
				Signing: g.Identity.SigningKey()}}
	}
	var mu sync.Mutex
	replies := 0
	reply := func(ipc.Request) error { mu.Lock(); replies++; mu.Unlock(); return nil }
	ctx := context.Background()
	if err := d.handle(ctx, join(), reply); err == nil {
		t.Fatal("an admission before the invite was offered was answered")
	}
	inv, err := enroll.NewInvite([]netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41642")})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.handle(ctx, &ipc.Event{Kind: ipc.EventInviteReady, Code: inv.Code().String(),
		Link: inv.Link().String()}, reply); err != nil {
		t.Fatal(err)
	}
	if err := d.handle(ctx, join(), reply); err != nil {
		t.Fatalf("the invite's one admission: %v", err)
	}
	if err := d.handle(ctx, join(), reply); err == nil {
		t.Fatal("a second admission in one invite was answered")
	}
	d.admitting.Wait()
	if n := len(openLog(t, c).State().Nodes()); n != 2 || replies != 1 {
		t.Fatalf("%d members and %d answers after one invite", n, replies)
	}
}

// A request naming no valid ML-DSA key is refused before anything is asked
// or signed, and a member asking again under another ML-DSA key is not sent
// an admission for the keys it holds.
func TestAnAdmissionHoldsTheGuestToItsSigningKey(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home")
	var out syncBuffer
	a := c.app(&out, "")
	a.home, _ = openHome(c.home)
	auth := openLog(t, c)
	key, err := a.admittingKey(auth)
	if err != nil {
		t.Fatal(err)
	}
	a.node = &localNode{h: a.home}
	g, err := keys.GenerateNode()
	if err != nil {
		t.Fatal(err)
	}
	adm := &admitter{a: a, key: key}
	d := &daemonInvite{a: a, auth: auth, adm: adm, o: inviteOptions{expires: time.Minute}}
	inv, err := enroll.NewInvite([]netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41642")})
	if err != nil {
		t.Fatal(err)
	}
	reply := func(ipc.Request) error { return nil }
	ctx := context.Background()
	if err := d.handle(ctx, &ipc.Event{Kind: ipc.EventInviteReady, Code: inv.Code().String(),
		Link: inv.Link().String()}, reply); err != nil {
		t.Fatal(err)
	}
	unsigned := &enroll.JoinRequest{Name: "phone", Identity: g.Identity.Public(), Keys: g.Public}
	if err := d.handle(ctx, &ipc.Event{Kind: ipc.EventInviteAdmit, Join: unsigned}, reply); err == nil {
		t.Fatal("a request without a signing key was taken up")
	}
	d.admitting.Wait()

	req := &enroll.JoinRequest{Name: "phone", Identity: g.Identity.Public(), Keys: g.Public,
		Signing: g.Identity.SigningKey()}
	noWait := func(uint32, uint32) error { return nil }
	if _, _, err := adm.Admit(ctx, req, noWait, nil); err != nil {
		t.Fatal(err)
	}
	other, err := keys.GenerateNode()
	if err != nil {
		t.Fatal(err)
	}
	swapped := *req
	swapped.Signing = other.Identity.SigningKey()
	if _, adm, err := adm.Admit(ctx, &swapped, noWait, nil); err == nil || adm != nil {
		t.Fatalf("a member asking under another signing key: %v", err)
	}
}

// With the words compared, a "no" admits nobody.
func TestAdmissionWaitsForTheWordsToMatch(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home")
	var out syncBuffer
	a := c.app(&out, "n")
	a.home, _ = openHome(c.home)
	a.node = &localNode{h: a.home}
	auth := openLog(t, c)
	key, err := a.admittingKey(auth)
	if err != nil {
		t.Fatal(err)
	}
	g, err := keys.GenerateNode()
	if err != nil {
		t.Fatal(err)
	}
	adm := &admitter{a: a, key: key, compare: true}
	nonce := enroll.Nonce{7}
	req := &enroll.JoinRequest{Identity: g.Identity.Public(), Keys: g.Public, Commit: enroll.CommitNonce(nonce)}
	var salt enroll.Salt
	_, _, err = adm.Admit(context.Background(), req, func(uint32, uint32) error { return nil },
		func(s enroll.Salt) (enroll.Nonce, error) { salt = s; return nonce, nil })
	if err == nil || !strings.Contains(err.Error(), "not confirmed") {
		t.Fatalf("admit after a no: %v", err)
	}
	mustContain(t, out.String(), enroll.Fingerprint(salt, nonce, req))
	if len(openLog(t, c).State().Nodes()) != 1 {
		t.Fatal("the device was admitted anyway")
	}

	// The words are made only from the nonce the request committed to: one
	// the device in between chose after seeing the salt is refused.
	out = syncBuffer{}
	_, _, err = adm.Admit(context.Background(), req, func(uint32, uint32) error { return nil },
		func(enroll.Salt) (enroll.Nonce, error) { return enroll.Nonce{8}, nil })
	if err == nil || !strings.Contains(err.Error(), "commitment") {
		t.Fatalf("a nonce other than the committed one: %v", err)
	}
	if strings.Contains(out.String(), "Are they the same?") {
		t.Fatal("words were shown for a nonce the request did not commit to")
	}
}

// Addresses skip the prefix's first and last, and a full prefix says so.
func TestFirstFreeV4(t *testing.T) {
	t.Parallel()
	r := netip.MustParsePrefix("10.111.0.0/28")
	taken := map[netip.Addr]bool{}
	for want := netip.MustParseAddr("10.111.0.1"); want.Less(netip.MustParseAddr("10.111.0.15")); want = want.Next() {
		got, err := firstFreeV4(r, taken)
		if err != nil || got != want {
			t.Fatalf("got %v (%v), want %v", got, err, want)
		}
		taken[got] = true
	}
	if a, err := firstFreeV4(r, taken); err == nil {
		t.Fatalf("a full /28 handed out %v", a)
	}
}

func TestAnAddressIsNeverGivenOutTwice(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home")
	enrollDevice(t, admin, "phone")
	admin.mustRun("remove", "phone", "--yes")
	tablet := enrollDevice(t, admin, "tablet")
	self, _ := openLog(t, admin).State().Node(nodeKeysOf(t, tablet).Identity.Public())
	if self.V4 == nil || *self.V4 == netip.MustParseAddr("198.18.0.2") {
		t.Fatalf("the tablet got %v, the removed phone's address", self.V4)
	}
}

// Names that "juist remove" holds equal are not both admitted.
func TestNamesAreUniqueAsRemoveComparesThem(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "server")
	if got := uniqueName(openLog(t, c).State(), "ſerver"); strings.EqualFold(got, "server") {
		t.Fatalf("uniqueName(ſerver) = %q, which remove cannot tell from server", got)
	}
}

// An admission on a branch that lost fork choice gave out its address too,
// and may be reissued: the next invite must not hand that address on.
func TestInvitesSkipAddressesOnLosingBranches(t *testing.T) {
	t.Parallel()
	for attempt := 0; attempt < 8; attempt++ {
		one := newCLI(t)
		one.mustRun("create", "home")
		two := newCLI(t)
		copyTree(t, one.home, two.home)
		enrollDevice(t, one, "a")
		enrollDevice(t, two, "b")
		enrollDevice(t, two, "c")
		// Records only: each side keeps its own epoch floor, as a daemon
		// receiving the other branch by gossip would.
		copyTree(t, filepath.Join(two.home, logDir, "records"), filepath.Join(one.home, logDir, "records"))

		auth := openLog(t, one)
		if auth.Alarm() != nil {
			t.Fatalf("concurrent admissions raised an alarm: %v", auth.Alarm())
		}
		st, err := store.Open(filepath.Join(one.home, logDir))
		if err != nil {
			t.Fatal(err)
		}
		var lost []netip.Addr
		for _, o := range auth.Orphans() {
			for _, h := range o.Records {
				if aum, err := st.AUM(h); err == nil && aum.Node != nil && aum.Node.V4 != nil {
					lost = append(lost, *aum.Node.V4)
				}
			}
		}
		if len(lost) < 2 {
			continue // the one-admission branch lost; the chain holds every address
		}
		probe := nodeKeysOf(t, enrollDevice(t, one, "probe")).Identity.Public()
		n, ok := openLog(t, one).State().Node(probe)
		if !ok || n.V4 == nil {
			t.Fatal("the probe device was not admitted with an address")
		}
		if slices.Contains(lost, *n.V4) {
			t.Fatalf("the probe was given %v, which a losing branch's admission holds", *n.V4)
		}
		return
	}
	t.Skip("the two-admission branch never lost fork choice")
}

// The link an invite prints is one word to a shell as printed: IPv6
// addresses in brackets are globs to zsh, and commas split nothing but look
// as if they might.
func TestThePrintedLinkIsOneShellWord(t *testing.T) {
	t.Parallel()
	link, err := enroll.NewLink([]netip.AddrPort{
		netip.MustParseAddrPort("[fd00::1]:41642"), netip.MustParseAddrPort("192.168.1.20:41642")})
	if err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	a := newCLI(t).app(&out, "")
	a.announceInvite("home", "", link, DefaultInvitePort, inviteOptions{expires: time.Hour})
	var line string
	for l := range strings.Lines(out.String()) {
		if cmd, ok := strings.CutPrefix(strings.TrimSpace(l), "juist join "); ok {
			line = cmd
		}
	}
	if line == "" {
		t.Fatalf("no join command printed:\n%s", out.String())
	}
	// sh leaves a glob that matches nothing as it is, and zsh fails on it,
	// so the quotes are asserted, and a shell run where there is one.
	if !strings.HasPrefix(line, "'") || !strings.HasSuffix(line, "'") {
		t.Fatalf("the link is printed unquoted: %s", line)
	}
	shell := "sh"
	if _, err := exec.LookPath("zsh"); err == nil {
		shell = "zsh"
	}
	got, err := exec.Command(shell, "-c", `printf '%s|' `+line).Output()
	if err != nil {
		t.Fatalf("%s: %v", shell, err)
	}
	if string(got) != link.String()+"|" {
		t.Fatalf("a shell reads %q as %q, want the link as one word", line, got)
	}
}

// An invite sets each join command apart from the text around it, so a long
// link is selected whole.
func TestTheInviteSetsItsCommandsApart(t *testing.T) {
	t.Parallel()
	link, err := enroll.NewLink([]netip.AddrPort{netip.MustParseAddrPort("10.11.1.11:41642")})
	if err != nil {
		t.Fatal(err)
	}
	link = link.WithRelays([]netip.AddrPort{netip.MustParseAddrPort("203.0.113.34:41645")}, nil)
	var out syncBuffer
	a := newCLI(t).app(&out, "")
	a.announceInvite("lab", "865-endow-millionaire-blockade", link, DefaultInvitePort,
		inviteOptions{expires: time.Hour, lan: true})
	want := "invite to \"lab\", expires in 1h; on the new device:\n\n" +
		"  juist join '" + link.String() + "'\n\n" +
		"meets through relay 203.0.113.34:41645 where this device is unreachable\n\n" +
		"  juist join 865-endow-millionaire-blockade  # same LAN\n\n"
	if got := out.String(); !strings.HasPrefix(got, want) {
		t.Fatalf("the invite reads\n%s\nwant\n%s", got, want)
	}
}

// The change that leaves a checkpoint's worth of records past the last one
// is followed by a checkpoint, with no admin asking; the next is not.
func TestAChangePastTheIntervalIsFollowedByACheckpoint(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home")
	if out := c.mustRun("network", "rename", "first"); strings.Contains(out, "checkpoint") {
		t.Fatalf("the first change drafted a checkpoint:\n%s", out)
	}
	h, err := openHome(c.home)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := h.adminKeyFiles()
	if err != nil || len(keys) != 1 {
		t.Fatalf("admin keys: %d, %v", len(keys), err)
	}
	auth := openLog(t, c)
	b := auth.Builder()
	var records []types.AUM
	for i := range checkpointEvery - 2 {
		rec, err := b.RenameNetwork(fmt.Sprintf("home-%d", i))
		if err == nil {
			err = rec.Sign(keys[0].priv)
		}
		if err != nil {
			t.Fatal(err)
		}
		next, err := b.Dry(&rec)
		if err != nil {
			t.Fatal(err)
		}
		b, records = log.NewBuilder(next), append(records, rec)
	}
	if err := auth.Inform(records...); err != nil {
		t.Fatal(err)
	}
	mustContain(t, c.mustRun("network", "rename", "last"), "checkpoint recorded")
	auth = openLog(t, c)
	head, err := auth.Record(auth.Head())
	if err != nil || head.Kind != types.KindCheckpoint {
		t.Fatalf("the head is no checkpoint: %v", err)
	}
	if out := c.mustRun("network", "rename", "after"); strings.Contains(out, "checkpoint") {
		t.Fatalf("the change after a checkpoint drafted another:\n%s", out)
	}
}

type statusNode struct {
	*localNode
	st *ipc.Status
}

func (n statusNode) restatus() (*ipc.Status, error) { return n.st, nil }

// No checkpoint is drafted of a log juistd holds under an alarm: devices
// would compact to it, past what the alarm is about.
func TestNoCheckpointOfALogUnderAnAlarm(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home")
	h, err := openHome(c.home)
	if err != nil {
		t.Fatal(err)
	}
	auth := openLog(t, c)
	for _, st := range []*ipc.Status{{Derived: ipc.Derived{Alarm: "log: fork alarm"}}, {SchemaAlarm: "too new"}} {
		if unsettled(statusNode{&localNode{h: h}, st}, auth) == nil {
			t.Fatalf("a checkpoint of a log under %+v", st)
		}
	}
	if err := unsettled(statusNode{&localNode{h: h}, &ipc.Status{}}, auth); err != nil {
		t.Fatalf("a settled log: %v", err)
	}
}
