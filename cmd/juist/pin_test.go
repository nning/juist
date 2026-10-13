package main

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

func noOrphans() ([]types.AUM, error) { return nil, nil }

func chainOf(t *testing.T, c *cli) ([]types.AUM, *log.Authority) {
	t.Helper()
	h, err := openHome(c.home)
	if err != nil {
		t.Fatal(err)
	}
	records, err := (&localNode{h: h}).chain()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := log.FromRecords(log.NewMemStorage(), records)
	if err != nil {
		t.Fatal(err)
	}
	return records, auth
}

// The keystore holds a daemon to the network it last verified there: a log
// that does not continue it, or another network at the same socket, is
// refused, while the network's own growth is not.
func TestTheKeystoreAnchorsWhatItVerified(t *testing.T) {
	t.Parallel()
	real, other := newCLI(t), newCLI(t)
	real.mustRun("create", "home")
	other.mustRun("create", "elsewhere")
	keystore, err := openHome(filepath.Join(shortTempDir(t), "keystore"))
	if err != nil {
		t.Fatal(err)
	}
	sock := "/run/juist/juistd.sock"

	recs, auth := chainOf(t, real)
	if err := keystore.checkPin(sock, auth, recs, noOrphans); err != nil {
		t.Fatalf("the first sight of a network: %v", err)
	}
	real.mustRun("grant", filepath.Base(displayName(nodeKeysOf(t, real))), "relay")
	recs, auth = chainOf(t, real)
	if err := keystore.checkPin(sock, auth, recs, noOrphans); err != nil {
		t.Fatalf("the network's own next record: %v", err)
	}

	// Another network where the daemon held this one.
	orecs, oauth := chainOf(t, other)
	if err := keystore.checkPin(sock, oauth, orecs, noOrphans); err == nil || !strings.Contains(err.Error(), "now holds network") {
		t.Fatalf("a daemon that switched networks: %v", err)
	}

	// A checkpoint of the other network's making that claims this one's
	// genesis: consistent in itself, and not what the keystore verified.
	fake, err := oauth.Builder().Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	g := auth.State().GenesisHash()
	fake.State.GenesisHash = &g
	h, err := openHome(other.home)
	if err != nil {
		t.Fatal(err)
	}
	admins, err := h.adminKeys()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range admins {
		if err := fake.Sign(k); err != nil {
			t.Fatal(err)
		}
	}
	fauth, err := log.FromRecords(log.NewMemStorage(), []types.AUM{fake})
	if err != nil {
		t.Skipf("the log itself refuses the counterfeit checkpoint: %v", err)
	}
	if fauth.State().GenesisHash() != g {
		t.Fatal("the counterfeit does not claim the real genesis")
	}
	if err := keystore.checkPin("/other.sock", fauth, []types.AUM{fake}, noOrphans); err == nil ||
		!strings.Contains(err.Error(), "does not continue") {
		t.Fatalf("a counterfeit checkpoint claiming the network: %v", err)
	}
}

// orphansOf is what a daemon over c's store would answer for its records off
// the active chain.
func orphansOf(t *testing.T, c *cli) func() ([]types.AUM, error) {
	t.Helper()
	return func() ([]types.AUM, error) {
		st, err := store.Open(filepath.Join(c.home, logDir))
		if err != nil {
			return nil, err
		}
		recs, _ := chainOf(t, c)
		on := map[types.Hash]bool{}
		for i := range recs {
			on[recs[i].Hash()] = true
		}
		hashes, err := st.Hashes()
		if err != nil {
			return nil, err
		}
		var out []types.AUM
		for _, h := range hashes {
			if !on[h] {
				aum, err := st.AUM(h)
				if err != nil {
					return nil, err
				}
				out = append(out, aum)
			}
		}
		return out, nil
	}
}

// A head that lost fork choice to a concurrent removal is no alarm: the
// branch it lost on is shown, and fork choice here picks the same winner.
func TestTheAnchorFollowsForkChoice(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home")
	enrollDevice(t, admin, "phone")
	twin := newCLI(t)
	copyTree(t, admin.home, twin.home)
	admin.mustRun("grant", "phone", "relay")
	keystore, err := openHome(filepath.Join(shortTempDir(t), "keystore"))
	if err != nil {
		t.Fatal(err)
	}
	sock := "/run/juist/juistd.sock"
	recs, auth := chainOf(t, admin)
	if err := keystore.checkPin(sock, auth, recs, noOrphans); err != nil {
		t.Fatal(err)
	}
	// Another admin removes phone on a sibling of the grant; revocations
	// win, so the grant — the pinned head — is orphaned.
	twin.mustRun("remove", "phone", "--yes")
	trecs, _ := chainOf(t, twin)
	if err := openLog(t, admin).Inform(trecs[len(trecs)-1]); err != nil {
		t.Fatal(err)
	}
	recs, auth = chainOf(t, admin)
	if slices.ContainsFunc(recs, func(a types.AUM) bool { return a.Kind == types.KindSetNodeRoutes }) {
		t.Skip("the removal did not orphan the grant")
	}
	if err := keystore.checkPin(sock, auth, recs, noOrphans); err == nil {
		t.Fatal("a head gone without its branch shown was accepted")
	}
	if err := keystore.checkPin(sock, auth, recs, orphansOf(t, admin)); err != nil {
		t.Fatalf("a legitimate fork resolution: %v", err)
	}
}

// A daemon that truncates the log to an older head cannot pass the later
// history off as a lost branch: fork choice here would pick it.
func TestTheAnchorRefusesARollback(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home")
	name := displayName(nodeKeysOf(t, c))
	c.mustRun("grant", name, "relay")
	c.mustRun("revoke", name, "relay")
	keystore, err := openHome(filepath.Join(shortTempDir(t), "keystore"))
	if err != nil {
		t.Fatal(err)
	}
	sock := "/run/juist/juistd.sock"
	recs, auth := chainOf(t, c)
	if err := keystore.checkPin(sock, auth, recs, noOrphans); err != nil {
		t.Fatal(err)
	}
	short := recs[:len(recs)-2]
	sauth, err := log.FromRecords(log.NewMemStorage(), short)
	if err != nil {
		t.Fatal(err)
	}
	cut := func() ([]types.AUM, error) { return recs[len(recs)-2:], nil }
	for _, orphans := range []func() ([]types.AUM, error){noOrphans, cut} {
		if err := keystore.checkPin(sock, sauth, short, orphans); err == nil {
			t.Fatal("a truncated log was accepted")
		}
	}
}

// A join by a link that names its admin anchors the keystore in what that
// admin signed, not in whatever log the daemon hands back first: a juistd
// compromised before the join cannot have its own network pinned.
func TestAJoinAnchorsTheAdmittedNetwork(t *testing.T) {
	t.Parallel()
	real, other := newCLI(t), newCLI(t)
	real.mustRun("create", "home")
	other.mustRun("create", "elsewhere")
	recs, auth := chainOf(t, real)
	orecs, oauth := chainOf(t, other)
	h, err := openHome(real.home)
	if err != nil {
		t.Fatal(err)
	}
	admins, err := h.adminKeys()
	if err != nil {
		t.Fatal(err)
	}
	admin := admins[0]
	guest, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := enroll.SignAdmission(admin, auth.State().GenesisHash(), auth.Head(), guest.Public())
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	forged, err := enroll.SignAdmission(stranger, oauth.State().GenesisHash(), oauth.Head(), guest.Public())
	if err != nil {
		t.Fatal(err)
	}
	sock := "/run/juist/juistd.sock"
	for _, a := range []*enroll.Admission{nil, forged} {
		keystore, err := openHome(filepath.Join(shortTempDir(t), "keystore"))
		if err != nil {
			t.Fatal(err)
		}
		if keystore.expectAdmitted(sock, enroll.Link{}.WithAdmin(admin.Public(), new(admin.SigningKey())), a, guest.Public()) == nil {
			t.Errorf("an admission %v not by the link's admin was taken", a)
		}
	}

	keystore, err := openHome(filepath.Join(shortTempDir(t), "keystore"))
	if err != nil {
		t.Fatal(err)
	}
	stranger2, _ := types.GenerateIdentity()
	if keystore.expectAdmitted(sock, enroll.Link{}.WithAdmin(admin.Public(), new(admin.SigningKey())), admitted, stranger2.Public()) == nil {
		t.Fatal("another device's admission anchored this keystore")
	}
	if err := keystore.expectAdmitted(sock, enroll.Link{}.WithAdmin(admin.Public(), new(admin.SigningKey())), admitted, guest.Public()); err != nil {
		t.Fatal(err)
	}
	if err := keystore.checkPin(sock, oauth, orecs, noOrphans); err == nil {
		t.Fatal("the daemon's own network was pinned in place of the admitted one")
	}
	if err := keystore.checkPin(sock, auth, recs, noOrphans); err != nil {
		t.Fatalf("the admitted network: %v", err)
	}
}

// A daemon answering with more orphans than any honest one sends is not
// worked through: it could otherwise keep the CLI resolving forks for as
// long as it liked.
func TestTooManyOrphansAreNotResolved(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home")
	recs, auth := chainOf(t, c)
	flood := func() ([]types.AUM, error) { return make([]types.AUM, maxOrphans+1), nil }
	if lost, _ := lostForkChoice(recs[0].Hash(), auth, recs, flood); lost {
		t.Fatal("a flood of orphans was taken as a lost fork choice")
	}
}

// Two sockets are two daemons, whatever their paths look like.
func TestSocketPinsDoNotCollide(t *testing.T) {
	t.Parallel()
	h, err := openHome(filepath.Join(shortTempDir(t), "keystore"))
	if err != nil {
		t.Fatal(err)
	}
	if h.daemonPinPath("/run/a_b.sock") == h.daemonPinPath("/run/a/b.sock") {
		t.Fatal("two sockets share a pin")
	}
}

// A daemon that cannot show where the pinned head went is reported for
// that, not as a rollback.
func TestAnOrphansFailureIsReportedAsSuch(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home")
	recs, auth := chainOf(t, c)
	keystore, err := openHome(filepath.Join(shortTempDir(t), "keystore"))
	if err != nil {
		t.Fatal(err)
	}
	sock := "/run/juist/juistd.sock"
	c.mustRun("grant", filepath.Base(displayName(nodeKeysOf(t, c))), "relay")
	later, lauth := chainOf(t, c)
	if err := keystore.checkPin(sock, lauth, later, noOrphans); err != nil {
		t.Fatal(err)
	}
	broken := func() ([]types.AUM, error) { return nil, errors.New("the daemon hung up") }
	err = keystore.checkPin(sock, auth, recs, broken)
	if err == nil || !strings.Contains(err.Error(), "the daemon hung up") {
		t.Fatalf("got %v", err)
	}
}
