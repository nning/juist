package main

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
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
		if keystore.expectAdmitted(sock, enroll.Link{}.WithAdmin(admin.Public(), new(admin.SigningKey())), a, guest.Public(), noOrphans) == nil {
			t.Errorf("an admission %v not by the link's admin was taken", a)
		}
	}

	keystore, err := openHome(filepath.Join(shortTempDir(t), "keystore"))
	if err != nil {
		t.Fatal(err)
	}
	stranger2, _ := types.GenerateIdentity()
	if keystore.expectAdmitted(sock, enroll.Link{}.WithAdmin(admin.Public(), new(admin.SigningKey())), admitted, stranger2.Public(), noOrphans) == nil {
		t.Fatal("another device's admission anchored this keystore")
	}
	if err := keystore.expectAdmitted(sock, enroll.Link{}.WithAdmin(admin.Public(), new(admin.SigningKey())), admitted, guest.Public(), noOrphans); err != nil {
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

// A copy of the pinned head, which a late signature or a relay's stripped one
// makes, continues the log even where the daemon holds the pinned copy no
// more, while another record in its place does not.
func TestACopyOfThePinnedHeadContinuesTheLog(t *testing.T) {
	t.Parallel()
	var admins []types.PrivateIdentity
	var adminKeys []types.AdminKey
	for i := range 3 {
		priv, err := types.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		admins = append(admins, priv)
		adminKeys = append(adminKeys, types.AdminKey{Public: priv.Public(), Votes: 1, Name: string(rune('a' + i)),
			Signing: new(priv.SigningKey()), Endorsement: priv.Endorsement()})
	}
	secret := make([]byte, types.DisablementSecretSize)
	rand.Read(secret)
	sealer := func(epoch uint64, members []types.NodeRecord) (*types.EpochRecord, error) {
		_, rec, err := secrets.NewEpoch(epoch, members)
		return rec, err
	}
	genesis, err := log.Genesis("net", 2, adminKeys, []types.Hash{types.DisablementCommit(secret)}, nil, sealer)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range admins[:2] {
		if err := genesis.Sign(k); err != nil {
			t.Fatal(err)
		}
	}
	bump := func() types.AUM {
		auth, err := log.FromRecords(log.NewMemStorage(), []types.AUM{genesis})
		if err != nil {
			t.Fatal(err)
		}
		r, err := auth.Builder().EpochBump(sealer)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range admins[:2] {
			if err := r.Sign(k); err != nil {
				t.Fatal(err)
			}
		}
		return r
	}
	var rec, lower types.AUM
	for {
		rec = bump()
		c := rec.Clone()
		if err := c.Sign(admins[2]); err != nil {
			t.Fatal(err)
		}
		if c.Hash().Compare(rec.Hash()) < 0 {
			lower = *c
			break
		}
	}
	// What a daemon holding chain hands over: the chain, and no copy off it.
	handOver := func(chain ...types.AUM) ([]types.AUM, *log.Authority) {
		recs := append([]types.AUM{genesis}, chain...)
		auth, err := log.FromRecords(log.NewMemStorage(), recs)
		if err != nil {
			t.Fatal(err)
		}
		return recs, auth
	}
	keystore, err := openHome(filepath.Join(shortTempDir(t), "keystore"))
	if err != nil {
		t.Fatal(err)
	}
	sock := "/run/juist/juistd.sock"
	recs, auth := handOver(rec)
	if err := keystore.checkPin(sock, auth, recs, noOrphans); err != nil {
		t.Fatal(err)
	}
	other := bump()
	recs, auth = handOver(other)
	if err := keystore.checkPin(sock, auth, recs, noOrphans); err == nil {
		t.Fatal("another record in the pinned head's place was taken")
	}
	recs, auth = handOver(lower)
	if err := keystore.checkPin(sock, auth, recs, noOrphans); err != nil {
		t.Fatalf("a copy of the pinned head: %v", err)
	}
}

// twoAdminNetwork is a genesis two admin keys sign for, at quorum one, and a
// record on it setting domain, signed by keys alone.
func twoAdminNetwork(t *testing.T) (genesis types.AUM, admins []types.PrivateIdentity,
	record func(domain string, keys ...int) types.AUM) {
	t.Helper()
	var adminKeys []types.AdminKey
	for i := range 2 {
		priv, err := types.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		admins = append(admins, priv)
		adminKeys = append(adminKeys, types.AdminKey{Public: priv.Public(), Votes: 1, Name: string(rune('a' + i)),
			Signing: new(priv.SigningKey()), Endorsement: priv.Endorsement()})
	}
	secret := make([]byte, types.DisablementSecretSize)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	sealer := func(epoch uint64, members []types.NodeRecord) (*types.EpochRecord, error) {
		_, rec, err := secrets.NewEpoch(epoch, members)
		return rec, err
	}
	genesis, err := log.Genesis("net", 1, adminKeys, []types.Hash{types.DisablementCommit(secret)}, nil, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if err := genesis.Sign(admins[0]); err != nil {
		t.Fatal(err)
	}
	auth, err := log.FromRecords(log.NewMemStorage(), []types.AUM{genesis})
	if err != nil {
		t.Fatal(err)
	}
	return genesis, admins, func(domain string, keys ...int) types.AUM {
		r, err := auth.Builder().SetDomain(domain)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			if err := r.Sign(admins[k]); err != nil {
				t.Fatal(err)
			}
		}
		return r
	}
}

// pinAt writes the pin a build that stored no content left on head.
func pinAt(t *testing.T, h *home, genesis, head types.Hash) {
	t.Helper()
	if err := h.pinsReady(); err != nil {
		t.Fatal(err)
	}
	b, err := cbor.Marshal(pin{Head: head})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.pinPath(genesis), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A pin without content, as older builds wrote, continues on a log that holds
// another copy of its head alone where the signatures of the pinned copy are
// among those the daemon holds, and is given its content; it is refused where
// they are not, and where another record stands in its place.
func TestAContentlessPinOnAPrunedCopyContinuesTheLog(t *testing.T) {
	t.Parallel()
	genesis, _, record := twoAdminNetwork(t)
	pinned, both := record("example.org", 0), record("example.org", 0, 1)
	sock := "/run/juist/juistd.sock"
	check := func(pinnedHead types.Hash, onChain types.AUM, orphans ...types.AUM) (*home, error) {
		t.Helper()
		keystore, err := openHome(filepath.Join(shortTempDir(t), "keystore"))
		if err != nil {
			t.Fatal(err)
		}
		pinAt(t, keystore, genesis.Hash(), pinnedHead)
		records := []types.AUM{genesis, onChain}
		auth, err := log.FromRecords(log.NewMemStorage(), records)
		if err != nil {
			t.Fatal(err)
		}
		return keystore, keystore.checkPin(sock, auth, records, func() ([]types.AUM, error) { return orphans, nil })
	}

	keystore, err := check(pinned.Hash(), both)
	if err != nil {
		t.Fatalf("a copy carrying the pinned copy's signatures: %v", err)
	}
	if p, err := keystore.loadPin(genesis.Hash()); err != nil || p.Content == nil || *p.Content != both.SigHash() {
		t.Fatalf("the pin was not given its content: %+v, %v", p, err)
	}
	second := record("example.org", 1)
	if _, err := check(second.Hash(), pinned, both); err != nil {
		t.Fatalf("the pinned copy's signatures on the chain's copy and an orphan: %v", err)
	}
	if _, err := check(both.Hash(), pinned); err == nil {
		t.Fatal("a copy lacking a signature the pinned copy carried was taken for it")
	}
	if _, err := check(pinned.Hash(), record("example.net", 0, 1)); err == nil {
		t.Fatal("another record in the pinned head's place was taken")
	}
}

// A join pins the content of the admitted head, which the daemon holds then,
// so the pin continues once the daemon holds a copy of it alone that carries
// none of the admitted copy's signatures.
func TestAnAdmissionPinsTheAdmittedHeadsContent(t *testing.T) {
	t.Parallel()
	genesis, admins, record := twoAdminNetwork(t)
	admitted, other := record("example.org", 0), record("example.org", 1)
	guest, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	a, err := enroll.SignAdmission(admins[0], genesis.Hash(), admitted.Hash(), guest.Public())
	if err != nil {
		t.Fatal(err)
	}
	keystore, err := openHome(filepath.Join(shortTempDir(t), "keystore"))
	if err != nil {
		t.Fatal(err)
	}
	sock := "/run/juist/juistd.sock"
	link := enroll.Link{}.WithAdmin(admins[0].Public(), new(admins[0].SigningKey()))
	held := func() ([]types.AUM, error) { return []types.AUM{genesis, admitted}, nil }
	if err := keystore.expectAdmitted(sock, link, a, guest.Public(), held); err != nil {
		t.Fatal(err)
	}
	records := []types.AUM{genesis, other}
	auth, err := log.FromRecords(log.NewMemStorage(), records)
	if err != nil {
		t.Fatal(err)
	}
	if err := keystore.checkPin(sock, auth, records, noOrphans); err != nil {
		t.Fatalf("a copy of the admitted head: %v", err)
	}
}
