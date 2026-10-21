package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nning/juist/types"
)

// adminKeyNamed loads the keystore's admin key called name.
func adminKeyNamed(t *testing.T, c *cli, name string) types.PrivateIdentity {
	t.Helper()
	priv, ok, err := c.home2().adminKey(name)
	if err != nil || !ok {
		t.Fatalf("admin key %q: found %v, %v", name, ok, err)
	}
	return priv
}

// Networks founded one after another in one keystore are governed by keys of
// their own, neither of which counts in the other network; --admin-key shares
// one on purpose, and "juist admins" shows it under both.
func TestEachNetworkHasAnAdminKeyOfItsOwn(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop", "--admin-name", "alice")
	h.mustRun("create", "work", "--device", "laptop", "--admin-name", "alice")
	home, work := adminKeyNamed(t, h.cli, "alice@home"), adminKeyNamed(t, h.cli, "alice@work")
	if home.Public() == work.Public() {
		t.Fatal("home and work share an admin key")
	}
	homeLog := openLog(t, &cli{t: t, home: h.layout.home(0)})
	workLog := openLog(t, &cli{t: t, home: h.layout.home(1)})
	for _, c := range []struct {
		network    string
		own, other types.PrivateIdentity
		state      interface {
			Admin(types.Identity) (types.AdminKey, bool)
		}
	}{{"home", home, work, homeLog.State()}, {"work", work, home, workLog.State()}} {
		if _, ok := c.state.Admin(c.own.Public()); !ok {
			t.Errorf("%s is not governed by its own key", c.network)
		}
		if _, ok := c.state.Admin(c.other.Public()); ok {
			t.Errorf("%s is governed by the other network's key", c.network)
		}
	}
	intruder, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	aum, err := workLog.Builder().AddAdminKey(types.AdminKey{Public: intruder.Public(), Signing: new(intruder.SigningKey()), Endorsement: intruder.Endorsement(), Votes: 1, Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := aum.Sign(home); err != nil {
		t.Fatal(err)
	}
	if st := workLog.State().SignatureStatus(&aum); st.Authorized() || len(st.Untrusted) != 1 {
		t.Fatalf("home's key on a change to work: %+v", st)
	}
	// The CLI signs a change to work with work's key alone.
	mustContain(t, h.mustRun("admins", "add", "work", "bob",
		adminKeyText(t, intruder)), "added bob's key")

	if _, err := h.run("create", "lab", "--device", "laptop", "--admin-key", "alice@nowhere"); err == nil ||
		!strings.Contains(err.Error(), `no admin key "alice@nowhere"`) {
		t.Fatalf("--admin-key naming no key: %v", err)
	}
	if fileExists(filepath.Join(h.cli.home, breakGlassFile("lab"))) {
		t.Fatal("a refused --admin-key left the network's files behind")
	}
	mustContain(t, h.mustRun("create", "lab", "--device", "laptop", "--admin-key", "alice@home"),
		`using admin key "alice@home"`, `created network "lab"`)
	labLog := openLog(t, &cli{t: t, home: h.layout.home(2)})
	if k, ok := labLog.State().Admin(home.Public()); !ok || k.Holder != "alice" {
		t.Fatalf("lab's admin: %+v, %v; want alice with home's key", k, ok)
	}
	out := h.mustRun("admins")
	for _, want := range []string{`alice@home\s+home, lab\s+nid:`, `alice@work\s+work\s+nid:`} {
		if !regexp.MustCompile(want).MatchString(out) {
			t.Errorf("admins lacks %q:\n%s", want, out)
		}
	}
}

// A keystore from before keys were named for their network signs for its
// network as it did, and its key keeps its name.
func TestAKeyFromBeforeKeysPerNetworkSignsUnchanged(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop", "--admin-name", "alice")
	admins := filepath.Join(c.home, adminsDir)
	if err := os.Rename(filepath.Join(admins, "alice@home.key"), filepath.Join(admins, "alice.key")); err != nil {
		t.Fatal(err)
	}
	bob, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, c.mustRun("admins", "add", "bob", adminKeyText(t, bob)),
		"added bob's key")
	if _, ok := openLog(t, c).State().Admin(bob.Public()); !ok {
		t.Fatal("the change signed with the old key did not apply")
	}
	if !fileExists(filepath.Join(admins, "alice.key")) || fileExists(filepath.Join(admins, "alice@home.key")) {
		t.Fatal("the old key was renamed")
	}
	if out := c.mustRun("admins"); !regexp.MustCompile(`alice\s+home\s+nid:`).MatchString(out) {
		t.Fatalf("admins does not say what the old key governs:\n%s", out)
	}
}

// keyMadeBeforeItsNetwork is a device holding alice's unfiled key, which the
// log it holds names, and the keystore's admins directory.
func keyMadeBeforeItsNetwork(t *testing.T) (*cli, string) {
	t.Helper()
	laptop1 := newCLI(t)
	laptop1.mustRun("create", "home", "--device", "laptop1", "--admin-name", "alice")
	laptop2 := enrollDevice(t, laptop1, "laptop2")
	enrollDevice(t, laptop1, "phone")
	add := regexp.MustCompile(`juist admins add alice (nid:\S+)`).FindStringSubmatch(
		laptop2.mustRun("admins", "new", "alice"))
	if add == nil {
		t.Fatal("admins new printed no command to run")
	}
	admins := filepath.Join(laptop2.home, adminsDir)
	if !fileExists(filepath.Join(admins, "alice.key")) {
		t.Fatal("the new key is not named for its admin alone")
	}
	laptop1.mustRun("admins", "add", "alice", add[1], "--on", "laptop2")
	copyTree(t, filepath.Join(laptop1.home, logDir), filepath.Join(laptop2.home, logDir))
	return laptop2, admins
}

// A key made before its network is filed under it once the network's log
// names it, and signs there.
func TestAKeyMadeBeforeItsNetworkIsFiledUnderIt(t *testing.T) {
	t.Parallel()
	laptop2, admins := keyMadeBeforeItsNetwork(t)
	mustContain(t, laptop2.mustRun("remove", "phone", "--yes"), "removed phone")
	if fileExists(filepath.Join(admins, "alice.key")) || !fileExists(filepath.Join(admins, "alice@home.key")) {
		t.Fatal("the key was not filed under its network")
	}
	if out := laptop2.mustRun("admins"); !regexp.MustCompile(`alice@home\s+home\s+nid:`).MatchString(out) {
		t.Fatalf("admins does not list the filed key:\n%s", out)
	}
}

// Reading the log writes nothing to the keystore; "juist admins" files.
func TestReadingTheLogFilesNoKey(t *testing.T) {
	t.Parallel()
	laptop2, admins := keyMadeBeforeItsNetwork(t)
	for _, args := range [][]string{{"log"}, {"status"}, {"devices"}, {"health"}} {
		_, _ = laptop2.run(args...)
		if !fileExists(filepath.Join(admins, "alice.key")) || fileExists(filepath.Join(admins, "alice@home.key")) {
			t.Fatalf("juist %s filed the key", args[0])
		}
	}
	if out := laptop2.mustRun("admins"); !regexp.MustCompile(`alice@home\s+home\s+nid:`).MatchString(out) {
		t.Fatalf("admins does not file the key:\n%s", out)
	}
}

// An unfiled key a network on this host names is that network's: a new
// network takes it only by the name it is filed under, on purpose.
func TestANewNetworkTakesAnotherNetworksKeyOnlyByItsFiledName(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop", "--admin-name", "first")
	add := regexp.MustCompile(`juist admins add alice (nid:\S+)`).FindStringSubmatch(h.mustRun("admins", "new", "alice"))
	if add == nil {
		t.Fatal("admins new printed no command to run")
	}
	h.mustRun("admins", "add", "alice", add[1])
	if !fileExists(filepath.Join(h.cli.home, adminsDir, "alice.key")) {
		t.Fatal("the key was filed before the test asked for it")
	}
	if _, err := h.run("create", "lab", "--device", "laptop", "--admin-key", "alice"); err == nil ||
		!strings.Contains(err.Error(), `no admin key "alice"`) {
		t.Fatalf("--admin-key naming home's key by its unfiled name: %v", err)
	}
	mustContain(t, h.mustRun("create", "lab", "--device", "laptop", "--admin-key", "alice@home"),
		`using admin key "alice@home"`, `created network "lab"`)
}

// On a machine with no log, keys filed under two networks do not both sign
// a change, which the other's signature would spoil: --key picks one.
func TestWithoutALogKeysOfTwoNetworksSignByName(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	signer := newCLI(t)
	homeKey := regexp.MustCompile(`juist admins add alice (nid:\S+)`).FindStringSubmatch(
		signer.mustRun("admins", "new", "alice"))[1]
	first := newCLI(t)
	first.mustRun("create", "home", "--admin-name", "first", "--quorum", "2", "--admin", "alice="+homeKey)
	genesis := filepath.Join(first.home, genesisFileFor("home"))
	signer.mustRun("approve", "--yes", genesis)
	first.mustRun("apply", genesis)
	// The genesis named the key, and filed it.
	adminKeyNamed(t, signer, "alice@home")

	out := signer.mustRun("--network", "work", "admins", "new", "alice")
	mustContain(t, out, `created admin key "alice@work"`)
	workKey := regexp.MustCompile(`juist admins add alice (nid:\S+)`).FindStringSubmatch(out)[1]
	boss := newCLI(t)
	boss.mustRun("create", "work", "--admin-name", "boss", "--quorum", "2", "--admin", "alice="+workKey)
	genesis = filepath.Join(boss.home, genesisFileFor("work"))
	signer.mustRun("approve", "--yes", genesis)
	boss.mustRun("apply", genesis)

	boss.mustRun("rotate", "group-secret")
	change := filepath.Join(dir, "rotate-group-secret.rec")
	if _, err := signer.run("approve", "--yes", change); err == nil ||
		!strings.Contains(err.Error(), "alice@home, alice@work") || !strings.Contains(err.Error(), "--key") {
		t.Fatalf("both networks' keys offered for one change: %v", err)
	}
	mustContain(t, signer.mustRun("approve", "--yes", "--key", "alice@work", change), "signed as")
	mustContain(t, boss.mustRun("approve", change), "applied")
}

// Without a log, two keys that no network has filed yet do not both sign a
// change either: only one can be the network's.
func TestWithoutALogTwoUnfiledKeysSignByName(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	signer := newCLI(t)
	alice := regexp.MustCompile(`juist admins add alice (nid:\S+)`).FindStringSubmatch(
		signer.mustRun("admins", "new", "alice"))[1]
	signer.mustRun("admins", "new", "carol")
	first := newCLI(t)
	first.mustRun("create", "home", "--admin-name", "first")
	first.mustRun("admins", "add", "alice", alice)
	first.mustRun("admins", "quorum", "2", "--yes")
	first.mustRun("rotate", "group-secret")
	change := filepath.Join(dir, "rotate-group-secret.rec")
	if _, err := signer.run("approve", "--yes", change); err == nil || !strings.Contains(err.Error(), "--key") {
		t.Fatalf("two unfiled keys offered for one change: %v", err)
	}
	mustContain(t, signer.mustRun("approve", "--yes", "--key", "alice", change), "signed as")
	mustContain(t, first.mustRun("approve", change), "applied")
}

// An encryption key's change says whose key it is, once.
func TestAnEncryptionKeysChangeReads(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop", "--admin-name", "alice")
	auth := openLog(t, c)
	k := auth.State().Admins()[0]
	aum, err := auth.Builder().SetAdminRecipient(k.Public, types.RecipientKey{X25519: types.X25519Key{1},
		MLKEM: k.Recipient.MLKEM})
	if err != nil {
		t.Fatal(err)
	}
	got := effect(&aum, auth.State(), 0)
	want := fmt.Sprintf("gives alice's admin key %v on laptop the encryption key %s", k.Public.ShortString(),
		recipientDigest(*aum.Recipient))
	if len(got) != 1 || got[0] != want {
		t.Fatalf("reads %q, want %q", got, want)
	}
}

// A keystore directory someone else owns, as a user's is to root under
// sudo, is not one to file keys in.
func TestKeysAreFiledOnlyInOnesOwnKeystore(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root owns what this test needs someone else to")
	}
	if !ownedByUs(t.TempDir()) || ownedByUs("/") {
		t.Fatal("ownership is not told apart")
	}
}

func adminKeyText(t *testing.T, priv types.PrivateIdentity) string {
	t.Helper()
	s, err := types.AdminKeyText(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
