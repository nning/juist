package main

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/daemon"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

// cli runs the tool in-process against a home directory, returning everything
// it printed. In-process rather than through a built binary so that a failure
// points at a line of code.
type cli struct {
	t    *testing.T
	home string
}

func newCLI(t *testing.T) *cli {
	t.Helper()
	return &cli{t: t, home: filepath.Join(shortTempDir(t), "home")}
}

// shortTempDir is t.TempDir() without the test's name in the path: $home
// holds the control socket, and a sockaddr_un path is capped at 104 bytes on
// macOS and the BSDs, which t.TempDir() alone exceeds under /var/folders. A
// bind over the cap fails with EINVAL, which does not mention length.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "juist")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func (c *cli) run(args ...string) (string, error) {
	c.t.Helper()
	saved := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		c.t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		done <- b.String()
	}()
	runErr := run(append([]string{"-home", c.home}, args...))
	w.Close()
	os.Stdout = saved
	return <-done, runErr
}

func (c *cli) mustRun(args ...string) string {
	c.t.Helper()
	out, err := c.run(args...)
	if err != nil {
		c.t.Fatalf("juist %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// openLog opens the CLI's log directly, for assertions the tool does not print.
func openLog(t *testing.T, c *cli) *log.Authority {
	t.Helper()
	st, err := store.Open(filepath.Join(c.home, logDir))
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	auth, err := log.Open(st)
	if err != nil {
		t.Fatalf("opening the log: %v", err)
	}
	return auth
}

func field(t *testing.T, out, label string) string {
	t.Helper()
	for line := range strings.Lines(out) {
		if after, ok := strings.CutPrefix(strings.TrimSpace(line), label); ok {
			return strings.TrimSpace(after)
		}
	}
	t.Fatalf("no %q line in output:\n%s", label, out)
	return ""
}

// TestFullCeremony walks the whole M1 workflow: create a network, enroll a
// second device through a proposal that is signed and then applied, grant it a
// role, revoke it, and checkpoint. Every step goes through the real log.
func TestFullCeremony(t *testing.T) {
	admin := newCLI(t)
	out := admin.mustRun("init", "-network", "demo", "-node-name", "laptop")
	if !strings.Contains(out, `created network "demo"`) {
		t.Fatalf("init said:\n%s", out)
	}
	overlay := field(t, out, "overlay")
	if !strings.HasPrefix(overlay, "fd") || !strings.HasSuffix(overlay, "/48") {
		t.Fatalf("overlay prefix %q is not a ULA /48", overlay)
	}

	// A second device generates its own keys and hands over the public halves.
	peer := newCLI(t)
	peerOut := peer.mustRun("key", "-create")
	identity := field(t, peerOut, "node identity")
	x := field(t, peerOut, "node x25519")
	m := field(t, peerOut, "node mlkem")

	recPath := filepath.Join(t.TempDir(), "add.rec")
	admin.mustRun("propose", "add-node", "-name", "phone",
		"-identity", identity, "-wg", field(t, peerOut, "node wireguard"), "-x25519", x, "-mlkem", m,
		"-roles", "relay-capable", "-o", recPath)

	// Unsigned, the record must be reported as unauthorized and refused.
	out = admin.mustRun("verify", recPath)
	if !strings.Contains(out, "needs 1 more") {
		t.Fatalf("verify did not report the missing signature:\n%s", out)
	}
	if _, err := admin.run("apply", recPath); err == nil {
		t.Fatal("applied an unsigned record")
	}

	out = admin.mustRun("sign", recPath)
	if !strings.Contains(out, "authorized") {
		t.Fatalf("sign did not report the record as authorized:\n%s", out)
	}
	admin.mustRun("apply", recPath)

	out = admin.mustRun("log", "show")
	if !strings.Contains(out, "phone") || !strings.Contains(out, "relay-capable") {
		t.Fatalf("the member does not appear in the log:\n%s", out)
	}
	if !strings.Contains(out, "members (2)") {
		t.Fatalf("expected two members:\n%s", out)
	}

	// Grant an exit-node role with a default route, which is only legal
	// together with that role.
	routePath := filepath.Join(t.TempDir(), "routes.rec")
	admin.mustRun("propose", "set-routes", "-identity", identity,
		"-roles", "relay-capable,exit-node", "-routes", "0.0.0.0/0,192.168.7.0/24", "-o", routePath)
	admin.mustRun("sign", routePath)
	admin.mustRun("apply", routePath)
	out = admin.mustRun("log", "show")
	if !strings.Contains(out, "0.0.0.0/0") || !strings.Contains(out, "192.168.7.0/24") {
		t.Fatalf("the route grant does not appear in the log:\n%s", out)
	}

	// Revoke, which must bump the epoch.
	epochBefore := field(t, admin.mustRun("verify"), "epoch")
	removePath := filepath.Join(t.TempDir(), "remove.rec")
	admin.mustRun("propose", "remove-node", "-identity", identity, "-o", removePath)
	admin.mustRun("sign", removePath)
	admin.mustRun("apply", removePath)
	out = admin.mustRun("verify")
	if field(t, out, "epoch") == epochBefore {
		t.Fatalf("revocation did not bump the epoch:\n%s", out)
	}
	if strings.Contains(admin.mustRun("log", "show"), identity) {
		t.Fatal("the revoked member is still listed")
	}

	// Checkpoint, then confirm the state survives it.
	cpPath := filepath.Join(t.TempDir(), "cp.rec")
	admin.mustRun("propose", "checkpoint", "-o", cpPath)
	admin.mustRun("sign", cpPath)
	admin.mustRun("apply", cpPath)
	out = admin.mustRun("verify")
	if !strings.Contains(out, "state        ok") {
		t.Fatalf("verify is not clean after a checkpoint:\n%s", out)
	}
	if !strings.Contains(out, "group secret readable by this device") {
		t.Fatalf("this device lost access to the group secret:\n%s", out)
	}
}

// TestQuorumCeremonyAcrossKeystores is the property docs/05-roadmap.md asks for
// at M4 and that the log has to support from here: a change is authorized by
// admins on separate machines, and no machine ever holds k keys.
func TestQuorumCeremonyAcrossKeystores(t *testing.T) {
	first := newCLI(t)
	second := newCLI(t)

	// The second admin's machine holds nothing but its signing key: no
	// network, no log. That is the configuration a quorum depends on — if one
	// machine held both keys, k-of-n would be decoration.
	secondKey := field(t, second.mustRun("key", "-create-admin", "second"), "admin key")

	// With a quorum of two the genesis itself needs a ceremony: init writes
	// the record out for the other admin, and no network exists until it
	// comes back.
	first.mustRun("init", "-network", "twoadmin", "-quorum", "2",
		"-admin", "second="+secondKey)
	st, err := store.Open(filepath.Join(first.home, logDir))
	if err != nil {
		t.Fatalf("the unfinished ceremony left an unopenable store: %v", err)
	}
	if _, ok, err := st.Anchor(); err != nil || ok {
		t.Fatal("a genesis the local key could not authorize created a network anyway")
	}
	genesisRec := filepath.Join(first.home, genesisFile)
	if _, err := os.Stat(genesisRec); err != nil {
		t.Fatalf("init did not leave the genesis record for co-signing: %v", err)
	}

	// With a quorum of one and two admin keys, the founder can create the
	// network; tightening the policy afterwards is a record like any other.
	third := newCLI(t)
	third.mustRun("init", "-network", "twoadmin", "-quorum", "1", "-admin", "second="+secondKey)
	tightenPath := filepath.Join(t.TempDir(), "tighten.rec")
	third.mustRun("propose", "set-quorum", "-k", "2", "-o", tightenPath)
	third.mustRun("sign", tightenPath)
	third.mustRun("apply", tightenPath)

	// Now a change needs both admins. The founder's signature alone is not
	// enough, and the second admin's keystore supplies the rest.
	peer := newCLI(t)
	peerOut := peer.mustRun("key", "-create")
	addPath := filepath.Join(t.TempDir(), "add.rec")
	third.mustRun("propose", "add-node", "-name", "phone",
		"-identity", field(t, peerOut, "node identity"),
		"-wg", field(t, peerOut, "node wireguard"),
		"-x25519", field(t, peerOut, "node x25519"),
		"-mlkem", field(t, peerOut, "node mlkem"),
		"-o", addPath)
	third.mustRun("sign", addPath)
	if _, err := third.run("apply", addPath); err == nil {
		t.Fatal("applied a record with one of two required votes")
	}
	// The second admin signs on its own machine, which holds only its own key.
	second.mustRun("sign", addPath)
	third.mustRun("apply", addPath)
	if !strings.Contains(third.mustRun("log", "show"), "phone") {
		t.Fatal("the two-admin ceremony did not admit the member")
	}
}

func TestInitRefusesSecondNetwork(t *testing.T) {
	c := newCLI(t)
	c.mustRun("init", "-network", "one")
	if _, err := c.run("init", "-network", "two"); err == nil {
		t.Fatal("created a second network in the same home directory")
	}
}

func TestInitRefusesUnreachableQuorum(t *testing.T) {
	c := newCLI(t)
	if _, err := c.run("init", "-network", "impossible", "-quorum", "5"); err == nil {
		t.Fatal("created a network whose quorum exceeds the admin vote weight")
	}
}

func TestProposeRejectsOverlayOverlappingRoute(t *testing.T) {
	c := newCLI(t)
	out := c.mustRun("init", "-network", "demo", "-node-name", "laptop")
	overlay := field(t, out, "overlay")
	identity := field(t, c.mustRun("key"), "node identity")
	_, err := c.run("propose", "set-routes", "-identity", identity,
		"-roles", "exit-node", "-routes", overlay)
	if err == nil {
		t.Fatal("accepted a route grant covering the overlay prefix")
	}
	if !strings.Contains(err.Error(), "overlay") {
		t.Errorf("error should mention the overlay: %v", err)
	}
}

func TestKeyRotationPromotesStagedKeysOnlyOnApply(t *testing.T) {
	c := newCLI(t)
	c.mustRun("init", "-network", "demo", "-node-name", "laptop")
	before := field(t, c.mustRun("key"), "node x25519")

	wgBefore := field(t, c.mustRun("key"), "node wireguard")
	recPath := filepath.Join(t.TempDir(), "rotate.rec")
	c.mustRun("propose", "rotate-key", "-o", recPath)
	// Until the record is applied, this device's keys must not change: the
	// current epoch's wrap is still addressed to them.
	if got := field(t, c.mustRun("key"), "node x25519"); got != before {
		t.Fatal("proposing a rotation already replaced this device's keys")
	}
	if !strings.Contains(c.mustRun("verify"), "group secret readable by this device") {
		t.Fatal("this device lost access to the group secret while a rotation was pending")
	}

	c.mustRun("sign", recPath)
	c.mustRun("apply", recPath)
	if got := field(t, c.mustRun("key"), "node x25519"); got == before {
		t.Fatal("applying the rotation did not promote the staged keys")
	}
	if !strings.Contains(c.mustRun("verify"), "group secret readable by this device") {
		t.Fatal("this device cannot open the group secret after rotating its keys")
	}
	// A rotation replaces every rotatable key, so the log must name the
	// WireGuard key this keystore now holds.
	wgAfter := field(t, c.mustRun("key"), "node wireguard")
	if wgAfter == wgBefore {
		t.Fatal("the rotation did not replace the WireGuard key")
	}
	auth := openLog(t, c)
	id, err := types.ParseIdentity(field(t, c.mustRun("key"), "node identity"))

	if err != nil {
		t.Fatalf("parsing this device's identity: %v", err)
	}
	member, ok := auth.State().Node(id)
	if !ok {
		t.Fatal("this device is not a member after rotating its keys")
	}
	if member.WireGuard.String() != wgAfter {
		t.Fatalf("the log names WireGuard key %v but the keystore holds %s",
			member.WireGuard, wgAfter)
	}
}

// TestStagedKeysNotPromotedWhenRotationLosesForkChoice: a rotation can be
// fully authorized and still lose fork choice, and promoting then would leave
// the device holding keys the log does not name.
func TestStagedKeysNotPromotedWhenRotationLosesForkChoice(t *testing.T) {
	c := newCLI(t)
	c.mustRun("init", "-network", "demo", "-node-name", "laptop")

	// A second member, so there is something to revoke.
	peer := newCLI(t)
	peerOut := peer.mustRun("key", "-create")
	victim := field(t, peerOut, "node identity")
	addPath := filepath.Join(t.TempDir(), "add.rec")
	c.mustRun("propose", "add-node", "-name", "phone",
		"-identity", victim,
		"-wg", field(t, peerOut, "node wireguard"),
		"-x25519", field(t, peerOut, "node x25519"),
		"-mlkem", field(t, peerOut, "node mlkem"),
		"-o", addPath)
	c.mustRun("sign", addPath)
	c.mustRun("apply", addPath)

	wgBefore := field(t, c.mustRun("key"), "node wireguard")

	// Two records against the same head. A revocation always wins fork choice,
	// so the rotation is the branch that gets orphaned.
	rotatePath := filepath.Join(t.TempDir(), "rotate.rec")
	c.mustRun("propose", "rotate-key", "-o", rotatePath)
	c.mustRun("sign", rotatePath)
	removePath := filepath.Join(t.TempDir(), "remove.rec")
	c.mustRun("propose", "remove-node", "-identity", victim, "-o", removePath)
	c.mustRun("sign", removePath)

	c.mustRun("apply", rotatePath, removePath)

	auth := openLog(t, c)
	if auth.State().IsMember(mustIdentity(t, victim)) {
		t.Fatal("the revocation did not win fork choice, so this test proves nothing")
	}
	if got := field(t, c.mustRun("key"), "node wireguard"); got != wgBefore {
		t.Fatal("staged keys were promoted even though the rotation was orphaned")
	}
	member, ok := auth.State().Node(mustIdentity(t, field(t, c.mustRun("key"), "node identity")))
	if !ok {
		t.Fatal("this device stopped being a member")
	}
	if member.WireGuard.String() != wgBefore {
		t.Fatal("the log names keys this device does not hold")
	}
	if !strings.Contains(c.mustRun("verify"), "group secret readable by this device") {
		t.Fatal("this device lost access to the group secret")
	}
}

func mustIdentity(t *testing.T, s string) types.Identity {
	t.Helper()
	id, err := types.ParseIdentity(s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return id
}

func TestVerifyReportsCorruption(t *testing.T) {
	c := newCLI(t)
	c.mustRun("init", "-network", "demo")
	st, err := store.Open(filepath.Join(c.home, logDir))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	anchor, ok, err := st.Anchor()
	if err != nil || !ok {
		t.Fatalf("Anchor: %v (ok=%v)", err, ok)
	}
	name := filepath.Join(c.home, logDir, "records", anchor.String()+".cbor")
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	body[len(body)-1] ^= 0x01
	if err := os.WriteFile(name, body, 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	if _, err := c.run("verify"); err == nil {
		t.Fatal("verify accepted a corrupt log")
	}
}

// TestSignRefusesBrokenStore separates "this machine holds no network" — the
// air-gapped signing keystore, which must work — from "this machine's log is
// damaged", which must not be silently treated as the former.
func TestSignRefusesBrokenStore(t *testing.T) {
	c := newCLI(t)
	c.mustRun("init", "-network", "demo")
	st, err := store.Open(filepath.Join(c.home, logDir))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	anchor, ok, err := st.Anchor()
	if err != nil || !ok {
		t.Fatalf("Anchor: %v (ok=%v)", err, ok)
	}
	name := filepath.Join(c.home, logDir, "records", anchor.String()+".cbor")
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	body[len(body)-1] ^= 0x01
	if err := os.WriteFile(name, body, 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}

	// A record from elsewhere, to be signed.
	other := newCLI(t)
	other.mustRun("init", "-network", "elsewhere")
	peer := newCLI(t)
	peerOut := peer.mustRun("key", "-create")
	recPath := filepath.Join(t.TempDir(), "add.rec")
	other.mustRun("propose", "add-node", "-name", "phone",
		"-identity", field(t, peerOut, "node identity"),
		"-wg", field(t, peerOut, "node wireguard"),
		"-x25519", field(t, peerOut, "node x25519"),
		"-mlkem", field(t, peerOut, "node mlkem"),
		"-o", recPath)

	if _, err := c.run("sign", recPath); err == nil {
		t.Fatal("signed while the local log was corrupt, instead of reporting it")
	}
}

func TestSignRefusesUntrustedKey(t *testing.T) {
	// An operator with a keystore but no membership in this network must not be
	// able to add a signature that would make the record invalid rather than
	// merely unauthorized.
	owner := newCLI(t)
	owner.mustRun("init", "-network", "demo")
	stranger := newCLI(t)
	stranger.mustRun("init", "-network", "elsewhere")

	peer := newCLI(t)
	peerOut := peer.mustRun("key", "-create")
	recPath := filepath.Join(t.TempDir(), "add.rec")
	owner.mustRun("propose", "add-node", "-name", "phone",
		"-identity", field(t, peerOut, "node identity"),
		"-wg", field(t, peerOut, "node wireguard"),
		"-x25519", field(t, peerOut, "node x25519"),
		"-mlkem", field(t, peerOut, "node mlkem"),
		"-o", recPath)
	// Signing it would not merely fail to authorize the record, it would make
	// it invalid — an untrusted signature is rejected outright — so the tool
	// must refuse before touching the file.
	_, err := stranger.run("sign", recPath)
	if err == nil {
		t.Fatal("a stranger's keystore signed a record from another network")
	}
	if !strings.Contains(err.Error(), "another network") {
		t.Errorf("error should explain the record belongs elsewhere: %v", err)
	}
	owner.mustRun("sign", recPath)
	owner.mustRun("apply", recPath)
}

func TestLogShowRecords(t *testing.T) {
	c := newCLI(t)
	c.mustRun("init", "-network", "demo", "-node-name", "laptop")
	out := c.mustRun("log", "show", "-records")
	if !strings.Contains(out, "genesis") {
		t.Fatalf("record listing does not show the genesis record:\n%s", out)
	}
}

// TestHomeIsOwnerOnly checks that nothing in the keystore is readable by anyone
// else: it holds admin signing keys and the break-glass secrets.
func TestHomeIsOwnerOnly(t *testing.T) {
	c := newCLI(t)
	c.mustRun("init", "-network", "demo", "-node-name", "laptop")
	err := filepath.WalkDir(c.home, func(path string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		perm := info.Mode().Perm()
		switch {
		case e.IsDir():
			if perm&0o077 != 0 {
				t.Errorf("directory %s is mode %o", path, perm)
			}
		case strings.HasSuffix(path, ".key") || strings.HasSuffix(path, ".keys") ||
			strings.HasSuffix(path, secretsSuffix):
			if perm&0o077 != 0 {
				t.Errorf("key material %s is mode %o", path, perm)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the home directory: %v", err)
	}
}

const secretsSuffix = ".secrets"

// TestFailedRotationProposalStagesNothing checks that a proposal the log
// refuses leaves no staged key material behind: staging refuses to write over
// an earlier file, so debris blocks every later rotation.
func TestFailedRotationProposalStagesNothing(t *testing.T) {
	c := newCLI(t)
	// A network this device is not a member of: it has node keys, but no
	// membership for a rotation record to name.
	c.mustRun("init", "-network", "demo")
	c.mustRun("key", "-create")

	staged := filepath.Join(c.home, nodeKeysFile+stagedSuffix)
	for _, kind := range []string{"rotate-key", "rotate-identity"} {
		out, err := c.run("propose", kind, "-o", filepath.Join(t.TempDir(), "r.rec"))
		if err == nil {
			t.Fatalf("propose %s succeeded for a device that is not a member\n%s", kind, out)
		}
		if _, err := os.Stat(staged); !os.IsNotExist(err) {
			t.Fatalf("propose %s failed but left %s behind", kind, staged)
		}
	}

	// The proof that nothing is wedged: enrolling the device and rotating for
	// real still works.
	k := c.mustRun("key")
	recPath := filepath.Join(t.TempDir(), "add.rec")
	c.mustRun("propose", "add-node", "-name", "laptop",
		"-identity", field(t, k, "node identity"),
		"-wg", field(t, k, "node wireguard"),
		"-x25519", field(t, k, "node x25519"),
		"-mlkem", field(t, k, "node mlkem"), "-o", recPath)
	c.mustRun("sign", recPath)
	c.mustRun("apply", recPath)
	c.mustRun("propose", "rotate-key", "-o", filepath.Join(t.TempDir(), "rot.rec"))
	if _, err := os.Stat(staged); err != nil {
		t.Fatalf("a rotation that succeeded staged nothing: %v", err)
	}
}

// TestUnreadableKeyFileIsReportedNotIgnored checks that a key file which is
// present but cannot be loaded is an error everywhere, rather than being
// reported as "this device has no keys": conflating the two sends the operator
// to -create, and makes "sign" omit the signature a rotation needs.
func TestUnreadableKeyFileIsReportedNotIgnored(t *testing.T) {
	c := newCLI(t)
	c.mustRun("init", "-network", "demo", "-node-name", "laptop")
	recPath := filepath.Join(t.TempDir(), "bump.rec")
	c.mustRun("propose", "epoch-bump", "-o", recPath)

	keys := filepath.Join(c.home, nodeKeysFile)
	if err := os.Chmod(keys, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	for _, args := range [][]string{{"key"}, {"sign", recPath}} {
		out, err := c.run(args...)
		if err == nil {
			t.Errorf("juist %s ignored an unreadable %s\n%s", strings.Join(args, " "), keys, out)
			continue
		}
		if !strings.Contains(err.Error(), "mode 644") {
			t.Errorf("juist %s: error does not name the problem: %v", strings.Join(args, " "), err)
		}
	}

	// verify reports rather than aborts, the way it does for a fork alarm, but
	// it has to say so: silently printing nothing is what it did before.
	out := c.mustRun("verify")
	if !strings.Contains(out, "mode 644") {
		t.Errorf("juist verify did not report an unreadable %s\n%s", keys, out)
	}
}

// TestUnreadableStagedKeysAreReportedOnApply is the same rule for the staged
// file: swallowing its error would report a rotation applied while leaving the
// keys the log now names unpromoted.
func TestUnreadableStagedKeysAreReportedOnApply(t *testing.T) {
	c := newCLI(t)
	c.mustRun("init", "-network", "demo", "-node-name", "laptop")
	recPath := filepath.Join(t.TempDir(), "rotate.rec")
	c.mustRun("propose", "rotate-key", "-o", recPath)
	c.mustRun("sign", recPath)

	staged := filepath.Join(c.home, nodeKeysFile+stagedSuffix)
	if err := os.Chmod(staged, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	out, err := c.run("apply", recPath)
	if err == nil {
		t.Fatalf("apply ignored an unreadable %s\n%s", staged, out)
	}
	if !strings.Contains(err.Error(), "mode 644") {
		t.Errorf("apply: error does not name the problem: %v", err)
	}
}

// TestMemberNameIsCheckedWhereItIsChosen checks that a name the log will not
// accept is refused at the machine that chooses it, rather than by whoever
// runs the enrollment command it was printed into.
func TestMemberNameIsCheckedWhereItIsChosen(t *testing.T) {
	tooLong := strings.Repeat("a", types.MaxNameLen+1)

	t.Run("key -create", func(t *testing.T) {
		c := newCLI(t)
		c.mustRun("init", "-network", "demo")
		if _, err := c.run("key", "-create", "-name", tooLong); err == nil {
			t.Fatal("key -create accepted a name over the schema's limit")
		}
		// Refused, not half-applied: the keys are still absent, so the
		// operator can simply run the command again with a shorter name.
		if _, err := os.Stat(filepath.Join(c.home, nodeKeysFile)); !os.IsNotExist(err) {
			t.Fatal("key -create rejected the name but wrote the keys anyway")
		}
		c.mustRun("key", "-create", "-name", "laptop")
	})

	t.Run("init -node-name", func(t *testing.T) {
		c := newCLI(t)
		if _, err := c.run("init", "-network", "demo", "-node-name", tooLong); err == nil {
			t.Fatal("init accepted a node name over the schema's limit")
		}
		// The ceremony writes files that refuse to be overwritten, so a
		// rejected one has to leave none of them behind or the operator
		// cannot retry.
		for _, name := range []string{nodeKeysFile, disablementFile, adminsDir} {
			if _, err := os.Stat(filepath.Join(c.home, name)); !os.IsNotExist(err) {
				t.Errorf("init failed but left %s behind; a retry will refuse to overwrite it", name)
			}
		}
		c.mustRun("init", "-network", "demo", "-node-name", "laptop")
	})

	t.Run("enrollment command works as printed", func(t *testing.T) {
		c := newCLI(t)
		c.mustRun("init", "-network", "demo")
		k := c.mustRun("key", "-create", "-name", "laptop")
		if !strings.Contains(k, `-name "laptop"`) {
			t.Fatalf("key did not print the chosen name in the enrollment command:\n%s", k)
		}
		// The command "juist key" prints has to be one that runs.
		recPath := filepath.Join(t.TempDir(), "add.rec")
		c.mustRun("propose", "add-node", "-name", "laptop",
			"-identity", field(t, k, "node identity"),
			"-wg", field(t, k, "node wireguard"),
			"-x25519", field(t, k, "node x25519"),
			"-mlkem", field(t, k, "node mlkem"), "-o", recPath)
		c.mustRun("sign", recPath)
		c.mustRun("apply", recPath)
	})

	t.Run("hand-edited name in the key file", func(t *testing.T) {
		c := newCLI(t)
		c.mustRun("init", "-network", "demo", "-node-name", "laptop")
		keys := filepath.Join(c.home, nodeKeysFile)
		body, err := os.ReadFile(keys)
		if err != nil {
			t.Fatal(err)
		}
		// A name carrying an ANSI escape would otherwise be printed straight
		// to the operator's terminal.
		edited := regexpReplaceNameLine(string(body), "\x1b[2K\rmember")
		if err := os.WriteFile(keys, []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := c.run("key"); err == nil {
			t.Fatal("a key file naming the device with a control sequence loaded without complaint")
		}
	})
}

// regexpReplaceNameLine rewrites the persisted name to want, leaving the rest
// of the key file alone.
func regexpReplaceNameLine(body, want string) string {
	var out []string
	for line := range strings.Lines(body) {
		if strings.HasPrefix(strings.TrimSpace(line), nameTag+" ") {
			line = nameTag + " " + b64.EncodeToString([]byte(want)) + "\n"
		}
		out = append(out, line)
	}
	return strings.Join(out, "")
}

// TestMultiAdminGenesisCeremonyCompletes walks a 2-of-2 genesis through:
// started on one machine, signed on another that holds nothing but its admin
// key, and created back on the first. This is the ceremony k-of-n exists for.
func TestMultiAdminGenesisCeremonyCompletes(t *testing.T) {
	founder := newCLI(t)
	other := newCLI(t)
	otherKey := field(t, other.mustRun("key", "-create-admin", "other"), "admin key")

	out := founder.mustRun("init", "-network", "ceremony", "-quorum", "2",
		"-admin", "other="+otherKey)
	if !strings.Contains(out, "needs 1 more") {
		t.Fatalf("init did not report what the ceremony still needs:\n%s", out)
	}
	rec := filepath.Join(founder.home, genesisFile)

	// Applying it early is refused, and says why rather than reading as a
	// broken record.
	if _, err := founder.run("apply", rec); err == nil {
		t.Fatal("an under-signed genesis created a network")
	} else if !strings.Contains(err.Error(), "1 more") {
		t.Errorf("apply did not report the missing vote weight: %v", err)
	}

	// The record travels to the other admin's machine, which has no network of
	// its own and never will.
	travelled := filepath.Join(t.TempDir(), genesisFile)
	copyFile(t, rec, travelled)
	signed := other.mustRun("sign", travelled)
	if !strings.Contains(signed, "authorized") {
		t.Fatalf("the second admin's keystore did not report the genesis authorized:\n%s", signed)
	}
	copyFile(t, travelled, rec)

	founder.mustRun("apply", rec)
	auth := openLog(t, founder)
	if got := auth.State().Network(); got != "ceremony" {
		t.Fatalf("network name %q, want %q", got, "ceremony")
	}
	if q, total := auth.State().Quorum(), auth.State().TotalVotes(); q != 2 || total != 2 {
		t.Fatalf("quorum %d of %d votes, want 2 of 2", q, total)
	}
	// A network created this way is a normal one: it takes both admins to
	// change it, which is what the ceremony was for.
	bumpPath := filepath.Join(t.TempDir(), "bump.rec")
	founder.mustRun("propose", "epoch-bump", "-o", bumpPath)
	founder.mustRun("sign", bumpPath)
	if _, err := founder.run("apply", bumpPath); err == nil {
		t.Fatal("one admin of two reached quorum on its own")
	}
	other.mustRun("sign", bumpPath)
	founder.mustRun("apply", bumpPath)
}

// TestSignWarnsWhenTheParentIsNotTheHead: a record on a stale parent is judged
// against the state there, so if the admin set moved in between, a signature
// by a current admin is untrusted at that parent and invalidates the record
// outright — and a signature cannot be taken back.
func TestSignWarnsWhenTheParentIsNotTheHead(t *testing.T) {
	c := newCLI(t)
	c.mustRun("init", "-network", "demo")

	// Built while the founder is the only admin, and left unsigned.
	stale := filepath.Join(t.TempDir(), "stale.rec")
	c.mustRun("propose", "epoch-bump", "-o", stale)

	// The admin set then changes underneath it.
	secondKey := field(t, c.mustRun("key", "-create-admin", "second"), "admin key")
	addAdmin := filepath.Join(t.TempDir(), "add-admin.rec")
	c.mustRun("propose", "add-admin", "-name", "second", "-key", secondKey, "-o", addAdmin)
	c.mustRun("sign", addAdmin)
	c.mustRun("apply", addAdmin)

	out, err := c.run("sign", stale)
	if err != nil {
		t.Fatalf("sign: %v\n%s", err, out)
	}
	// The verdict must not be reported against a state the record will never be
	// judged by. Reporting it is how an operator is told to apply a record that
	// signing has just invalidated.
	if strings.Contains(out, "authorized — apply it") {
		t.Errorf("sign reported a stale-parent record as ready to apply:\n%s", out)
	}
	// The trap is real: the new admin's signature is untrusted at the parent,
	// so the record is now rejected outright rather than merely forking.
	if _, err := c.run("apply", stale); err == nil {
		t.Error("a record carrying a signature untrusted at its parent was applied")
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatalf("reading %s: %v", from, err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatalf("writing %s: %v", to, err)
	}
}

// TestSharedWritableHomeRefused holds the keystore directory to the rule
// trust/store applies to the log directory: a writable directory undoes the
// key files' own modes, since one can be replaced or a new one dropped in.
func TestSharedWritableHomeRefused(t *testing.T) {
	c := newCLI(t)
	c.mustRun("init", "-network", "demo")
	if err := os.Chmod(c.home, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	out, err := c.run("key")
	if err == nil {
		t.Fatalf("a world-writable keystore was accepted\n%s", out)
	}
	if !strings.Contains(err.Error(), "chmod 700") {
		t.Errorf("the error does not say how to fix it: %v", err)
	}
	if err := os.Chmod(c.home, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	c.mustRun("key")
}

// TestStatusWithoutADaemon: the common answer, whose underlying failure is a
// bare ENOENT from connect(2) and reads like a bug unless it is translated.
func TestStatusWithoutADaemon(t *testing.T) {
	c := newCLI(t)
	c.mustRun("key", "-create", "-name", "laptop")
	_, err := c.run("status")
	if err == nil {
		t.Fatal("status succeeded with no daemon running")
	}
	if !strings.Contains(err.Error(), "no daemon is running") {
		t.Errorf("error %q does not say that no daemon is running", err)
	}
}

// TestStatusRefusedByPermission: a packaged daemon runs as its own account, so
// a socket the caller may not connect to is an ordinary answer rather than a
// bug, and the message has to name the account to run as instead.
func TestStatusRefusedByPermission(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is not subject to the mode bits this test refuses with")
	}
	c := newCLI(t)
	c.mustRun("key", "-create", "-name", "laptop")

	sock := daemon.SocketPath(c.home)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	if err := os.Chmod(sock, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if _, err := c.run("status"); err == nil {
		t.Fatal("status succeeded against a socket it may not connect to")
	} else if !strings.Contains(err.Error(), "not permitted to reach the daemon") {
		t.Errorf("error %q does not say the call was refused", err)
	} else if self, uerr := user.Current(); uerr == nil &&
		!strings.Contains(err.Error(), "sudo -u "+self.Username) {
		t.Errorf("error %q does not name the account that owns the state directory", err)
	}
}

// TestKeyRotationPromotesWhenADaemonOwnsTheLog is the same property as
// TestKeyRotationPromotesStagedKeysOnlyOnApply with a daemon running, so
// "apply" hands the record over IPC. Promotion is still the CLI's job: the
// daemon never reads staged keys.
func TestKeyRotationPromotesWhenADaemonOwnsTheLog(t *testing.T) {
	c := newCLI(t)
	c.mustRun("init", "-network", "demo", "-node-name", "laptop")
	before := field(t, c.mustRun("key"), "node x25519")

	recPath := filepath.Join(t.TempDir(), "rotate.rec")
	c.mustRun("propose", "rotate-key", "-o", recPath)
	c.mustRun("sign", recPath)

	stopDaemon := startDaemonOn(t, c.home)
	defer stopDaemon()

	c.mustRun("apply", recPath)
	if got := field(t, c.mustRun("key"), "node x25519"); got == before {
		t.Fatal("applying through the daemon did not promote the staged keys")
	}
	if !strings.Contains(c.mustRun("verify"), "group secret readable by this device") {
		t.Fatal("this device cannot open the group secret after rotating through the daemon")
	}
}

// startDaemonOn runs a daemon over a CLI home directory, with a data plane
// that records rather than connects and LAN discovery off: what is under test
// is which process owns the log, not the mesh.
func startDaemonOn(t *testing.T, home string) func() {
	t.Helper()
	k, err := keys.LoadNode(filepath.Join(home, keys.NodeKeysFile))
	if err != nil {
		t.Fatalf("loading node keys: %v", err)
	}
	st, err := store.Open(filepath.Join(home, keys.LogDir))
	if err != nil {
		t.Fatalf("opening the log: %v", err)
	}
	auth, err := log.Open(st)
	if err != nil {
		t.Fatalf("opening the authority: %v", err)
	}
	d, err := daemon.New(daemon.Options{
		Authority: auth, Storage: st,
		Identity: k.Identity, Recipient: k.Recipient, WireGuard: k.WireGuardPrivate(),
		Connect:          func(conn.Options) (conn.Manager, error) { return stubManager{}, nil },
		DisableDiscovery: true,
		DisableDHT:       true,
		SocketPath:       daemon.SocketPath(home),
		Logf:             func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("starting the daemon: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go d.Run(ctx)
	// Wait for the control socket to answer, so the CLI does not race the
	// daemon's accept loop and quietly take the no-daemon path instead.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := daemon.Call(daemon.SocketPath(home), daemon.Request{Command: daemon.CmdStatus}); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			d.Close()
			t.Fatal("the daemon never answered on its control socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return func() { cancel(); d.Close() }
}

// stubManager is a data plane that accepts everything and does nothing.
type stubManager struct{}

func (stubManager) SetPeers([]conn.Peer) error             { return nil }
func (stubManager) SetRelays([]conn.Relay) error           { return nil }
func (stubManager) HomeRelay() int                         { return 0 }
func (stubManager) LocalEndpoints() []netip.AddrPort       { return nil }
func (stubManager) LocalPort() uint16                      { return 41641 }
func (stubManager) Ping(netip.Addr, func(conn.PingResult)) {}
func (stubManager) Close() error                           { return nil }

// TestSignOnAnUnenrolledDeviceDoesNotRuinTheRecord: a device with node keys
// and no network is sent the record admitting it and runs "sign" out of
// caution. An untrusted signature invalidates the record outright, and
// log.SelfSigner decides from the record alone, so no log is needed to refuse.
func TestSignOnAnUnenrolledDeviceDoesNotRuinTheRecord(t *testing.T) {
	admin := newCLI(t)
	admin.mustRun("init", "-network", "demo")

	device := newCLI(t)
	out := device.mustRun("key", "-create")
	recPath := filepath.Join(t.TempDir(), "add.rec")
	admin.mustRun("propose", "add-node", "-name", "phone",
		"-identity", field(t, out, "node identity"),
		"-wg", field(t, out, "node wireguard"),
		"-x25519", field(t, out, "node x25519"),
		"-mlkem", field(t, out, "node mlkem"),
		"-o", recPath)
	admin.mustRun("sign", recPath)

	// The device signs its own enrollment record: nothing may be added.
	before, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatal(err)
	}
	device.run("sign", recPath)
	after, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("signing on the enrolling device changed the record")
	}

	// The record must still be one the admin's log accepts.
	if _, err := admin.run("apply", recPath); err != nil {
		t.Fatalf("the record no longer applies after the device signed it: %v", err)
	}
}

// TestStagedKeysPromoteWhenTheRotationArrivesElsewhere: a rotation is normally
// applied on an admin's machine and reaches the device as log records, with no
// CLI run there. Opening the state directory is what promotes the staged keys,
// which is what makes the daemon's advice to restart true.
func TestStagedKeysPromoteWhenTheRotationArrivesElsewhere(t *testing.T) {
	c := newCLI(t)
	c.mustRun("init", "-network", "demo", "-node-name", "laptop")
	before := field(t, c.mustRun("key"), "node wireguard")

	recPath := filepath.Join(t.TempDir(), "rotate.rec")
	c.mustRun("propose", "rotate-key", "-o", recPath)
	c.mustRun("sign", recPath)

	// The record is applied to the log without this device's CLI promoting
	// anything — what gossip delivering it to a running daemon looks like.
	auth := openLog(t, c)
	rec, err := readRecordFile(recPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.Inform(rec); err != nil {
		t.Fatalf("applying the rotation to the log directly: %v", err)
	}
	if got := field(t, c.mustRun("key"), "node wireguard"); got != before {
		t.Fatal("the keys were promoted by something other than opening the directory")
	}

	// Opening the state directory, as juistd does at startup.
	fresh := openLog(t, c)
	promoted, err := keys.MaybePromoteStaged(c.home, fresh.State().Node)
	if err != nil {
		t.Fatalf("promoting staged keys: %v", err)
	}
	if promoted == nil {
		t.Fatal("the log names this device's staged keys and they were not promoted")
	}
	after := field(t, c.mustRun("key"), "node wireguard")
	if after == before {
		t.Fatal("the keystore still holds the old WireGuard key")
	}
	id, err := types.ParseIdentity(field(t, c.mustRun("key"), "node identity"))
	if err != nil {
		t.Fatal(err)
	}
	member, ok := fresh.State().Node(id)
	if !ok {
		t.Fatal("this device is not a member after the rotation")
	}
	if member.WireGuard.String() != after {
		t.Fatalf("the log names %v but the keystore holds %s", member.WireGuard, after)
	}
}

// TestAWritableAdminsDirIsRefused: the check on the home directory does not
// see a subdirectory restored from a backup with its stored mode, and anyone
// who can write to admins/ can replace or delete a signing key.
func TestAWritableAdminsDirIsRefused(t *testing.T) {
	c := newCLI(t)
	c.mustRun("init", "-network", "demo", "-node-name", "laptop")
	admins := filepath.Join(c.home, adminsDir)
	if err := os.Chmod(admins, 0o770); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(admins, 0o700) })

	out, err := c.run("verify")
	if err == nil {
		t.Fatalf("ran with a group-writable admins directory; output was:\n%s", out)
	}
	if !strings.Contains(err.Error(), adminsDir) {
		t.Errorf("the error does not name the directory at fault: %v", err)
	}
}

// TestUnwritableOutputStagesNothing: a rotation whose record never reached the
// operator must leave no staged keys, or staging — which refuses to write over
// an earlier rotation — blocks every later rotation over a file the failing
// command never named.
func TestUnwritableOutputStagesNothing(t *testing.T) {
	c := newCLI(t)
	c.mustRun("init", "-network", "demo", "-node-name", "laptop")

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if os.Geteuid() == 0 {
		t.Skip("root is not subject to the mode bits this test refuses with")
	}

	staged := filepath.Join(c.home, nodeKeysFile+stagedSuffix)
	if out, err := c.run("propose", "rotate-key", "-o", filepath.Join(dir, "rot.rec")); err == nil {
		t.Fatalf("propose wrote to an unwritable directory\n%s", out)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatalf("a rotation whose record was never written left %s behind", staged)
	}
	// And the next rotation, to a path that works, is not blocked by it.
	c.mustRun("propose", "rotate-key", "-o", filepath.Join(t.TempDir(), "rot.rec"))
	if _, err := os.Stat(staged); err != nil {
		t.Fatalf("the retried rotation staged nothing: %v", err)
	}
}

// TestSecondRotationRefusesBeforeEmittingARecord: staging refuses to write
// over an earlier rotation, and that refusal has to arrive before the record
// does. Otherwise the operator holds a rotation record naming keys this device
// never kept — and applying it cuts the device off the network.
func TestSecondRotationRefusesBeforeEmittingARecord(t *testing.T) {
	c := newCLI(t)
	c.mustRun("init", "-network", "demo", "-node-name", "laptop")
	c.mustRun("propose", "rotate-key", "-o", filepath.Join(t.TempDir(), "first.rec"))

	second := filepath.Join(t.TempDir(), "second.rec")
	out, err := c.run("propose", "rotate-key", "-o", second)
	if err == nil {
		t.Fatalf("a second rotation was allowed over staged keys\n%s", out)
	}
	if _, err := os.Stat(second); !os.IsNotExist(err) {
		t.Fatal("the refused rotation wrote its record anyway")
	}

	// The same rule on the path that prints to stdout rather than to a file.
	out, err = c.run("propose", "rotate-key")
	if err == nil {
		t.Fatalf("a second rotation printed a record over staged keys\n%s", out)
	}
	if strings.Contains(out, recordTag) {
		t.Fatalf("the refused rotation printed a record anyway:\n%s", out)
	}
}

// TestProposeRefusesToOverwriteARecord: a record collects signatures in place,
// so writing over one silently discards the ceremony it was holding.
func TestProposeRefusesToOverwriteARecord(t *testing.T) {
	c := newCLI(t)
	c.mustRun("init", "-network", "demo", "-node-name", "laptop")
	rec := filepath.Join(t.TempDir(), "bump.rec")
	c.mustRun("propose", "epoch-bump", "-o", rec)
	c.mustRun("sign", rec)
	before, err := os.ReadFile(rec)
	if err != nil {
		t.Fatalf("reading the signed record: %v", err)
	}

	out, err := c.run("propose", "epoch-bump", "-o", rec)
	if err == nil {
		t.Fatalf("propose overwrote a record that was collecting signatures\n%s", out)
	}
	after, err := os.ReadFile(rec)
	if err != nil {
		t.Fatalf("reading the record afterwards: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the refused propose changed the record anyway")
	}
}

// TestInitChecksEveryCeremonyFileFirst: init writes three files it will not
// write over, so a failure at the third must not leave a home that can neither
// finish the ceremony nor start it again.
func TestInitChecksEveryCeremonyFileFirst(t *testing.T) {
	c := newCLI(t)
	// A device with keys already, so the node-enrolment step of a ceremony
	// naming a member is the one that cannot proceed.
	c.mustRun("key", "-create", "-name", "laptop")

	out, err := c.run("init", "-network", "demo", "-node-name", "laptop")
	if err == nil {
		t.Fatalf("init enrolled a node over existing keys\n%s", out)
	}
	for _, name := range []string{filepath.Join(adminsDir, "admin.key"), disablementFile, genesisFile} {
		if _, err := os.Stat(c.home + "/" + name); !os.IsNotExist(err) {
			t.Fatalf("a refused init left %s behind", name)
		}
	}

	// The proof it is not wedged: the ceremony this home *can* run still runs.
	c.mustRun("init", "-network", "demo")
}
