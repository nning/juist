package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

func TestRotateOnAnAdminDevice(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home")
	before := nodeKeysOf(t, c)
	mustContain(t, c.mustRun("rotate"), "rotated this device's keys", "new keys live")
	after := nodeKeysOf(t, c)
	if after.Public == before.Public {
		t.Fatal("rotate did not replace the keys")
	}
	if after.Identity.Public() != before.Identity.Public() {
		t.Fatal("rotate changed the device's identity")
	}
	member, _ := openLog(t, c).State().Node(after.Identity.Public())
	if member.WireGuard != after.Public.WireGuard || member.X25519 != after.Public.X25519 {
		t.Fatal("the log names keys this device does not hold")
	}
	mustContain(t, c.mustRun("log", "verify"), "group secret: ok")
}

func TestRotateIdentity(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--device", "laptop")
	before := nodeKeysOf(t, c).Identity.Public()
	c.mustRun("rotate", "identity")
	after := nodeKeysOf(t, c).Identity.Public()
	state := openLog(t, c).State()
	if after == before || state.IsMember(before) || !state.IsMember(after) {
		t.Fatal("the identity rotation did not move the membership to the new key")
	}
	if n, _ := state.Node(after); n.Name != "laptop" || n.V4 == nil {
		t.Fatalf("the rotated member lost its name or address: %+v", n)
	}
}

// TestRotationOnAMemberWaitsForAnAdmin: a device without an admin key stages
// its new keys and hands the record to an admin; nothing changes until the
// log names the new keys, and then the device's copy promotes them.
func TestRotationOnAMemberWaitsForAnAdmin(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	admin := newCLI(t)
	admin.mustRun("create", "home")
	phone := enrollDevice(t, admin, "phone")
	before := nodeKeysOf(t, phone)

	out := phone.mustRun("rotate")
	mustContain(t, out, "1 more vote", "juist approve rotate-phone.rec")
	if nodeKeysOf(t, phone).Public != before.Public {
		t.Fatal("the keys changed before any admin approved the rotation")
	}
	mustContain(t, phone.mustRun("log", "verify"), "group secret: ok")

	pending := filepath.Join(dir, "rotate-phone.rec")
	mustContain(t, admin.mustRun("approve", "--yes", pending), "applied")
	mustContain(t, phone.mustRun("apply", pending), "new keys live")
	after := nodeKeysOf(t, phone)
	member, _ := openLog(t, admin).State().Node(after.Identity.Public())
	if after.Public == before.Public || member.WireGuard != after.Public.WireGuard {
		t.Fatal("the approved rotation did not leave the device holding the keys the log names")
	}
}

// TestRotationThatLosesForkChoiceIsNotPromoted: a rotation can be approved
// and still lose to a concurrent removal, and promoting then would leave the
// device holding keys the log does not name.
func TestRotationThatLosesForkChoiceIsNotPromoted(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	first, second := newCLI(t), newCLI(t)
	key := regexp.MustCompile(`(nid:\S+)`).FindString(second.mustRun("admins", "new", "second"))
	first.mustRun("create", "home", "--admin", "second="+key)
	phone := enrollDevice(t, first, "phone")
	first.mustRun("admins", "quorum", "2", "--yes")
	// The second admin approves a removal only where the log is: on a device
	// of its own, admitted with its own vote.
	inv, link := startInvite(t, first)
	joined := second.start("join", link, "--name", "desk")
	inv.waitFor(t, regexp.MustCompile(`juist approve add-desk\.rec`))
	second.mustRun("approve", "--yes", filepath.Join(dir, "add-desk.rec"))
	first.mustRun("apply", filepath.Join(dir, "add-desk.rec"))
	if out, err := inv.wait(t); err != nil {
		t.Fatalf("invite: %v\n%s", err, out)
	}
	if out, err := joined.wait(t); err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}

	before := nodeKeysOf(t, first).Public
	first.mustRun("rotate")
	first.mustRun("remove", "phone", "--yes")
	rotate, remove := filepath.Join(dir, "rotate-"+fileSafe(displayName(nodeKeysOf(t, first)))+".rec"),
		filepath.Join(dir, "remove-phone.rec")
	second.mustRun("approve", "--yes", "--no-apply", rotate, remove)
	// The removal was started with the rotation, and undoes it.
	mustContain(t, first.mustRun("apply", rotate, remove), "lost to a concurrent change")

	state := openLog(t, first).State()
	if state.IsMember(nodeKeysOf(t, phone).Identity.Public()) {
		t.Fatal("the removal did not win fork choice, so this test proves nothing")
	}
	if nodeKeysOf(t, first).Public != before {
		t.Fatal("staged keys were promoted although the rotation was orphaned")
	}
	mustContain(t, first.mustRun("log", "verify"), "group secret: ok")
}

// TestFailedRotationStagesNothing: staging refuses to write over an earlier
// rotation, so debris from one that never produced a record would block
// every later one.
func TestFailedRotationStagesNothing(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home", "--no-device")
	if _, err := c.home2().createNodeKeys("laptop"); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(c.home, nodeKeysFile+stagedSuffix)
	for _, args := range [][]string{{"rotate"}, {"rotate", "identity"}} {
		if out, err := c.run(args...); err == nil {
			t.Fatalf("%v succeeded for a device that is not a member\n%s", args, out)
		}
		if _, err := os.Stat(staged); !os.IsNotExist(err) {
			t.Fatalf("%v failed but left %s behind", args, staged)
		}
	}
}

// TestUnwritablePendingDirectoryStagesNothing: a rotation whose record could
// not be saved must leave no staged keys behind.
func TestUnwritablePendingDirectoryStagesNothing(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root is not subject to the mode bits this test refuses with")
	}
	dir := workDir(t)
	admin := newCLI(t)
	admin.mustRun("create", "home")
	phone := enrollDevice(t, admin, "phone")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if out, err := phone.run("rotate"); err == nil {
		t.Fatalf("rotate saved a record into an unwritable directory\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(phone.home, nodeKeysFile+stagedSuffix)); !os.IsNotExist(err) {
		t.Fatal("a rotation whose record was never written left staged keys behind")
	}
	os.Chmod(dir, 0o700)
	phone.mustRun("rotate")
}

// TestSecondRotationIsRefusedBeforeARecord: the refusal must arrive before a
// record naming keys this device never kept.
func TestSecondRotationIsRefusedBeforeARecord(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	admin := newCLI(t)
	admin.mustRun("create", "home")
	phone := enrollDevice(t, admin, "phone")
	phone.mustRun("rotate")
	if out, err := phone.run("rotate"); err == nil {
		t.Fatalf("a second rotation was allowed over staged keys\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "rotate-phone-2.rec")); !os.IsNotExist(err) {
		t.Fatal("the refused rotation wrote a record anyway")
	}
}

// TestRotationThroughARunningDaemon: with a daemon owning the log and the
// device's keys, the daemon stages them, signs its part, and switches to them
// once the log names them, with no restart.
func TestRotationThroughARunningDaemon(t *testing.T) {
	t.Parallel()
	d := newDaemonDevice(t, nil)
	d.mustRun("create", "home")
	load := func() types.NodeKeys {
		k, err := keys.LoadNode(filepath.Join(d.state, nodeKeysFile))
		if err != nil {
			t.Fatal(err)
		}
		return k.Public
	}
	before := load()
	mustContain(t, d.mustRun("rotate"), "rotated this device's keys")
	if load() == before {
		t.Fatal("the daemon did not switch to the rotated keys")
	}
}

// TestAMemberRotatesThroughItsDaemon: the daemon stages the keys and signs its
// part, an admin approves, and applying it on the device switches the daemon
// to the new keys without a restart.
func TestAMemberRotatesThroughItsDaemon(t *testing.T) {
	t.Parallel()
	dir := workDir(t)
	laptop := newDaemonDevice(t, nil)
	laptop.mustRun("create", "home")
	phone := newDaemonDevice(t, nil)
	inv := laptop.start("invite", "--no-lan", "--port", "0", "--yes")
	phone.mustRun("join", inv.waitFor(t, linkRE)[1], "--name", "phone")
	if _, err := inv.wait(t); err != nil {
		t.Fatal(err)
	}
	before, err := keys.LoadNode(filepath.Join(phone.state, nodeKeysFile))
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, phone.mustRun("rotate"), "juist approve rotate-phone.rec")
	pending := filepath.Join(dir, "rotate-phone.rec")
	laptop.mustRun("approve", "--yes", pending)
	phone.mustRun("apply", pending) // a no-op where gossip brought it first
	after, err := keys.LoadNode(filepath.Join(phone.state, nodeKeysFile))
	if err != nil {
		t.Fatal(err)
	}
	if after.Public == before.Public {
		t.Fatal("the daemon did not switch to the rotated keys")
	}
	mustContain(t, phone.mustRun("log", "verify"), "group secret: ok")

	// Abandoning a rotation leaves the device as it was.
	phone.mustRun("rotate")
	mustContain(t, phone.mustRun("rotate", "abandon"), "rotation abandoned")
	if _, err := os.Stat(filepath.Join(phone.state, nodeKeysFile+stagedSuffix)); !os.IsNotExist(err) {
		t.Fatal("the abandoned keys are still staged")
	}
}

// The CLI signs a rotation the daemon built only if its own log builds the
// same record: a compromised juistd must not be able to pass off an
// admission or a quorum change as its rotation and collect the admin's vote.
func TestRotationRecordsFromTheDaemonAreChecked(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create")
	auth := openLog(t, c)
	me := nodeKeysOf(t, c).Identity
	self := me.Public()
	// signed signs a record as a device holding keys would, and proves it
	// with prover's key.
	type rotation struct {
		aum   *types.AUM
		proof types.Sig
	}
	signed := func(a types.AUM, prover types.PrivateIdentity, keys ...types.PrivateIdentity) rotation {
		t.Helper()
		a.Signatures = nil
		for _, k := range keys {
			if err := a.Sign(k); err != nil {
				t.Fatal(err)
			}
		}
		proof, err := prover.Sign(ipc.RotationProof(&a))
		if err != nil {
			t.Fatal(err)
		}
		return rotation{&a, proof}
	}
	check := func(identity bool, r rotation) error {
		return checkRotation(auth, self, identity, r.aum, r.proof)
	}
	fresh, err := keys.GenerateNode()
	if err != nil {
		t.Fatal(err)
	}
	good, err := auth.Builder().RotateNodeKey(self, fresh.Public, sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := check(false, signed(good, me, me)); err != nil {
		t.Fatalf("the honest rotation was refused: %v", err)
	}
	if err := check(true, signed(good, me, me)); err == nil {
		t.Error("a key rotation passed as an identity rotation")
	}
	if check(false, signed(good, me)) == nil {
		t.Error("a rotation without the device's signature passed")
	}
	quorum, err := auth.Builder().SetQuorum(1)
	if err == nil {
		quorum.Subject = &self
		if check(false, signed(quorum, me)) == nil {
			t.Error("a quorum change passed as a rotation")
		}
	}
	other, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	admit, err := auth.Builder().AddNode(types.NodeRecord{Identity: other.Public(), Name: "intruder",
		WireGuard: fresh.Public.WireGuard, X25519: fresh.Public.X25519, MLKEM: fresh.Public.MLKEM}, sealer())
	if err != nil {
		t.Fatal(err)
	}
	admit.Subject = &self
	if check(false, signed(admit, me)) == nil {
		t.Error("an admission passed as a rotation")
	}
	k := fresh.Public
	k.WireGuard[0] ^= 1
	tampered := good
	tampered.Keys = &k
	if check(false, signed(tampered, me, me)) != nil {
		// Different keys are a different honest rotation; what matters is
		// that the rest of the record is the log's.
		t.Error("a rotation to other keys was refused")
	}
	stale := good
	prev := types.Hash{1}
	stale.Prev = &prev
	if check(false, signed(stale, me, me)) == nil {
		t.Error("a rotation on another head passed")
	}

	// Which device this is, is the daemon's word. Under schema 0 an identity
	// rotation carries only the new key's signature, so one claiming to be
	// this device could move its slot to a key of its own, were it not for
	// the proof by the key it claims.
	auth = schema0Log(t, auth, self)
	taken, err := auth.Builder().RotateIdentity(self, other.Public(), sealer())
	if err != nil {
		t.Fatal(err)
	}
	if check(true, signed(taken, other, other)) == nil {
		t.Error("an identity rotation proved by another key passed")
	}
	if err := check(true, signed(taken, me, other)); err != nil {
		t.Errorf("the honest identity rotation was refused: %v", err)
	}
}
