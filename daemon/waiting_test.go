package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/waiting"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// waitingDaemon runs device i of nw with its waiting changes kept at path.
func waitingDaemon(t *testing.T, nw *network, i int, path string, clock *fakeClock) (*Daemon, *log.Authority) {
	t.Helper()
	auth, st := nw.authorityFor(t)
	self := nw.devices[i]
	d, err := New(Options{
		Authority: auth, Storage: st,
		Identity: self.identity, Recipient: self.recipient, WireGuard: self.wgPrivate,
		Connect:          func(conn.Options) (conn.Manager, error) { return &fakeManager{}, nil },
		DisableDiscovery: true, DisableDHT: true,
		WaitingPath: path,
		Clock:       clock.Now,
		Logf:        safeLogf(t, ""),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d, auth
}

// sealedChange hands on a removal of device i of nw as signer, sealed to an
// admin key of its own.
func sealedChange(t *testing.T, nw *network, auth *log.Authority, i int, signer types.PrivateIdentity,
	now time.Time) []byte {
	t.Helper()
	aum, err := auth.Builder().RemoveNode(nw.devices[i].identity.Public(), nw.sealer())
	if err != nil {
		t.Fatal(err)
	}
	return sealedAUM(t, auth, aum, signer, now)
}

// sealedAUM hands on aum as signer, sealed to an admin key of its own.
func sealedAUM(t *testing.T, auth *log.Authority, aum types.AUM, signer types.PrivateIdentity, now time.Time) []byte {
	t.Helper()
	if err := aum.Sign(signer); err != nil {
		t.Fatal(err)
	}
	reader, err := secrets.AdminRecipient(signer.Seed())
	if err != nil {
		t.Fatal(err)
	}
	r, _ := reader.Recipient()
	c, err := waiting.Seal(auth.State().GenesisHash(), &aum, []types.AdminKey{{Public: signer.Public(), Votes: 1,
		Recipient: &r}}, signer, types.Identity{}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A daemon holds a change that fits its log, handed on by a current admin
// key, and drops every other: one by a key that is none, one built on
// another head, one expired, one that no longer fits once the log moves, and
// the same again when replayed. What it holds outlives a restart.
func TestADaemonHoldsOnlyChangesThatFit(t *testing.T) {
	nw := newNetworkWithAdminDevices(t, 3, 0, 1)
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	path := filepath.Join(t.TempDir(), "waiting.cbor")
	d, auth := waitingDaemon(t, nw, 0, path, clock)

	stranger, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := clock.Now()
	if err := d.OfferWaiting([][]byte{sealedChange(t, nw, auth, 2, stranger, now)}); err == nil {
		t.Error("held a change handed on by a key that is no admin's")
	}
	if err := d.OfferWaiting([][]byte{sealedChange(t, nw, auth, 2, nw.admin, now.Add(-2*time.Hour))}); err == nil {
		t.Error("held an expired change")
	}
	if err := d.OfferWaiting([][]byte{sealedChange(t, nw, auth, 2, nw.admin, now.Add(time.Hour))}); err == nil {
		t.Error("held a change handed on an hour from now")
	}
	if err := d.OfferWaiting([][]byte{[]byte("not a change")}); err == nil {
		t.Error("held bytes that are no change")
	}
	good := sealedChange(t, nw, auth, 2, nw.admin, now)
	if err := d.OfferWaiting([][]byte{good}); err != nil {
		t.Fatalf("a change that fits: %v", err)
	}
	if got := d.Waiting(); len(got) != 1 || d.Status().Waiting != 1 {
		t.Fatalf("holds %d changes, status says %d; want 1", len(got), d.Status().Waiting)
	}

	restarted, _ := waitingDaemon(t, nw, 0, path, clock)
	if got := restarted.Waiting(); len(got) != 1 {
		t.Fatalf("after a restart, holds %d changes", len(got))
	}

	bump, err := auth.Builder().EpochBump(nw.sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := bump.Sign(nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := d.Inform([]types.AUM{bump}); err != nil {
		t.Fatal(err)
	}
	// The reconcile the change brought pruned it: not the listing.
	if n := d.Status().Waiting; n != 0 {
		t.Fatalf("holds %d changes the log has moved past", n)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw [][]byte
	if err := cbor.Unmarshal(b, &raw); err != nil || len(raw) != 0 {
		t.Fatalf("the file keeps %d changes the log has moved past (%v)", len(raw), err)
	}
	if err := d.OfferWaiting([][]byte{good}); err == nil {
		t.Fatal("took a replayed change that no longer fits the log")
	}
}

// A daemon hands a change to an admin device, but not to one without the
// role, nor to the device the change is about; and it takes none from its
// peers unless it is an admin device itself.
func TestADaemonHandsChangesToAdminDevicesAlone(t *testing.T) {
	nw := newNetworkWithAdminDevices(t, 4, 0, 1, 3)
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	d, auth := waitingDaemon(t, nw, 0, "", clock)
	change := sealedChange(t, nw, auth, 3, nw.admin, clock.Now())
	if err := d.OfferWaiting([][]byte{change}); err != nil {
		t.Fatal(err)
	}
	w := (*waitingAdapter)(d)
	if got := w.For(nw.devices[1].identity.Public(), nil); len(got) != 1 {
		t.Errorf("an admin device is handed %d changes", len(got))
	}
	if got := w.For(nw.devices[1].identity.Public(), w.Held(nw.devices[1].identity.Public())); len(got) != 0 {
		t.Errorf("an admin device holding the change is handed it again")
	}
	if got := w.For(nw.devices[2].identity.Public(), nil); len(got) != 0 {
		t.Errorf("a device without the admin role is handed %d changes", len(got))
	}
	if got := w.For(nw.devices[3].identity.Public(), nil); len(got) != 0 {
		t.Errorf("the device a removal is about is handed it")
	}

	plain, _ := waitingDaemon(t, nw, 2, "", clock)
	if (*waitingAdapter)(plain).Take([][]byte{change}) || len(plain.Waiting()) != 0 {
		t.Error("a device without the admin role took a change from a peer")
	}
}

// One admin key cannot fill a device's room for waiting changes, and two
// copies of one change by one signer settle on the same one everywhere.
func TestOneSignerCannotFillTheRoom(t *testing.T) {
	nw := newNetworkWithAdminDevices(t, 2, 0)
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	d, auth := waitingDaemon(t, nw, 0, "", clock)
	other, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	add, err := auth.Builder().AddAdminKey(types.AdminKey{Public: other.Public(), Votes: 1, Name: "other"})
	if err != nil {
		t.Fatal(err)
	}
	if err := add.Sign(nw.admin); err != nil {
		t.Fatal(err)
	}
	if err := d.Inform([]types.AUM{add}); err != nil {
		t.Fatal(err)
	}
	rename := func(signer types.PrivateIdentity, i int) []byte {
		aum, err := auth.Builder().RenameNetwork(fmt.Sprintf("n%d", i))
		if err != nil {
			t.Fatal(err)
		}
		return sealedAUM(t, auth, aum, signer, clock.Now())
	}
	for i := range maxWaitingPerSignerCount {
		if err := d.OfferWaiting([][]byte{rename(nw.admin, i)}); err != nil {
			t.Fatalf("change %d: %v", i, err)
		}
	}
	if err := d.OfferWaiting([][]byte{rename(nw.admin, 99)}); err == nil {
		t.Fatal("one signer held more than its share of the room")
	}
	if err := d.OfferWaiting([][]byte{rename(other, 0)}); err != nil {
		t.Fatalf("another admin's change, beside a full share: %v", err)
	}

	// On the genesis head, which each fresh daemon below holds.
	fresh, _ := nw.authorityFor(t)
	aum, err := fresh.Builder().RenameNetwork("tie")
	if err != nil {
		t.Fatal(err)
	}
	a, b := sealedAUM(t, fresh, aum, nw.admin, clock.Now()), sealedAUM(t, fresh, aum, nw.admin, clock.Now())
	keep := a
	if waiting.Hash(b).Compare(waiting.Hash(a)) < 0 {
		keep = b
	}
	for _, order := range [][][]byte{{a, b}, {b, a}} {
		e, _ := waitingDaemon(t, nw, 0, "", clock)
		for _, c := range order {
			_ = e.OfferWaiting([][]byte{c})
		}
		held := (*waitingAdapter)(e).Held(nw.devices[0].identity.Public())
		if len(held) != 1 || held[0] != waiting.Hash(keep) {
			t.Fatalf("offered in one order, holds %v; want the one copy %v", held, waiting.Hash(keep))
		}
	}
}

// A device says what it holds only to an admin device, and only where it is
// one; an expired copy is handed to nobody.
func TestHeldChangesAreSaidToAdminDevicesAlone(t *testing.T) {
	nw := newNetworkWithAdminDevices(t, 3, 0, 1)
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	d, auth := waitingDaemon(t, nw, 0, "", clock)
	if err := d.OfferWaiting([][]byte{sealedChange(t, nw, auth, 2, nw.admin, clock.Now())}); err != nil {
		t.Fatal(err)
	}
	w := (*waitingAdapter)(d)
	if len(w.Held(nw.devices[1].identity.Public())) != 1 {
		t.Error("an admin device is not told what another holds")
	}
	if len(w.Held(nw.devices[2].identity.Public())) != 0 {
		t.Error("a device without the admin role is told what is held")
	}
	plain, plainAuth := waitingDaemon(t, nw, 2, "", clock)
	if err := plain.OfferWaiting([][]byte{sealedChange(t, nw, plainAuth, 1, nw.admin, clock.Now())}); err != nil {
		t.Fatal(err)
	}
	if len((*waitingAdapter)(plain).Held(nw.devices[0].identity.Public())) != 0 {
		t.Error("a device without the admin role says what it holds")
	}
	clock.Set(clock.Now().Add(2 * time.Hour))
	if got := w.For(nw.devices[1].identity.Public(), nil); len(got) != 0 {
		t.Error("an expired change is handed on")
	}
}

// A peer that does not say what it holds is handed a copy again only after
// a while, not in every session.
func TestACopyIsNotHandedToASilentPeerInEverySession(t *testing.T) {
	nw := newNetworkWithAdminDevices(t, 3, 1)
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	d, auth := waitingDaemon(t, nw, 0, "", clock)
	if err := d.OfferWaiting([][]byte{sealedChange(t, nw, auth, 2, nw.admin, clock.Now())}); err != nil {
		t.Fatal(err)
	}
	w, admin := (*waitingAdapter)(d), nw.devices[1].identity.Public()
	offered := w.For(admin, nil)
	if len(offered) != 1 || len(w.For(admin, nil)) != 1 {
		t.Fatal("a copy offered but not handed over is not offered again")
	}
	w.Handed(admin, offered)
	if len(w.For(admin, nil)) != 0 {
		t.Fatal("the copy is handed again in the next session")
	}
	clock.Set(clock.Now().Add(waitingResend + time.Second))
	if len(w.For(admin, nil)) != 1 {
		t.Fatal("the copy is never handed again")
	}
}
