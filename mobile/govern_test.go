package mobile

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/internal/backupline"
	"github.com/nning/juist/internal/govern"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/internal/waiting"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// startCore starts a core for a test, closed with it.
func startCore(t *testing.T) *Core {
	t.Helper()
	t.Cleanup(func() { keys.SealWith(nil) })
	gossipOnLoopback(t)
	p := &vpnPlatform{fakePlatform: fakePlatform{t: t}}
	t.Cleanup(p.close)
	c, err := Start(filepath.Join(t.TempDir(), "juist"), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// A phone founds a network alone: it is the one member, holds no role, the
// admin key handed in is the one admin with a quorum of one, and the
// break-glass secret is handed back once.
func TestAPhoneFoundsANetworkOfItsOwn(t *testing.T) {
	c := startCore(t)
	seed, err := NewAdminKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Create("home", "pixel; rm", seed); err == nil {
		t.Error("a name a shell reads as code was taken")
	}
	f, err := c.Create("home", "pixel", seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backupline.Parse(f.BreakGlass, backupline.BreakGlass); err != nil {
		t.Errorf("break-glass line %q: %v", f.BreakGlass, err)
	}
	n, err := c.on(f.Slot)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := n.log()
	if err != nil {
		t.Fatal(err)
	}
	state := auth.State()
	key, _ := types.NewPrivateIdentity(seed)
	if a, ok := state.Admin(key.Public()); !ok || a.Recipient == nil || state.Quorum() != 1 || len(state.Admins()) != 1 {
		t.Errorf("admins %+v, quorum %d", state.Admins(), state.Quorum())
	}
	self, ok := state.Node(n.s.Status().Self)
	if !ok || self.Name != "pixel" || len(self.Roles) != 0 || len(state.Nodes()) != 1 {
		t.Errorf("members %+v", state.Nodes())
	}
	if !state.PublicDERP().Tailscale {
		t.Error("a network of phones names no public DERP servers")
	}
	if r := state.V4Range(); !slices.Contains(govern.V4DrawCandidates(), r) {
		t.Errorf("range %v is not drawn", r)
	}
	if st := n.s.Status(); st.LeaseSigners != 0 || st.Stale {
		t.Errorf("a network of phones is vouched for: %d signers, stale %v", st.LeaseSigners, st.Stale)
	}
	views := statusesOf(t, c)
	if pub, _ := AdminKeyOf(seed); len(views) != 1 || !slices.Equal(views[0].Admins, []string{pub}) {
		t.Errorf("the view names admins %v", views[0].Admins)
	}
	if _, err := c.Create("office", "pixel", seed); err != nil {
		t.Fatalf("a second network: %v", err)
	}
	if v := statusesOf(t, c); len(v) != 2 || v[1].Network != "office" {
		t.Errorf("networks %+v", v)
	}
}

// The admin key grants and revokes roles and removes a member; another key,
// or none, changes nothing.
func TestThePhonesAdminKeyChangesTheNetwork(t *testing.T) {
	c := startCore(t)
	seed, _ := NewAdminKey()
	f, err := c.Create("home", "pixel", seed)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := c.on(f.Slot)
	self := n.s.Status().Self.String()

	other, _ := NewAdminKey()
	if _, err := c.Grant(f.Slot, self, "relay", true, other, false); err == nil || !strings.Contains(err.Error(), "no vote") {
		t.Errorf("another key granted: %v", err)
	}
	if _, err := c.Grant(f.Slot, self, "ingress", true, seed, false); err == nil {
		t.Error("a role the app does not grant was granted")
	}
	if _, err := c.Grant(f.Slot, self, "voucher", true, seed, false); err != nil {
		t.Fatal(err)
	}
	roles := func(id string) []types.Role {
		auth, err := n.log()
		if err != nil {
			t.Fatal(err)
		}
		m, err := memberIn(auth, id)
		if err != nil {
			t.Fatal(err)
		}
		return m.Roles
	}
	if r := roles(self); !slices.Equal(r, []types.Role{types.RoleAdmin}) {
		t.Errorf("roles %v after the grant", r)
	}
	if _, err := c.Grant(f.Slot, self, "voucher", false, seed, true); err != nil {
		t.Fatal(err)
	}
	if r := roles(self); len(r) != 0 {
		t.Errorf("roles %v after the revocation", r)
	}

	// A second member, admitted as an invite would.
	key, _ := types.NewPrivateIdentity(seed)
	g, err := keys.GenerateNode()
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := n.log()
	v4, err := govern.NextV4(auth.State(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := types.NodeRecord{Identity: g.Identity.Public(), Name: "laptop", WireGuard: g.Public.WireGuard,
		X25519: g.Public.X25519, MLKEM: g.Public.MLKEM, Signing: new(g.Identity.SigningKey()), V4: &v4}
	add, err := auth.Builder().AddNode(rec, govern.Sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := add.Sign(key); err != nil {
		t.Fatal(err)
	}
	if err := n.apply(add); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Remove(f.Slot, self, seed, false); err == nil {
		t.Error("the phone removed itself")
	}
	if _, err := c.Remove(f.Slot, "laptop", seed, false); err != nil {
		t.Fatal(err)
	}
	if auth, _ := n.log(); len(auth.State().Nodes()) != 1 {
		t.Errorf("members %+v after the removal", auth.State().Nodes())
	}
}

// What the app keeps of an admin key reads back: the line as `juist admins
// export` prints it, and the one sealed by a password.
func TestAnAdminKeysLinesReadBack(t *testing.T) {
	seed, _ := NewAdminKey()
	got, err := OpenAdminLine(AdminLine(seed), "")
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("the line: %x, %v", got, err)
	}
	sealed, err := SealAdminLine(seed, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := OpenAdminLine(sealed, "correct horse battery"); err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("the sealed line: %x, %v", got, err)
	}
	if _, err := OpenAdminLine(sealed, "another password!"); err == nil {
		t.Error("the sealed line opened under another password")
	}
	pub, err := AdminKeyOf(seed)
	if k, _ := types.NewPrivateIdentity(seed); err != nil || pub != k.Public().String() {
		t.Errorf("AdminKeyOf = %q, %v", pub, err)
	}
}

// inviteHeard is what an invite told the app.
type inviteHeard struct {
	ready   chan string
	compare chan string
	events  chan string
}

func (h *inviteHeard) Ready(code, link string)             { h.ready <- link }
func (h *inviteHeard) Compare(words, name string)          { h.compare <- words + " " + name }
func (h *inviteHeard) Event(kind int32, name, text string) { h.events <- name + " " + text }

type joinHeard struct{ words chan string }

func (j joinHeard) Progress(kind int32, text string, votes, quorum int32) {
	if kind == 5 {
		j.words <- text
	}
}

// The phone invites into the network it founded: the person compares the
// words both sides show, and the admin key, handed in only then, admits the
// device. Words not confirmed admit nothing.
func TestThePhoneInvitesWithItsAdminKey(t *testing.T) {
	inviteOnLoopback(t)
	c := startCore(t)
	seed, _ := NewAdminKey()
	f, err := c.Create("home", "pixel", seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Invite(f.Slot, 1, "", &inviteHeard{}); err == nil || !strings.Contains(err.Error(), "no admin key") {
		t.Fatalf("an invite without the admin key named: %v", err)
	}
	stranger, _ := NewAdminKey()
	notHere, _ := AdminKeyOf(stranger)
	if err := c.Invite(f.Slot, 1, notHere, &inviteHeard{}); err == nil || !strings.Contains(err.Error(), "no vote") {
		t.Fatalf("an invite naming a key with no vote: %v", err)
	}
	pub, _ := AdminKeyOf(seed)

	invite := func(confirm func(words string)) (joinErr, inviteErr error) {
		h := &inviteHeard{ready: make(chan string, 1), compare: make(chan string, 1), events: make(chan string, 16)}
		done := make(chan error, 1)
		go func() { done <- c.Invite(f.Slot, 1, pub, h) }()
		var link string
		select {
		case link = <-h.ready:
		case err := <-done:
			t.Fatalf("the invite ended before it was offered: %v", err)
		}
		j := joinHeard{words: make(chan string, 1)}
		joined := make(chan error, 1)
		go func() { _, err := c.Join(link, "laptop", j); joined <- err }()
		var asked string
		select {
		case asked = <-h.compare:
		case <-time.After(30 * time.Second):
			t.Fatal("the invite asked for no comparison")
		}
		guest := <-j.words
		if !strings.HasPrefix(asked, guest+" ") || !strings.HasSuffix(asked, " laptop") {
			t.Errorf("the phone shows %q, the device %q", asked, guest)
		}
		confirm(asked)
		return <-joined, <-done
	}

	joinErr, _ := invite(func(string) { c.Refuse() })
	if joinErr == nil {
		t.Error("a device was admitted with the words refused")
	}
	n, _ := c.on(f.Slot)
	if auth, _ := n.log(); len(auth.State().Nodes()) != 1 {
		t.Fatalf("words refused, the network has %d members", len(auth.State().Nodes()))
	}

	other, _ := NewAdminKey()
	joinErr, _ = invite(func(string) {
		if err := c.Admit(other); err != nil {
			t.Error(err)
		}
	})
	if joinErr == nil {
		t.Error("another admin key admitted a device")
	}

	// Admitted, the device is a member, and the join goes through to the
	// end, where this phone being in the network already undoes it.
	joinErr, _ = invite(func(string) {
		// The app wipes its array as soon as the call returns.
		lent := bytes.Clone(seed)
		if err := c.Admit(lent); err != nil {
			t.Error(err)
		}
		clear(lent)
	})
	if joinErr == nil || !strings.Contains(joinErr.Error(), "home already") {
		t.Errorf("the join: %v", joinErr)
	}
	auth, _ := n.log()
	if m, err := memberIn(auth, "laptop"); err != nil || m.V4 == nil {
		t.Errorf("the device admitted: %+v, %v", m, err)
	}
}

// sign signs and applies a record the builder made, with key.
func sign(t *testing.T, n *network, key types.PrivateIdentity, build func(*log.Builder) (types.AUM, error),
	also ...types.PrivateIdentity) {
	t.Helper()
	auth, err := n.log()
	if err != nil {
		t.Fatal(err)
	}
	aum, err := build(auth.Builder())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range append([]types.PrivateIdentity{key}, also...) {
		if err := aum.Sign(k); err != nil {
			t.Fatal(err)
		}
	}
	if err := n.apply(aum); err != nil {
		t.Fatal(err)
	}
}

// admitByHand adds a member named name, as an invite would.
func admitByHand(t *testing.T, n *network, key types.PrivateIdentity, name string) types.NodeRecord {
	t.Helper()
	g, err := keys.GenerateNode()
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := n.log()
	v4, err := govern.NextV4(auth.State(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := types.NodeRecord{Identity: g.Identity.Public(), Name: name, WireGuard: g.Public.WireGuard,
		X25519: g.Public.X25519, MLKEM: g.Public.MLKEM, Signing: new(g.Identity.SigningKey()), V4: &v4}
	sign(t, n, key, func(b *log.Builder) (types.AUM, error) { return b.AddNode(rec, govern.Sealer()) })
	return rec
}

// The app keeps the network's vouchers at its threshold, as `juist revoke`
// and `juist remove` do: below it every device goes stale.
func TestTheAppKeepsTheVoucherThreshold(t *testing.T) {
	c := startCore(t)
	seed, _ := NewAdminKey()
	f, err := c.Create("home", "pixel", seed)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := c.on(f.Slot)
	key, _ := types.NewPrivateIdentity(seed)
	laptop := admitByHand(t, n, key, "laptop")
	self := n.s.Status().Self.String()
	for _, id := range []string{self, laptop.Identity.String()} {
		if _, err := c.Grant(f.Slot, id, "voucher", true, seed, false); err != nil {
			t.Fatal(err)
		}
	}
	sign(t, n, key, func(b *log.Builder) (types.AUM, error) { return b.SetVouchers(2) })
	// The app shows the error as it is: no command for a computer in it.
	if _, err := c.Grant(f.Slot, "laptop", "voucher", false, seed, false); err == nil || !strings.Contains(err.Error(), "vouchers needed") || strings.Contains(err.Error(), "hint:") {
		t.Errorf("a voucher below the threshold was revoked: %v", err)
	}
	if _, err := c.Remove(f.Slot, "laptop", seed, false); err == nil || !strings.Contains(err.Error(), "vouchers needed") || strings.Contains(err.Error(), "hint:") {
		t.Errorf("a voucher below the threshold was removed: %v", err)
	}
	sign(t, n, key, func(b *log.Builder) (types.AUM, error) { return b.SetVouchers(1) })
	if _, err := c.Grant(f.Slot, "laptop", "voucher", false, seed, false); err != nil {
		t.Errorf("a voucher above the threshold: %v", err)
	}
	// The last one goes only where the person agreed: freshness is then
	// unchecked, as in a network of phones.
	if _, err := c.Grant(f.Slot, self, "voucher", false, seed, false); !errors.Is(err, govern.ErrLastVoucher) {
		t.Errorf("the last voucher, unasked: %v", err)
	}
	if _, err := c.Grant(f.Slot, self, "voucher", false, seed, true); err != nil {
		t.Errorf("the last voucher, agreed: %v", err)
	}
}

// An answer nobody asks for is wiped, as the app wipes its own array.
func TestTheCoreWipesAnAnswerNobodyAsksFor(t *testing.T) {
	c := startCore(t)
	seed := bytes.Repeat([]byte{7}, 32)
	if err := c.answer(seed); err == nil {
		t.Error("an answer was taken with no invite")
	}
	if !bytes.Equal(seed, make([]byte, 32)) {
		t.Error("the answer nobody asked for was kept")
	}
}

// An admission waiting for votes is held no longer than its invite stays
// open, and cut to withdrawHold once the invite is cancelled: approved
// after, it would admit a device told it failed.
func TestACancelledInviteWithdrawsItsAdmission(t *testing.T) {
	inviteOnLoopback(t)
	c := startCore(t)
	seed, _ := NewAdminKey()
	f, err := c.Create("home", "pixel", seed)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := c.on(f.Slot)
	key, _ := types.NewPrivateIdentity(seed)
	quorumOfTwo(t, n, key)

	pub, _ := AdminKeyOf(seed)
	h := heard()
	link, done := openInvite(t, c, f.Slot, pub, h)
	go func() { _, _ = c.Join(link, "laptop", joinHeard{words: make(chan string, 1)}) }()
	<-h.compare
	if err := c.Admit(seed); err != nil {
		t.Fatal(err)
	}
	held := func() time.Duration {
		resp, _ := n.call(ipc.Request{Command: ipc.CmdWaiting})
		var longest time.Duration
		for _, b := range resp.Waiting {
			w, err := waiting.Decode(b)
			if err != nil {
				t.Fatal(err)
			}
			longest = max(longest, time.Until(time.Unix(w.Expires, 0)))
		}
		return longest
	}
	waitFor(t, "the admission handed on", func() bool { return held() > 0 })
	if h := held(); h > time.Minute {
		t.Errorf("an admission is held %v, past its one-minute invite", h)
	}
	c.CancelInvite()
	<-done
	if h := held(); h > withdrawHold+2*time.Second || h < withdrawHold-5*time.Second {
		t.Errorf("a cancelled invite's admission is held %v more, not about %v", h, withdrawHold)
	}
}

// A grant or removal the phone's key alone does not authorize is handed on
// for the other admins' votes, and changes nothing yet.
func TestAChangeTheKeyAloneDoesNotAuthorizeWaits(t *testing.T) {
	c := startCore(t)
	seed, _ := NewAdminKey()
	f, err := c.Create("home", "pixel", seed)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := c.on(f.Slot)
	key, _ := types.NewPrivateIdentity(seed)
	laptop := admitByHand(t, n, key, "laptop")
	quorumOfTwo(t, n, key)
	waitingNow := func() int {
		resp, err := n.call(ipc.Request{Command: ipc.CmdWaiting})
		if err != nil {
			t.Fatal(err)
		}
		return len(resp.Waiting)
	}
	if applied, err := c.Grant(f.Slot, "laptop", "relay", true, seed, false); applied || err != nil {
		t.Fatalf("the grant: applied %v, %v", applied, err)
	}
	if got := waitingNow(); got != 1 {
		t.Errorf("%d changes wait after the grant, not 1", got)
	}
	if applied, err := c.Remove(f.Slot, "laptop", seed, false); applied || err != nil {
		t.Fatalf("the removal: applied %v, %v", applied, err)
	}
	if got := waitingNow(); got != 2 {
		t.Errorf("%d changes wait after the removal, not 2", got)
	}
	auth, _ := n.log()
	m, err := memberIn(auth, laptop.Identity.String())
	if err != nil || len(m.Roles) != 0 {
		t.Errorf("the laptop changed before the votes: %+v, %v", m, err)
	}
}

// quorumOfTwo gives n's network a second admin key and a quorum of two.
func quorumOfTwo(t *testing.T, n *network, key types.PrivateIdentity) {
	t.Helper()
	other, _ := types.GenerateIdentity()
	recipient, _ := govern.AdminRecipient(other)
	sign(t, n, key, func(b *log.Builder) (types.AUM, error) {
		return b.AddAdminKey(types.AdminKey{Public: other.Public(), Votes: 1, Name: "laptop",
			Signing: new(other.SigningKey()), Endorsement: other.Endorsement()})
	})
	sign(t, n, key, func(b *log.Builder) (types.AUM, error) { return b.SetAdminRecipient(other.Public(), recipient) }, other)
	sign(t, n, key, func(b *log.Builder) (types.AUM, error) { return b.SetQuorum(2) })
}

// openInvite offers an invite on f's slot, and returns its link and its end.
func openInvite(t *testing.T, c *Core, slot int32, pub string, h *inviteHeard) (string, chan error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- c.Invite(slot, 1, pub, h) }()
	select {
	case link := <-h.ready:
		return link, done
	case err := <-done:
		t.Fatalf("the invite ended before it was offered: %v", err)
	}
	return "", nil
}

func heard() *inviteHeard {
	return &inviteHeard{ready: make(chan string, 1), compare: make(chan string, 1), events: make(chan string, 16)}
}

// The core takes an admin key for an admission only while it asks the
// person to compare words: one handed in before admits nobody unseen.
func TestTheCoreTakesNoAnswerBeforeItAsks(t *testing.T) {
	inviteOnLoopback(t)
	c := startCore(t)
	seed, _ := NewAdminKey()
	f, err := c.Create("home", "pixel", seed)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := AdminKeyOf(seed)
	h := heard()
	link, done := openInvite(t, c, f.Slot, pub, h)
	if err := c.Admit(seed); err == nil {
		t.Error("an answer was taken before any comparison")
	}
	joined := make(chan error, 1)
	go func() { _, err := c.Join(link, "laptop", joinHeard{words: make(chan string, 1)}); joined <- err }()
	select {
	case <-h.compare:
	case err := <-joined:
		t.Fatalf("the device joined without a comparison: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("no comparison asked")
	}
	c.Refuse()
	if err := <-joined; err == nil {
		t.Error("a device joined with the words refused")
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "not confirmed") {
		t.Errorf("the invite ended with %v", err)
	}
}

// Words answered as the invite ends admit nobody: the device would be a
// member that never got the log.
func TestNoAdmissionOnceTheInviteEnded(t *testing.T) {
	c := startCore(t)
	seed, _ := NewAdminKey()
	f, err := c.Create("home", "pixel", seed)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := c.on(f.Slot)
	key, _ := types.NewPrivateIdentity(seed)
	for i := 0; i < 20; i++ {
		g, err := keys.GenerateNode()
		if err != nil {
			t.Fatal(err)
		}
		var nonce enroll.Nonce
		nonce[0] = byte(i + 1)
		req := &enroll.JoinRequest{Name: "late", Identity: g.Identity.Public(), Keys: g.Public,
			Signing: g.Identity.SigningKey(), Commit: enroll.CommitNonce(nonce)}
		ctx, cancel := context.WithCancel(context.Background())
		l := &endingListener{cancel: cancel, c: c, seed: seed}
		_, _, err = c.admit(ctx, n, req, func(uint32, uint32) error { return nil },
			func(enroll.Salt) (enroll.Nonce, error) { return nonce, nil }, l, key.Public())
		if err == nil {
			t.Fatal("admitted as the invite ended")
		}
		if auth, _ := n.log(); auth.State().IsMember(req.Identity) {
			t.Fatal("a member as the invite ended")
		}
	}
}

// endingListener ends the invite as the words are shown, and answers them.
type endingListener struct {
	cancel context.CancelFunc
	c      *Core
	seed   []byte
}

func (e *endingListener) Ready(string, string) {}
func (e *endingListener) Compare(string, string) {
	e.cancel()
	_ = e.c.Admit(e.seed)
}
func (e *endingListener) Event(int32, string, string) {}

// An admission waiting for other admins' votes is held on the admin devices
// for as long as its invite is open, at most admissionHold: approved after,
// it would admit a device that never got the log.
func TestAnAdmissionWaitsNoLongerThanItsInvite(t *testing.T) {
	inviteOnLoopback(t)
	admissionHold = 3 * time.Second
	t.Cleanup(func() { admissionHold = 5 * time.Minute })
	c := startCore(t)
	seed, _ := NewAdminKey()
	f, err := c.Create("home", "pixel", seed)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := c.on(f.Slot)
	key, _ := types.NewPrivateIdentity(seed)
	other, _ := types.GenerateIdentity()
	recipient, _ := govern.AdminRecipient(other)
	sign(t, n, key, func(b *log.Builder) (types.AUM, error) {
		return b.AddAdminKey(types.AdminKey{Public: other.Public(), Votes: 1, Name: "laptop",
			Signing: new(other.SigningKey()), Endorsement: other.Endorsement()})
	})
	sign(t, n, key, func(b *log.Builder) (types.AUM, error) { return b.SetAdminRecipient(other.Public(), recipient) }, other)
	sign(t, n, key, func(b *log.Builder) (types.AUM, error) { return b.SetQuorum(2) })

	pub, _ := AdminKeyOf(seed)
	h := heard()
	link, done := openInvite(t, c, f.Slot, pub, h)
	go func() { _, _ = c.Join(link, "laptop", joinHeard{words: make(chan string, 1)}) }()
	<-h.compare
	if err := c.Admit(seed); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the admission handed on", func() bool {
		resp, err := n.call(ipc.Request{Command: ipc.CmdWaiting})
		return err == nil && len(resp.Waiting) > 0
	})
	resp, _ := n.call(ipc.Request{Command: ipc.CmdWaiting})
	for _, b := range resp.Waiting {
		w, err := waiting.Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		if held := time.Duration(w.Expires-w.Issued) * time.Second; held > admissionHold {
			t.Errorf("an admission is held %v, past its invite's hold", held)
		}
	}
	c.CancelInvite()
	<-done
}

// inviteOnLoopback has invites reached on the loopback, as a phone with no
// interface of a test's reaches none.
func inviteOnLoopback(t *testing.T) {
	inviteAddrsForTests = func(port uint16) []netip.AddrPort {
		return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
	}
	t.Cleanup(func() { inviteAddrsForTests = nil })
}

// An error the core hands the app keeps no hint for a computer's command
// line, and an error without one stays as it is.
func TestNoComputersHintReachesTheApp(t *testing.T) {
	err := withoutHint(errors.New("no free address in 10.0.0.0/22\nhint: juist network renumber PREFIX, into a larger range"))
	if err == nil || err.Error() != "no free address in 10.0.0.0/22" {
		t.Errorf("the app is told %q", err)
	}
	if err := withoutHint(govern.ErrLastVoucher); err != govern.ErrLastVoucher {
		t.Errorf("an error without a hint became %v", err)
	}
	if withoutHint(nil) != nil {
		t.Error("no error became one")
	}
}

// Genesis where the network beneath covers every range to draw says so
// without the command line's --ipv4.
func TestAGenesisWithNoRangeLeftGivesNoHint(t *testing.T) {
	c := startCore(t)
	all := []netip.Prefix{types.OverlayV4}
	c.routes.Store(&all)
	seed, _ := NewAdminKey()
	_, err := c.Create("home", "pixel", seed)
	if err == nil || !strings.Contains(err.Error(), "overlaps") || strings.Contains(err.Error(), "hint:") {
		t.Errorf("genesis without a range: %v", err)
	}
}
