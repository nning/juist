package enroll

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"filippo.io/edwards25519"

	"github.com/nning/juist/types"
)

// pipe is a bidirectional in-memory connection.
type pipe struct {
	io.Reader
	io.Writer
}

func pipePair() (pipe, pipe, func()) {
	ar, bw := io.Pipe()
	br, aw := io.Pipe()
	return pipe{ar, aw}, pipe{br, bw}, func() {
		ar.Close()
		br.Close()
		aw.Close()
		bw.Close()
	}
}

func newTestInvite(t *testing.T) *Invite {
	t.Helper()
	inv, err := NewInvite([]netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41642")})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

type result struct {
	ch  *Channel
	err error
}

// session runs one handshake and returns both ends' results.
func session(t *testing.T, inv *Invite, s Secret) (host, guest result) {
	t.Helper()
	h, g, closeAll := pipePair()
	defer closeAll()
	done := make(chan result, 1)
	go func() {
		ch, err := inv.Accept(h)
		if err != nil {
			// Unblock a guest still waiting for a frame the host will not send.
			closeAll()
		}
		done <- result{ch, err}
	}()
	ch, err := Join(g, s)
	if err != nil {
		closeAll()
	}
	return <-done, result{ch, err}
}

func wrongCode(c Code) Code {
	c.Words[2]++
	return c
}

func TestInviteAdmitsTheRightCodeOnce(t *testing.T) {
	inv := newTestInvite(t)
	host, guest := session(t, inv, inv.Code())
	if host.err != nil || guest.err != nil {
		t.Fatalf("host: %v, guest: %v", host.err, guest.err)
	}
	if host.ch.Binding() != guest.ch.Binding() {
		t.Fatal("the two ends disagree on the session binding")
	}
	if inv.Open() {
		t.Fatal("the invite is still open after admitting a device")
	}
	_, again := session(t, inv, inv.Code())
	var refused *RefusedError
	if !errors.As(again.err, &refused) || refused.Reason != RefusedClosed {
		t.Fatalf("a second use of the invite got %v, want a refusal as closed", again.err)
	}
}

func TestLinkAdmits(t *testing.T) {
	inv := newTestInvite(t)
	parsed, err := ParseLink(inv.Link().String())
	if err != nil {
		t.Fatal(err)
	}
	if host, guest := session(t, inv, parsed); host.err != nil || guest.err != nil {
		t.Fatalf("host: %v, guest: %v", host.err, guest.err)
	}
}

// TestOneGuessPerInvite is M4's first exit criterion: a wrong guess is
// detected by the host, reported loudly on both sides, and leaves the code
// dead, so the right code does not work after it. The link, a secret of its
// own, still does.
func TestOneGuessPerInvite(t *testing.T) {
	inv := newTestInvite(t)
	host, guest := session(t, inv, wrongCode(inv.Code()))
	if !errors.Is(host.err, ErrWrongCode) {
		t.Fatalf("host saw %v, want ErrWrongCode", host.err)
	}
	var refused *RefusedError
	if !errors.As(guest.err, &refused) || refused.Reason != RefusedWrongCode {
		t.Fatalf("guest saw %v, want a wrong-code refusal", guest.err)
	}
	if inv.CodeOpen() {
		t.Fatal("the code survived a wrong guess")
	}
	_, second := session(t, inv, inv.Code())
	if !errors.As(second.err, &refused) || refused.Reason != RefusedClosed {
		t.Fatalf("the right code after a wrong guess got %v, want a refusal", second.err)
	}
	if host, _ := session(t, inv, inv.Link()); host.err != nil {
		t.Fatalf("the link after a wrong code: %v", host.err)
	}
}

// Asking for other nameplates costs a guesser nothing, so after enough of
// them the code goes out of use: otherwise finding the nameplate and then
// spending the code's guess would take a thousand connections.
func TestNameplateMissesRetireTheCode(t *testing.T) {
	inv := newTestInvite(t)
	other := inv.Code()
	for range MaxNameplateMisses {
		other.Nameplate = other.Nameplate%999 + 1
		if other.Nameplate == inv.Code().Nameplate {
			other.Nameplate = other.Nameplate%999 + 1
		}
		_, _ = session(t, inv, other)
	}
	if inv.CodeOpen() {
		t.Fatal("the code survived a scan of nameplates")
	}
	if host, _ := session(t, inv, inv.Link()); host.err != nil {
		t.Fatalf("the link after a nameplate scan: %v", host.err)
	}
}

// A wrong link voids nothing: guessing 128 bits online is hopeless, and a
// stranger who reaches the port must not end the invite with one connection.
func TestWrongLinkSecretLeavesTheInviteOpen(t *testing.T) {
	inv := newTestInvite(t)
	other := newTestInvite(t)
	host, guest := session(t, inv, other.Link())
	var refused *RefusedError
	if !errors.Is(host.err, ErrWrongLink) || !errors.As(guest.err, &refused) || refused.Reason != RefusedWrongLink {
		t.Fatalf("host saw %v, guest %v", host.err, guest.err)
	}
	if !inv.Open() {
		t.Fatal("a wrong link voided the invite")
	}
	if host, _ := session(t, inv, inv.Code()); host.err != nil {
		t.Fatalf("the right code after a wrong link: %v", host.err)
	}
}

// A guest asking for another nameplate made no guess, so the invite stays
// usable: two concurrent invites on one network must not void each other.
func TestOtherNameplateIsNotAGuess(t *testing.T) {
	inv := newTestInvite(t)
	c := inv.Code()
	c.Nameplate = c.Nameplate%MaxNameplate + 1
	_, guest := session(t, inv, c)
	var refused *RefusedError
	if !errors.As(guest.err, &refused) || refused.Reason != RefusedNoSuchInvite {
		t.Fatalf("guest saw %v", guest.err)
	}
	if !inv.Open() {
		t.Fatal("a nameplate mismatch voided the invite")
	}
}

// A session that ends before the guest's confirmation gave the peer nothing to
// test, so it must not spend the invite either: otherwise any flaky network
// or idle port scanner kills invites.
func TestAbortBeforeConfirmationKeepsTheInvite(t *testing.T) {
	inv := newTestInvite(t)
	h, g, closeAll := pipePair()
	done := make(chan error, 1)
	go func() {
		_, err := inv.Accept(h)
		done <- err
	}()
	s, err := newSpake(true, inv.Code().password(), aadFor(modeCode))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeHandshake(g, &hsFrame{Kind: hsHello, Version: ProtocolVersion, Mode: modeCode,
		Nameplate: inv.Code().Nameplate, Element: s.message()}); err != nil {
		t.Fatal(err)
	}
	if _, err := readHandshake(g); err != nil {
		t.Fatal(err)
	}
	closeAll()
	if err := <-done; err == nil || errors.Is(err, ErrWrongCode) {
		t.Fatalf("host returned %v", err)
	}
	if !inv.Open() {
		t.Fatal("an aborted session voided the invite")
	}
}

// A host that does not know the code cannot complete the guest's side: the
// guest reports an impostor instead of joining whatever answered.
func TestGuestDetectsAnImpostor(t *testing.T) {
	real := newTestInvite(t)
	impostor := newTestInvite(t)
	// The impostor answers under the same nameplate with a different code.
	impostor.code.Nameplate = real.code.Nameplate
	host, guest := session(t, impostor, real.Code())
	if !errors.Is(host.err, ErrWrongCode) {
		t.Fatalf("impostor saw %v", host.err)
	}
	var refused *RefusedError
	if guest.err == nil || (!errors.Is(guest.err, ErrImpostor) && !errors.As(guest.err, &refused)) {
		t.Fatalf("guest joined an impostor: %v", guest.err)
	}
}

func TestChannelCarriesMessagesAndRejectsTampering(t *testing.T) {
	inv := newTestInvite(t)
	h, g, closeAll := pipePair()
	defer closeAll()
	type out struct {
		ch  *Channel
		err error
	}
	hc := make(chan out, 1)
	go func() {
		ch, err := inv.Accept(h)
		hc <- out{ch, err}
	}()
	guest, err := Join(g, inv.Code())
	if err != nil {
		t.Fatal(err)
	}
	host := <-hc
	if host.err != nil {
		t.Fatal(host.err)
	}

	id, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewJoinRequest(guest, "phone", id, types.NodeKeys{}, Nonce{1})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = guest.Send(&Message{Kind: KindJoin, Join: req}) }()
	got, err := host.ch.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != KindJoin || got.Join.Name != "phone" {
		t.Fatalf("host received %+v", got)
	}
	if err := got.Join.Verify(host.ch); err != nil {
		t.Fatalf("proof of possession: %v", err)
	}

	// A proof made for another session does not verify in this one.
	other := &Channel{binding: [32]byte{1}}
	if err := got.Join.Verify(other); err == nil {
		t.Fatal("a proof verified against another session's binding")
	}

	// A frame replayed from earlier in the session fails authentication.
	var replay strings.Builder
	guest.rw = pipe{nil, &replay}
	guest.sent--
	if err := guest.Send(&Message{Kind: KindJoined}); err != nil {
		t.Fatal(err)
	}
	host.ch.rw = pipe{strings.NewReader(replay.String()), io.Discard}
	if _, err := host.ch.Receive(); err == nil {
		t.Fatal("a frame sealed under a reused nonce was accepted")
	}
}

func TestMessageShapes(t *testing.T) {
	for name, m := range map[string]Message{
		"two payloads":              {Kind: KindRecord, Record: []byte{1}, Reason: "x"},
		"missing":                   {Kind: KindWaiting},
		"unknown kind":              {Kind: 99},
		"control char":              {Kind: KindRefused, Reason: "a\x1b[2Jb"},
		"empty welcome":             {Kind: KindWelcome, Welcome: &Welcome{}},
		"joined payload":            {Kind: KindJoined, Reason: "x"},
		"announcement off a joined": {Kind: KindWaiting, Waiting: &Waiting{}, Announcement: []byte{1}},
		"oversized announcement":    {Kind: KindJoined, Announcement: make([]byte, MaxAnnouncementLen+1)},
	} {
		if err := m.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, m := range map[string]Message{
		"joined":                   {Kind: KindJoined},
		"joined with announcement": {Kind: KindJoined, Announcement: []byte{1}},
	} {
		if err := m.validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCodeRoundTrip(t *testing.T) {
	for range 50 {
		c, err := NewCode()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseCode(strings.ToUpper(strings.ReplaceAll(c.String(), "-", " ")))
		if err != nil || got != c {
			t.Fatalf("%s parsed as %v, %v", c, got, err)
		}
	}
}

func TestParseCodeExplains(t *testing.T) {
	good, _ := NewCode()
	w := strings.Split(good.String(), "-")
	for input, want := range map[string]string{
		"42":                            "a number and 3 words",
		"0-" + strings.Join(w[1:], "-"): "from 1 to 999",
		w[0] + "-" + w[2] + "-" + w[1] + "-" + w[3]: "wrong place",
		w[0] + "-" + w[1] + "-" + w[2] + "-zzz":     "not a word",
	} {
		_, err := ParseCode(input)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseCode(%q) = %v, want an error mentioning %q", input, err, want)
		}
	}
}

func TestParseLinkRejects(t *testing.T) {
	inv := newTestInvite(t)
	good := inv.Link().String()
	secret, _, _ := strings.Cut(strings.TrimPrefix(good, LinkPrefix), "@")
	for _, bad := range []string{
		"juist:" + secret,
		"juist:" + secret + "@",
		"juist:" + secret[:10] + "@192.0.2.1:1",
		"juist:" + secret + "@192.0.2.1",
		"juist:" + secret + "@192.0.2.1:0",
		"juist:" + secret + "@[fe80::1%eth0]:1",
		"juist:" + secret + "@0.0.0.0:41642",
		"juist:" + secret + "@[::]:41642",
		"juist:" + secret + "@224.0.0.251:5353",
		"http://" + secret,
	} {
		if _, err := ParseLink(bad); err == nil {
			t.Errorf("ParseLink(%q) accepted", bad)
		}
	}
	twice, err := ParseLink("juist:" + secret + "@192.0.2.1:1,192.0.2.1:1")
	if err != nil || len(twice.Addrs) != 1 {
		t.Errorf("a repeated address: %v, %v", twice.Addrs, err)
	}
}

// The rendezvous keys are the link's alone: another link's differ, and none
// of them is derived like the password the key exchange runs on.
func TestRendezvousKeysAreTheLinks(t *testing.T) {
	a, b := newTestInvite(t).Link(), newTestInvite(t).Link()
	h1, g1, s1 := a.RendezvousKeys()
	h2, _, _ := b.RendezvousKeys()
	if h1 == h2 || h1 == g1 || g1 == s1 || h1 == s1 {
		t.Fatal("rendezvous keys collide")
	}
	again, _ := ParseLink(a.String())
	if h, g, s := again.RendezvousKeys(); h != h1 || g != g1 || s != s1 {
		t.Fatal("a parsed link derives different rendezvous keys")
	}
}

// probeElement sends a hello whose element is w'·M for guess — no secret
// scalar, so it tests the guess against the host's K — and walks away before
// confirming. It reports whether the host answered.
func probeElement(t *testing.T, inv *Invite, guess Code) (replied bool, hostErr error) {
	t.Helper()
	h, g, closeAll := pipePair()
	done := make(chan error, 1)
	go func() {
		_, err := inv.Accept(h)
		closeAll()
		done <- err
	}()
	w, err := passwordScalar(guess.password())
	if err != nil {
		t.Fatal(err)
	}
	element := new(edwards25519.Point).ScalarMult(w, spakeM).Bytes()
	if err := writeHandshake(g, &hsFrame{Kind: hsHello, Version: ProtocolVersion, Mode: modeCode,
		Nameplate: guess.Nameplate, Element: element}); err != nil {
		t.Fatal(err)
	}
	f, err := readHandshake(g)
	replied = err == nil && f.Kind == hsReply
	closeAll()
	return replied, <-done
}

// A guest that sends the password's own element learns from the host whether
// its guess was right unless that, too, spends the invite: otherwise it could
// walk away after every wrong one and try the next, all 2^24 codes.
func TestAnElementBuiltFromTheCodeIsItsOneGuess(t *testing.T) {
	inv := newTestInvite(t)
	if replied, _ := probeElement(t, inv, wrongCode(inv.Code())); !replied || !inv.Open() {
		t.Fatalf("a wrong probe: replied=%v open=%v", replied, inv.Open())
	}
	replied, err := probeElement(t, inv, inv.Code())
	if replied || !errors.Is(err, ErrWrongCode) {
		t.Fatalf("the right probe: replied=%v, host %v; want the invite spent as a wrong code", replied, err)
	}
	if inv.CodeOpen() {
		t.Fatal("the code still works after a guest tested it for free")
	}
	if host, _ := session(t, inv, inv.Code()); host.err == nil {
		t.Fatal("the right code joined after the probe")
	}
}

// A link can name the admin whose admission the guest will require, and an
// admission verifies only as what it says.
func TestLinksNameTheAdminAndAdmissionsBindTheGuest(t *testing.T) {
	admin, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	l := newTestInvite(t).Link().WithAdmin(admin.Public())
	again, err := ParseLink(l.String())
	if err != nil || again.Admin == nil || *again.Admin != admin.Public() || again.String() != l.String() {
		t.Fatalf("round trip: %v, %v", again, err)
	}
	if again.password() == nil || string(again.password()) != string(l.password()) {
		t.Fatal("the admin changed the link's secret")
	}
	secret, rest, _ := strings.Cut(strings.TrimPrefix(l.String(), LinkPrefix), ".")
	if _, err := ParseLink(LinkPrefix + secret + ".AAAA" + rest[strings.Index(rest, "@"):]); err == nil {
		t.Fatal("a damaged admin key parsed")
	}

	guest, _ := types.GenerateIdentity()
	var network, head types.Hash
	network[0], head[0] = 1, 2
	a, err := SignAdmission(admin, network, head, guest.Public())
	if err != nil || a.Verify() != nil {
		t.Fatalf("an honest admission: %v", err)
	}
	for _, tamper := range []func(*Admission){
		func(x *Admission) { x.Head[0] ^= 1 },
		func(x *Admission) { x.Network[0] ^= 1 },
		func(x *Admission) { x.Guest[0] ^= 1 },
	} {
		b := *a
		tamper(&b)
		if b.Verify() == nil {
			t.Error("a tampered admission verified")
		}
	}
}

// A link names the relays its host waits at apart from the host's own
// addresses, and the id it waits under is the same on both sides but says
// nothing about the secret.
func TestLinksNameRelays(t *testing.T) {
	l, err := NewLink([]netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41642")})
	if err != nil {
		t.Fatal(err)
	}
	relay := netip.MustParseAddrPort("203.0.113.5:41645")
	l = l.WithRelays([]netip.AddrPort{relay})
	again, err := ParseLink(l.String())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(again.Relays, []netip.AddrPort{relay}) || !slices.Equal(again.Addrs, l.Addrs) {
		t.Fatalf("%s parsed as addrs %v, relays %v", l, again.Addrs, again.Relays)
	}
	if id := l.ForwardID(); again.ForwardID() != id || bytes.Contains(id[:], l.secret[:4]) {
		t.Fatal("the forward id does not follow from the secret alone")
	}
	other, _ := NewLink(nil)
	if other.ForwardID() == l.ForwardID() {
		t.Fatal("two links share a forward id")
	}
}
