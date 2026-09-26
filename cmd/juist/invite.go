package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nning/juist/ipc"

	"github.com/nning/juist/internal/host"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// DefaultInvitePort is the TCP port an invite listens on unless told
// otherwise: fixed, so a firewall can be opened for it once.
const DefaultInvitePort = host.DefaultPort

// admissionPoll is how often the log is re-read for an admission other admins
// completed. The guest is told it is still waiting on each; the host decides
// how often that reaches it.
const admissionPoll = 2 * time.Second

type inviteOptions struct {
	name    string
	relay   bool
	admin   bool
	expires time.Duration
	port    uint
	lan     bool
	dht     bool
	yes     bool
}

func cmdInvite(a *app, args []string) error {
	s := spec{name: "juist invite", args: "[NAME]", max: 1, about: `
Invite one device, then wait for it to join. Prints a code, for the same
LAN, and a link, for anywhere; behind NAT, the two devices meet through the
public BitTorrent DHT. Both end when a device joins, the invite expires, or
the code is guessed wrong once.

NAME is the device's name in the network (default: its own). Where more
than one admin must approve, the invite waits for them.`}
	fs := newFlags(s.name)
	var o inviteOptions
	fs.BoolVar(&o.relay, "relay", false, "make the device a relay")
	fs.BoolVar(&o.admin, "voucher", false, "make the device a voucher")
	fs.DurationVar(&o.expires, "expires", time.Hour, "invite lifetime, like 30m or 2h")
	fs.UintVar(&o.port, "port", DefaultInvitePort, "TCP port to listen on")
	noLAN := fs.Bool("no-lan", false, "no code on the LAN; link only")
	noDHT := fs.Bool("no-dht", false, "do not meet through the public DHT")
	fs.BoolVar(&o.yes, "yes", false, "admit without comparing words")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	o.lan, o.dht = !*noLAN, !*noDHT
	if len(pos) == 1 {
		o.name = pos[0]
		if err := checkName("device name", o.name); err != nil {
			return err
		}
	}
	if o.port > 0xffff {
		return errors.New("--port must be below 65536")
	}
	if o.expires <= 0 || o.expires > 7*24*time.Hour {
		return errors.New("--expires must be between 1s and 7d")
	}

	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	key, err := a.admittingKey(auth)
	if err != nil {
		return err
	}
	adm := &admitter{a: a, o: o, key: key}
	ctx, cancel := context.WithTimeout(a.ctx, o.expires)
	defer cancel()

	var serveErr error
	if a.node.status() != nil {
		if !o.yes && !a.interactive {
			return errors.New("comparing the device's words needs a terminal; pass --yes to skip")
		}
		// juistd runs the session, and so could put a device of its own in
		// the guest's place: the words the guest shows are what say it did
		// not.
		adm.compare = !o.yes
		serveErr = a.inviteThroughDaemon(ctx, auth, adm, o)
	} else {
		serveErr = a.inviteHere(ctx, auth, adm, o)
	}
	return a.inviteOutcome(serveErr)
}

// inviteHere runs the invite in this process, on a state directory no daemon
// owns.
func (a *app) inviteHere(ctx context.Context, auth *log.Authority, adm *admitter, o inviteOptions) error {
	opts := host.Options{Port: uint16(o.port), LAN: o.lan, SkipInterface: "juist0",
		Addrs: func(port uint16) []netip.AddrPort { return a.inviteAddrs(port, auth.State()) }}
	if o.dht {
		opts.Helpers = a.helpers
	}
	h, err := host.Listen(opts)
	if err != nil {
		return err
	}
	inv := h.Invite()
	a.announceInvite(auth.State().Network(), inv.Code().String(), inv.Link().WithAdmin(adm.key.Public()), h.Port(), o)
	chain := func() ([]types.AUM, [][]byte, [][]byte, error) {
		records, err := a.node.chain()
		return records, nil, nil, err
	}
	return h.Serve(ctx, adm, chain, a.reportHostEvent)
}

// inviteThroughDaemon has juistd offer the invite: the listener, the LAN
// answers and the public DHT run there, apart from the admin keys, and the
// daemon asks this process to decide and sign each admission.
func (a *app) inviteThroughDaemon(ctx context.Context, auth *log.Authority, adm *admitter, o inviteOptions) error {
	// Whole seconds, rounded up: an invite shorter than one still gets one.
	expires := uint32((o.expires + time.Second - 1) / time.Second)
	req := ipc.Request{Command: ipc.CmdInvite, Offer: &ipc.InviteOffer{
		Port: uint16(o.port), LAN: o.lan, DHT: o.dht, Expires: expires}}
	conv := &daemonInvite{a: a, auth: auth, adm: adm, o: o}
	err := a.node.converse(ctx, req, conv.handle)
	// The admission ends with the conversation's context; nothing of it is
	// left running, or asking, once the invite has ended.
	conv.admitting.Wait()
	if err != nil && ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return host.ErrExpired
		}
		return host.ErrCancelled
	}
	return daemonHostError(err)
}

// A daemonInvite is this side of a CmdInvite conversation. It trusts the
// daemon for nothing it signs: the invite it offers is checked and printed
// here, with the admin's key added, and it answers one admission at most.
type daemonInvite struct {
	a     *app
	auth  *log.Authority
	adm   *admitter
	o     inviteOptions
	ready bool
	asked bool

	// reveal carries the guest's nonce from its event to the admission,
	// which runs apart from the events so that it can wait for one, and
	// admitting is that admission.
	reveal    chan enroll.Nonce
	admitting sync.WaitGroup
}

func (d *daemonInvite) handle(ctx context.Context, e *ipc.Event, reply func(ipc.Request) error) error {
	a := d.a
	switch e.Kind {
	case ipc.EventInviteReady:
		if d.ready {
			return errors.New("juistd offered a second invite")
		}
		d.ready = true
		code, err := enroll.ParseCode(e.Code)
		if err != nil {
			return fmt.Errorf("juistd offered an invalid code: %w", err)
		}
		link, err := enroll.ParseLink(e.Link)
		if err != nil {
			return fmt.Errorf("juistd offered an invalid link: %w", err)
		}
		// The admin's key goes into the link here, where the daemon cannot
		// change what is printed.
		a.announceInvite(d.auth.State().Network(), code.String(), link.WithAdmin(d.adm.key.Public()), e.Port, d.o)
	case ipc.EventInviteAdmit:
		// One invite admits one device. A daemon that asks again, or before
		// it offered the invite, is not running the protocol.
		if !d.ready || d.asked {
			return errors.New("juistd asked to admit a device the invite did not bring; nothing more is " +
				"signed. juistd on this device may be compromised")
		}
		d.asked = true
		if e.Join == nil || e.Join.Identity.Validate() != nil ||
			(e.Join.Name != "" && types.ValidateName(e.Join.Name) != nil) {
			return errors.New("juistd asked to admit a malformed request")
		}
		wait := func(votes, quorum uint32) error {
			return reply(ipc.Request{Reply: &ipc.InviteReply{
				Waiting: &enroll.Waiting{Votes: votes, Quorum: quorum}}})
		}
		d.reveal = make(chan enroll.Nonce, 1)
		compare := func(s enroll.Salt) (enroll.Nonce, error) {
			if err := reply(ipc.Request{Reply: &ipc.InviteReply{Salt: &s}}); err != nil {
				return enroll.Nonce{}, err
			}
			select {
			case n := <-d.reveal:
				return n, nil
			case <-ctx.Done():
				return enroll.Nonce{}, errors.New("the invite ended before the new device answered")
			}
		}
		join := e.Join
		d.admitting.Add(1)
		go func() {
			defer d.admitting.Done()
			name, admission, err := d.adm.Admit(ctx, join, wait, compare)
			if err != nil {
				// Said once, when the invite ends with it.
				_ = reply(ipc.Request{Reply: &ipc.InviteReply{Refused: enroll.ReasonText(err)}})
				return
			}
			_ = reply(ipc.Request{Reply: &ipc.InviteReply{Name: name, Admission: admission}})
		}()
	case ipc.EventInviteReveal:
		if d.reveal == nil || e.Reveal == nil {
			return errors.New("juistd answered words nobody asked it to compare; nothing more is signed")
		}
		select {
		case d.reveal <- *e.Reveal:
		default:
			return errors.New("juistd answered the words twice; nothing more is signed")
		}
	default:
		ev := host.Event{Name: e.Name, Addr: e.Addr, Err: e.Text}
		switch e.Kind {
		case ipc.EventInviteFailed:
			ev.Kind = host.Failed
		case ipc.EventInviteJoined:
			ev.Kind = host.Joined
		case ipc.EventInviteNoLAN:
			ev.Kind = host.NoLAN
		case ipc.EventInviteNoDHT:
			ev.Kind = host.NoDHT
		case ipc.EventCodeVoided:
			ev.Kind = host.CodeVoided
		case ipc.EventInviteNoRelay:
			ev.Kind = host.NoRelay
		default:
			return nil
		}
		a.reportHostEvent(ev)
	}
	return nil
}

// daemonHostError recovers host's outcomes from the text they cross the
// socket as.
func daemonHostError(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{host.ErrExpired, host.ErrCancelled} {
		if rest, ok := strings.CutPrefix(err.Error(), known.Error()); ok {
			return fmt.Errorf("%w%s", known, rest)
		}
	}
	return err
}

func (a *app) announceInvite(network, code string, link enroll.Link, port uint16, o inviteOptions) {
	var roles []types.Role
	if o.relay {
		roles = append(roles, types.RoleRelayCapable)
	}
	if o.admin {
		roles = append(roles, types.RoleAdmin)
	}
	as := ""
	if len(roles) > 0 {
		as = " as " + describeRoles(roles)
	}
	a.printf("invite to %q%s, expires in %s; on the new device:\n", network, as, shortDuration(o.expires))
	if o.lan {
		a.printf("  %s  %s\n", a.bold("juist join "+code), a.dim("# same LAN"))
	}
	a.command("juist join %s", link)
	if len(link.Relays) > 0 {
		a.printf("%s\n", a.dim(fmt.Sprintf("meets through relay %s where this device is unreachable", link.Relays[0])))
	}
	if cmd := invitePortHint(port); cmd != "" {
		a.hint("the firewall may block the device: %s", cmd)
	}
	if port != DefaultInvitePort && o.port == DefaultInvitePort {
		a.printf("%s\n", a.dim(fmt.Sprintf("listening on %d; %d is taken", port, DefaultInvitePort)))
	}
}

func (a *app) reportHostEvent(e host.Event) {
	switch e.Kind {
	case host.Failed:
		a.printf("%s\n", a.dim(fmt.Sprintf("connection from %v failed: %v", e.Addr, e.Err)))
	case host.Joined:
		a.ok("%s joined", e.Name)
	case host.NoLAN:
		a.warn("code not announced on the LAN (%s); use the link", e.Err)
	case host.NoDHT:
		a.printf("%s\n", a.dim(fmt.Sprintf("link does not meet through the DHT: %s", e.Err)))
	case host.NoRelay:
		a.warn("cannot wait at relay %s (%s); retrying", e.Addr, e.Err)
	case host.CodeVoided:
		if e.Err != "" {
			a.warn("code voided: %s, from %s", e.Err, e.Addr)
		} else {
			a.warn("code voided: wrong guess from %s", e.Addr)
		}
		a.hint("if that was not your device, someone else knows this invite; the link still works")
	}
}

// inviteOutcome says what an ended invite means.
func (a *app) inviteOutcome(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, host.ErrExpired):
		return errors.New("invite expired")
	case errors.Is(err, host.ErrCancelled):
		return errors.New("invite cancelled")
	default:
		return err
	}
}

// admittingKey is the admin key an invite from here admits with, refusing
// early where this device could never admit anyone rather than after a guest
// has spent the invite.
func (a *app) admittingKey(auth *log.Authority) (types.PrivateIdentity, error) {
	if alarm := auth.Alarm(); alarm != nil {
		return types.PrivateIdentity{}, fmt.Errorf("cannot admit during a log alarm: %v", alarm)
	}
	admins, err := a.adminKeys()
	if err != nil {
		return types.PrivateIdentity{}, err
	}
	for _, k := range admins {
		if _, ok := auth.State().Admin(k.Public()); ok {
			return k, nil
		}
	}
	return types.PrivateIdentity{}, errors.New("no admin key of this network here\nhint: invite from an admin's device")
}

// An admitter decides and signs admissions: the half of an invite that needs
// the admin keys, run against this keystore's own verified log whoever runs
// the other half.
type admitter struct {
	a   *app
	o   inviteOptions
	key types.PrivateIdentity

	// compare asks the person to compare the device's words before signing.
	compare bool
}

// Admit admits the device a join request names, waits for the other admins
// where the network needs them, and signs the admission the guest checks: the
// admin's statement that it is a member as of a head of this log.
func (m *admitter) Admit(ctx context.Context, req *enroll.JoinRequest, wait func(votes, quorum uint32) error,
	compare func(enroll.Salt) (enroll.Nonce, error)) (string, *enroll.Admission, error) {
	a := m.a
	auth, err := a.freshLog()
	if err != nil {
		return "", nil, err
	}
	if m.compare {
		if err := m.compareWords(ctx, req, compare); err != nil {
			return "", nil, err
		}
	}
	id := req.Identity
	if cur, ok := auth.State().Node(id); ok {
		// Already a member with these keys: the device lost its log, and
		// needs only to be sent it again.
		if !sameKeys(cur, req) {
			return "", nil, fmt.Errorf("%s is a member already, with other keys", displayMember(cur))
		}
		a.printf("%s is a member already; resending the log\n", displayMember(cur))
	} else if err := m.addNode(ctx, auth, req, wait); err != nil {
		return "", nil, err
	}
	// The admission is stated against the log as verified now, which has to
	// admit the device under exactly the keys it asked with.
	if auth, err = a.freshLog(); err != nil {
		return "", nil, err
	}
	cur, ok := auth.State().Node(id)
	if !ok || !sameKeys(cur, req) {
		return "", nil, errors.New("log does not admit the device under the keys it asked with")
	}
	admission, err := enroll.SignAdmission(m.key, auth.State().GenesisHash(), auth.Head(), id)
	if err != nil {
		return "", nil, err
	}
	return cur.Name, admission, nil
}

func sameKeys(n types.NodeRecord, req *enroll.JoinRequest) bool {
	return n.WireGuard == req.Keys.WireGuard && n.X25519 == req.Keys.X25519 && n.MLKEM == req.Keys.MLKEM
}

// compareWords has the person compare the words the device shows with those
// shown here. The salt is drawn now, after the request committed to its
// nonce, and the nonce is held to that commitment: neither the device that
// asked nor the one in between can search for matching words.
func (m *admitter) compareWords(ctx context.Context, req *enroll.JoinRequest,
	compare func(enroll.Salt) (enroll.Nonce, error)) error {
	a := m.a
	if req.Commit == ([32]byte{}) {
		return errors.New("joining device's juist is too old to compare words; update it")
	}
	var salt enroll.Salt
	if _, err := rand.Read(salt[:]); err != nil {
		return err
	}
	nonce, err := compare(salt)
	if err != nil {
		return err
	}
	if enroll.CommitNonce(nonce) != req.Commit {
		return errors.New("nonce does not match the join request's commitment; nothing signed. " +
			"juistd here may be compromised")
	}
	a.printf("%s wants to join; compare with the words it shows:\n", cmp.Or(m.o.name, memberName(req.Name)))
	a.command("%s", enroll.Fingerprint(salt, nonce, req.Identity, req.Keys))
	ok, err := a.askNow(ctx, "same?")
	if err != nil {
		return fmt.Errorf("not admitted: %w", err)
	}
	if !ok {
		return errors.New("words not confirmed; nothing signed\nhint: if they differed, " +
			"the device asking is not the one you invited")
	}
	return nil
}

// addNode admits a device that is no member yet, and waits for the other
// admins where they must approve.
func (m *admitter) addNode(ctx context.Context, auth *log.Authority, req *enroll.JoinRequest,
	wait func(votes, quorum uint32) error) error {
	a, o, state := m.a, m.o, auth.State()
	name := uniqueName(state, cmp.Or(o.name, memberName(req.Name)))
	rec := req.NodeRecord(name)
	history, err := a.addressHistory()
	if err != nil {
		return err
	}
	v4, err := nextV4(state, history)
	if err != nil {
		return err
	}
	rec.V4 = &v4
	var roles []types.Role
	if o.relay {
		roles = append(roles, types.RoleRelayCapable)
	}
	if o.admin {
		roles = append(roles, types.RoleAdmin)
	}
	rec.Roles = sortRoles(roles)
	aum, err := auth.Builder().AddNode(rec, sealer())
	if err != nil {
		return fmt.Errorf("cannot admit %s: %w", name, err)
	}
	a.printf("admitting %s (%v)\n", name, req.Identity.ShortString())
	c := &change{
		aum:  aum,
		file: "add-" + fileSafe(name) + ".rec",
		done: fmt.Sprintf("admitted %s at %s", name, v4),
	}
	// The invite may have ended while a person looked at the words: a device
	// admitted then would be a member that never got the log.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("not admitted: %w", err)
	}
	applied, err := a.submit(auth, c)
	if err != nil || applied {
		return err
	}
	err = a.awaitAdmission(ctx, wait, req.Identity, auth.State().SignatureStatus(&c.aum))
	// Approved after the invite, the record would admit a device that never
	// received the log.
	if err != nil && ctx.Err() != nil && c.written != "" && os.Remove(a.path(c.written)) == nil {
		// Said here too: what reaches the guest as a refusal is replaced by
		// the invite's own ending on this side.
		a.warn("invite ended before %s was approved; deleted %s, do not approve copies of it", name, c.written)
		err = fmt.Errorf("%w; its record is deleted", err)
	}
	return err
}

// awaitAdmission waits for other admins to approve an admission, however it
// reaches this device's log, telling the guest as it goes.
func (a *app) awaitAdmission(ctx context.Context, wait func(votes, quorum uint32) error, id types.Identity,
	st log.SignatureStatus) error {
	if err := wait(st.Votes, st.Quorum); err != nil {
		return err
	}
	a.printf("%s\n", a.dim("waiting for the other admins"))
	poll := time.NewTicker(admissionPoll)
	defer poll.Stop()
	var lastHead types.Hash
	for {
		select {
		case <-ctx.Done():
			return errors.New("invite ended before the other admins approved")
		case <-poll.C:
		}
		// The head is cheap to ask for; the log is re-read only when it moved.
		head, err := a.node.head()
		if err != nil {
			return err
		}
		if head != lastHead {
			lastHead = head
			auth, err := a.freshLog()
			if err != nil {
				return err
			}
			if auth.State().IsMember(id) {
				a.ok("approved")
				return nil
			}
		}
		if err := wait(st.Votes, st.Quorum); err != nil {
			return err
		}
	}
}

// hostAddrs is where an invite run here can be reached: every interface
// address outside the overlay.
func hostAddrs(port uint16, state *log.State) []netip.AddrPort {
	return host.Addrs(port, append([]netip.Prefix{state.ULA()}, state.V4Ranges()...))
}

func sortRoles(roles []types.Role) []types.Role {
	slices.Sort(roles)
	return slices.Compact(roles)
}
