package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/nning/juist/ipc"

	"github.com/nning/juist/internal/govern"
	"github.com/nning/juist/internal/host"
	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/internal/waiting"
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

// admissionHold is how long a copy of an admission waits on the admin
// devices, unless the app says otherwise; the invite renews it while it runs.
const admissionHold = 5 * time.Minute

type inviteOptions struct {
	name    string
	relay   bool
	admin   bool
	ingress bool
	service string // the name it publishes as a service member
	expires time.Duration
	port    uint
	lan     bool
	dht     bool
	yes     bool
}

func cmdInvite(a *app, args []string) error {
	s := spec{name: "juist invite", args: "[NAME]", max: 1, about: `
Invite one device and wait until it joins. Prints a code for the same LAN,
and a link and QR code for anywhere; behind NAT the devices meet through the
public BitTorrent DHT. Both end when a device joins or the invite expires. A
wrong guess voids the code; the link still works.

NAME is the device's name in the network (default: its own). Where more
admins must approve, the invite waits for them.`}
	fs := newFlags(s.name)
	var o inviteOptions
	fs.BoolVar(&o.relay, "relay", false, "make the device a relay")
	fs.BoolVar(&o.admin, "voucher", false, "make the device a voucher")
	fs.BoolVar(&o.ingress, "ingress", false, "make the device an ingress")
	fs.StringVar(&o.service, "service", "", "make the device a service member publishing `NAME`")
	expires := longDuration(time.Hour)
	fs.Var(&expires, "expires", "invite lifetime `DURATION`, like 30m, 2h or 7d")
	fs.UintVar(&o.port, "port", DefaultInvitePort, "TCP port to listen on")
	noLAN := fs.Bool("no-lan", false, "no code on the LAN; link only")
	noDHT := fs.Bool("no-dht", false, "do not meet through the public DHT")
	fs.BoolVar(&o.yes, "yes", false, "admit without comparing words")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	o.lan, o.dht, o.expires = !*noLAN, !*noDHT, time.Duration(expires)
	if len(pos) == 1 {
		o.name = pos[0]
		if err := checkName("device name", o.name); err != nil {
			return a.usageErr("%v", err)
		}
	}
	if o.port > 0xffff {
		return a.usageErr("\"%d\" is not a port", o.port)
	}
	if o.ingress && o.admin {
		return a.usageErr("--ingress cannot be used with --voucher")
	}
	if o.service != "" && (o.ingress || o.admin || o.relay) {
		return a.usageErr("--service cannot be used with --relay, --voucher or --ingress")
	}
	if o.expires <= 0 || o.expires > 7*24*time.Hour {
		return a.usageErr("--expires must be between 1s and 7d")
	}

	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	if o.service != "" {
		if auth.State().Domain() == "" {
			return fmt.Errorf("the network has no domain to publish under\nhint: juist network domain pub.example.org")
		}
		if o.service, err = parseLabel(o.service, auth.State().Domain()); err != nil {
			return a.usageErr("--service: %v", err)
		}
		if err := labelFree(auth.State(), o.service, types.Identity{}, a.now().Unix()); err != nil {
			return err
		}
	}
	key, err := a.admittingKey(auth)
	if err != nil {
		return err
	}
	adm := &admitter{a: a, o: o, key: key}
	ctx, cancel := context.WithTimeout(a.ctx, o.expires)
	defer cancel()

	var serveErr error
	if d := daemonOf(a.node); d != nil {
		if !o.yes && !a.interactive {
			return errors.New("comparing words needs a terminal; --yes skips it")
		}
		// juistd runs the session, and so could put a device of its own in
		// the guest's place: the words the guest shows are what say it did
		// not.
		adm.compare = !o.yes
		serveErr = a.inviteThroughDaemon(ctx, d, auth, adm, o)
	} else {
		serveErr = a.inviteHere(ctx, auth, adm, o)
	}
	return a.inviteOutcome(serveErr)
}

// inviteHere runs the invite in this process, on a state directory no daemon
// owns.
func (a *app) inviteHere(ctx context.Context, auth *log.Authority, adm *admitter, o inviteOptions) error {
	opts := host.Options{Port: uint16(o.port), LAN: o.lan, SkipInterface: instance.Device(0),
		Addrs: func(port uint16) []netip.AddrPort { return a.inviteAddrs(port, auth.State()) }}
	if o.dht {
		opts.Helpers = a.helpers
	}
	h, err := host.Listen(opts)
	if err != nil {
		return err
	}
	inv := h.Invite()
	a.announceInvite(auth.State().Network(), inv.Code().String(), inv.Link().WithAdmin(adm.key.Public(), new(adm.key.SigningKey())), h.Port(), o)
	chain := func() ([]types.AUM, [][]byte, [][]byte, error) {
		records, err := a.node.chain()
		return records, nil, nil, err
	}
	return h.Serve(ctx, adm, chain, a.reportHostEvent)
}

// inviteThroughDaemon has juistd offer the invite: the listener, the LAN
// answers and the public DHT run there, apart from the admin keys, and the
// daemon asks this process to decide and sign each admission.
func (a *app) inviteThroughDaemon(ctx context.Context, d *daemonNode, auth *log.Authority, adm *admitter,
	o inviteOptions) error {
	// Whole seconds, rounded up: an invite shorter than one still gets one.
	expires := uint32((o.expires + time.Second - 1) / time.Second)
	req := ipc.Request{Command: ipc.CmdInvite, Offer: &ipc.InviteOffer{
		Port: uint16(o.port), LAN: o.lan, DHT: o.dht, Expires: expires}}
	network := auth.State().Network()
	conv := &govern.Invite{
		Key: adm.key.Public(), Signing: adm.key.SigningKey(),
		Announce: func(code enroll.Code, link enroll.Link, port uint16) {
			a.announceInvite(network, code.String(), link, port, o)
		},
		Admit: adm.Admit,
		Event: a.reportHostEvent,
	}
	err := d.converse(ctx, req, conv.Handle)
	// The admission ends with the conversation's context; nothing of it is
	// left running, or asking, once the invite has ended.
	conv.Wait()
	if err != nil && ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return host.ErrExpired
		}
		return host.ErrCancelled
	}
	return daemonHostError(err)
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

// roles are the roles the invited device is admitted with.
func (o inviteOptions) roles() []types.Role {
	var roles []types.Role
	if o.relay {
		roles = append(roles, types.RoleRelayCapable)
	}
	if o.admin {
		roles = append(roles, types.RoleAdmin)
	}
	if o.ingress {
		roles = append(roles, types.RoleIngress)
	}
	if o.service != "" {
		roles = append(roles, types.RoleService)
	}
	return sortRoles(roles)
}

// published is what the invited device is admitted publishing.
func (o inviteOptions) published() []types.PublishedName {
	if o.service == "" {
		return nil
	}
	return []types.PublishedName{{Label: o.service, Port: 443}}
}

func (a *app) announceInvite(network, code string, link enroll.Link, port uint16, o inviteOptions) {
	roles := o.roles()
	as := ""
	if len(roles) > 0 {
		as = " as " + describeRoles(roles)
	}
	// Each command on a line of its own, set apart, so that a long link is
	// easy to select whole.
	a.printf("invite to %q%s, expires in %s; on the new device:\n\n", network, as, shortDuration(o.expires))
	a.showQR(link.String())
	// Quoted: a link holds brackets around IPv6 addresses, which zsh
	// globs, and commas; pasted as printed, it must reach juist as one word.
	a.command("juist join '%s'", link)
	a.printf("\n")
	switch {
	case len(link.Relays) > 0:
		a.printf("%s\n\n", a.dim(fmt.Sprintf("meets through relay %s where this device is unreachable", link.Relays[0])))
	case len(link.Named) > 0:
		a.printf("%s\n\n", a.dim(fmt.Sprintf("meets through relay %s on 443 where this device is unreachable", link.Named[0])))
	}
	// Last, so that a window shorter than the QR code still shows it.
	if o.lan {
		a.printf("  %s  %s\n\n", a.bold("juist join "+code), a.dim("# same LAN"))
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
		a.printf("%s\n", a.dim(fmt.Sprintf("no DHT for the link: %s", e.Err)))
	case host.NoRelay:
		a.warn("cannot wait at relay %s (%s); retrying", e.Addr, e.Err)
	case host.CodeVoided:
		if e.Err != "" {
			a.warn("code voided: %s, from %s", e.Err, e.Addr)
		} else {
			a.warn("code voided: wrong guess from %s", e.Addr)
		}
		a.hint("if that was not your device, someone else knows the code; the link still works")
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
		return "", nil, errors.New("the log lists the device with other keys")
	}
	admission, err := enroll.SignAdmission(m.key, auth.State().GenesisHash(), auth.Head(), id)
	if err != nil {
		return "", nil, err
	}
	return cur.Name, admission, nil
}

func sameKeys(n types.NodeRecord, req *enroll.JoinRequest) bool { return govern.SameKeys(n, req) }

// compareWords has the person compare the words the device shows with those
// shown here. The salt is drawn now, after the request committed to its
// nonce, and the nonce is held to that commitment: neither the device that
// asked nor the one in between can search for matching words.
func (m *admitter) compareWords(ctx context.Context, req *enroll.JoinRequest,
	compare func(enroll.Salt) (enroll.Nonce, error)) error {
	a := m.a
	words, err := govern.Words(req, compare)
	if err != nil {
		return err
	}
	a.printf("%s wants to join; compare with the words it shows:\n", cmp.Or(m.o.name, memberName(req.Name)))
	a.command("%s", words)
	ok, err := a.askNow(ctx, "same?")
	if err != nil {
		return fmt.Errorf("not admitted: %w", err)
	}
	if !ok {
		return errors.New("words not confirmed; not admitted\nhint: other words mean another device is asking")
	}
	return nil
}

// addNode admits a device that is no member yet, and waits for the other
// admins where they must approve.
func (m *admitter) addNode(ctx context.Context, auth *log.Authority, req *enroll.JoinRequest,
	wait func(votes, quorum uint32) error) (err error) {
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
	rec.Roles, rec.Published = o.roles(), o.published()
	aum, err := auth.Builder().AddNode(rec, sealer())
	if err != nil {
		return fmt.Errorf("cannot admit %s: %w", name, err)
	}
	a.printf("admitting %s (%v)\n", name, req.Identity.ShortString())
	// After the outcome, where it is an admission.
	if p := state.Policy(); p != nil && !slices.ContainsFunc(p.Rules, func(r types.PolicyRule) bool { return r.From.Any || r.To.Any }) {
		defer func() {
			if err == nil {
				a.hint("the policy passes no traffic for %s until it names it: juist policy edit", name)
			}
		}()
	}
	c := &change{
		aum:  aum,
		file: "add-" + fileSafe(name) + ".rec",
		done: fmt.Sprintf("admitted %s at %s", name, v4),
	}
	// Approved after the invite, it would admit a device that never got the
	// log, so a copy on the admin devices outlives the invite by little.
	end, _ := ctx.Deadline()
	holdFor := func() time.Duration { return max(min(time.Until(end), a.admissionHold), time.Second) }
	c.wait = holdFor()
	// The invite may have ended while a person looked at the words: a device
	// admitted then would be a member that never got the log.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("not admitted: %w", err)
	}
	applied, err := a.submit(auth, c)
	if err != nil || applied {
		return err
	}
	// The votes its copies gathered lapse with them: each is folded in as it
	// arrives, and handed on at once, not at the next renewal. The copies are
	// opened only when the daemon holds others than at the last look.
	var held []types.Hash
	renew := func(due bool) bool {
		if ctx.Err() != nil {
			return false
		}
		grew := false
		d := daemonOf(a.node)
		if d == nil {
			return false
		}
		raw, err := d.waiting(nil)
		var now []types.Hash
		for _, b := range raw {
			now = append(now, waiting.Hash(b))
		}
		slices.SortFunc(now, types.Hash.Compare)
		if err == nil && (due || !slices.Equal(now, held)) {
			held = now
			changes, _ := a.openWaiting(auth, raw)
			for _, w := range changes {
				if w.aum.SigHash() == c.aum.SigHash() {
					merged := mergeSignatures(auth.State(), &c.aum, w.aum.Signatures)
					grew = len(merged) > len(c.aum.Signatures)
					c.aum.Signatures = merged
				}
			}
		}
		// An invite ended meanwhile admits no one, nor hands its admission on.
		if !due && !grew || ctx.Err() != nil {
			return false
		}
		if auth.State().SignatureStatus(&c.aum).Authorized() {
			if err := a.applyRecords([]types.AUM{c.aum}); err != nil {
				a.warn("%v", err)
			}
			return true
		}
		if _, _, err := a.carry(auth, &c.aum, holdFor(), types.Identity{}); err != nil {
			a.warn("%v", err)
		}
		return true
	}
	err = a.awaitAdmission(ctx, wait, req.Identity, auth.State().SignatureStatus(&c.aum), renew)
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
// reaches this device's log, telling the guest as it goes. renew, given
// whether a renewal is due, reports whether it renewed.
func (a *app) awaitAdmission(ctx context.Context, wait func(votes, quorum uint32) error, id types.Identity,
	st log.SignatureStatus, renew func(due bool) bool) error {
	if err := wait(st.Votes, st.Quorum); err != nil {
		return err
	}
	a.printf("%s\n", a.dim("waiting for the other admins"))
	poll := time.NewTicker(min(admissionPoll, a.admissionHold/4))
	defer poll.Stop()
	renewed := time.Now()
	var lastHead types.Hash
	for {
		select {
		case <-ctx.Done():
			return errors.New("invite ended before the other admins approved")
		case <-poll.C:
		}
		// A copy's hold runs from before the work of renewing it.
		if now := time.Now(); renew(now.Sub(renewed) > a.admissionHold/2) {
			renewed = now
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
