// Package guest is the joining device's half of an enrollment: find the
// inviting device, run the key exchange, ask to be admitted, and take the log
// it is sent — verified in full before anything is stored. It is shared by
// the daemon, which runs it for "juist join", and the CLI, which runs it
// itself on a state directory no daemon owns.
package guest

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/nning/juist/discovery/mdns"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/internal/underlay"
	"github.com/nning/juist/relay/forward"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// Timeouts for the guest's side.
const (
	// FindTimeout bounds the LAN search for the inviting device.
	FindTimeout = 10 * time.Second

	dialTimeout      = 5 * time.Second
	handshakeTimeout = 20 * time.Second

	// meetAfter is the head start the link's addresses get before the
	// public DHT is asked too: on a LAN or a reachable host they answer well
	// within it, and no outside service hears of the join.
	meetAfter = 2 * time.Second

	// meetTimeout bounds the meeting: a few DHT round trips and the punching.
	meetTimeout = 2 * time.Minute

	// silenceTimeout is how long the guest waits for the next message. A host
	// waiting on approvals says so every 15 seconds, so only a host that went
	// away is silent this long.
	silenceTimeout = time.Minute

	// maxLogBytes bounds what a guest buffers of the log it is sent.
	maxLogBytes = 256 << 20
)

// An EventKind is a step of a join worth telling the person waiting on it.
type EventKind uint8

const (
	// Looking: searching the LAN for the invite's number.
	Looking EventKind = 1

	// Connected: the key exchange succeeded with the device at Addr.
	Connected EventKind = 2

	// Waiting: admission needs more admins' votes than the host holds.
	Waiting EventKind = 3

	// Meeting: the link's addresses did not answer at once, so the join
	// looks for the host through the public DHT as well.
	Meeting EventKind = 4

	// Compare: the inviting admin is asked whether this device shows Words.
	Compare EventKind = 5
)

// An Event reports progress.
type Event struct {
	Kind          EventKind
	Addr          netip.AddrPort
	Votes, Quorum uint32
	Words         string

	// Relayed says the connection runs through the member relay at Addr.
	Relayed bool
}

// Options configures a join.
type Options struct {
	// Invite is the code or link, as typed or pasted.
	Invite string

	// Name is the member name to ask for; the host may choose another.
	Name string

	// Keys are this device's; the request proves possession of Identity.
	Keys *keys.Node

	// Network is the genesis hash of the log this device already holds, or
	// zero. A device holding one may only join that network again.
	Network types.Hash
	// NetworkName names it, for the refusal.
	NetworkName string

	// Elsewhere are networks the host is in through another of its juistd
	// instances, which this device must not join a second time.
	Elsewhere []types.Hash

	// Adopt stores the chain once it has been verified to admit this device,
	// anchor first. It is the only thing that writes.
	Adopt func(records []types.AUM) error

	// Announce, after Adopt, starts the device in the network with the
	// member announcements and leases the host sent, and returns its own
	// signed announcement for the host, or nil. Nil skips it.
	Announce func(endpoints, leases [][]byte) []byte

	// Find asks the LAN who holds an invite. Nil uses mDNS.
	Find func(ctx context.Context, nameplate uint16) ([]mdns.InviteHost, error)

	// SkipInterface is never searched on: in practice the overlay device.
	SkipInterface string

	// Meet reaches a link's host where its addresses cannot be dialled, as
	// when both devices are behind NAT; see internal/rendezvous. Nil tries
	// the addresses alone.
	Meet func(ctx context.Context, link enroll.Link) (net.Conn, error)

	// Progress receives events. Nil discards them.
	Progress func(Event)

	// HTTPSOnly reaches the host through the relays the link names on 443
	// alone, through Proxy: no LAN search, no DHT, no address of the host's.
	HTTPSOnly bool
	Proxy     forward.Proxy
}

// ErrNoNamedRelay is a link that names no relay on 443, which is all a
// device on HTTPS alone reaches.
var ErrNoNamedRelay = errors.New("the invite link names no relay on 443, which is all this device reaches")

// A Result is a completed join.
type Result struct {
	// Log is the chain as the host sent it, verified in memory.
	Log *log.Authority

	// Endpoints are member announcements, and Leases the leases among those
	// sent that vouch for Log. Neither is verified beyond that; both are
	// hints.
	Endpoints, Leases [][]byte

	// Admission is the inviting admin's, verified against the link's admin
	// key, where the link names one.
	Admission *enroll.Admission
}

// ParseInvite reads a code or a link. One pasted with the quotes it was
// printed in, where no shell took them off, is read without them.
func ParseInvite(s string) (enroll.Secret, error) {
	s = strings.TrimSpace(s)
	for _, q := range []string{"'", `"`} {
		if len(s) >= 2 && strings.HasPrefix(s, q) && strings.HasSuffix(s, q) {
			s = s[1 : len(s)-1]
			break
		}
	}
	if enroll.IsLink(s) {
		return enroll.ParseLink(s)
	}
	return enroll.ParseCode(s)
}

// Join runs one join to completion.
func Join(ctx context.Context, o Options) (*Result, error) {
	secret, err := ParseInvite(o.Invite)
	if err != nil {
		return nil, err
	}
	progress := o.Progress
	if progress == nil {
		progress = func(Event) {}
	}
	conn, err := reachHost(ctx, secret, o, progress)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	ch, err := enroll.Join(conn, secret)
	if err != nil {
		return nil, explain(err)
	}
	if ap, err := netip.ParseAddrPort(conn.RemoteAddr().String()); err == nil {
		_, relayed := conn.(relayedConn)
		progress(Event{Kind: Connected, Addr: ap, Relayed: relayed})
	}
	// The nonce is fixed, and committed to, before any salt exists; see
	// [enroll.Fingerprint].
	var nonce enroll.Nonce
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	req, err := enroll.NewJoinRequest(ch, o.Name, o.Keys.Identity, o.Keys.Public, nonce)
	if err != nil {
		return nil, err
	}
	if err := ch.Send(&enroll.Message{Kind: enroll.KindJoin, Join: req}); err != nil {
		return nil, err
	}

	var records []types.AUM
	received := 0
	compared := false
	for {
		_ = conn.SetDeadline(time.Now().Add(silenceTimeout))
		msg, err := ch.Receive()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("the inviting device went away: %w", err)
		}
		switch msg.Kind {
		case enroll.KindWaiting:
			progress(Event{Kind: Waiting, Votes: msg.Waiting.Votes, Quorum: msg.Waiting.Quorum})
		case enroll.KindCompare:
			// One salt, answered once: a host that could ask again could
			// try salts until the words matched another device's.
			if compared {
				return nil, errors.New("the inviting device asked to compare words twice, which the " +
					"protocol never does; it may be compromised")
			}
			compared = true
			if err := ch.Send(&enroll.Message{Kind: enroll.KindReveal, Reveal: &nonce}); err != nil {
				return nil, err
			}
			progress(Event{Kind: Compare,
				Words: enroll.Fingerprint(*msg.Compare, nonce, o.Keys.Identity.Public(), o.Keys.Public)})
		case enroll.KindRecord:
			received += len(msg.Record)
			if len(records) >= enroll.MaxRecords || received > maxLogBytes {
				return nil, errors.New("the inviting device sent more records than a log can hold")
			}
			aum, err := types.DecodeAUM(msg.Record)
			if err != nil {
				return nil, fmt.Errorf("the inviting device sent an invalid record: %w", err)
			}
			records = append(records, aum)
		case enroll.KindWelcome:
			return welcome(ch, secret, records, msg.Welcome, o)
		case enroll.KindRefused:
			return nil, fmt.Errorf("the inviting device gave up: %s", msg.Reason)
		default:
			return nil, fmt.Errorf("the inviting device sent a %v", msg.Kind)
		}
	}
}

// welcome takes the host's welcome, which follows the records: the chain is
// verified and adopted, and the host hears that the device joined.
func welcome(ch *enroll.Channel, secret enroll.Secret, records []types.AUM, w *enroll.Welcome, o Options) (*Result, error) {
	if int(w.Records) != len(records) {
		return nil, fmt.Errorf("the inviting device announced %d records and sent %d", w.Records, len(records))
	}
	var link *enroll.Link
	if l, ok := secret.(enroll.Link); ok && l.Admin != nil {
		link = &l
	}
	sent, err := adopt(records, o, link, w.Admission)
	if err != nil {
		_ = ch.Send(&enroll.Message{Kind: enroll.KindRefused, Reason: enroll.ReasonText(err)})
		return nil, err
	}
	leases := vouching(sent, w.Leases, time.Now().Unix())
	var announcement []byte
	if o.Announce != nil {
		if announcement = o.Announce(w.Endpoints, leases); len(announcement) > enroll.MaxAnnouncementLen {
			announcement = nil
		}
	}
	// A host that does not hear this still admitted the device, and the log
	// is stored: the join succeeded either way.
	_ = ch.Send(&enroll.Message{Kind: enroll.KindJoined, Announcement: announcement})
	res := &Result{Log: sent, Endpoints: w.Endpoints, Leases: leases}
	if link != nil {
		res.Admission = w.Admission
	}
	return res, nil
}

// reachHost connects to the inviting device: at the link's addresses, or at
// whichever device answers for the code's number on the LAN.
func reachHost(ctx context.Context, secret enroll.Secret, o Options, progress func(Event)) (net.Conn, error) {
	if o.HTTPSOnly {
		link, ok := secret.(enroll.Link)
		switch {
		case !ok:
			return nil, errors.New("an invite code is found on the LAN, which this device does not use on HTTPS alone\n" +
				"Use the link \"juist invite\" printed instead")
		case len(link.Named) == 0:
			return nil, fmt.Errorf("%w\nAsk for a new link once a relay serves a name on 443", ErrNoNamedRelay)
		}
		conn, err := dialFirst(ctx, named(link, o.Proxy))
		if err != nil {
			return nil, fmt.Errorf("cannot reach the inviting device through the relays %v: %w\n%s",
				link.Named, err, "It may have stopped waiting")
		}
		return conn, nil
	}
	var addrs []netip.AddrPort
	switch s := secret.(type) {
	case enroll.Link:
		addrs = s.Addrs
	case enroll.Code:
		progress(Event{Kind: Looking})
		find := o.Find
		if find == nil {
			find = func(ctx context.Context, nameplate uint16) ([]mdns.InviteHost, error) {
				return mdns.FindInvite(ctx, nameplate, FindTimeout, mdns.InviteOptions{SkipInterface: o.SkipInterface})
			}
		}
		hosts, err := find(ctx, s.Nameplate)
		if err != nil {
			return nil, fmt.Errorf("cannot search this network for the inviting device: %w\n"+
				"Use the link \"juist invite\" printed instead of the code", err)
		}
		switch len(hosts) {
		case 0:
			return nil, fmt.Errorf("no device on this network has an invite numbered %d\n"+
				"Check that the inviting device is on the same network and still waiting, "+
				"or use the link it printed", s.Nameplate)
		case 1:
			addrs = hosts[0].Addrs
		default:
			// Trying one would spend a guess on an invite that may not be ours.
			return nil, fmt.Errorf("%d devices on this network have an invite numbered %d\n"+
				"Ask for a new invite, or use the link it printed", len(hosts), s.Nameplate)
		}
	}
	link, isLink := secret.(enroll.Link)
	if isLink && o.Meet != nil {
		return dialOrMeet(ctx, link, o.Meet, progress)
	}
	if isLink {
		conn, err := dialLink(ctx, link)
		if err != nil {
			return nil, fmt.Errorf("cannot reach the inviting device%s%s: %w\n%s", at(addrs), viaRelays(link), err,
				stillWaiting(addrs))
		}
		return conn, nil
	}
	conn, err := dialAny(ctx, addrs)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the inviting device%s: %w\n%s", at(addrs), err, stillWaiting(addrs))
	}
	return conn, nil
}

// at and stillWaiting word a failure to reach addrs, which may be none: a
// link may name relays only, and a LAN answer no address.
func at(addrs []netip.AddrPort) string {
	if len(addrs) == 0 {
		return ""
	}
	return fmt.Sprintf(" at %v", addrs)
}

func stillWaiting(addrs []netip.AddrPort) string {
	if len(addrs) == 0 {
		return "It may have stopped waiting"
	}
	return fmt.Sprintf("It may have stopped waiting, or a firewall may block TCP port %d", addrs[0].Port())
}

func viaRelays(link enroll.Link) string {
	var relays []string
	for _, r := range link.Relays {
		relays = append(relays, r.String())
	}
	relays = append(relays, link.Named...)
	switch {
	case len(relays) == 0:
		return ""
	case len(link.Addrs) == 0:
		return fmt.Sprintf(" through the relays at %v", relays)
	default:
		return fmt.Sprintf(", or through the relays at %v", relays)
	}
}

// dialAny connects to the first of addrs that answers, trying all at once.
func dialAny(ctx context.Context, addrs []netip.AddrPort) (net.Conn, error) {
	return dialFirst(ctx, direct(addrs))
}

// dialLink connects to the link's host at its own addresses or through the
// relays it waits at, trying all at once. What the relays carry is the same
// handshake, keyed by the link's secret, which the relays never see.
func dialLink(ctx context.Context, link enroll.Link) (net.Conn, error) {
	dials := direct(link.Addrs)
	id := link.ForwardID()
	for _, r := range link.Relays {
		dials = append(dials, func(ctx context.Context) (net.Conn, error) {
			c, err := untilWaiting(ctx, func(ctx context.Context) (net.Conn, error) { return forward.Dial(ctx, r, id) })
			if err != nil {
				return nil, err
			}
			return relayedConn{c}, nil
		})
	}
	return dialFirst(ctx, append(dials, named(link, nil)...))
}

// named are the dials to the link's relays by their names on 443, through
// proxy, verified by WebPKI.
func named(link enroll.Link, proxy forward.Proxy) []func(context.Context) (net.Conn, error) {
	id := link.ForwardID()
	var out []func(context.Context) (net.Conn, error)
	for _, name := range link.Named {
		out = append(out, func(ctx context.Context) (net.Conn, error) {
			c, err := untilWaiting(ctx, func(ctx context.Context) (net.Conn, error) {
				return forward.DialNamed(ctx, name, id, proxy)
			})
			if err != nil {
				return nil, err
			}
			return relayedConn{c}, nil
		})
	}
	return out
}

// relayWait is how long a guest asks a relay again whose host has not
// registered yet, as one that printed its link a moment ago may not have.
var relayWait = 30 * time.Second

// untilWaiting dials again while the relay says no host waits there yet.
func untilWaiting(ctx context.Context, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	until := time.Now().Add(relayWait)
	for {
		c, err := dial(ctx)
		if err == nil || !errors.Is(err, forward.ErrNotWaiting) || time.Now().After(until) {
			return c, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(time.Second):
		}
	}
}

// relayedConn marks a connection that runs through a member relay.
type relayedConn struct{ net.Conn }

func direct(addrs []netip.AddrPort) []func(context.Context) (net.Conn, error) {
	out := make([]func(context.Context) (net.Conn, error), 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, func(ctx context.Context) (net.Conn, error) {
			return underlay.Dialer(dialTimeout).DialContext(ctx, "tcp", addr.String())
		})
	}
	return out
}

// dialFirst runs every dial at once and keeps the first connection made.
func dialFirst(ctx context.Context, dials []func(context.Context) (net.Conn, error)) (net.Conn, error) {
	if len(dials) == 0 {
		return nil, errors.New("no address to try")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan dialed, len(dials))
	for _, dial := range dials {
		go func() {
			conn, err := dial(ctx)
			results <- dialed{conn: conn, err: err}
		}()
	}
	// The first connection is taken at once, rather than once every dial
	// has ended: the host times out a connection that says nothing, and a
	// slow relay would otherwise hold a direct winner past that. The rest
	// are closed as they come.
	var errs []error
	for pending := len(dials); pending > 0; pending-- {
		r := <-results
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		cancel()
		closeLate(results, pending-1)
		return r.conn, nil
	}
	return nil, errors.Join(errs...)
}

// dialed is one dial's outcome; met marks a meeting through the DHT.
type dialed struct {
	conn net.Conn
	err  error
	met  bool
}

// closeLate closes, as they arrive, the connections the n dials still
// running make: a dial that lost the race may yet connect, and its
// connection must not be left for the host to time out.
func closeLate(results <-chan dialed, n int) {
	go func() {
		for ; n > 0; n-- {
			if late := <-results; late.conn != nil {
				late.conn.Close()
			}
		}
	}()
}

// dialOrMeet races the link's addresses against a meeting through the DHT,
// which starts once the addresses have had their head start or have all
// failed. The loser is closed before the key exchange, which leaves the
// invite open.
func dialOrMeet(ctx context.Context, link enroll.Link, meet func(context.Context, enroll.Link) (net.Conn, error),
	progress func(Event)) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan dialed, 2)
	pending := 1
	defer func() { closeLate(results, pending) }()
	go func() {
		conn, err := dialLink(ctx, link)
		results <- dialed{conn: conn, err: err}
	}()
	headStart := time.NewTimer(meetAfter)
	defer headStart.Stop()
	meeting := false
	begin := func() {
		if meeting {
			return
		}
		meeting = true
		pending++
		progress(Event{Kind: Meeting})
		go func() {
			mctx, mcancel := context.WithTimeout(ctx, meetTimeout)
			defer mcancel()
			conn, err := meet(mctx, link)
			results <- dialed{conn: conn, err: err, met: true}
		}()
	}
	var dialErr, meetErr error
	for pending > 0 {
		select {
		case <-headStart.C:
			begin()
		case r := <-results:
			pending--
			switch {
			case r.err == nil:
				return r.conn, nil
			case r.met:
				meetErr = r.err
			default:
				dialErr = r.err
				begin()
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if len(link.Addrs) == 0 {
		return nil, fmt.Errorf("cannot reach the inviting device through the public DHT: %w\n"+
			"Is it still waiting?", meetErr)
	}
	return nil, fmt.Errorf("cannot reach the inviting device, neither at %v%s (%v) nor through the "+
		"public DHT (%v)\nIs it still waiting? If both devices are behind NAT, running \"juist join\" "+
		"on a network that can reach one of those addresses works around it", link.Addrs, viaRelays(link),
		dialErr, meetErr)
}

func explain(err error) error {
	var refused *enroll.RefusedError
	switch {
	case errors.As(err, &refused) && refused.Reason == enroll.RefusedWrongCode:
		return fmt.Errorf("the inviting device refused: %s\nIf the code was typed correctly, tell the "+
			"admin: something on this network may be impersonating the inviting device", refused.Reason)
	case errors.As(err, &refused):
		return fmt.Errorf("the inviting device refused: %s", refused.Reason)
	case errors.Is(err, enroll.ErrImpostor):
		return errors.New("the device that answered does not know the invite code, so it is not the " +
			"one that invited you\nSomeone on this network may be impersonating it. Do not retry " +
			"blindly: tell the admin, and ask for a new invite")
	default:
		return fmt.Errorf("could not complete the invite: %w", err)
	}
}

// adopt verifies the chain in memory and hands it to Adopt only if it admits
// this device under exactly its keys and the group secret opens: anything
// less would leave a log on disk that makes the device look enrolled.
//
// A link that names the inviting admin also requires that admin's signed
// admission of this device, on the chain it was sent: the device that ran the
// invite chose the log, and only the admin's signature says it is the
// admin's network.
func adopt(records []types.AUM, o Options, link *enroll.Link, admission *enroll.Admission) (*log.Authority, error) {
	sent, err := log.FromRecords(log.NewMemStorage(), records)
	if err != nil {
		return nil, fmt.Errorf("the log the inviting device sent does not verify: %w", err)
	}
	state, err := sent.TrustedState()
	if err != nil {
		return nil, err
	}
	self, ok := state.Node(o.Keys.Identity.Public())
	if !ok || !o.Keys.NamedBy(&self) {
		return nil, errors.New("the log the inviting device sent does not admit this device")
	}
	if _, err := secrets.Open(state.EpochRecord(), o.Keys.Identity.Public(), o.Keys.Recipient); err != nil {
		return nil, fmt.Errorf("the log admits this device, but its group secret is unreadable here: %w", err)
	}
	if link != nil {
		if err := checkAdmission(sent, link, admission, o.Keys.Identity.Public()); err != nil {
			return nil, err
		}
	}
	if !o.Network.IsZero() && state.GenesisHash() != o.Network {
		return nil, fmt.Errorf("this device still holds the log of %q, and the invite is for another "+
			"network\nhint: juist reset --force forgets %q; then join again", o.NetworkName, o.NetworkName)
	}
	if slices.Contains(o.Elsewhere, state.GenesisHash()) {
		return nil, fmt.Errorf("this host is in %q already, through another juistd, so it did not join it "+
			"again\nhint: the invite admitted it as %q all the same; an admin removes that: juist remove %s",
			state.Network(), self.Name, self.Name)
	}
	if err := o.Adopt(records); err != nil {
		return nil, err
	}
	return sent, nil
}

func checkAdmission(sent *log.Authority, link *enroll.Link, a *enroll.Admission, self types.Identity) error {
	const hint = "\nThe device that ran the invite may be compromised; ask the admin for a new invite"
	if a == nil {
		return errors.New("the invite link names the admin who admits this device, and the inviting " +
			"device sent no admission by that admin" + hint)
	}
	state := sent.State()
	key := state.SigningKey(*link.Admin)
	if state.PQ() && key == nil || a.Admin != *link.Admin || a.Verify(*link.AdminSigning, key) != nil ||
		a.Guest != self || a.Network != state.GenesisHash() {
		return errors.New("the admission the inviting device sent is not the admin's admission of this " +
			"device into this network" + hint)
	}
	chain, err := sent.Chain()
	if err != nil {
		return err
	}
	if !slices.Contains(chain, a.Head) {
		return errors.New("the log the inviting device sent is not the one the admin admitted this " +
			"device into" + hint)
	}
	return nil
}

// vouching keeps the leases that vouch for the adopted log; the rest would
// only crowd the real ones out of the lease file.
func vouching(auth *log.Authority, leases [][]byte, now int64) [][]byte {
	var keep [][]byte
	for _, b := range leases {
		l, err := types.DecodeLease(b)
		if err == nil && auth.CheckLease(&l, now) == nil {
			keep = append(keep, b)
		}
	}
	return keep
}
