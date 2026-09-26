package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/nning/juist/internal/statedir"

	"github.com/nning/juist/ipc"

	"github.com/nning/juist/discovery/mdns"
	"github.com/nning/juist/internal/guest"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/internal/rendezvous"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

// A node is where this device's membership lives: a running juistd, reached
// over its control socket, or — where none runs — a state directory this tool
// opens itself. Admin keys are never part of it; they stay in the keystore,
// which is the CLI user's own.
type node interface {
	// log returns a verified copy of the network's log, or errNoNetwork.
	// forget drops it, for a caller waiting on a change made elsewhere.
	log() (*log.Authority, error)
	forget()

	// chain returns the records log was verified from, anchor first, and
	// orphans the stored records off it.
	chain() ([]types.AUM, error)
	orphans() ([]types.AUM, error)

	// head is the head of the log as it is now.
	head() (types.Hash, error)

	// apply commits records the log will find authorized.
	apply(records []types.AUM) error

	// self returns this device's public keys and proposed name.
	self() (*ipc.Self, error)

	// create founds a network from a fully signed genesis admitting this
	// device; a daemon is held to that network from then on.
	create(genesis types.AUM, op operatorChoice) error

	// join redeems an invite.
	// Where the invite is a link that names its admin, it returns that
	// admin's admission, as the device that joined was handed it, and a
	// daemon is held to the network and head it names.
	join(ctx context.Context, invite, name string, op operatorChoice, progress func(guest.Event)) (*enroll.Admission, error)

	// rotate stages new keys for this device and returns the rotation record
	// with this device's own signature on it, and the current identity key's
	// signature over [ipc.RotationProof] of it.
	rotate(identity bool) (types.AUM, types.Sig, error)

	// unstage abandons staged keys the log does not name.
	unstage() error

	// standing is what a reset would forget; reset forgets it.
	standing(force bool) (resetStanding, error)
	reset(force bool) error

	// hints returns what a device joining through this one should start from.
	hints() (endpoints, leases [][]byte)

	// status is the daemon's report, or nil where no daemon runs; restatus
	// asks for it again.
	status() *ipc.Status
	restatus() (*ipc.Status, error)

	// socket is the daemon's control socket, or "" where none runs.
	socket() string

	// setOperator appoints the daemon's operator.
	setOperator(op operatorChoice) error

	// converse runs a conversation with the daemon, such as an invite.
	converse(ctx context.Context, req ipc.Request, handle eventHandler) error
}

// An eventHandler answers a daemon's events in a conversation; an error hangs up.
type eventHandler = func(ctx context.Context, e *ipc.Event, reply func(ipc.Request) error) error

// A resetStanding is what a device holds that a reset would forget.
type resetStanding struct {
	network string
	member  bool
	// logOnly is a keystore that holds a network's log and no device.
	logOnly bool
}

var errNoNetwork = errors.New("not in a network\nhint: juist join CODE, or juist init")

// An operatorChoice is who should operate the daemon after a create or join.
type operatorChoice struct {
	set bool
	uid uint32
}

// --- a running daemon ----------------------------------------------------

type daemonNode struct {
	sock string
	st   *ipc.Status
	home *home

	// auth is the log as last verified, and verified the records it was
	// verified from: what is sent on is exactly what was checked.
	auth     *log.Authority
	verified []types.AUM
}

func (n *daemonNode) call(req ipc.Request) (ipc.Response, error) {
	resp, err := ipc.Call(n.sock, req)
	if err != nil && resp.Err == ipc.ErrNotOperator {
		return resp, errNotOperator()
	}
	return resp, err
}

func (n *daemonNode) status() *ipc.Status { return n.st }
func (n *daemonNode) socket() string      { return n.sock }

func (n *daemonNode) restatus() (*ipc.Status, error) {
	resp, err := n.call(ipc.Request{Command: ipc.CmdStatus})
	if err != nil {
		return nil, err
	}
	if resp.Status == nil {
		return nil, errNoStatus
	}
	n.st = resp.Status
	return n.st, nil
}

var errNoStatus = errors.New("juistd sent no status; version mismatch?")

func (n *daemonNode) head() (types.Hash, error) {
	st, err := n.restatus()
	if err != nil {
		return types.Hash{}, err
	}
	return st.Head, nil
}

func (n *daemonNode) forget() { n.auth, n.verified = nil, nil }

// chain is exactly the records checked against the keystore's anchor, rather
// than a second read that could differ.
func (n *daemonNode) chain() ([]types.AUM, error) {
	if n.verified == nil {
		if _, err := n.log(); err != nil {
			return nil, err
		}
	}
	return n.verified, nil
}

func (n *daemonNode) records() ([]types.AUM, error) {
	if !n.st.InNetwork {
		return nil, errNoNetwork
	}
	resp, err := n.call(ipc.Request{Command: ipc.CmdLog})
	if err != nil {
		return nil, err
	}
	out := make([]types.AUM, 0, len(resp.Records))
	for _, b := range resp.Records {
		aum, err := types.DecodeAUM(b)
		if err != nil {
			return nil, fmt.Errorf("juistd sent an undecodable record: %w", err)
		}
		out = append(out, aum)
	}
	return out, nil
}

// log rebuilds the daemon's chain in memory and verifies it here: the CLI
// signs against this state, so it checks the state for itself.
func (n *daemonNode) log() (*log.Authority, error) {
	if n.auth != nil {
		return n.auth, nil
	}
	records, err := n.records()
	if err != nil {
		return nil, err
	}
	auth, err := log.FromRecords(log.NewMemStorage(), records)
	if err != nil {
		return nil, fmt.Errorf("juistd's log does not verify: %w", err)
	}
	if err := n.home.checkPin(n.sock, auth, records, n.orphans); err != nil {
		return nil, err
	}
	n.auth, n.verified = auth, records
	return auth, nil
}

// orphans returns the daemon's records off the active chain.
func (n *daemonNode) orphans() ([]types.AUM, error) {
	resp, err := n.call(ipc.Request{Command: ipc.CmdLog, Orphans: true})
	if err != nil {
		return nil, err
	}
	out := make([]types.AUM, 0, len(resp.Orphans))
	for _, b := range resp.Orphans {
		aum, err := types.DecodeAUM(b)
		if err != nil {
			return nil, fmt.Errorf("juistd sent an invalid record: %w", err)
		}
		out = append(out, aum)
	}
	return out, nil
}

func (n *daemonNode) apply(records []types.AUM) error {
	bodies := make([][]byte, 0, len(records))
	for i := range records {
		b, err := records[i].Encode()
		if err != nil {
			return err
		}
		bodies = append(bodies, b)
	}
	if _, err := n.call(ipc.Request{Command: ipc.CmdInform, Records: bodies}); err != nil {
		return fmt.Errorf("refused: %w", err)
	}
	n.forget()
	return nil
}

func (n *daemonNode) self() (*ipc.Self, error) {
	resp, err := n.call(ipc.Request{Command: ipc.CmdSelf})
	if err != nil {
		return nil, err
	}
	return resp.Self, nil
}

func (n *daemonNode) create(genesis types.AUM, op operatorChoice) error {
	b, err := genesis.Encode()
	if err != nil {
		return err
	}
	if _, err := n.call(ipc.Request{Command: ipc.CmdCreate, Records: [][]byte{b},
		SetOperator: op.set, OperatorUID: op.uid}); err != nil {
		return err
	}
	// The first log the daemon hands back is held to the genesis just
	// created through it, not trusted on sight.
	return n.home.expectNetwork(n.sock, genesis.Hash())
}

func (n *daemonNode) join(ctx context.Context, invite, name string, op operatorChoice,
	progress func(guest.Event)) (*enroll.Admission, error) {
	resp, err := ipc.Stream(ctx, n.sock, ipc.Request{Command: ipc.CmdJoin, Invite: invite, Name: name,
		SetOperator: op.set, OperatorUID: op.uid}, func(e *ipc.Event) {
		ev := guest.Event{Kind: guest.EventKind(e.Kind), Votes: e.Votes, Quorum: e.Quorum, Words: e.Text}
		if ev.Kind == guest.Connected {
			ev.Words, ev.Relayed = "", e.Text == "relay"
		}
		if ap, err := netip.ParseAddrPort(e.Addr); err == nil {
			ev.Addr = ap
		}
		progress(ev)
	})
	if err != nil {
		return nil, notOperator(err)
	}
	if secret, _ := guest.ParseInvite(invite); secret != nil {
		if link, ok := secret.(enroll.Link); ok && link.Admin != nil {
			if err := n.home.expectAdmitted(n.sock, *link.Admin, resp.Admission, n.st.Self); err != nil {
				return nil, err
			}
		}
	}
	return resp.Admission, nil
}

func (n *daemonNode) rotate(identity bool) (types.AUM, types.Sig, error) {
	resp, err := n.call(ipc.Request{Command: ipc.CmdRotate, Identity: identity})
	if err != nil {
		return types.AUM{}, types.Sig{}, err
	}
	if len(resp.Records) != 1 {
		return types.AUM{}, types.Sig{}, errors.New("juistd answered a rotation without a record")
	}
	aum, err := types.DecodeUnsignedAUM(resp.Records[0])
	if err != nil {
		return types.AUM{}, types.Sig{}, err
	}
	var proof types.Sig
	if resp.Proof != nil {
		proof = *resp.Proof
	}
	return aum, proof, nil
}

func (n *daemonNode) unstage() error {
	_, err := n.call(ipc.Request{Command: ipc.CmdUnstage})
	return err
}

func (n *daemonNode) standing(bool) (resetStanding, error) {
	if !n.st.InNetwork {
		return resetStanding{}, nil
	}
	return resetStanding{network: n.st.NetworkName, member: !n.st.NotMember}, nil
}

func (n *daemonNode) reset(force bool) error {
	// The network whose pin goes is the one this keystore recorded for the
	// daemon, not whatever the daemon says it held.
	network, pinned := n.home.daemonPinnedNetwork(n.sock)
	if _, err := n.call(ipc.Request{Command: ipc.CmdReset, Force: force}); err != nil {
		if strings.Contains(err.Error(), ipc.ErrStillMember) {
			return errors.New("the network still lists this device\nhint: --force")
		}
		return err
	}
	// The keystore would otherwise refuse the next network this daemon holds
	// as a network swapped under it.
	if err := removeIfPresent(n.home.daemonPinPath(n.sock)); err != nil {
		return err
	}
	if pinned {
		return removeIfPresent(n.home.pinPath(network))
	}
	return nil
}

func (n *daemonNode) setOperator(op operatorChoice) error {
	_, err := n.call(ipc.Request{Command: ipc.CmdSetOperator, SetOperator: true, OperatorUID: op.uid})
	return err
}

func (n *daemonNode) converse(ctx context.Context, req ipc.Request, handle eventHandler) error {
	_, err := ipc.Converse(ctx, n.sock, req, handle)
	return notOperator(err)
}

func (n *daemonNode) hints() (endpoints, leases [][]byte) {
	resp, err := n.call(ipc.Request{Command: ipc.CmdBootstrap})
	if err != nil || resp.Bootstrap == nil {
		return nil, nil
	}
	return resp.Bootstrap.Endpoints, resp.Bootstrap.Leases
}

// notOperator is err, or where it is the daemon's refusal of a user who may
// not manage it, the way to become its operator.
func notOperator(err error) error {
	if err != nil && err.Error() == ipc.ErrNotOperator {
		return errNotOperator()
	}
	return err
}

func errNotOperator() error {
	return fmt.Errorf("operator only\nhint: sudo juist set --operator=%s", currentUser())
}

// --- a state directory ----------------------------------------------------

// localNode is a state directory no daemon owns: a developer's, a test's, or
// an air-gapped admin machine's. It is the home itself, so node keys and admin
// keys share a directory there.
type localNode struct {
	h       *home
	find    func(ctx context.Context, nameplate uint16) ([]mdns.InviteHost, error)
	helpers *rendezvous.Helpers

	// lock is the home's lock, held shared for as long as this process
	// works on the directory; see [daemon.ShareHome].
	lock *os.File
}

func (n *localNode) status() *ipc.Status              { return nil }
func (n *localNode) restatus() (*ipc.Status, error)   { return nil, nil }
func (n *localNode) socket() string                   { return "" }
func (n *localNode) forget()                          {}
func (n *localNode) setOperator(operatorChoice) error { return errNoDaemon }

func (n *localNode) converse(context.Context, ipc.Request, eventHandler) error { return errNoDaemon }

var errNoDaemon = errors.New("juistd not running")

func (n *localNode) head() (types.Hash, error) {
	auth, err := n.log()
	if err != nil {
		return types.Hash{}, err
	}
	return auth.Head(), nil
}

func (n *localNode) log() (*log.Authority, error) {
	_, auth, have, err := n.h.openAuthorityAllowingNone()
	if err != nil {
		return nil, err
	}
	if !have {
		if keys.NestedLog(n.h.join(logDir)) {
			return nil, fmt.Errorf("no network in %s, but in %s\nhint: move its contents up one level",
				n.h.join(logDir), n.h.join(logDir, keys.LogDir))
		}
		return nil, errNoNetwork
	}
	return auth, nil
}

func (n *localNode) chain() ([]types.AUM, error) {
	st, auth, have, err := n.h.openAuthorityAllowingNone()
	if err != nil {
		return nil, err
	}
	if !have {
		return nil, errNoNetwork
	}
	hashes, err := auth.Chain()
	if err != nil {
		return nil, err
	}
	out := make([]types.AUM, 0, len(hashes))
	for _, h := range hashes {
		aum, err := st.AUM(h)
		if err != nil {
			return nil, err
		}
		out = append(out, aum)
	}
	return out, nil
}

func (n *localNode) orphans() ([]types.AUM, error) {
	st, auth, have, err := n.h.openAuthorityAllowingNone()
	if err != nil || !have {
		return nil, err
	}
	var out []types.AUM
	for _, o := range auth.Orphans() {
		for _, h := range o.Records {
			aum, err := st.AUM(h)
			if err != nil {
				return nil, err
			}
			out = append(out, aum)
		}
	}
	return out, nil
}

func (n *localNode) apply(records []types.AUM) error {
	auth, err := n.log()
	if err != nil {
		return err
	}
	if err := auth.Inform(records...); err != nil {
		return fmt.Errorf("refused: %w", err)
	}
	// The log is re-read, since the copy from before says a rotation never
	// happened; the keys are promoted only once the log names them.
	if auth, err = n.log(); err != nil {
		return err
	}
	_, err = keys.MaybePromote(n.h.path, auth.State().Node)
	return err
}

func (n *localNode) keys(create bool, name string) (*nodeKeys, error) {
	k, err := n.h.nodeKeys()
	if keys.Missing(err) && create {
		return n.h.createNodeKeys(name)
	}
	return k, err
}

func (n *localNode) self() (*ipc.Self, error) {
	k, err := n.keys(true, "")
	if err != nil {
		return nil, err
	}
	return &ipc.Self{Identity: k.Identity.Public(), Keys: k.Public, Name: displayName(k)}, nil
}

func (n *localNode) create(genesis types.AUM, _ operatorChoice) error {
	st, err := store.Open(n.h.join(logDir))
	if err != nil {
		return err
	}
	_, err = log.Create(st, genesis)
	return err
}

func (n *localNode) join(ctx context.Context, invite, name string, _ operatorChoice, progress func(guest.Event)) (*enroll.Admission, error) {
	k, err := n.keys(true, name)
	if err != nil {
		return nil, err
	}
	_, prior, have, err := n.h.openAuthorityAllowingNone()
	if err != nil {
		return nil, err
	}
	o := guest.Options{Invite: invite, Name: name, Keys: k, Progress: progress, Find: n.find,
		Meet: n.helpers.Meeter(nil)}
	if o.Name == "" {
		o.Name = displayName(k)
	}
	if have {
		o.Network, o.NetworkName = prior.State().GenesisHash(), prior.State().Network()
	}
	o.Adopt = func(records []types.AUM) error {
		if have {
			return prior.Inform(records...)
		}
		st, err := store.Open(n.h.join(logDir))
		if err != nil {
			return err
		}
		_, err = log.FromRecords(st, records)
		return err
	}
	res, err := guest.Join(ctx, o)
	if err != nil {
		return nil, err
	}
	return res.Admission, statedir.SeedHints(n.h.path, res.Endpoints, res.Leases)
}

func (n *localNode) rotate(identity bool) (types.AUM, types.Sig, error) {
	auth, err := n.log()
	if err != nil {
		return types.AUM{}, types.Sig{}, err
	}
	if err := n.h.canStageNodeKeys(); err != nil {
		return types.AUM{}, types.Sig{}, err
	}
	cur, err := n.h.nodeKeys()
	if err != nil {
		return types.AUM{}, types.Sig{}, fmt.Errorf("no keys to rotate: %w", err)
	}
	if !auth.State().IsMember(cur.Identity.Public()) {
		return types.AUM{}, types.Sig{}, errors.New("this device is not a member")
	}
	var staged *nodeKeys
	var aum types.AUM
	b := auth.Builder()
	if identity {
		if staged, err = n.h.rotatedIdentity(); err == nil {
			aum, err = b.RotateIdentity(cur.Identity.Public(), staged.Identity.Public(), sealer())
		}
	} else if staged, err = n.h.rotatedKeys(); err == nil {
		aum, err = b.RotateNodeKey(staged.Identity.Public(), staged.Public, sealer())
	}
	if err != nil {
		return types.AUM{}, types.Sig{}, err
	}
	if err := log.SignAsDevice(&aum, auth.State().Schema(), cur.Identity, staged.Identity); err != nil {
		return types.AUM{}, types.Sig{}, err
	}
	proof, err := cur.Identity.Sign(ipc.RotationProof(&aum))
	if err != nil {
		return types.AUM{}, types.Sig{}, err
	}
	return aum, proof, n.h.stageNodeKeys(staged)
}

func (n *localNode) unstage() error {
	staged, err := n.h.stagedNodeKeys()
	if keys.Missing(err) {
		return errors.New(ipc.ErrNothingStaged)
	}
	if err != nil {
		return err
	}
	auth, err := n.log()
	if err != nil {
		return fmt.Errorf("staged keys kept; cannot tell whether the log names them: %w", err)
	}
	if rec, ok := auth.State().Node(staged.Identity.Public()); ok && staged.NamedBy(&rec) {
		return errors.New("the log names the staged keys already; kept")
	}
	// Archived, not deleted: the record carries this device's signature, and
	// an admin may still approve it.
	return keys.Abandon(n.h.path)
}

func (n *localNode) hints() (endpoints, leases [][]byte) { return nil, nil }

func (n *localNode) standing(force bool) (resetStanding, error) {
	k, err := n.h.optionalNodeKeys()
	if err != nil && !force {
		return resetStanding{}, err
	}
	auth, err := n.log()
	switch {
	case err == nil:
		state := auth.State()
		s := resetStanding{network: state.Network(), logOnly: k == nil}
		if k != nil {
			s.member = state.IsMember(k.Identity.Public())
		}
		return s, nil
	case errors.Is(err, errNoNetwork), force:
		return resetStanding{}, nil
	default:
		return resetStanding{}, fmt.Errorf("%w\nhint: --force resets an unreadable log", err)
	}
}

func (n *localNode) reset(bool) error {
	var network types.Hash
	if auth, err := n.log(); err == nil {
		network = auth.State().GenesisHash()
	}
	if err := resetLocalHome(n.h); err != nil {
		return err
	}
	if network.IsZero() {
		return nil
	}
	return removeIfPresent(n.h.pinPath(network))
}

// --- choosing one ---------------------------------------------------------

// systemHome is the packaged service's state directory. Its existence says
// the service is installed, whether or not it runs.
const systemHome = "/var/lib/juist"

// openNode finds this device's node. --socket names the daemon outright.
// Otherwise a daemon on the home's own socket wins, then a home that holds a
// device of its own — a developer's, or one set up before the service — and
// then the installed service; only where none of them is there does the CLI
// start a device in the home itself. What it must never do is quietly enroll
// a device in the keystore while the installed service sits outside the
// network.
func (a *app) openNode() (node, error) {
	if a.node != nil {
		return a.node, nil
	}
	try := func(sock string) (bool, error) {
		resp, err := ipc.Call(sock, ipc.Request{Command: ipc.CmdStatus})
		if err == nil && resp.Status == nil {
			return false, errNoStatus
		}
		if err == nil {
			a.node = &daemonNode{sock: sock, st: resp.Status, home: a.home}
			return true, nil
		}
		if noDaemon(err) {
			return false, nil
		}
		return false, describeCallFailure(sock, err)
	}
	if a.socketExplicit {
		if ok, err := try(a.socket); ok || err != nil {
			return a.node, err
		}
		return nil, fmt.Errorf("juistd not running at %s", a.socket)
	}
	if ok, err := try(ipc.SocketPath(a.home.path)); ok || err != nil {
		return a.node, err
	}
	if holdsNode(a.home) {
		if statedir.HomeInUse(a.home.path) {
			// A daemon runs from this directory: its state is changed through
			// it, never behind its back.
			if ok, err := try(ipc.SystemSocket); ok || err != nil {
				return a.node, err
			}
			return nil, fmt.Errorf("juistd owns %s\nhint: use --socket, or drop --home", a.home.path)
		}
		if serviceInstalled() && !a.homeExplicit {
			a.warn("juistd not running for %s; using %s", systemHome, a.home.path)
		}
		return a.localNode()
	}
	if ok, err := try(ipc.SystemSocket); ok || err != nil {
		return a.node, err
	}
	if serviceInstalled() {
		return nil, errors.New("juistd not running\nhint: sudo systemctl enable --now juistd")
	}
	return a.localNode()
}

// localNode works on the home's files itself, holding its lock.
func (a *app) localNode() (node, error) {
	lock, err := statedir.ShareHome(a.home.path)
	if errors.Is(err, statedir.ErrHomeInUse) {
		return nil, fmt.Errorf("juistd just started from %s; retry", a.home.path)
	}
	if err != nil {
		return nil, err
	}
	a.node = &localNode{h: a.home, find: a.findInvite, helpers: a.helpers, lock: lock}
	return a.node, nil
}

func serviceInstalled() bool {
	_, err := os.Stat(systemHome)
	return err == nil
}

// holdsNode reports whether a home is a device's state directory of its own.
func holdsNode(h *home) bool {
	for _, name := range []string{nodeKeysFile, filepath.Join(logDir, "anchor")} {
		if _, err := os.Stat(h.join(name)); err == nil {
			return true
		}
	}
	return false
}
