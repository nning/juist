package daemon

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nning/juist/internal/statedir"

	"github.com/nning/juist/ipc"

	"golang.org/x/sys/unix"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/discovery/mdns"
	"github.com/nning/juist/internal/guest"
	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/internal/rendezvous"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

// A Service is juistd: it owns a state directory and its control socket, runs
// the mesh while this device is in a network, and otherwise waits to be put in
// one. Every call on the socket is attributed to a local user by the kernel:
// anyone may ask for status; root, the daemon's own user and the operator may
// do everything else; only root and the daemon's own user may choose the
// operator. Admin keys never reach it — a change arrives already signed.
type Service struct {
	opts    ServiceOptions
	logf    func(string, ...any)
	selfUID uint32
	lock    *os.File
	ipc     *ipcServer

	// mu guards everything below. It is never held across network I/O — a
	// join marks busy and runs unlocked — but it is held while the mesh
	// stops and starts, which can take a moment and makes status wait.
	mu       sync.Mutex
	ctx      context.Context
	keys     *keys.Node
	store    *store.Dir
	auth     *log.Authority // the log while no mesh owns it; nil if none
	mesh     *Daemon
	meshStop context.CancelFunc
	meshDone chan struct{}
	busy     bool
	closed   bool

	// meshErr is why the mesh last failed to start over a log that lists
	// this device; the watcher retries.
	meshErr error

	// hostConflict is what a lower instance on the host held of this
	// network's claims when the mesh last started, or nil; hostErr is the
	// last failure to read the host, logged once.
	hostConflict *hostConflictError
	hostErr      string
	clearChecks  int  // checks in a row that found the conflict gone
	meshStarted  bool // a mesh ran in this process: the host is known

	// session is what a restarted mesh announces again, for as long as the
	// device's keys are sessionKeys: new keys take a new one, since a
	// rotation answers a device that may have been copied.
	session     *Session
	sessionKeys types.NodeKeys
	sessionID   types.Identity

	// operator is 0 for none: root needs no appointment. Atomic, since the
	// accept loop asks for every connection and must not wait on mu.
	operator atomic.Uint32
}

// ServiceOptions configures a [Service].
type ServiceOptions struct {
	// Home is the state directory. Only the service writes it.
	Home string

	// Socket is where the control socket listens. Empty uses SocketPath(Home).
	Socket string

	// InviteAddrs lists where a guest can reach this device's invite at
	// port; nil scans the interfaces. Tests replace it.
	InviteAddrs func(port uint16) []netip.AddrPort

	// Mesh is what the mesh starts from; the service fills in the log, the
	// keys and the files it keeps in Home.
	Mesh Options

	// Find replaces the LAN search for an invite, for tests.
	Find func(ctx context.Context, nameplate uint16) ([]mdns.InviteHost, error)

	// Logf receives diagnostics. Nil discards them.
	Logf func(format string, args ...any)
}

// rotationCheckInterval is how often the service looks for a key rotation
// the log has adopted, however it arrived, so it can restart the mesh on the
// new keys.
const rotationCheckInterval = 5 * time.Second

// NewService opens a state directory: it takes the directory's lock, loads
// this device's keys or creates them, opens the log if there is one, and
// listens on the control socket. Call [Service.Start].
func NewService(opts ServiceOptions) (*Service, error) {
	s := &Service{opts: opts, logf: opts.Logf, selfUID: uint32(os.Getuid())}
	if s.logf == nil {
		s.logf = func(string, ...any) {}
	}
	// Only a real device puts anything into the host's tables.
	if s.opts.Mesh.HostHoldings == nil && s.opts.Mesh.TunName != "" {
		s.opts.Mesh.HostHoldings = conn.InstanceHoldings
	}
	if s.opts.Mesh.LowerStatus == nil && s.opts.Mesh.HostHoldings != nil {
		sock := cmp.Or(opts.Socket, ipc.SocketPath(opts.Home))
		s.opts.Mesh.LowerStatus = lowerStatusBeside(sock)
	}
	if s.opts.Mesh.LowerHome == nil && s.opts.Mesh.HostHoldings != nil {
		s.opts.Mesh.LowerHome = lowerHomesBeside(opts.Home, opts.Mesh.Instance)
	}
	home := opts.Home
	if err := os.MkdirAll(home, keys.DirMode); err != nil {
		return nil, fmt.Errorf("daemon: creating %s: %w", home, err)
	}
	if err := keys.RefuseSharedWritable(home); err != nil {
		return nil, err
	}
	if err := refuseForeignOwner(home); err != nil {
		return nil, err
	}
	// The daemon is the side of a device an attacker reaches first: it
	// parses what the network sends. Admin keys must not be where it runs.
	if holdsAdminKeys(home) {
		return nil, fmt.Errorf("daemon: %s holds admin keys (%s), and juistd does not run next to them; "+
			"give it a state directory of its own", home, keys.AdminsDir)
	}
	lock, err := lockHome(home)
	if err != nil {
		return nil, err
	}
	s.lock = lock
	ok := false
	defer func() {
		if !ok {
			lock.Close()
		}
	}()

	if s.keys, err = loadOrCreateKeys(home); err != nil {
		return nil, err
	}
	if s.store, err = store.Open(filepath.Join(home, keys.LogDir)); err != nil {
		return nil, err
	}
	if _, has, err := s.store.Anchor(); err != nil {
		return nil, err
	} else if has {
		if s.auth, err = log.Open(s.store); err != nil {
			return nil, err
		}
		// A rotation adopted while the daemon was down, including one it
		// had abandoned and an admin approved anyway.
		promoted, err := keys.MaybePromote(home, s.auth.State().Node)
		if err != nil {
			return nil, err
		}
		if promoted != nil {
			s.keys = promoted
			s.logf("daemon: promoted this device's staged keys; the log names them")
		}
	}
	s.operator.Store(loadOperator(filepath.Join(home, statedir.OperatorFile), s.logf))

	sock := opts.Socket
	if sock == "" {
		sock = ipc.SocketPath(home)
	}
	if s.ipc, err = newIPCServer(sock, s.handle, s.mayOperate, s.logf); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

// holdsAdminKeys reports whether home has an admin key in it, or cannot tell.
// Read as a directory rather than globbed: a home whose path has glob
// metacharacters in it would match nothing.
func holdsAdminKeys(home string) bool {
	entries, err := os.ReadDir(filepath.Join(home, keys.AdminsDir))
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".key") {
			return true
		}
	}
	return false
}

// lockHome takes the state directory's exclusive lock, which makes this
// service the single writer of the store beneath it. The kernel drops it if
// the process dies, so a crash leaves no stale lock.
func lockHome(home string) (*os.File, error) {
	path := filepath.Join(home, statedir.LockName)
	f, err := statedir.OpenLock(path)
	if err != nil {
		return nil, fmt.Errorf("daemon: opening the lock file %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("daemon: another juistd is already running on %s", home)
		}
		return nil, fmt.Errorf("daemon: locking %s: %w", path, err)
	}
	return f, nil
}

func loadOrCreateKeys(home string) (*keys.Node, error) {
	path := filepath.Join(home, keys.NodeKeysFile)
	k, err := keys.LoadNode(path)
	if !keys.Missing(err) {
		return k, err
	}
	if k, err = keys.GenerateNode(); err != nil {
		return nil, err
	}
	if host, err := os.Hostname(); err == nil && types.ValidateName(host) == nil {
		k.Name = host
	}
	if err := keys.WriteSecret(path, k.Lines("juist node keys")); err != nil {
		return nil, err
	}
	return k, nil
}

// loadOperator reads the operator's uid. A file that does not parse appoints
// nobody, which is the direction to fail in.
func loadOperator(path string, logf func(string, ...any)) uint32 {
	b, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logf("daemon: reading %s: %v", path, err)
		}
		return 0
	}
	uid, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if err != nil {
		logf("daemon: %s does not name a uid; no operator is appointed", path)
		return 0
	}
	return uint32(uid)
}

// Start runs the mesh if this device is in a network, and starts answering on
// the control socket. It returns at once; ctx ends everything. A mesh that
// cannot start is no reason to stop: the service keeps answering, reports why
// in [Status.StartError], and retries, as it does when the same failure comes
// later — a daemon that exited instead would restart in a loop under systemd
// and never be there to say what is wrong.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	s.ctx = ctx
	_ = s.startMeshLocked() // logged, reported and retried
	s.mu.Unlock()
	go s.ipc.serve()
	go s.watch(ctx)
	return nil
}

// Close stops the control socket, then the mesh, then releases the lock.
func (s *Service) Close() {
	s.ipc.close()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.stopMeshLocked()
	s.lock.Close()
}

// Mesh returns the running mesh, or nil.
func (s *Service) Mesh() *Daemon {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mesh
}

func (s *Service) watch(ctx context.Context) {
	t := time.NewTicker(rotationCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.adoptRotation()
			s.followAddrs()
			s.checkHost()
			s.retryMesh()
		}
	}
}

// startMeshLocked starts the mesh over the log the service holds. A log that
// does not list this device leaves the service outside the network, still
// holding the log, which is what a rejoin extends.
func (s *Service) startMeshLocked() error {
	if s.auth == nil || s.mesh != nil || s.closed {
		return nil
	}
	o := s.opts.Mesh
	// A lower instance on the host holding what this network claims routes
	// it into its own network: this one runs without IPv4 then, and does not
	// run at all where that instance is in this very network.
	prev := s.hostConflict
	s.hostConflict = nil
	if state := s.auth.State(); state.IsMember(s.keys.Identity.Public()) {
		c, err := s.hostConflictLocked(state)
		if err != nil {
			// Unreadable is no verdict: keep what was last found, if anything.
			s.logHostOnce(err)
			c = prev
		} else {
			s.hostErr = ""
		}
		// A lower instance that restarts holds nothing for a moment; the
		// conflict ends once it has been seen gone a few times over.
		if c == nil && prev != nil {
			if s.clearChecks++; s.clearChecks < conflictClearChecks {
				c = prev
			}
		}
		if c != prev {
			s.clearChecks = 0
		}
		switch {
		case c != nil && (prev == nil || prev.Error() != c.Error()) && c.SameNetwork:
			s.logf("daemon: not starting the mesh: %v", c)
		case c != nil && (prev == nil || prev.Error() != c.Error()):
			s.logf("daemon: running without IPv4: %v", c)
		case c == nil && prev != nil:
			s.logf("daemon: IPv4 back: no instance below this one holds what %q claims", state.Network())
		}
		s.hostConflict = c
		if c != nil && c.SameNetwork {
			s.meshErr = c
			return c
		}
		o.NoV4 = c != nil
	}
	o.Authority, o.Storage = s.auth, s.store
	o.Identity, o.Recipient, o.WireGuard = s.keys.Identity, s.keys.Recipient, s.keys.WireGuardPrivate()
	if s.session == nil || s.sessionID != s.keys.Identity.Public() || s.sessionKeys != s.keys.Public {
		sess, err := NewSession()
		if err != nil {
			return err
		}
		s.session, s.sessionID, s.sessionKeys = sess, s.keys.Identity.Public(), s.keys.Public
	}
	o.Session = s.session
	o.EndpointCachePath = statedir.EndpointCachePath(s.opts.Home)
	o.LeasePath = statedir.LeasePath(s.opts.Home)
	o.WaitingPath = statedir.WaitingPath(s.opts.Home)
	o.OnAddrsMoved = s.followAddrs
	o.KeyringPath = statedir.KeyringPath(s.opts.Home)
	if o.Logf == nil {
		o.Logf = s.logf
	}
	d, err := New(o)
	if errors.Is(err, ErrNotMember) {
		if s.meshErr == nil || !errors.Is(s.meshErr, ErrNotMember) {
			s.logf("daemon: %v; waiting to rejoin", err)
		}
		s.meshErr = err
		return nil
	}
	if err != nil {
		if s.meshErr == nil || s.meshErr.Error() != err.Error() {
			s.logf("daemon: starting the mesh: %v; retrying", err)
		}
		s.meshErr = err
		return err
	}
	s.meshErr = nil
	if err := d.Reconcile(); err != nil {
		s.logf("daemon: initial reconcile: %v", err)
	}
	ctx, cancel := context.WithCancel(s.ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = d.Run(ctx)
	}()
	// The mesh owns the authority from here; the service asks it.
	s.mesh, s.meshStop, s.meshDone, s.auth = d, cancel, done, nil
	s.meshStarted = true
	return nil
}

func (s *Service) stopMeshLocked() {
	if s.mesh == nil {
		return
	}
	s.meshStop()
	s.mesh.Close()
	<-s.meshDone
	s.mesh = nil
}

// checkHost restarts the mesh when what a lower instance on the host holds
// has come to conflict with this network, or stopped doing so: one started
// later, or a network renumbered into this one's addresses or out of them.
// See [Service.startMeshLocked] for what a conflict does.
func (s *Service) checkHost() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mesh == nil || s.opts.Mesh.HostHoldings == nil {
		return
	}
	state, err := s.mesh.TrustedState()
	if err != nil {
		return
	}
	c, err := s.hostConflictLocked(state)
	if err != nil {
		s.logHostOnce(err)
		return
	}
	s.hostErr = ""
	if c == nil && s.hostConflict != nil {
		if s.clearChecks++; s.clearChecks < conflictClearChecks {
			return
		}
	} else if c != nil {
		s.clearChecks = 0
	}
	if (c == nil) == (s.hostConflict == nil) && (c == nil || !c.SameNetwork) {
		s.hostConflict = c // the same mode; what it names may have moved
		return
	}
	s.restartMeshLocked(nil, "a change on the host")
}

// retryMesh starts a mesh that failed to start, which a transient cause —
// a missing capability fixed, an interface that appeared — lets it do later.
func (s *Service) retryMesh() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mesh == nil && s.auth != nil && s.meshErr != nil && !errors.Is(s.meshErr, ErrNotMember) {
		_ = s.startMeshLocked()
	}
}

// adoptRotation promotes staged keys once the log names them — applied here
// or arriving by gossip — and restarts the mesh on them, since the data plane
// and the group secret both need the new keys.
//
// It runs without a mesh too: after an identity rotation the old identity is
// no member, so the mesh does not start until the new keys are live.
func (s *Service) adoptRotation() {
	s.mu.Lock()
	defer s.mu.Unlock()
	var state *log.State
	switch {
	case s.mesh != nil:
		st, err := s.mesh.TrustedState()
		if err != nil {
			return
		}
		state = st
	case s.auth != nil:
		state = s.auth.State()
	default:
		return
	}
	promoted, err := keys.MaybePromote(s.opts.Home, state.Node)
	if err != nil {
		s.logf("daemon: promoting staged keys: %v", err)
		return
	}
	if promoted == nil {
		return
	}
	s.logf("daemon: the log names this device's new keys; restarting on them")
	s.restartMeshLocked(func() { s.keys = promoted }, "a key rotation")
}

// followAddrs restarts the mesh when the log gives this device other overlay
// addresses than the ones it started on, as reissuing its admission after a
// fork can: the tunnel device and the log sync listener hold the old ones,
// and with log sync inside the tunnel nothing else would ever fix it.
func (s *Service) followAddrs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mesh == nil || !s.mesh.addrsMoved() {
		return
	}
	s.logf("daemon: the log gives this device new overlay addresses; restarting on them")
	s.restartMeshLocked(nil, "an address change")
}

// restartMeshLocked stops the mesh, runs change, and starts it again over the
// log reopened from the store.
func (s *Service) restartMeshLocked(change func(), why string) {
	held := s.auth
	if s.mesh != nil {
		held = s.mesh.authority
	}
	s.stopMeshLocked()
	if change != nil {
		change()
	}
	// The log as the stopped mesh held it is kept should the store not
	// reopen: without one the service would look as if it were in no
	// network, and retry nothing.
	if auth, err := log.Open(s.store); err != nil {
		s.logf("daemon: reopening the log: %v; going on with the log as it was", err)
		s.auth = held
	} else {
		s.auth = auth
	}
	if err := s.startMeshLocked(); err != nil {
		s.logf("daemon: restarting after %s: %v", why, err)
	}
}

// Status reports the daemon's state. Outside a running mesh it is assembled
// from what the service holds.
func (s *Service) Status() ipc.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	var st ipc.Status
	var state *log.State
	switch {
	case s.mesh != nil:
		st = s.mesh.Status()
		st.InNetwork = true
		// Whoever reads the warning may be fixing the firewall, and should
		// see it gone on their next look, not the next tunnel check's.
		s.mesh.recheckFirewall()
		state, _ = s.mesh.TrustedState()
	case s.auth != nil:
		state = s.auth.State()
		st = ipc.Status{
			Network: state.GenesisHash(), InNetwork: true,
			Derived: ipc.Derived{
				NetworkName: state.Network(), Head: state.Head(), Epoch: state.Epoch(),
				Members: len(state.Nodes()), NotMember: !state.IsMember(s.keys.Identity.Public()),
			},
		}
		if s.meshErr != nil && !errors.Is(s.meshErr, ErrNotMember) {
			st.StartError = s.meshErr.Error()
		}
	}
	st.Instance, st.Device = s.opts.Mesh.Instance, s.opts.Mesh.TunName
	if state != nil {
		st.V4Claims, _ = hostClaims(state, s.now().Unix())
	}
	if s.hostConflict != nil {
		c := s.hostConflict.HostConflict
		st.HostConflict = &c
	}
	st.Self = s.keys.Identity.Public()
	if st.SelfName == "" {
		st.SelfName = s.keys.Name
	}
	st.Joining = s.busy
	st.Rendezvous = s.helpers()
	if op := s.operator.Load(); op != 0 {
		st.Operator = userName(op)
	}
	return st
}

// helpers are the public services an invite may meet through, or nil: the
// DHT and STUN switches the mesh obeys cover invites too.
func (s *Service) helpers() *rendezvous.Helpers {
	o := s.opts.Mesh
	if o.DisableDHT || len(o.STUN) == 0 {
		return nil
	}
	return &rendezvous.Helpers{STUN: o.STUN, Bootstrap: o.DHTBootstrap}
}

func userName(uid uint32) string {
	id := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(id); err == nil {
		return u.Username
	}
	return id
}

// --- the control socket --------------------------------------------------

// mayOperate reports whether who may do more than read the status. A caller
// the platform cannot identify reached a 0600 socket, so it is the daemon's
// own user.
func (s *Service) mayOperate(who caller) bool {
	if !who.known || who.uid == 0 || who.uid == s.selfUID {
		return true
	}
	op := s.operator.Load()
	return op != 0 && who.uid == op
}

// mayAppoint reports whether who may choose the operator.
func (s *Service) mayAppoint(who caller) bool {
	return !who.known || who.uid == 0 || who.uid == s.selfUID
}

func (s *Service) handle(ctx context.Context, req *ipc.Request, who caller, events func(*ipc.Event) error,
	replies <-chan ipc.Request) ipc.Response {
	if req.Command == ipc.CmdStatus {
		st := s.Status()
		st.CanOperate = s.mayOperate(who)
		if !st.CanOperate {
			st = st.ForReader()
		}
		return ipc.Response{Status: &st}
	}
	if !s.mayOperate(who) {
		return ipc.Response{Err: ipc.ErrNotOperator}
	}
	if req.SetOperator && !s.mayAppoint(who) {
		return ipc.Response{Err: "only root may choose this device's operator"}
	}
	var err error
	switch req.Command {
	case ipc.CmdSetOperator:
		err = s.appoint(req)
	case ipc.CmdSelf:
		s.mu.Lock()
		self := &ipc.Self{Identity: s.keys.Identity.Public(), Keys: s.keys.Public, Name: s.keys.Name}
		s.mu.Unlock()
		return ipc.Response{Self: self}
	case ipc.CmdLog:
		var records, orphans [][]byte
		if records, err = s.chain(); err == nil && req.Orphans {
			orphans, err = s.orphans(records)
		}
		if err == nil {
			return ipc.Response{Records: records, Orphans: orphans}
		}
	case ipc.CmdBootstrap:
		if m := s.Mesh(); m != nil {
			return ipc.Response{Bootstrap: m.bootstrapHints()}
		}
		return ipc.Response{Bootstrap: &ipc.Bootstrap{}}
	case ipc.CmdInform:
		err = s.inform(req.Records)
	case ipc.CmdCreate:
		err = s.create(req)
	case ipc.CmdJoin:
		var adm *enroll.Admission
		if adm, err = s.join(ctx, req, events); err == nil {
			st := s.Status()
			st.CanOperate = true
			return ipc.Response{Status: &st, Admission: adm}
		}
	case ipc.CmdInvite:
		err = s.invite(ctx, req.Offer, events, replies)
	case ipc.CmdInviteReply:
		err = errors.New("an invite reply is sent inside the invite it answers")
	case ipc.CmdRotate:
		var rec []byte
		var proof *types.Sig
		if rec, proof, err = s.rotate(req.Identity); err == nil {
			return ipc.Response{Records: [][]byte{rec}, Proof: proof}
		}
	case ipc.CmdUnstage:
		err = s.unstage()
	case ipc.CmdReset:
		err = s.reset(req.Force)
	case ipc.CmdWaiting:
		m := s.Mesh()
		if m == nil {
			err = errNoNetwork
			break
		}
		if err = m.OfferWaiting(req.Waiting); err == nil {
			return ipc.Response{Waiting: m.Waiting()}
		}
	default:
		err = fmt.Errorf("unhandled %v", req.Command)
	}
	if err != nil {
		return ipc.Response{Err: err.Error()}
	}
	st := s.Status()
	st.CanOperate = true
	return ipc.Response{Status: &st}
}

var errNoNetwork = errors.New("this device is not in a network yet")

// reset returns the device to a fresh install: everything in the state
// directory but the lock, the socket and the homes of the host's other
// instances goes, and the device gets new keys. A member is reset only when
// forced, since the others keep listing it.
func (s *Service) reset(force bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busy {
		return errors.New("this device is joining a network; wait for the join to end")
	}
	member := false
	switch {
	case s.mesh != nil:
		member = !s.mesh.Status().NotMember
	case s.auth != nil:
		member = s.auth.State().IsMember(s.keys.Identity.Public())
	}
	if member && !force {
		return errors.New(ipc.ErrStillMember)
	}
	home := s.opts.Home
	// Every juist state directory holds node keys from its first start; one
	// that does not is not a juist home, and deleting it would be deleting
	// somebody's files.
	if _, err := os.Stat(filepath.Join(home, keys.NodeKeysFile)); err != nil {
		return fmt.Errorf("daemon: %s holds no %s, so it is not reset: %w", home, keys.NodeKeysFile, err)
	}
	s.stopMeshLocked()
	s.auth, s.meshErr, s.hostConflict = nil, nil, nil

	entries, err := os.ReadDir(home)
	if err != nil {
		return err
	}
	for _, e := range entries {
		// The default instance's home holds the others' (juist1 …), which
		// are other networks' devices, not this one's state.
		if e.Name() == statedir.LockName || e.Name() == ipc.SocketName || e.IsDir() && instance.IsName(e.Name()) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(home, e.Name())); err != nil {
			return fmt.Errorf("daemon: resetting %s: %w", home, err)
		}
	}
	if err := keys.SyncDir(home); err != nil {
		return err
	}
	s.operator.Store(0)
	if s.keys, err = loadOrCreateKeys(home); err != nil {
		return err
	}
	if s.store, err = store.Open(filepath.Join(home, keys.LogDir)); err != nil {
		return err
	}
	s.logf("daemon: reset; %s (%v) is in no network yet", s.keys.Name, s.keys.Identity.Public().ShortString())
	return nil
}

// relayedText is the Text of a join's Connected event through a member relay.
const relayedText = "relay"

func (s *Service) appoint(req *ipc.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appointLocked(req)
}

func (s *Service) appointLocked(req *ipc.Request) error {
	if !req.SetOperator {
		return nil
	}
	return s.setOperatorLocked(req.OperatorUID)
}

// appointUndoable is appointLocked for a step that may still fail, returning
// how to put the previous operator back.
func (s *Service) appointUndoable(req *ipc.Request) (undo func(), err error) {
	prev := s.operator.Load()
	if err := s.appointLocked(req); err != nil {
		return nil, err
	}
	return func() {
		if req.SetOperator {
			if err := s.setOperatorLocked(prev); err != nil {
				s.logf("daemon: restoring the operator: %v", err)
			}
		}
	}, nil
}

func (s *Service) setOperatorLocked(uid uint32) error {
	path := filepath.Join(s.opts.Home, statedir.OperatorFile)
	if uid == 0 {
		if err := removeIfExists(path); err != nil {
			return err
		}
		s.operator.Store(0)
		return keys.SyncDir(s.opts.Home)
	}
	if err := statedir.WriteFilePrivate(path, []byte(strconv.FormatUint(uint64(uid), 10)+"\n")); err != nil {
		return err
	}
	s.operator.Store(uid)
	return nil
}

// maxOrphans bounds the records off the active chain one reply carries.
const maxOrphans = 4096

// orphans returns the stored records that are not on chain, the active chain
// as encoded.
func (s *Service) orphans(chain [][]byte) ([][]byte, error) {
	on := make(map[types.Hash]bool, len(chain))
	for _, b := range chain {
		aum, err := types.DecodeAUM(b)
		if err != nil {
			return nil, err
		}
		on[aum.Hash()] = true
	}
	s.mu.Lock()
	st := s.store
	s.mu.Unlock()
	hashes, err := st.Hashes()
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, h := range hashes {
		if len(out) == maxOrphans {
			break
		}
		if on[h] {
			continue
		}
		aum, err := st.AUM(h)
		if err != nil {
			continue
		}
		if b, err := aum.Encode(); err == nil {
			out = append(out, b)
		}
	}
	return out, nil
}

func (s *Service) chain() ([][]byte, error) {
	s.mu.Lock()
	mesh, auth := s.mesh, s.auth
	var records []types.AUM
	var err error
	switch {
	case mesh != nil:
	case auth != nil:
		records, err = chainOf(auth, s.store)
	default:
		err = errNoNetwork
	}
	s.mu.Unlock()
	if mesh != nil {
		records, err = mesh.Chain()
	}
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(records))
	for i := range records {
		b, err := records[i].Encode()
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func chainOf(auth *log.Authority, st log.Storage) ([]types.AUM, error) {
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

func decodeRecords(raw [][]byte) ([]types.AUM, error) {
	out := make([]types.AUM, 0, len(raw))
	for _, b := range raw {
		aum, err := types.DecodeAUM(b)
		if err != nil {
			return nil, fmt.Errorf("undecodable record: %w", err)
		}
		out = append(out, aum)
	}
	return out, nil
}

// inform applies authorized records: through the mesh while it runs, or to the
// log the service holds, starting the mesh if they make this device a member.
func (s *Service) inform(raw [][]byte) error {
	records, err := decodeRecords(raw)
	if err != nil {
		return err
	}
	// A device the records remove is told first, while it still has a
	// tunnel to be told through; outside mu, since that is network I/O.
	s.mu.Lock()
	mesh := s.mesh
	s.mu.Unlock()
	if mesh != nil {
		mesh.farewell(context.Background(), records)
	}
	s.mu.Lock()
	switch {
	case s.mesh != nil:
		// Under mu, so a mesh restart cannot come between the records and
		// the authority that takes them.
		err = s.mesh.Inform(records)
	case s.auth != nil:
		if err = s.auth.Inform(records...); err == nil {
			_ = s.startMeshLocked() // a failure is reported in the status and retried
		}
	default:
		err = errNoNetwork
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	s.adoptRotation()
	return nil
}

// create founds a network from a fully signed genesis record, which must
// admit this device under exactly its keys.
func (s *Service) create(req *ipc.Request) error {
	records, err := decodeRecords(req.Records)
	if err != nil {
		return err
	}
	if records[0].Kind != types.KindGenesis {
		return errors.New("a network is created from a genesis record")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mesh != nil || s.auth != nil || s.busy {
		return errors.New("this device is already in a network")
	}
	probe, err := log.FromRecords(log.NewMemStorage(), records)
	if err != nil {
		return err
	}
	if self, ok := probe.State().Node(s.keys.Identity.Public()); !ok || !s.keys.NamedBy(&self) {
		return errors.New("the genesis record does not make this device a member")
	}
	// The operator first, since once the network exists a failure here would
	// leave it created and its operator unset; and put back if the network
	// cannot be created after all.
	undo, err := s.appointUndoable(req)
	if err != nil {
		return err
	}
	if s.auth, err = log.Create(s.store, records[0]); err != nil {
		undo()
		return err
	}
	_ = s.startMeshLocked() // a failure is reported in the status and retried
	return nil
}

// join redeems an invite. The network I/O runs without the lock; only storing
// the verified log takes it.
func (s *Service) join(ctx context.Context, req *ipc.Request, events func(*ipc.Event) error) (*enroll.Admission, error) {
	s.mu.Lock()
	if s.busy {
		s.mu.Unlock()
		return nil, errors.New("this device is already joining a network")
	}
	s.busy = true
	k := s.keys
	var network types.Hash
	var networkName string
	switch {
	case s.mesh != nil:
		st := s.mesh.Status()
		network, networkName = st.Network, st.NetworkName
	case s.auth != nil:
		network, networkName = s.auth.State().GenesisHash(), s.auth.State().Network()
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.busy = false
		s.mu.Unlock()
	}()

	name := req.Name
	if name == "" {
		name = k.Name
	}
	res, err := guest.Join(ctx, guest.Options{
		Invite:        req.Invite,
		Name:          name,
		Keys:          k,
		Network:       network,
		NetworkName:   networkName,
		Elsewhere:     req.Elsewhere,
		Find:          s.opts.Find,
		SkipInterface: s.opts.Mesh.TunName,
		Meet:          s.helpers().Meeter(s.logf),
		Progress: func(e guest.Event) {
			ev := &ipc.Event{Kind: uint8(e.Kind), Votes: e.Votes, Quorum: e.Quorum, Text: e.Words}
			if e.Relayed {
				ev.Text = relayedText
			}
			if e.Addr.IsValid() {
				ev.Addr = e.Addr.String()
			}
			_ = events(ev)
		},
		Adopt: func(records []types.AUM) (err error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			// The operator is appointed by a join that succeeds, and only
			// then: a mistyped code must not leave one behind.
			undo, err := s.appointUndoable(req)
			if err != nil {
				return err
			}
			defer func() {
				if err != nil {
					undo()
				}
			}()
			switch {
			case s.mesh != nil:
				return s.mesh.Inform(records)
			case s.auth != nil:
				return s.auth.Inform(records...)
			default:
				auth, err := log.FromRecords(s.store, records)
				if err != nil {
					// The chain was verified in memory, so this is the disk;
					// whatever did get written is the log from here on.
					if _, has, aerr := s.store.Anchor(); aerr == nil && has {
						if s.auth, aerr = log.Open(s.store); aerr != nil {
							s.logf("daemon: opening the log a failed join left: %v", aerr)
						}
					}
					return err
				}
				s.auth = auth
				return nil
			}
		},
		// Started before the join ends, so the host is handed this device's
		// announcement: a host behind NAT would otherwise learn where it is
		// only through the DHT.
		Announce: func(endpoints, leases [][]byte) []byte {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.mesh == nil {
				if err := statedir.SeedHints(s.opts.Home, endpoints, leases); err != nil {
					s.logf("daemon: keeping the hints an inviting device sent: %v", err)
				}
				_ = s.startMeshLocked() // a failure is reported in the status and retried
			}
			if s.mesh == nil {
				return nil
			}
			e, ok := s.mesh.announcement()
			if !ok {
				return nil
			}
			b, err := e.Encode()
			if err != nil {
				return nil
			}
			return b
		},
	})
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mesh != nil {
		s.mesh.OfferHints(res.Endpoints, res.Leases)
		return res.Admission, nil
	}
	if err := statedir.SeedHints(s.opts.Home, res.Endpoints, res.Leases); err != nil {
		s.logf("daemon: keeping the hints an inviting device sent: %v", err)
	}
	_ = s.startMeshLocked() // a failure is reported in the status and retried
	return res.Admission, nil
}

// rotate stages replacement keys and returns the record naming them, signed by
// whichever of this device's keys the record needs, and the current identity
// key's [RotationProof]. It never applies anything: the record still needs its
// admins, who sign it in the CLI.
func (s *Service) rotate(identity bool) ([]byte, *types.Sig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mesh == nil {
		return nil, nil, errors.New("this device is not a member of a network, so it has no keys there to rotate")
	}
	stagedPath := filepath.Join(s.opts.Home, keys.NodeKeysFile+keys.StagedSuffix)
	if _, err := os.Stat(stagedPath); err == nil {
		return nil, nil, errors.New("a rotation of this device's keys is already waiting for approval; " +
			"approve that one, or abandon it with \"juist rotate abandon\"")
	}
	state, err := s.mesh.TrustedState()
	if err != nil {
		return nil, nil, err
	}
	cur := s.keys
	var staged *keys.Node
	if identity {
		id, err := types.GenerateIdentity()
		if err != nil {
			return nil, nil, err
		}
		staged, err = keys.NewNode(id, cur.Recipient, cur.WGPrivate)
		if err != nil {
			return nil, nil, err
		}
	} else {
		fresh, err := keys.GenerateNode()
		if err != nil {
			return nil, nil, err
		}
		if staged, err = keys.NewNode(cur.Identity, fresh.Recipient, fresh.WGPrivate); err != nil {
			return nil, nil, err
		}
	}
	staged.Name = cur.Name
	seal := func(epoch uint64, members []types.NodeRecord) (*types.EpochRecord, error) {
		_, rec, err := secrets.NewEpoch(epoch, members)
		return rec, err
	}
	b := log.NewBuilder(state)
	var aum types.AUM
	if identity {
		aum, err = b.RotateIdentity(cur.Identity.Public(), staged.Identity.Public(), seal)
	} else {
		aum, err = b.RotateNodeKey(cur.Identity.Public(), staged.Public, seal)
	}
	if err != nil {
		return nil, nil, err
	}
	if err := log.SignAsDevice(&aum, state.Schema(), cur.Identity, staged.Identity); err != nil {
		return nil, nil, err
	}
	proof, err := cur.Identity.Sign(ipc.RotationProof(&aum))
	if err != nil {
		return nil, nil, err
	}
	body, err := aum.Encode()
	if err != nil {
		return nil, nil, err
	}
	if err := keys.WriteSecret(stagedPath, staged.Lines("juist node keys, staged for rotation")); err != nil {
		return nil, nil, err
	}
	return body, &proof, nil
}

// unstage abandons staged keys. They are archived rather than deleted: the
// rotation record already carries this device's signature, and if an admin
// approves it anyway the log names keys only this device holds.
func (s *Service) unstage() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.opts.Home, keys.NodeKeysFile+keys.StagedSuffix)
	staged, err := keys.LoadNode(path)
	if keys.Missing(err) {
		return errors.New(ipc.ErrNothingStaged)
	}
	if err != nil {
		return err
	}
	var state *log.State
	switch {
	case s.mesh != nil:
		if state, err = s.mesh.TrustedState(); err != nil {
			return fmt.Errorf("cannot tell whether the log names the staged keys, so they stay: %w", err)
		}
	case s.auth != nil:
		state = s.auth.State()
	}
	if state != nil {
		if rec, ok := state.Node(staged.Identity.Public()); ok && staged.NamedBy(&rec) {
			return errors.New("the log already names the staged keys; they are adopted, not abandoned")
		}
	}
	return keys.Abandon(s.opts.Home)
}
