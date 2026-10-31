package daemon

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nning/juist/internal/atomicfile"
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

	// runs are the goroutines Start began, which Close waits for after
	// cancelling stop, before it takes mu.
	runs      waitSet
	closeOnce sync.Once
	// moved is every mesh's [Options.Moved], which the watcher follows.
	moved chan struct{}

	// mu guards everything below. It is never held across network I/O — a
	// join marks busy and runs unlocked — but it is held while the mesh
	// stops and starts, which can take a moment and makes status wait.
	mu       sync.Mutex
	ctx      context.Context
	stop     context.CancelFunc
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
	clearChecks  int        // checks in a row that found the conflict gone
	meshStarted  bool       // a mesh ran in this process: the host is known
	exitUnkept   ExitChoice // the rotated choice last not kept, logged once

	// session is what a restarted mesh announces again, for as long as the
	// device's keys are sessionKeys: new keys take a new one, since a
	// rotation answers a device that may have been copied. Its relay
	// certificate outlives the process too (NewStoredSession).
	session     *Session
	sessionKeys types.NodeKeys
	sessionID   types.Identity

	// operator is 0 for none: root needs no appointment. Atomic, since the
	// accept loop asks for every connection and must not wait on mu.
	operator atomic.Uint32

	// ingressUID and serveUID are the users juist-ingress's and
	// juist-serve's, 0 where there is none: the ingress, which may ask what
	// is published, and the terminator, what this device ends TLS for,
	// and nothing else.
	ingressUID, serveUID uint32
	// ingressAsked is when the ingress last asked what is published, in Unix
	// seconds, and ingressSaid what it said then.
	ingressAsked atomic.Int64
	ingressSaid  atomic.Pointer[ipc.IngressReport]

	// relayNamed is the name the ingress role gave the running mesh's relay.
	relayNamed string

	// prefs are the device's settings, as kept in Home but for a service
	// member's ServeTo.
	prefs Prefs
}

// ServiceOptions configures a [Service].
type ServiceOptions struct {
	// Home is the state directory. Only the service writes it.
	Home string

	// Socket is where the control socket listens. Empty uses SocketPath(Home).
	Socket string

	// InProcess listens on no socket: calls come through [Service.Pipe]
	// alone, each an operator's, as in an app whose sandbox is the boundary.
	InProcess bool

	// InviteAddrs lists where a guest can reach this device's invite at
	// port; nil scans the interfaces. Tests replace it.
	InviteAddrs func(port uint16) []netip.AddrPort

	// Mesh is what the mesh starts from; the service fills in the log, the
	// keys and the files it keeps in Home.
	Mesh Options

	// Find replaces the LAN search for an invite, for tests.
	Find func(ctx context.Context, nameplate uint16) ([]mdns.InviteHost, error)

	// ServeTo, where set, is the operator's word on serving what is
	// published here and where it goes, by label, given on the command line
	// of a service member rather than kept.
	ServeTo map[string]string
	// ServeMembers are the labels of ServeTo whose service is for members
	// alone.
	ServeMembers map[string]bool

	// Join, where set, is an invite this node joins by once started, unless
	// it is in a network; Say receives how that goes.
	Join string
	Say  func(format string, args ...any)

	// Logf receives diagnostics. Nil discards them.
	Logf func(format string, args ...any)
}

// The service looks for a key rotation or a move the log has adopted,
// however it arrived, every watchEvery, which the mesh's own calls on a
// change make a backstop, and every watchRetryEvery while the mesh failed to
// start or an instance below on the host may come to hold what this one
// claims.
const (
	watchEvery      = time.Minute
	watchRetryEvery = 5 * time.Second
)

// NewService opens a state directory: it takes the directory's lock, loads
// this device's keys or creates them, opens the log if there is one, and
// listens on the control socket. Call [Service.Start].
func NewService(opts ServiceOptions) (*Service, error) {
	s := &Service{opts: opts, logf: opts.Logf, selfUID: uint32(os.Getuid()),
		ingressUID: lookupUID(IngressUser), serveUID: lookupUID(ServeUser), moved: make(chan struct{}, 1)}
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
			statedir.Unlock(lock)
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
	s.prefs = LoadPrefs(home, s.logf)
	if s.opts.ServeTo != nil {
		s.prefs.ServePublished, s.prefs.ServeTo, s.prefs.ServeMembers = true, maps.Clone(s.opts.ServeTo), maps.Clone(s.opts.ServeMembers)
	}
	s.clearEgressUnlessChosen()
	s.holdExitLocked()

	sock := opts.Socket
	if sock == "" {
		sock = ipc.SocketPath(home)
	}
	if opts.InProcess {
		s.ipc = newPipeServer(s.handle, s.tierOf, s.logf)
	} else if s.ipc, err = newIPCServer(sock, s.handle, s.tierOf, s.logf); err != nil {
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
// the control socket. It returns at once; ctx ends everything. Once Close has
// begun it refuses. A mesh that cannot start is no reason to stop: the
// service keeps answering, reports why in [Status.StartError], and retries,
// as it does when the same failure comes later — a daemon that exited
// instead would restart in a loop under systemd and never be there to say
// what is wrong.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("daemon: the service is closed")
	}
	s.ctx = ctx
	// The mesh ends with ctx or Close's stopping it; the rest with stop.
	ctx, s.stop = context.WithCancel(ctx)
	_ = s.startMeshLocked() // logged, reported and retried
	s.mu.Unlock()
	s.goTracked(s.ipc.serve)
	s.goTracked(func() { s.watch(ctx) })
	if s.opts.Join != "" {
		s.goTracked(func() { s.joinAtStart(ctx) })
	}
	return nil
}

// goTracked runs f on a goroutine Close waits for, unless Close has begun.
func (s *Service) goTracked(f func()) {
	if !s.runs.track() {
		return
	}
	go func() {
		defer s.runs.done()
		f()
	}()
}

// joinAtStart joins by [ServiceOptions.Join] where this node is in no
// network, saying how it goes.
func (s *Service) joinAtStart(ctx context.Context) {
	say := s.opts.Say
	if say == nil {
		say = func(string, ...any) {}
	}
	s.mu.Lock()
	alone := s.mesh == nil && s.auth == nil
	s.mu.Unlock()
	if !alone {
		return
	}
	var shown [2]uint32
	_, err := s.join(ctx, &ipc.Request{Command: ipc.CmdJoin, Invite: s.opts.Join}, func(e *ipc.Event) error {
		switch guest.EventKind(e.Kind) {
		case guest.Meeting:
			say("no direct answer; meeting through the DHT (up to a minute)")
		case guest.Connected:
			if e.Text == relayedText {
				say("connected to %s via relay", e.Addr)
			} else {
				say("connected to %s", e.Addr)
			}
		case guest.Compare:
			say("tell the inviting admin these words: %s", e.Text)
		case guest.Waiting:
			if e.Quorum != 0 && shown != [2]uint32{e.Votes, e.Quorum} {
				shown = [2]uint32{e.Votes, e.Quorum}
				say("waiting for approval (%d of %d votes)", e.Votes, e.Quorum)
			}
		}
		return nil
	})
	switch {
	case ctx.Err() != nil:
	case err != nil:
		say("cannot join: %v", err)
	default:
		st := s.Status()
		say("joined %q as %s", st.NetworkName, st.SelfName)
	}
}

// Close stops the control socket and what Start began, then the mesh, then
// releases the lock. A second Close waits for the first.
func (s *Service) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		stop := s.stop
		s.mu.Unlock()
		if stop != nil {
			stop()
		}
		s.ipc.close()
		// Outside mu, which they take.
		s.runs.stop()
		s.runs.wait()
		s.mu.Lock()
		defer s.mu.Unlock()
		s.stopMeshLocked()
		// Stopped for good, the host routes by itself again.
		s.clearEgress()
		statedir.Unlock(s.lock)
	})
}

// clearEgress ends what a stopped mesh left refusing, on a device of its own:
// in tests there is no device, and the host's routing is another juistd's.
func (s *Service) clearEgress() {
	if s.opts.Mesh.TunName == "" {
		return
	}
	if err := s.hostControl().ClearEgress(); err != nil {
		s.logf("daemon: %v", err)
	}
}

// hostControl is how this service's device's egress is held while no mesh
// runs.
func (s *Service) hostControl() conn.HostControl {
	return conn.HostControl{Instance: s.opts.Mesh.Instance, Plumber: s.opts.Mesh.Plumber, Dev: s.opts.Mesh.TunName}
}

func (s *Service) clearEgressUnlessChosen() {
	if !s.prefs.Exit.Refuses() {
		s.clearEgress()
	}
}

// exitWithoutMeshLocked is what becomes of exit nodes while no mesh runs.
func (s *Service) exitWithoutMeshLocked(state *log.State, notMember bool) *ipc.Exit {
	if !s.prefs.Exit.Refuses() && !s.prefs.ServeExit {
		return nil
	}
	why := "the tunnels are not up"
	if notMember {
		why = "this device is no member of the network"
	}
	e := &ipc.Exit{Consent: s.prefs.ServeExit}
	if s.prefs.ServeExit {
		e.NotServing = why
	}
	if s.prefs.Exit.Refuses() {
		e.Node, e.Refused = s.prefs.Exit.Node, why
		if s.prefs.Exit.Unreadable {
			e.Refused = errUnreadableChoice
		}
		if n, ok := state.Node(s.prefs.Exit.Node); ok {
			e.Name = n.Name
		}
	}
	return e
}

// holdExitLocked refuses the chosen exit node's traffic while no mesh runs to
// route it, so that none leaves directly meanwhile; a mesh's router takes the
// refusal over.
func (s *Service) holdExitLocked() {
	if s.opts.Mesh.TunName == "" || s.mesh != nil || !s.prefs.Exit.Refuses() {
		return
	}
	if err := s.hostControl().RefuseEgress(s.prefs.Exit.Isolate); err != nil {
		s.logf("daemon: %v", err)
	}
}

// followExit keeps the choice the mesh followed to the chosen node's rotated
// identity. The mesh's choice is set with the service's under mu, so where
// the two differ the mesh followed a rotation.
func (s *Service) followExit() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mesh == nil || !s.prefs.Exit.Refuses() || s.prefs.Exit.Unreadable {
		return
	}
	c := s.mesh.exitChoiceNow()
	if c == s.prefs.Exit {
		return
	}
	if err := SaveExitChoice(filepath.Join(s.opts.Home, statedir.ExitFile), c); err != nil {
		if c != s.exitUnkept {
			s.exitUnkept = c
			s.logf("daemon: keeping the exit node's new identity: %v", err)
		}
		return
	}
	s.prefs.Exit, s.exitUnkept = c, ExitChoice{}
}

// setSubnet records the operator's word on routing this device's subnets, or
// the owner's on routing its peers', and hands it to the running mesh. Each
// is a file whose presence says yes.
func (s *Service) setSubnet(req *ipc.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, on := statedir.SubnetServeFile, req.ServeSubnets
	if req.AcceptSubnets != nil {
		off := !*req.AcceptSubnets
		name, on = statedir.SubnetsFile, &off
	}
	if err := setFlagFile(s.opts.Home, name, *on); err != nil {
		return err
	}
	if req.ServeSubnets != nil {
		s.prefs.ServeSubnets = *on
	} else {
		s.prefs.SubnetsOff = *on
	}
	if s.mesh != nil {
		s.mesh.SetPrefs(s.prefs)
		_ = s.mesh.Reconcile() // so that the status answered says what came of it
	}
	return nil
}

// setPublish records the operator's word on serving the names the network
// publishes on this device, a file whose presence says yes, and where those
// whose TLS juist ends go, a line "LABEL HOST:PORT" each in a file of their
// own, kept while not serving. It hands both to the running mesh.
func (s *Service) setPublish(req *ipc.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	on, to, members := s.prefs.ServePublished, maps.Clone(s.prefs.ServeTo), maps.Clone(s.prefs.ServeMembers)
	if req.ServePublished != nil {
		on = *req.ServePublished
	}
	for _, label := range req.Unserve {
		delete(to, label)
		delete(members, label)
	}
	for _, t := range req.ServeTo {
		if to == nil {
			to = map[string]string{}
		}
		to[t.Label] = t.To
		delete(members, t.Label)
		if t.Members {
			if members == nil {
				members = map[string]bool{}
			}
			members[t.Label] = true
		}
	}
	if len(to) > ipc.MaxServeTo {
		return fmt.Errorf("this device says where %d names go, the most it may", ipc.MaxServeTo)
	}
	toPath := filepath.Join(s.opts.Home, statedir.PublishToFile)
	if len(to) > 0 {
		var b strings.Builder
		for _, label := range slices.Sorted(maps.Keys(to)) {
			fmt.Fprintf(&b, "%s %s", cmp.Or(label, domainItself), to[label])
			if members[label] {
				b.WriteString(" " + forMembers)
			}
			b.WriteString("\n")
		}
		if err := statedir.WriteFilePrivate(toPath, []byte(b.String())); err != nil {
			return err
		}
	}
	// Rewritten before the names' file may go, so that the lines an older
	// version kept in it never come back.
	if err := setFlagFile(s.opts.Home, statedir.PublishServeFile, on); err != nil {
		return err
	}
	if len(to) == 0 {
		if err := setFlagFile(s.opts.Home, statedir.PublishToFile, false); err != nil {
			return err
		}
		to, members = nil, nil
	}
	s.prefs.ServePublished, s.prefs.ServeTo, s.prefs.ServeMembers = on, to, members
	if s.mesh != nil {
		s.mesh.SetPrefs(s.prefs)
		_ = s.mesh.Reconcile() // so that the status answered says what came of it
	}
	return nil
}

// domainItself is the domain's own empty label as the names' file holds it,
// and forMembers the word after a line's address for a service for members
// alone, which an older version, reading no such line, serves to nobody.
const (
	domainItself = "@"
	forMembers   = "members"
)

// loadServeTo reads the operator's word on serving what is published here,
// and where to: from home's names' file, or, without one, from the lines an
// older version kept in the word's. A line it cannot read is left out, and
// said so.
func loadServeTo(home string, logf func(string, ...any)) (bool, map[string]string, map[string]bool) {
	consent := fileExists(filepath.Join(home, statedir.PublishServeFile))
	path := filepath.Join(home, statedir.PublishToFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		path = filepath.Join(home, statedir.PublishServeFile)
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return consent, nil, nil
	}
	var to map[string]string
	var members map[string]bool
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		label, addr, ok := strings.Cut(line, " ")
		addr, mine := strings.CutSuffix(addr, " "+forMembers)
		if label == domainItself {
			label = ""
		}
		if t := (ipc.ServeTo{Label: label, To: addr}); !ok || !t.Valid() {
			logf("daemon: %s: leaving out %q, which names no published name and address", path, line)
			continue
		}
		if to == nil {
			to = map[string]string{}
		}
		to[label] = addr
		if mine {
			if members == nil {
				members = map[string]bool{}
			}
			members[label] = true
		}
	}
	return consent, to, members
}

// setNames records the owner's word on resolving the network's public names,
// a file whose presence says yes, and hands it to the running mesh.
func (s *Service) setNames(on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := setFlagFile(s.opts.Home, statedir.NamesFile, on); err != nil {
		return err
	}
	s.prefs.AcceptNames = on
	if s.mesh != nil {
		s.mesh.SetPrefs(s.prefs)
		_ = s.mesh.Reconcile() // so that the status answered says what came of it
	}
	return nil
}

// setFlagFile makes name in home exist where on, and not where off, durably.
func setFlagFile(home, name string, on bool) error {
	path := filepath.Join(home, name)
	if on {
		return statedir.WriteFilePrivate(path, nil)
	}
	if err := os.Remove(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	// So that a power cut does not bring the word back.
	return atomicfile.SyncDir(home)
}

// setExit records the owner's choice of exit node, or the operator's word on
// serving as one, and hands it to the running mesh.
func (s *Service) setExit(req *ipc.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	home := s.opts.Home
	switch {
	case req.Serve != nil:
		path := filepath.Join(home, statedir.ServeFile)
		var err error
		if *req.Serve {
			err = statedir.WriteFilePrivate(path, nil)
		} else if err = os.Remove(path); errors.Is(err, os.ErrNotExist) {
			err = nil
		} else if err == nil {
			// So that a power cut does not bring the consent back.
			err = atomicfile.SyncDir(home)
		}
		if err != nil {
			return err
		}
		s.prefs.ServeExit = *req.Serve
		if s.mesh != nil {
			s.mesh.SetPrefs(s.prefs)
			_ = s.mesh.Reconcile() // so that the status answered says what came of it
		}
		return nil
	}
	c := ExitChoice{Chosen: true, Node: req.ExitNode, Isolate: req.ExitIsolate}
	if req.ExitOff {
		c = ExitChoice{Chosen: true}
	} else if why := egressUserOf(s.opts.Mesh.EgressUser); why != "" {
		return errors.New(why + "; the packaged service runs it as its own user")
	}
	if err := SaveExitChoice(filepath.Join(home, statedir.ExitFile), c); err != nil {
		return err
	}
	s.prefs.Exit, s.exitUnkept = c, ExitChoice{}
	if s.mesh != nil {
		s.mesh.SetExitChoice(s.prefs.Exit)
		_ = s.mesh.Reconcile()
	}
	s.clearEgressUnlessChosen()
	s.holdExitLocked()
	return nil
}

// Pipe is a connection to the control protocol from this process, an
// [ipc.Dialer] for [ServiceOptions.InProcess].
func (s *Service) Pipe() (net.Conn, error) { return s.ipc.pipe() }

// Mesh returns the running mesh, or nil.
func (s *Service) Mesh() *Daemon {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mesh
}

func (s *Service) watch(ctx context.Context) {
	paced := s.opts.Mesh.Pace.Changed()
	t := time.NewTimer(s.watchWait())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.moved:
			s.followMesh()
			continue
		case <-paced:
		case <-t.C:
			s.followMesh()
			s.checkHost()
			s.retryMesh()
		}
		// The change taken before the wait, so that none comes between.
		paced = s.opts.Mesh.Pace.Changed()
		t.Reset(s.watchWait())
	}
}

// followMesh has the mesh follow what the log moved: this device's keys and
// addresses, the exit node chosen, and its relay's name.
func (s *Service) followMesh() {
	s.adoptRotation()
	s.followAddrs()
	s.followExit()
	s.followRelayName()
}

// relayNameLocked is the name this device's relay takes on 443 under state,
// and the part of it the ingress role gave, not the setting.
func (s *Service) relayNameLocked(state *log.State) (name, byRole string) {
	if s.prefs.RelayName != "" {
		return s.prefs.RelayName, ""
	}
	if name, id := IngressRelayName(state, s.now().Unix()); id == s.keys.Identity.Public() {
		return name, name
	}
	return "", ""
}

// followRelayName restarts the mesh where the name the ingress role gives
// this device's relay moved.
func (s *Service) followRelayName() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mesh == nil {
		return
	}
	state, err := s.mesh.TrustedState()
	if err != nil {
		return
	}
	if _, byRole := s.relayNameLocked(state); byRole != s.relayNamed {
		s.logf("daemon: the ingress role names this device's relay %q; restarting", byRole)
		s.restartMeshLocked(nil, "the relay's new name")
	}
}

// watchWait is how long the service waits before it looks again.
func (s *Service) watchWait() time.Duration {
	s.mu.Lock()
	failed := s.mesh == nil && s.auth != nil && s.meshErr != nil && !errors.Is(s.meshErr, ErrNotMember)
	lower := s.mesh != nil && s.opts.Mesh.Instance > 0 && s.opts.Mesh.HostHoldings != nil
	s.mu.Unlock()
	if failed || lower {
		return watchRetryEvery
	}
	return s.opts.Mesh.Pace.every(watchEvery, savingWatchEvery)
}

// startMeshLocked starts the mesh over the log the service holds. A log that
// does not list this device leaves the service outside the network, still
// holding the log, which is what a rejoin extends.
func (s *Service) startMeshLocked() error {
	if s.auth == nil || s.mesh != nil || s.closed {
		return nil
	}
	o := s.opts.Mesh
	if state := s.auth.State(); state.IsMember(s.keys.Identity.Public()) {
		c := s.followHostConflictLocked(state)
		if c != nil && c.SameNetwork {
			s.meshErr = c
			return c
		}
		o.NoV4 = c != nil
	} else {
		s.hostConflict = nil
	}
	if err := s.meshOptionsLocked(&o); err != nil {
		return err
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

// followHostConflictLocked reads anew what a lower instance on the host holds
// of what state claims, logs a change, and keeps it as s.hostConflict: such an
// instance routes it into its own network, so this one runs without IPv4,
// and not at all where that instance is in this very network.
func (s *Service) followHostConflictLocked(state *log.State) *hostConflictError {
	prev := s.hostConflict
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
	return c
}

// meshOptionsLocked fills in o what the mesh takes from the service: its
// log, keys, session, files and the device's settings.
func (s *Service) meshOptionsLocked(o *Options) error {
	o.Authority, o.Storage = s.auth, s.store
	o.Identity, o.Recipient, o.WireGuard = s.keys.Identity, s.keys.Recipient, s.keys.WireGuardPrivate()
	if s.session == nil || s.sessionID != s.keys.Identity.Public() || s.sessionKeys != s.keys.Public {
		sess, err := NewStoredSession(s.opts.Home, s.keys.Identity.Public(), s.keys.Public)
		if err != nil {
			return err
		}
		if s.session != nil && s.sessionID == s.keys.Identity.Public() {
			sess.follow(s.session)
		}
		s.session, s.sessionID, s.sessionKeys = sess, s.keys.Identity.Public(), s.keys.Public
	}
	o.Session = s.session
	o.EndpointCachePath = statedir.EndpointCachePath(s.opts.Home)
	o.LeasePath = statedir.LeasePath(s.opts.Home)
	o.WaitingPath = statedir.WaitingPath(s.opts.Home)
	o.Moved = s.moved
	o.Prefs = s.prefs
	o.RelayName, s.relayNamed = s.relayNameLocked(s.auth.State())
	o.RelayNameByRole = s.relayNamed
	o.RelayCertsPath = filepath.Join(s.opts.Home, statedir.RelayCertsDir)
	if !s.opts.InProcess {
		o.HandOffSocket = HandOffSocket(cmp.Or(s.opts.Socket, ipc.SocketPath(s.opts.Home)))
	}
	o.IngressUID = s.ingressUID
	o.KeyringPath = statedir.KeyringPath(s.opts.Home)
	o.PairsPath = statedir.PairsPath(s.opts.Home)
	if o.Logf == nil {
		o.Logf = s.logf
	}
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
	s.holdExitLocked()
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
	// IPv4 going or coming back moves the running mesh; an instance below in
	// this very network stops it.
	if c == nil || !c.SameNetwork {
		err := s.mesh.setNoV4(c != nil)
		if err == nil {
			if c != nil {
				s.logf("daemon: running without IPv4: %v", c)
			} else {
				s.logf("daemon: IPv4 back: no instance below this one holds what %q claims", state.Network())
			}
			s.hostConflict, s.clearChecks = c, 0
			return
		}
		s.logf("daemon: following a change on the host: %v; restarting", err)
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
// or arriving by gossip — and has the mesh run on them: in place, where only
// the WireGuard and sealing keys changed, and restarted otherwise.
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
		if s.mesh != nil && !s.mesh.keysNamedElsewhere(state) {
			s.mesh.sayKeysAgain()
		}
		return
	}
	if s.mesh != nil {
		err := s.mesh.adoptKeys(promoted)
		if err == nil {
			s.keys, s.sessionKeys = promoted, promoted.Public
			s.logf("daemon: the log names this device's new keys; running on them")
			return
		}
		s.logf("daemon: the log names this device's new keys: %v; restarting on them", err)
	} else {
		s.logf("daemon: the log names this device's new keys; restarting on them")
	}
	s.restartMeshLocked(func() { s.keys = promoted }, "a key rotation")
}

// followAddrs moves the mesh onto the overlay addresses the log gives this
// device, as a renumbering or reissuing its admission after a fork does: the
// tunnel device and the log sync listener hold the old ones, and with log
// sync inside the tunnel nothing else would ever fix it. Where the running
// mesh cannot move, it restarts on them.
func (s *Service) followAddrs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mesh == nil {
		return
	}
	if !s.mesh.addrsMoved() {
		s.mesh.sayMovesAgain()
		return
	}
	err := s.mesh.followAddrs()
	if err == nil {
		s.logf("daemon: moved onto the overlay addresses the log gives this device")
		return
	}
	s.logf("daemon: moving onto the log's overlay addresses: %v; restarting on them", err)
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
				NetworkName: state.Network(), Head: state.Head(), Epoch: state.Epoch(), Schema: state.Schema(),
				Members: len(state.Nodes()), NotMember: !state.IsMember(s.keys.Identity.Public()),
			},
		}
		if s.meshErr != nil && !errors.Is(s.meshErr, ErrNotMember) {
			st.StartError = s.meshErr.Error()
		}
		if d := s.auth.Disabled(); d != nil {
			st.Disabled = d.At.String()
		}
		st.Exit = s.exitWithoutMeshLocked(state, st.NotMember)
		if s.prefs.ServeSubnets || s.prefs.SubnetsOff {
			st.Subnets = &ipc.Subnets{Consent: s.prefs.ServeSubnets, Off: s.prefs.SubnetsOff}
			if s.prefs.ServeSubnets {
				st.Subnets.NotServing = "the tunnels are not up"
			}
		}
		if s.prefs.ServePublished {
			st.Publish = &ipc.Publish{Consent: true, NotServing: "the tunnels are not up"}
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
	if s.mesh != nil && state != nil {
		if self, ok := state.Node(st.Self); ok && self.HasRole(types.RoleIngress) {
			st.Ingress = &ipc.Ingress{Running: s.now().Unix()-s.ingressAsked.Load() <= int64(ingressSilence/time.Second)}
			p := s.mesh.Published()
			for _, t := range slices.Concat(p.Names, p.TCP) {
				if len(t.Addrs) > 0 {
					st.Ingress.Names = append(st.Ingress.Names, t.Name)
				}
			}
			if r := s.ingressSaid.Load(); r != nil && st.Ingress.Running {
				st.Ingress.Ports, st.Ingress.Unbound = slices.Clone(r.Listening), slices.Clone(r.Unbound)
				st.Ingress.NoQUIC = r.NoQUIC
			}
		}
		if st.Publish != nil && len(st.Publish.Ending)+len(st.Publish.Passing) > 0 {
			p := *st.Publish
			p.TerminatorSilent = s.mesh.terminatorSilent()
			st.Publish = &p
		}
		now := s.now()
		st.Shares = s.mesh.sharesStatus(state, s.mesh.freshness(now).Fresh(now.Unix()), now)
		st.Terminator = s.mesh.terminatorStatus()
	}
	if len(s.prefs.ServeTo) > 0 && st.InNetwork {
		p := ipc.Publish{NotServing: "the tunnels are not up"}
		switch {
		case st.Publish != nil:
			p = *st.Publish
		case s.mesh != nil:
			p.NotServing = nothingPublished
		}
		for _, label := range slices.Sorted(maps.Keys(s.prefs.ServeTo)) {
			p.To = append(p.To, ipc.ServeTo{Label: label, To: s.prefs.ServeTo[label], Members: s.prefs.ServeMembers[label]})
		}
		st.Publish = &p
	}
	if st.SelfName == "" {
		st.SelfName = s.keys.Name
	}
	st.Joining = s.busy
	st.Rendezvous = s.helpers()
	if st.HTTPS == nil && (s.prefs.HTTPSOnly || s.prefs.RelayName != "") {
		st.HTTPS = &ipc.HTTPS{Only: s.prefs.HTTPSOnly, Proxy: ipc.RedactProxy(s.prefs.Proxy), Name: s.prefs.RelayName}
	}
	if o := s.opts.Mesh; o.TunName != "" && !o.Netstack && runtime.GOOS != "android" {
		st.Multicast = &ipc.Multicast{Off: s.prefs.MulticastOff}
		for _, g := range s.prefs.Groups {
			if routesGroups(o) {
				st.Multicast.Groups = append(st.Multicast.Groups, g.String())
			}
		}
	}
	if op := s.operator.Load(); op != 0 {
		st.Operator = userName(op)
	}
	return st
}

// helpers are the public services an invite may meet through, or nil: the
// DHT and STUN switches the mesh obeys cover invites too.
func (s *Service) helpers() *rendezvous.Helpers {
	o := s.opts.Mesh
	if o.DisableDHT || len(o.STUN) == 0 || s.prefs.HTTPSOnly {
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

var errNoNetwork = errors.New("this device is not in a network yet")

// reset returns the device to a fresh install: everything in the state
// directory but the lock, the socket and the homes of the host's other
// instances goes, and the device gets new keys. A member of a network not
// disabled is reset only when forced, since the others keep listing it.
func (s *Service) reset(force bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busy {
		return errors.New("this device is joining a network; wait for the join to end")
	}
	member := false
	switch {
	case s.mesh != nil:
		st := s.mesh.Status()
		member = !st.NotMember && st.Disabled == ""
	case s.auth != nil:
		member = s.auth.Disabled() == nil && s.auth.State().IsMember(s.keys.Identity.Public())
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
	// The choice and the consent were this network's, and go with it.
	s.prefs, s.exitUnkept = Prefs{}, ExitChoice{}
	s.clearEgress()

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
	if err := atomicfile.SyncDir(home); err != nil {
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

// maxOrphans bounds the records off the active chain one reply carries.
const maxOrphans = 4096

// orphans returns up to limit stored records that are not on chain, the
// active chain as encoded; the record that disabled the network first.
func (s *Service) orphans(chain [][]byte, limit int) ([][]byte, error) {
	on := make(map[types.Hash]bool, len(chain))
	for _, b := range chain {
		aum, err := types.DecodeAUM(b)
		if err != nil {
			return nil, err
		}
		on[aum.Hash()] = true
	}
	s.mu.Lock()
	st, mesh := s.store, s.mesh
	var disabled *log.DisabledError
	if mesh == nil && s.auth != nil {
		disabled = s.auth.Disabled()
	}
	s.mu.Unlock()
	if mesh != nil {
		disabled = mesh.Disabled()
	}
	hashes, err := st.Hashes()
	if err != nil {
		return nil, err
	}
	var out [][]byte
	if disabled != nil && !on[disabled.At] {
		if aum, err := st.AUM(disabled.At); err == nil {
			if b, err := aum.Encode(); err == nil {
				out = append(out, b)
				on[disabled.At] = true
			}
		}
	}
	for _, h := range hashes {
		if len(out) >= limit {
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
	s.mu.Lock()
	httpsOnly, proxy, meet := s.prefs.HTTPSOnly, proxyRoute(s.prefs.Proxy, envProxyFunc()), s.helpers().Meeter(s.logf)
	s.mu.Unlock()
	res, err := guest.Join(ctx, guest.Options{
		HTTPSOnly:     httpsOnly,
		Proxy:         proxy,
		Invite:        req.Invite,
		Name:          name,
		Keys:          k,
		Network:       network,
		NetworkName:   networkName,
		Elsewhere:     req.Elsewhere,
		Find:          s.opts.Find,
		SkipInterface: s.opts.Mesh.TunName,
		Meet:          meet,
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
		Adopt: func(records []types.AUM, admitted bool) (err error) {
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
				anchor, err := s.mesh.AnchorRecord()
				if err != nil {
					return err
				}
				return guest.Extend(anchor, s.mesh.Inform, s.mesh.Rebase, records, admitted)
			case s.auth != nil:
				anchor, err := s.auth.Record(s.auth.Anchor())
				if err != nil {
					return err
				}
				return guest.Extend(anchor, func(r []types.AUM) error { return s.auth.Inform(r...) },
					s.auth.Rebase, records, admitted)
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
		aum, err = b.RotateIdentity(cur.Identity.Public(), staged.Identity.Public(), staged.Identity.SigningKey(), seal)
	} else {
		aum, err = b.RotateNodeKey(cur.Identity.Public(), staged.Public, seal)
	}
	if err != nil {
		return nil, nil, err
	}
	if err := log.SignAsDevice(&aum, cur.Identity, staged.Identity); err != nil {
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
