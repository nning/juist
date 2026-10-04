package daemon

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nning/juist/ipc"

	"golang.org/x/sys/unix"
)

// Rules the local API follows, from the local-API CVEs in this space
// (Tailscale CVE-2022-41924, NetBird GHSA-qcpp-8vwj-hhwr):
//
//   - No TCP listener, ever: a unix socket cannot be reached by a web page.
//   - Every call is attributed to a user by the kernel (SO_PEERCRED), and what
//     it may do follows from that user alone; see [Service.mayOperate]
//     and [Service.mayAppoint].
//
// The daemon holds no admin keys, so the most any caller can do through
// [CmdInform] is hand over records a quorum has already signed.

// Timeouts on a call. The request must arrive promptly: any local user can
// connect, and a slot held by a silent caller is one a real caller waits for.
const ipcRequestTimeout = 5 * time.Second

// Admission to the socket, which every local user can reach. Callers are
// identified at accept and take a slot in one of two pools, each user at most
// a share of it: those who may operate, and those who may only read the
// status, who also get a short deadline and a small request. A user looping
// on connections therefore cannot lock root or the operator out, nor make the
// daemon buffer much, and the operator cannot lock root out either. The
// readers' pool is shared, so two users — or one with a range of subuids —
// can keep the other unprivileged users from reading the status for as long
// as they loop.
const (
	maxIPCClients       = 8 // callers who may operate
	maxOperatorsPerUser = 4 // of those, per uid
	maxReaderClients    = 4 // callers who may only read the status
	maxClientsPerUser   = 2 // of those, per uid
	maxIngressClients   = 2 // the ingress and the terminator, in a pool of their own
	maxIngressPerUser   = 1 // so that neither crowds out the other
	readerTimeout       = time.Second
	maxReaderRequest    = 4 << 10
)

// A tier is what a caller may do, which decides the pool that admits it.
type tier uint8

const (
	tierReader   tier = iota // the status
	tierIngress              // what is published, and nothing else
	tierOperator             // everything
)

// A pool admits up to size callers at once, each uid at most perUser of them.
type pool struct {
	mu      sync.Mutex
	size    int
	perUser int
	total   int
	byUser  map[uint32]int
}

func newPool(size, perUser int) *pool {
	return &pool{size: size, perUser: perUser, byUser: map[uint32]int{}}
}

// take admits uid, returning how to give its slot back.
func (p *pool) take(uid uint32) (func(), bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.total >= p.size || p.byUser[uid] >= p.perUser {
		return nil, false
	}
	p.total++
	p.byUser[uid]++
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.total--
		if p.byUser[uid]--; p.byUser[uid] == 0 {
			delete(p.byUser, uid)
		}
	}, true
}

// A caller is who is on the other end of a call, as the kernel reports it.
// Known is false where the platform cannot say, and the socket's mode is the
// whole control.
type caller struct {
	uid   uint32
	known bool
}

// A handler answers one request. It may send events first, for a call that
// runs long; ctx ends when the caller hangs up or the server closes. replies
// carries the caller's [CmdInviteReply] requests, for a [CmdInvite].
type handler func(ctx context.Context, req *ipc.Request, who caller, events func(*ipc.Event) error,
	replies <-chan ipc.Request) ipc.Response

type ipcServer struct {
	h      handler
	tierOf func(caller) tier
	ln     net.Listener
	path   string
	logf   func(string, ...any)

	operators, readers, ingress *pool

	closeOnce sync.Once
	closed    chan struct{}
	waits     waitSet
}

// socketMode is 0666 where the kernel reports every caller, so any local user
// may ask for status and the daemon decides the rest per call, and 0600 where
// it cannot, so the mode is the control.
func socketMode() fs.FileMode {
	if peerCredSupported {
		return 0o666
	}
	return 0o600
}

// newIPCServer creates the socket. The caller must hold the state directory's
// lock: unlinking a socket path another daemon is listening on succeeds, so
// without it a second daemon would silently take over the first's socket.
func newIPCServer(path string, h handler, tierOf func(caller) tier, logf func(string, ...any)) (*ipcServer, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("daemon: creating %s: %w", dir, err)
	}
	if err := refuseSharedWritable(dir); err != nil {
		return nil, err
	}
	if err := removeIfExists(path); err != nil {
		return nil, fmt.Errorf("daemon: removing a stale socket at %s: %w", path, err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("daemon: listening on %s: %w", path, err)
	}
	// Chmod after bind, which applies the umask; either way the caller is
	// checked on every call.
	if err := os.Chmod(path, socketMode()); err != nil {
		ln.Close()
		return nil, fmt.Errorf("daemon: setting the mode of %s: %w", path, err)
	}
	return &ipcServer{
		h:         h,
		tierOf:    tierOf,
		ln:        ln,
		path:      path,
		logf:      logf,
		closed:    make(chan struct{}),
		operators: newPool(maxIPCClients, maxOperatorsPerUser),
		readers:   newPool(maxReaderClients, maxClientsPerUser),
		ingress:   newPool(maxIngressClients, maxIngressPerUser),
	}, nil
}

// refuseSharedWritable rejects a socket directory group or other can write to:
// anyone who can write there can replace the socket and impersonate the
// daemon to the CLI.
func refuseSharedWritable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("daemon: inspecting %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf(
			"daemon: %s is mode %o, writable by group or other; anyone who can write there can "+
				"replace the control socket. Run: chmod 755 %s", path, perm, path)
	}
	return refuseForeignOwner(path)
}

// refuseForeignOwner rejects a directory owned by another user than the
// daemon's. Its owner can write there whatever its mode, and for the state
// directory that means appointing an operator or planting files the daemon
// writes through — as root, where root runs it over a user's directory.
func refuseForeignOwner(path string) error {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return fmt.Errorf("daemon: inspecting %s: %w", path, err)
	}
	if uid := uint32(os.Geteuid()); st.Uid != uid {
		return fmt.Errorf("daemon: %s belongs to uid %d, not to uid %d this daemon runs as; "+
			"run juistd as its owner, or give it a directory of its own", path, st.Uid, uid)
	}
	return nil
}

func removeIfExists(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *ipcServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
			}
			s.logf("daemon: ipc accept: %v", err)
			select {
			case <-s.closed:
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		who, err := peerOf(c)
		if err != nil {
			c.Close()
			continue
		}
		t := s.tierOf(who)
		release, ok := s.admit(who, t)
		if !ok {
			c.Close()
			continue
		}
		if !s.waits.track() {
			release()
			c.Close()
			return
		}
		go func() {
			defer s.waits.done()
			defer release()
			defer c.Close()
			if err := s.handle(c, who, t); err != nil {
				s.logf("daemon: ipc: %v", err)
			}
		}()
	}
}

func (s *ipcServer) close() {
	s.closeOnce.Do(func() {
		s.waits.stop()
		close(s.closed)
		s.ln.Close()
		_ = removeIfExists(s.path)
	})
	s.waits.wait()
}

// admit takes a slot for a caller, returning how to give it back.
func (s *ipcServer) admit(who caller, t tier) (func(), bool) {
	switch t {
	case tierOperator:
		return s.operators.take(who.uid)
	case tierIngress:
		return s.ingress.take(who.uid)
	}
	return s.readers.take(who.uid)
}

func (s *ipcServer) handle(c net.Conn, who caller, t tier) error {
	timeout, limit := ipcRequestTimeout, uint32(ipc.MaxRequest)
	if t != tierOperator {
		timeout, limit = readerTimeout, maxReaderRequest
	}
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	raw, err := ipc.ReadMessage(c, limit)
	if err != nil {
		return err
	}
	req, err := ipc.DecodeRequest(raw)
	if err != nil {
		return ipc.WriteMessage(c, &ipc.Response{Err: err.Error()}, ipc.MaxResponse)
	}

	// The call ends when the caller hangs up, which for a long one is the
	// only sign it stopped waiting: it sends nothing after its request.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-s.closed:
			cancel()
		case <-ctx.Done():
		}
	}()
	_ = c.SetDeadline(time.Time{})
	replies := make(chan ipc.Request)
	go func() {
		defer cancel()
		if req.Command != ipc.CmdInvite {
			var b [1]byte
			_, _ = c.Read(b[:])
			return
		}
		// A conversation: everything the caller sends after its request is
		// a reply, and anything else ends the call.
		for {
			raw, err := ipc.ReadMessage(c, ipc.MaxReply)
			if err != nil {
				return
			}
			r, err := ipc.DecodeRequest(raw)
			if err != nil || r.Command != ipc.CmdInviteReply {
				return
			}
			select {
			case replies <- r:
			case <-ctx.Done():
				return
			}
		}
	}()
	events := func(e *ipc.Event) error {
		_ = c.SetWriteDeadline(time.Now().Add(ipc.CallTimeout))
		return ipc.WriteMessage(c, &ipc.Response{Event: e}, ipc.MaxResponse)
	}
	resp := s.h(ctx, &req, who, events, replies)
	_ = c.SetWriteDeadline(time.Now().Add(ipc.CallTimeout))
	return ipc.WriteMessage(c, &resp, ipc.MaxResponse)
}
