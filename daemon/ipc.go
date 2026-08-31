package daemon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/sys/unix"

	"github.com/nning/juist/types"
)

// The local API, and why it looks like this.
//
// Both surveyed local-API CVEs in this space (Tailscale CVE-2022-41924:
// DNS rebinding into a localhost TCP LocalAPI; NetBird GHSA-qcpp-8vwj-hhwr: a
// mode-0666 unix socket) come from the same two mistakes, and
// docs/04-architecture.md turns them into rules this file follows:
//
//   - No TCP listener, ever. A unix socket cannot be reached by a web page,
//     which is what made the rebinding attack possible.
//   - Mode 0600 in a 0700 directory, plus SO_PEERCRED. The mode is the
//     defence; the credential check is what makes it a check rather than an
//     assumption, and it is what catches a socket whose directory was made
//     permissive after the daemon started.
//
// The daemon deliberately cannot do the one thing an attacker would most want
// from it: authorize a membership change. Admin keys live in the operator's
// CLI keystore and never here, so the most a caller can do through [cmdInform]
// is hand over records a quorum has already signed — which any member could
// equally have gossiped.

// Limits on an IPC message. Small: every request here is a verb and at most a
// batch of records.
const (
	// MaxIPCMessage caps one encoded request or response.
	MaxIPCMessage = 8 << 20

	// MaxIPCRecords caps the records one inform request may carry.
	MaxIPCRecords = 256

	ipcMaxNestedLevels = 6
	ipcMaxArrayElems   = MaxIPCRecords
	ipcMaxMapPairs     = 32
)

// A Command is an IPC verb. Numbers are permanent; 0 is invalid.
type Command uint8

const (
	cmdInvalid Command = 0

	// CmdStatus asks what state the daemon is in.
	CmdStatus Command = 1

	// CmdInform hands the daemon log records to apply and gossip.
	CmdInform Command = 2
)

func (c Command) String() string {
	switch c {
	case cmdInvalid:
		return "no command"
	case CmdStatus:
		return "status"
	case CmdInform:
		return "inform"
	default:
		return fmt.Sprintf("command?<%d>", uint8(c))
	}
}

// A Request is one IPC call.
type Request struct {
	Command Command `cbor:"1,keyasint"`

	// Records are encoded AUMs, for [CmdInform]. They travel as raw bytes so
	// that they can only enter through types.DecodeAUM, the same rule the
	// gossip frame follows.
	Records [][]byte `cbor:"2,keyasint,omitempty"`
}

// A Response is one IPC reply. Err is set when the call failed, in which case
// nothing else is meaningful.
type Response struct {
	Err    string  `cbor:"1,keyasint,omitempty"`
	Status *Status `cbor:"2,keyasint,omitempty"`
}

func (r *Request) validate() error {
	switch r.Command {
	case CmdStatus:
		if len(r.Records) > 0 {
			return errors.New("daemon: a status request must not carry records")
		}
	case CmdInform:
		if len(r.Records) == 0 {
			return errors.New("daemon: an inform request carries no records")
		}
	default:
		return fmt.Errorf("daemon: request has %v", r.Command)
	}
	if len(r.Records) > MaxIPCRecords {
		return fmt.Errorf("daemon: request carries %d records, over the %d limit",
			len(r.Records), MaxIPCRecords)
	}
	return nil
}

// The IPC codec is the same canonical CBOR discipline the rest of the project
// uses, with its own limits. docs/06-verification.md schedules a fuzz target
// for this decoder at M2 because it is the one parser reachable from a local
// unprivileged process.
var ipcEnc = func() cbor.EncMode {
	m, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("daemon: building the IPC encoder: %v", err))
	}
	return m
}()

var ipcDec = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		UTF8:              cbor.UTF8RejectInvalid,
		MaxNestedLevels:   ipcMaxNestedLevels,
		MaxArrayElements:  ipcMaxArrayElems,
		MaxMapPairs:       ipcMaxMapPairs,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("daemon: building the IPC decoder: %v", err))
	}
	return m
}()

func ipcEncode(v any) ([]byte, error) {
	b, err := ipcEnc.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("daemon: encoding an IPC message: %w", err)
	}
	if len(b) > MaxIPCMessage {
		return nil, fmt.Errorf("daemon: IPC message is %d bytes, over the %d limit", len(b), MaxIPCMessage)
	}
	return b, nil
}

func ipcDecode[T any](b []byte) (T, error) {
	var zero, v T
	if len(b) == 0 {
		return zero, errors.New("daemon: empty IPC message")
	}
	if len(b) > MaxIPCMessage {
		return zero, fmt.Errorf("daemon: IPC message is %d bytes, over the %d limit", len(b), MaxIPCMessage)
	}
	if err := ipcDec.Unmarshal(b, &v); err != nil {
		return zero, fmt.Errorf("daemon: decoding an IPC message: %w", err)
	}
	re, err := ipcEnc.Marshal(v)
	if err != nil {
		return zero, fmt.Errorf("daemon: re-encoding an IPC message: %w", err)
	}
	if !bytes.Equal(re, b) {
		return zero, errors.New("daemon: non-canonical IPC message")
	}
	return v, nil
}

// DecodeRequest decodes and shape-checks an IPC request. Exported for the
// fuzz target.
func DecodeRequest(b []byte) (Request, error) {
	r, err := ipcDecode[Request](b)
	if err != nil {
		return Request{}, err
	}
	if err := r.validate(); err != nil {
		return Request{}, err
	}
	return r, nil
}

// DecodeResponse decodes an IPC reply.
func DecodeResponse(b []byte) (Response, error) { return ipcDecode[Response](b) }

// ipcTimeout bounds one call. A local caller that stops reading must not hold
// a daemon goroutine.
const ipcTimeout = 30 * time.Second

// maxIPCClients bounds concurrent callers.
const maxIPCClients = 8

type ipcServer struct {
	d    *Daemon
	ln   net.Listener
	path string

	// lock is the home-directory lock file, held for this server's lifetime.
	// It is what makes this daemon the single writer of the store beneath it;
	// see [newIPCServer].
	lock *os.File

	// closing guards the wait set; see [Daemon.track] for why an Add cannot
	// simply race the Wait in close.
	closeOnce sync.Once
	closed    chan struct{}
	slots     chan struct{}
	trackMu   sync.Mutex
	closing   bool
	wg        sync.WaitGroup
}

func (s *ipcServer) track() bool {
	s.trackMu.Lock()
	defer s.trackMu.Unlock()
	if s.closing {
		return false
	}
	s.wg.Add(1)
	return true
}

// LockName is the single-instance lock file's name inside a state directory.
const LockName = "daemon.lock"

// newIPCServer creates the socket.
//
// It first takes an exclusive advisory lock on a file in the state directory,
// and only then removes any stale socket and binds. The order matters, and the
// earlier reasoning here was wrong: a unix socket does not behave like a TCP
// port. Unlinking a path another daemon is listening on succeeds — the running
// daemon keeps its file descriptor and simply becomes unreachable by name —
// and net.Listen on the freed path then also succeeds. So without the lock a
// second daemon on the same home silently steals the control socket, leaving
// two log authorities writing one store: the CLI talks to the newcomer while
// the original keeps a revoked peer's tunnel up, and the split-brain that
// docs/09-mesh-layer-notes.md's "two writers" rule exists to prevent happens
// one layer down from where apply refuses it.
//
// The lock is held for the daemon's lifetime and released when this server
// closes (or when the process dies, since the kernel drops an flock with its
// open file). A crashed daemon therefore leaves no stale lock. With it held,
// removing the socket is finally safe for the reason the old comment claimed:
// this process is provably the only daemon on this home.
func newIPCServer(d *Daemon, path string) (*ipcServer, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("daemon: creating %s: %w", dir, err)
	}
	if err := refuseSharedWritable(dir); err != nil {
		return nil, err
	}

	lockPath := filepath.Join(dir, LockName)
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("daemon: opening the lock file %s: %w", lockPath, err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf(
				"daemon: another juistd is already running on %s (lock held on %s); "+
					"refusing to start a second one on the same home", dir, lockPath)
		}
		return nil, fmt.Errorf("daemon: locking %s: %w", lockPath, err)
	}

	if err := removeIfExists(path); err != nil {
		lock.Close()
		return nil, fmt.Errorf("daemon: removing a stale socket at %s: %w", path, err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		lock.Close()
		return nil, fmt.Errorf("daemon: listening on %s: %w", path, err)
	}
	// Chmod after bind: the socket is created with the process umask
	// applied, which on a default umask leaves it group- and
	// world-readable. A brief window exists between the two, which the
	// 0700 directory above closes.
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		lock.Close()
		return nil, fmt.Errorf("daemon: tightening %s: %w", path, err)
	}
	return &ipcServer{
		d:      d,
		ln:     ln,
		path:   path,
		lock:   lock,
		closed: make(chan struct{}),
		slots:  make(chan struct{}, maxIPCClients),
	}, nil
}

// refuseSharedWritable rejects a socket directory group or other can write to:
// anyone who can write there can replace the socket and impersonate the
// daemon to the CLI. Same rule the keystore applies to its own directory.
func refuseSharedWritable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("daemon: inspecting %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf(
			"daemon: %s is mode %o, writable by group or other; anyone who can write there can "+
				"replace the control socket. Run: chmod 700 %s", path, perm, path)
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
			s.d.logf("daemon: ipc accept: %v", err)
			select {
			case <-s.closed:
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		select {
		case s.slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		if !s.track() {
			<-s.slots
			c.Close()
			return
		}
		go func() {
			defer s.wg.Done()
			defer func() { <-s.slots }()
			defer c.Close()
			if err := s.handle(c); err != nil {
				s.d.logf("daemon: ipc: %v", err)
			}
		}()
	}
}

func (s *ipcServer) close() {
	s.closeOnce.Do(func() {
		s.trackMu.Lock()
		s.closing = true
		s.trackMu.Unlock()
		close(s.closed)
		s.ln.Close()
		// The listener's own cleanup removes the socket file; this covers
		// the case where it did not.
		_ = removeIfExists(s.path)
		// Releasing the lock is the last thing, so no successor daemon can
		// bind the socket until this one has let its own go.
		if s.lock != nil {
			s.lock.Close()
		}
	})
	s.wg.Wait()
}

func (s *ipcServer) handle(c net.Conn) error {
	if err := c.SetDeadline(time.Now().Add(ipcTimeout)); err != nil {
		return err
	}
	if err := checkPeerCred(c); err != nil {
		return err
	}
	raw, err := readMessage(c, MaxIPCMessage)
	if err != nil {
		return err
	}
	req, err := DecodeRequest(raw)
	if err != nil {
		return writeMessage(c, Response{Err: err.Error()})
	}
	return writeMessage(c, s.dispatch(&req))
}

func (s *ipcServer) dispatch(req *Request) Response {
	switch req.Command {
	case CmdStatus:
		st := s.d.Status()
		return Response{Status: &st}
	case CmdInform:
		records := make([]types.AUM, 0, len(req.Records))
		for _, b := range req.Records {
			aum, err := types.DecodeAUM(b)
			if err != nil {
				return Response{Err: fmt.Sprintf("undecodable record: %v", err)}
			}
			records = append(records, aum)
		}
		if err := s.d.Inform(records); err != nil {
			return Response{Err: err.Error()}
		}
		st := s.d.Status()
		return Response{Status: &st}
	default:
		// Unreachable: validate rejects unknown commands.
		return Response{Err: fmt.Sprintf("unhandled %v", req.Command)}
	}
}

// Messages on the socket are length-prefixed, checked against the limit before
// anything is buffered.
func readMessage(c net.Conn, limit uint32) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, fmt.Errorf("daemon: reading an IPC header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > limit {
		return nil, fmt.Errorf("daemon: peer announced a %d-byte IPC message, over the %d limit", n, limit)
	}
	// Grown as the bytes arrive, not allocated from the announced size: the
	// same rule the gossip framing follows, so that a caller that announces
	// the maximum and sends nothing costs nothing.
	var buf bytes.Buffer
	buf.Grow(min(int(n), 32<<10))
	if _, err := io.CopyN(&buf, c, int64(n)); err != nil {
		return nil, fmt.Errorf("daemon: reading an IPC body: %w", err)
	}
	return buf.Bytes(), nil
}

func writeMessage(c net.Conn, v any) error {
	b, err := ipcEncode(v)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := c.Write(hdr[:]); err != nil {
		return fmt.Errorf("daemon: writing an IPC message: %w", err)
	}
	if _, err := c.Write(b); err != nil {
		return fmt.Errorf("daemon: writing an IPC message: %w", err)
	}
	return nil
}

// --- client side -----------------------------------------------------------

// Call sends one request to a daemon's IPC socket and returns its reply.
//
// It is the CLI's half of the protocol, here rather than in cmd/ so that the
// two halves of a wire format stay in one file.
func Call(path string, req Request) (Response, error) {
	c, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return Response{}, err
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(ipcTimeout)); err != nil {
		return Response{}, err
	}
	if err := writeMessage(c, req); err != nil {
		return Response{}, err
	}
	raw, err := readMessage(c, MaxIPCMessage)
	if err != nil {
		return Response{}, err
	}
	resp, err := DecodeResponse(raw)
	if err != nil {
		return Response{}, err
	}
	if resp.Err != "" {
		return resp, errors.New(resp.Err)
	}
	return resp, nil
}

// SocketName is the socket's name inside a juist state directory.
const SocketName = "daemon.sock"

// SocketPath returns the control socket's path for a state directory.
func SocketPath(home string) string { return filepath.Join(home, SocketName) }
