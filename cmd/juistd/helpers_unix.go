//go:build unix

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nning/juist/internal/plumber"
	"github.com/nning/juist/internal/terminator"
	"github.com/nning/juist/ipc"
)

// envBinder names the descriptor a helper asks its root parent to
// listen through, and envBinderLifeline the one that ends with the parent.
const (
	envBinder         = "JUIST_BINDER_FD"
	envBinderLifeline = "JUIST_BINDER_LIFELINE"
)

func credential(u *user.User) (*syscall.Credential, error) {
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, err
	}
	if uid == 0 || gid == 0 {
		return nil, fmt.Errorf("the %s user is root's, uid %d, gid %d: the daemon would keep root's rights", u.Username, uid, gid)
	}
	cred := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	groups, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if n, err := strconv.ParseUint(g, 10, 32); err == nil {
			cred.Groups = append(cred.Groups, uint32(n))
		}
	}
	return cred, nil
}

// helperUser is the user a helper started as root runs as.
func helperUser(name string) (*syscall.Credential, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("started as root, the helper runs as the %s user, and there is none", name)
	}
	return credential(u)
}

// dropTo makes this process name's, for good: what root bound stays bound.
func dropTo(name string) error {
	cred, err := helperUser(name)
	if err != nil {
		return err
	}
	groups := make([]int, len(cred.Groups))
	for i, g := range cred.Groups {
		groups[i] = int(g)
	}
	if err := syscall.Setgroups(groups); err != nil {
		return err
	}
	if err := syscall.Setgid(int(cred.Gid)); err != nil {
		return err
	}
	if err := syscall.Setuid(int(cred.Uid)); err != nil {
		return err
	}
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return errors.New("still root after dropping to " + name)
	}
	return nil
}

// A child is this program run again as another user beside a parent that
// stays root: the two hold a socket between them, and the child a lifeline
// that ends with the parent.
type child struct {
	cmd      *exec.Cmd
	conn     *net.UnixConn
	held     *os.File // the parent's end of the lifeline
	stopping atomic.Bool
	// unwatch stops passing this process's stops on.
	unwatch func()
}

// startChild runs args as cred, what root holds kept from it, with a socket
// of sockType to this process on its descriptor 3, the lifeline on 4, env
// added to [daemonEnv]'s and its output on out and errOut; what names the
// child in an error. Each signal that stops this process, from before the
// child starts, is passed on to it as as maps it. The caller closes c.held
// and calls c.unwatch once done with the child.
func startChild(args []string, cred *syscall.Credential, sockType int, env []string, out, errOut io.Writer,
	what string, as func(os.Signal) os.Signal) (*child, error) {
	// What root was started holding stays with root.
	for fd := 3; fd < 1024; fd++ {
		syscall.CloseOnExec(fd)
	}
	fds, err := socketpair(sockType)
	if err != nil {
		return nil, err
	}
	parentEnd, childEnd := os.NewFile(uintptr(fds[0]), "parent"), os.NewFile(uintptr(fds[1]), "child")
	defer childEnd.Close()
	defer parentEnd.Close()
	// Orphaned, the child would hold on to what it was given for the next.
	lifeline, held, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer lifeline.Close()
	self, err := os.Executable()
	if err != nil {
		held.Close()
		return nil, err
	}
	cmd := exec.Command(self, args...)
	// Pipes, not root's terminal, which the child could read or type into,
	// and a session of its own, which the terminal is none of.
	cmd.Stdout, cmd.Stderr = struct{ io.Writer }{out}, struct{ io.Writer }{errOut}
	cmd.ExtraFiles = []*os.File{childEnd, lifeline}
	cmd.Env = append(daemonEnv(os.Environ()), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred, Setsid: true}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	if err := cmd.Start(); err != nil {
		signal.Stop(sigs)
		held.Close()
		return nil, fmt.Errorf("starting %s: %w", what, err)
	}
	conn, err := net.FileConn(parentEnd)
	if err != nil {
		signal.Stop(sigs)
		cmd.Process.Kill()
		held.Close()
		return nil, err
	}
	c := &child{cmd: cmd, conn: conn.(*net.UnixConn), held: held, unwatch: func() { signal.Stop(sigs) }}
	go func() {
		for s := range sigs {
			c.stop(as(s))
		}
	}()
	return c, nil
}

// stop passes s on to the child, and kills it past [stopWait].
func (c *child) stop(s os.Signal) {
	c.stopping.Store(true)
	c.cmd.Process.Signal(s)
	time.AfterFunc(stopWait, func() { c.cmd.Process.Kill() })
}

// runBinder, started as root, runs args again as the helper user name, and
// stays root to listen for it by bind, which refuses what it may not.
func runBinder(ctx context.Context, args []string, name string, bind func(context.Context, string) (*os.File, error),
	errOut io.Writer) error {
	cred, err := helperUser(name)
	if err != nil {
		return err
	}
	// One message to each request and each answer.
	c, err := startChild(args, cred, unix.SOCK_SEQPACKET, []string{envBinder + "=3", envBinderLifeline + "=4"},
		errOut, errOut, "the helper as "+name, func(os.Signal) os.Signal { return syscall.SIGTERM })
	if err != nil {
		return err
	}
	defer c.held.Close()
	defer c.unwatch()
	defer c.conn.Close()
	go serveBinds(ctx, c.conn, bind)
	context.AfterFunc(ctx, func() {
		c.stopping.Store(true)
		c.cmd.Process.Signal(syscall.SIGTERM)
	})
	return stoppedAsAsked(c.cmd.Wait(), c.stopping.Load())
}

// stoppedAsAsked is err, a child's exit, but nil where the child died of a
// stop it was asked to make: one that came before its handler did.
func stoppedAsAsked(err error, asked bool) error {
	var exit *exec.ExitError
	if !asked || !errors.As(err, &exit) {
		return err
	}
	if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() &&
		(ws.Signal() == syscall.SIGTERM || ws.Signal() == syscall.SIGINT) {
		return nil
	}
	return err
}

// stopWait is how long a process told to stop has before it is killed.
const stopWait = time.Minute

// serveBinds listens at each address the helper asks for on c, where bind
// lets it, and hands it the listener, its answer naming the address it
// answers.
func serveBinds(ctx context.Context, c *net.UnixConn, bind func(context.Context, string) (*os.File, error)) {
	buf := make([]byte, maxBindMessage)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		addr := strings.TrimSpace(string(buf[:n]))
		f, err := bind(ctx, addr)
		if err != nil {
			// The helper logs it, once; "2" is a port another program holds.
			code := "1 "
			if errors.Is(err, syscall.EADDRINUSE) {
				code = "2 "
			}
			msg := strings.ReplaceAll(err.Error(), "\n", " ")
			if _, err := c.Write([]byte((code + addr + " " + msg)[:min(len(msg)+len(addr)+3, maxBindMessage)])); err != nil {
				return
			}
			continue
		}
		_, _, err = c.WriteMsgUnix([]byte("0 "+addr), unix.UnixRights(int(f.Fd())), nil)
		f.Close()
		if err != nil {
			return
		}
	}
}

// bindWait is how long a helper waits for the binder's answer.
var bindWait = 30 * time.Second

// maxBindMessage bounds a request to the binder and its answer.
const maxBindMessage = 512

// bindServed listens at addr, where this device serves a name, or redirects
// HTTP for one. The address is not reused: root binding where another
// program listens on every address would take its connections there.
func bindServed(ctx context.Context, addr string, serving func(context.Context) (*ipc.Published, error)) (*os.File, error) {
	addr, udp := strings.CutSuffix(addr, "/udp")
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%q is no address and port", addr)
	}
	p, err := serving(ctx)
	if err != nil {
		return nil, fmt.Errorf("asking juistd what is served: %w", err)
	}
	if udp {
		// QUIC, for a name offered HTTP/3 alone.
		if !slices.ContainsFunc(p.Names, func(n ipc.PublishedTarget) bool {
			return terminator.HTTP3(n) && slices.Contains(n.Addrs, ap.Addr()) && n.Port == ap.Port()
		}) {
			return nil, fmt.Errorf("this device serves no QUIC at %v", ap)
		}
		pc, err := net.ListenPacket("udp", ap.String())
		if err != nil {
			return nil, err
		}
		defer pc.Close()
		return pc.(*net.UDPConn).File()
	}
	served := false
	for _, n := range p.Names {
		for _, a := range n.Addrs {
			served = served || netip.AddrPortFrom(a, n.Port) == ap || netip.AddrPortFrom(a, httpPort) == ap
		}
	}
	for _, n := range p.TCP {
		for _, a := range n.Addrs {
			served = served || netip.AddrPortFrom(a, n.Port) == ap
		}
	}
	if !served {
		return nil, fmt.Errorf("this device serves nothing at %v", ap)
	}
	lc := net.ListenConfig{Control: noReuse}
	ln, err := lc.Listen(ctx, "tcp", ap.String())
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	return ln.(*net.TCPListener).File()
}

// bindPublic listens on every address at addr, ":PORT", where an ingress
// serves: 443 and 80, and the ports published says names are published on
// by TCP; ":443/udp" is QUIC's socket.
func bindPublic(ctx context.Context, addr string, published func(context.Context) (*ipc.Published, error)) (*os.File, error) {
	if addr == ":443/udp" {
		pc, err := net.ListenPacket("udp", ":443")
		if err != nil {
			return nil, err
		}
		defer pc.Close()
		return pc.(*net.UDPConn).File()
	}
	p, ok := strings.CutPrefix(addr, ":")
	port, err := strconv.ParseUint(p, 10, 16)
	if !ok || err != nil || port == 0 {
		return nil, fmt.Errorf("%q is no port", addr)
	}
	if port != 443 && port != 80 {
		got, err := published(ctx)
		if err != nil {
			return nil, fmt.Errorf("asking juistd what is published: %w", err)
		}
		if !slices.ContainsFunc(got.TCP, func(t ipc.PublishedTarget) bool { return t.Public == uint16(port) }) {
			return nil, fmt.Errorf("nothing is published on port %d", port)
		}
	}
	// A public port is not reused, as bindServed's: BSD would bind every
	// address beside a program holding one of them, which keeps its clients.
	lc := net.ListenConfig{}
	if port != 443 && port != 80 {
		lc.Control = noReuse
	}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	return ln.(*net.TCPListener).File()
}

// noReuse turns SO_REUSEADDR off, which Go turns on.
func noReuse(_, _ string, rc syscall.RawConn) error {
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 0) }); err != nil {
		return err
	}
	return serr
}

// binder is a helper's end: it listens through its root parent.
type binder struct {
	mu sync.Mutex
	c  *net.UnixConn
}

// inheritedBinder is the root parent this helper was started by, if any,
// and a channel that closes once that parent is gone.
func inheritedBinder() (*binder, <-chan struct{}, error) {
	fd, err := inheritedFD(envBinder)
	if fd < 0 || err != nil {
		return nil, nil, err
	}
	c, err := net.FileConn(os.NewFile(uintptr(fd), "binder"))
	if err != nil {
		return nil, nil, err
	}
	gone := make(chan struct{})
	if lfd, err := inheritedFD(envBinderLifeline); lfd >= 0 && err == nil {
		go func() {
			io.Copy(io.Discard, os.NewFile(uintptr(lfd), "lifeline"))
			close(gone)
		}()
	}
	return &binder{c: c.(*net.UnixConn)}, gone, nil
}

func (b *binder) listen(_, addr string) (net.Listener, error) {
	f, err := b.bound(addr)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return net.FileListener(f)
}

// listenUDP is listen for a UDP socket.
func (b *binder) listenUDP(addr string) (*net.UDPConn, error) {
	f, err := b.bound(addr + "/udp")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pc, err := net.FilePacketConn(f)
	if err != nil {
		return nil, err
	}
	u, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, errors.New("the binder sent no UDP socket")
	}
	return u, nil
}

// bound asks the binder for a socket at addr.
func (b *binder) bound(addr string) (*os.File, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.c.SetDeadline(time.Now().Add(bindWait))
	if _, err := b.c.Write([]byte(addr)); err != nil {
		return nil, err
	}
	buf, oob := make([]byte, maxBindMessage), make([]byte, unix.CmsgSpace(8*4)) // room for extras, to be closed
	for {
		n, oobn, flags, _, err := b.c.ReadMsgUnix(buf, oob)
		if err != nil {
			return nil, err
		}
		f := receivedFile(oob[:oobn], flags, addr)
		code, rest, _ := strings.Cut(string(buf[:n]), " ")
		answered, msg, _ := strings.Cut(rest, " ")
		if answered != addr {
			// An answer to a request given up on: not this one's.
			if f != nil {
				f.Close()
			}
			continue
		}
		switch {
		case code != "0":
			if f != nil {
				f.Close()
			}
			if code == "2" {
				return nil, fmt.Errorf("%s: %w", msg, syscall.EADDRINUSE)
			}
			return nil, errors.New(msg)
		case f == nil:
			return nil, errors.New("the binder sent no listener")
		}
		return f, nil
	}
}

// receivedFile is the descriptor oob carries, nil for none; see
// [plumber.ReceivedFD].
func receivedFile(oob []byte, flags int, name string) *os.File {
	fd, err := plumber.ReceivedFD(oob, flags)
	if err != nil {
		return nil
	}
	return os.NewFile(uintptr(fd), name)
}

// inheritedFD is the descriptor env names, -1 for none.
func inheritedFD(env string) (int, error) {
	v := os.Getenv(env)
	if v == "" {
		return -1, nil
	}
	os.Unsetenv(env)
	fd, err := strconv.Atoi(v)
	if err != nil {
		return -1, fmt.Errorf("%s=%q", env, v)
	}
	unix.CloseOnExec(fd)
	return fd, nil
}

// socketpair is a local socket pair of typ, both ends close-on-exec: under
// ForkLock, since darwin has no SOCK_CLOEXEC to set it atomically.
func socketpair(typ int) ([2]int, error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fds, err := unix.Socketpair(unix.AF_UNIX, typ, 0)
	if err != nil {
		return fds, err
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	return fds, nil
}

// daemonEnv is what of root's environment a process run as another user
// gets: the locale, the time zone, the path, the CA certificates and juist's
// and Go's own, none of root's credentials or directories.
func daemonEnv(env []string) []string {
	var out []string
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		switch {
		case k == "PATH" || k == "TZ" || k == "LANG" || k == "GODEBUG" || k == "GOTRACEBACK" ||
			k == "SSL_CERT_FILE" || k == "SSL_CERT_DIR",
			strings.HasPrefix(k, "LC_"),
			strings.HasPrefix(k, "JUIST") && k != plumber.EnvFD && k != plumber.EnvLifeline && k != envBinder &&
				k != envBinderLifeline:
			out = append(out, kv)
		}
	}
	return out
}
