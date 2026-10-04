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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nning/juist/daemon"
	"github.com/nning/juist/internal/plumber"
	"github.com/nning/juist/ipc"
)

// envBinder names the descriptor a terminator asks its root parent to
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

// runBinder, started as root, runs args again as the terminator's user, and
// stays root to listen for it where the juistd on socket says this device
// serves, and nowhere else.
func runBinder(ctx context.Context, args []string, socket string, errOut io.Writer) error {
	cred, err := helperUser(daemon.ServeUser)
	if err != nil {
		return err
	}
	// What root was started holding stays with root.
	for fd := 3; fd < 1024; fd++ {
		syscall.CloseOnExec(fd)
	}
	// One message to each request and each answer.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	parentEnd, childEnd := os.NewFile(uintptr(fds[0]), "binder"), os.NewFile(uintptr(fds[1]), "terminator")
	// Orphaned, the terminator would keep its listeners from the next.
	lifeline, held, err := os.Pipe()
	if err != nil {
		return err
	}
	defer held.Close()
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, args...)
	cmd.Stdout, cmd.Stderr = struct{ io.Writer }{errOut}, struct{ io.Writer }{errOut}
	cmd.ExtraFiles = []*os.File{childEnd, lifeline}
	cmd.Env = append(daemonEnv(os.Environ()), envBinder+"=3", envBinderLifeline+"=4")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred, Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting the terminator as %s: %w", daemon.ServeUser, err)
	}
	childEnd.Close()
	lifeline.Close()
	c, err := net.FileConn(parentEnd)
	parentEnd.Close()
	if err != nil {
		cmd.Process.Kill()
		return err
	}
	defer c.Close()
	go serveBinds(ctx, c.(*net.UnixConn), func(ctx context.Context) (*ipc.Published, error) {
		return ipc.CallServing(ctx, socket, nil)
	})
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	go func() {
		for range sigs {
			cmd.Process.Signal(syscall.SIGTERM)
			time.AfterFunc(stopWait, func() { cmd.Process.Kill() })
		}
	}()
	context.AfterFunc(ctx, func() { cmd.Process.Signal(syscall.SIGTERM) })
	return cmd.Wait()
}

// stopWait is how long a process told to stop has before it is killed.
const stopWait = time.Minute

// serveBinds listens at each address the terminator asks for on c, where
// serving says this device serves it, and hands it the listener, its answer
// naming the address it answers.
func serveBinds(ctx context.Context, c *net.UnixConn, serving func(context.Context) (*ipc.Published, error)) {
	buf := make([]byte, maxBindMessage)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		addr := strings.TrimSpace(string(buf[:n]))
		f, err := bindServed(ctx, addr, serving)
		if err != nil {
			// The terminator logs it, once; "2" is a port another program holds.
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

// bindWait is how long the terminator waits for the binder's answer.
var bindWait = 30 * time.Second

// maxBindMessage bounds a request to the binder and its answer.
const maxBindMessage = 512

// bindServed listens at addr, where this device serves a name, or redirects
// HTTP for one. The address is not reused: root binding where another
// program listens on every address would take its connections there.
func bindServed(ctx context.Context, addr string, serving func(context.Context) (*ipc.Published, error)) (*os.File, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%q is no address and port", addr)
	}
	p, err := serving(ctx)
	if err != nil {
		return nil, fmt.Errorf("asking juistd what is served: %w", err)
	}
	served := false
	for _, n := range p.Names {
		for _, a := range n.Addrs {
			served = served || netip.AddrPortFrom(a, n.Port) == ap || netip.AddrPortFrom(a, httpPort) == ap
		}
	}
	if !served {
		return nil, fmt.Errorf("this device serves nothing at %v", ap)
	}
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 0) }); err != nil {
			return err
		}
		return serr
	}}
	ln, err := lc.Listen(ctx, "tcp", ap.String())
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	return ln.(*net.TCPListener).File()
}

// binder is the terminator's end: it listens through its root parent.
type binder struct {
	mu sync.Mutex
	c  *net.UnixConn
}

// inheritedBinder is the root parent this terminator was started by, if any,
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
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.c.SetDeadline(time.Now().Add(bindWait))
	if _, err := b.c.Write([]byte(addr)); err != nil {
		return nil, err
	}
	buf, oob := make([]byte, maxBindMessage), make([]byte, unix.CmsgSpace(4))
	for {
		n, oobn, _, _, err := b.c.ReadMsgUnix(buf, oob)
		if err != nil {
			return nil, err
		}
		f := receivedFile(oob[:oobn], addr)
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
		defer f.Close()
		return net.FileListener(f)
	}
}

// receivedFile is the descriptor oob carries, nil for none.
func receivedFile(oob []byte, name string) *os.File {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil || len(msgs) != 1 {
		return nil
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		return nil
	}
	return os.NewFile(uintptr(fds[0]), name)
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
