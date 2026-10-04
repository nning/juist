package main

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/plumber"
)

// runAs is the user the daemon runs as when juistd is started as root.
const runAs = "juist"

// permHint is what gives a device's creation the right it lacked.
const permHint = `creating %q needs root: start juistd as root, which runs the daemon as juist, the packaged service, or --tun ""`

// split, started as root, keeps this process as the helper that plumbs the
// daemon's devices and runs the daemon as [runAs], until it exits; it
// reports the daemon's exit code, and whether it split. Root always splits:
// a helper's descriptor in its environment is no helper's.
func split(args []string) (int, bool) {
	if os.Getuid() != 0 || onNoDevice(args) || slices.ContainsFunc(args, func(a string) bool {
		return a == "-h" || a == "--help" || a == "-help" || a == "__manpage"
	}) {
		return 0, false
	}
	if err := runSplit(args); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return max(exit.ExitCode(), 1), true
		}
		fmt.Fprintf(os.Stderr, "juistd: %v\n", err)
		return 1, true
	}
	return 0, true
}

func runSplit(args []string) error {
	if !slices.ContainsFunc(args, func(a string) bool {
		return a == "--home" || a == "-H" || strings.HasPrefix(a, "--home=") || strings.HasPrefix(a, "-H=")
	}) {
		// Root's own would be no directory the daemon may use.
		return errors.New("started as root, juistd needs --home, a directory the juist user owns\n" +
			"hint: service juistd start, which gives it")
	}
	u, err := user.Lookup(runAs)
	if err != nil {
		return fmt.Errorf("started as root, juistd runs as the %s user, and there is none\n"+
			"hint: pw useradd %s -u 829 -d /var/db/juist -s /usr/sbin/nologin, a system user", runAs, runAs)
	}
	cred, err := credential(u)
	if err != nil {
		return err
	}
	// What root was started holding stays with root.
	for fd := 3; fd < 1024; fd++ {
		syscall.CloseOnExec(fd)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	helperEnd, daemonEnd := os.NewFile(uintptr(fds[0]), "helper"), os.NewFile(uintptr(fds[1]), "daemon")
	self, err := os.Executable()
	if err != nil {
		return err
	}
	// Orphaned, the daemon could no longer route: it stops when this end
	// closes, and the next helper destroys what is left. A parent-death
	// signal would not do: FreeBSD drops it at the daemon's exec, which
	// follows a change of user.
	lifeline, held, err := os.Pipe()
	if err != nil {
		return err
	}
	defer held.Close()
	cmd := exec.Command(self, args...)
	// Pipes, not root's terminal, which the daemon could read or type into,
	// and a session of its own, which the terminal is none of.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, struct{ io.Writer }{os.Stdout}, struct{ io.Writer }{os.Stderr}
	cmd.ExtraFiles = []*os.File{daemonEnd, lifeline}
	cmd.Env = append(daemonEnv(os.Environ()), plumber.EnvFD+"=3", plumber.EnvLifeline+"=4",
		"HOME="+u.HomeDir, "USER="+u.Username, "LOGNAME="+u.Username)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred, Setsid: true}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting the daemon as %s: %w", runAs, err)
	}
	daemonEnd.Close()
	lifeline.Close()
	c, err := net.FileConn(helperEnd)
	helperEnd.Close()
	if err != nil {
		cmd.Process.Kill()
		return err
	}
	served := make(chan error, 1)
	var destroy func()
	go func() {
		var err error
		destroy, err = plumber.Serve(c.(*net.UnixConn), plumber.FreeBSD{}, int(cred.Uid), func(format string, a ...any) {
			fmt.Fprintf(os.Stderr, "juistd: "+format+"\n", a...)
		})
		served <- err
	}()
	// What the helper made goes once the daemon is gone.
	defer func() {
		if destroy != nil {
			destroy()
		}
	}()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	go func() {
		for s := range sigs {
			// A hangup ends the daemon as a stop does; one that does not
			// stop in time is killed, lest the helper wait for ever.
			if s == syscall.SIGHUP {
				s = syscall.SIGTERM
			}
			cmd.Process.Signal(s)
			time.AfterFunc(stopWait, func() { cmd.Process.Kill() })
		}
	}()
	select {
	case err = <-exited:
		// The daemon's end closed with it, and the helper destroys what it
		// made as it reads that.
		select {
		case serr := <-served:
			logServed(serr)
		case <-time.After(10 * time.Second):
			c.Close()
			logServed(<-served)
		}
	case serr := <-served:
		if serr == nil {
			// The daemon hung up, on its way out.
			err = <-exited
			break
		}
		// The helper stopped serving: the daemon, which could no longer
		// plumb, stops too.
		logServed(serr)
		// Closed first: the daemon's last calls, to destroy its device,
		// would otherwise wait for an answer to the end of their deadline.
		c.Close()
		held.Close()
		cmd.Process.Signal(syscall.SIGTERM)
		time.AfterFunc(stopWait, func() { cmd.Process.Kill() })
		err = <-exited
		if err == nil {
			err = errors.New("the helper stopped serving the daemon")
		}
	}
	return err
}

func logServed(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "juistd: helper: %v\n", err)
	}
}

// inheritedPlumber is the helper that started this daemon, if one did, and
// a channel that closes once that helper is gone.
func inheritedPlumber() (conn.Plumber, <-chan struct{}, error) {
	fd, err := inheritedFD(plumber.EnvFD)
	if fd < 0 || err != nil {
		return nil, nil, err
	}
	c, err := plumber.NewClient(os.NewFile(uintptr(fd), "helper"))
	if err != nil {
		return nil, nil, err
	}
	lfd, err := inheritedFD(plumber.EnvLifeline)
	if lfd < 0 || err != nil {
		c.Close()
		return nil, nil, cmp.Or(err, errors.New("the helper gave no lifeline"))
	}
	lifeline := make(chan struct{})
	go func() {
		io.Copy(io.Discard, os.NewFile(uintptr(lfd), "lifeline"))
		close(lifeline)
	}()
	// A helper gone or one that does not answer: either way the daemon can
	// no longer plumb.
	gone := make(chan struct{})
	go func() {
		select {
		case <-lifeline:
		case <-c.Broken():
		}
		close(gone)
	}()
	return c, gone, nil
}
