//go:build unix

package main

import (
	"io"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// spawnBackground starts juist with args in a session of its own, so that
// closing the terminal ends nothing, writing to this one's stdout and stderr
// until it says on ready that its share is up.
func spawnBackground(args []string) (io.ReadCloser, func() error, func(), error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, nil, err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	defer w.Close()
	cmd := exec.Command(exe, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{w}
	cmd.Env = append(os.Environ(), backgroundEnv+"=3")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		r.Close()
		return nil, nil, nil, err
	}
	return r, cmd.Wait, func() { _ = cmd.Process.Kill() }, nil
}

// backgroundShare is, in the run spawnBackground started, where to say the
// share is up, and how to let go of the terminal then; nil elsewhere.
func backgroundShare() (io.WriteCloser, func()) {
	if os.Getenv(backgroundEnv) != "3" {
		return nil, nil
	}
	os.Unsetenv(backgroundEnv)
	// What it runs, systemctl and the like, does not hold the parent waiting.
	syscall.CloseOnExec(3)
	return os.NewFile(3, "ready"), func() {
		null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		defer null.Close()
		_ = unix.Dup2(int(null.Fd()), 1)
		_ = unix.Dup2(int(null.Fd()), 2)
	}
}
