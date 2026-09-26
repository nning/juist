//go:build darwin || freebsd || netbsd || openbsd

package main

import "golang.org/x/sys/unix"

const ioctlGetTermios = unix.TIOCGETA

// fread is FREAD from <sys/fcntl.h>, the same on every BSD and missing from
// x/sys/unix on some: TIOCFLUSH with it discards the input queue only.
const fread = 0x1

// flushInput discards what was typed but not yet read, so that a key pressed
// before a question was asked is not taken as its answer.
func flushInput(fd int) { _ = unix.IoctlSetPointerInt(fd, unix.TIOCFLUSH, fread) }
