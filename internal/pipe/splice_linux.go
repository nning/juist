package pipe

import (
	"errors"
	"net"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// spliceMax bounds what one splice takes, as io.Copy's does.
const spliceMax = 1 << 20

// splice copies src to dst within the kernel where both are TCP, marking
// moved as data goes: rerr is src's failure, werr dst's. Where it does not
// run, or stops for want of a pipe, ok is false and the rest is the
// caller's to copy.
func splice(dst, src net.Conn, moved *atomic.Bool) (rerr, werr error, ok bool) {
	d, dok := dst.(*net.TCPConn)
	s, sok := src.(*net.TCPConn)
	if !dok || !sok {
		return nil, nil, false
	}
	rc, err := s.SyscallConn()
	if err != nil {
		return nil, nil, false
	}
	wc, err := d.SyscallConn()
	if err != nil {
		return nil, nil, false
	}
	var peek [1]byte
	for {
		// Readable, or ended, before a pipe is taken: a quiet way holds none.
		var perr error
		if err := rc.Read(func(fd uintptr) bool {
			_, _, perr = unix.Recvfrom(int(fd), peek[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
			return !errors.Is(perr, unix.EAGAIN)
		}); err != nil {
			return err, nil, true
		}
		if errors.Is(perr, unix.EINTR) {
			continue
		}
		if perr != nil {
			// The peek took the socket's error, which the splice after
			// would not see: a reset read as an end.
			return perr, nil, true
		}
		var p [2]int
		if err := unix.Pipe2(p[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
			return nil, nil, false
		}
		rerr, werr, done := burst(wc, rc, p, moved)
		unix.Close(p[0])
		unix.Close(p[1])
		if done {
			return rerr, werr, true
		}
	}
}

// burst splices from rc through the pipe p to wc until rc would block, or
// done, as rc ended or either failed.
func burst(wc, rc interface {
	Read(func(uintptr) bool) error
	Write(func(uintptr) bool) error
}, p [2]int, moved *atomic.Bool) (rerr, werr error, done bool) {
	for {
		var n int64
		var serr error
		err := rc.Read(func(fd uintptr) bool {
			n, serr = unix.Splice(int(fd), nil, p[1], nil, spliceMax, unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
			return true
		})
		err = errors.Join(err, serr)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			return nil, nil, false
		case err != nil:
			return err, nil, true
		case n == 0:
			return nil, nil, true
		}
		moved.Store(true)
		for n > 0 {
			var m int64
			var werr error
			err := wc.Write(func(fd uintptr) bool {
				m, werr = unix.Splice(p[0], nil, int(fd), nil, int(n), unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
				return !errors.Is(werr, unix.EAGAIN)
			})
			err = errors.Join(err, werr)
			switch {
			case errors.Is(err, unix.EINTR):
				continue
			case err != nil:
				return nil, err, true
			}
			n -= m
		}
		moved.Store(true)
	}
}
