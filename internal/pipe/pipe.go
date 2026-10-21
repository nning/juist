// Package pipe joins two connections and keeps what joins them bounded.
package pipe

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Join copies a to b and b to a until both ways end, or the connection
// idles both ways for idle, or ctx ends; then it closes both. Either way
// moving keeps it alive, as a download whose client says nothing. A way
// whose source fails, rather than ends, ends both; one that cannot write
// leaves its destination alone, so that what the other way carries still
// arrives.
func Join(ctx context.Context, a, b net.Conn, idle time.Duration) {
	closeBoth := func() { a.Close(); b.Close() }
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	defer closeBoth()
	// Each way says it moved, and the check below what time that was.
	var moved [2]atomic.Bool
	done := make(chan struct{}, 2)
	half := func(dst, src net.Conn, moved *atomic.Bool) {
		rerr, werr, ok := splice(dst, src, moved)
		if !ok {
			r := &reading{Reader: active{src, moved}}
			werr = copyAdaptive(active{dst, moved}, r)
			rerr = r.err
		}
		switch cw, ok := dst.(interface{ CloseWrite() error }); {
		case rerr != nil:
			closeBoth()
		case werr != nil: // dst failed
			// FreeBSD disconnects a socket shut for writing a second time.
		case ok:
			_ = cw.CloseWrite()
		default:
			dst.Close()
		}
		done <- struct{}{}
	}
	go half(b, a, &moved[0])
	go half(a, b, &moved[1])
	check := time.NewTicker(max(idle/4, 10*time.Millisecond))
	defer check.Stop()
	last := time.Now()
	for ended := 0; ended < 2; {
		select {
		case <-done:
			ended++
		case now := <-check.C:
			if a, b := moved[0].Swap(false), moved[1].Swap(false); a || b {
				last = now
			} else if now.Sub(last) > idle {
				closeBoth()
			}
		}
	}
}

// Buffer sizes: a quiet connection waits on a small one, and a burst, a read
// that fills it, moves on a large one from the pool until a read falls short.
const (
	smallBuf = 2 << 10
	largeBuf = 32 << 10
)

var largeBufs = sync.Pool{New: func() any { return new([largeBuf]byte) }}

// copyAdaptive copies src to dst as io.Copy does, holding a large buffer only
// while data comes faster than a small one takes it.
func copyAdaptive(dst io.Writer, src io.Reader) error {
	var small [smallBuf]byte
	for {
		n, err := src.Read(small[:])
		if werr := writeAll(dst, small[:n]); werr != nil {
			return werr
		}
		if err != nil {
			return ignoreEOF(err)
		}
		if n < len(small) {
			continue
		}
		large := largeBufs.Get().(*[largeBuf]byte)
		for {
			n, err = src.Read(large[:])
			if werr := writeAll(dst, large[:n]); werr != nil {
				largeBufs.Put(large)
				return werr
			}
			if err != nil || n < len(large) {
				break
			}
		}
		largeBufs.Put(large)
		if err != nil {
			return ignoreEOF(err)
		}
	}
}

func writeAll(w io.Writer, p []byte) error {
	if len(p) == 0 {
		return nil
	}
	n, err := w.Write(p)
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	return err
}

func ignoreEOF(err error) error {
	if err == io.EOF {
		return nil
	}
	return err
}

// reading keeps the error a read failed with, other than the end.
type reading struct {
	io.Reader
	err error
}

func (r *reading) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err != nil && err != io.EOF {
		r.err = err
	}
	return n, err
}

// active notes that a connection moved.
type active struct {
	net.Conn
	moved *atomic.Bool
}

func (c active) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.moved.Store(true)
	}
	return n, err
}

func (c active) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.moved.Store(true)
	}
	return n, err
}
