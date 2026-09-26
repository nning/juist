package rendezvous

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// deaf is a socket that never receives and drops what is sent.
type deaf struct{ closed chan struct{} }

func (d *deaf) ReadFrom([]byte) (int, net.Addr, error) {
	<-d.closed
	return 0, nil, net.ErrClosed
}
func (d *deaf) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (d *deaf) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
	}
	return nil
}
func (d *deaf) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (d *deaf) SetDeadline(time.Time) error        { return nil }
func (d *deaf) SetReadDeadline(t time.Time) error  { return nil }
func (d *deaf) SetWriteDeadline(t time.Time) error { return nil }

// FuzzStreamPackets feeds a stream whatever a stranger on the path could
// send it, interleaved with writes of its own, and checks the bookkeeping
// that bounds its memory and keeps its sequence numbers straight.
func FuzzStreamPackets(f *testing.F) {
	f.Add([]byte{pktData, 0, 0, 0, 0, 'h', 'i', pktAck, 0, 0, 0, 1})
	f.Add([]byte{pktData, 0, 0, 0, 5, 'x', pktData, 0, 0, 0, 0, 'y', pktAck, 0, 0, 0, 0})
	f.Add([]byte{0xff, pktAck, 0xff, 0xff, 0xff, 0xff, pktFin, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		s := newStream(&deaf{closed: make(chan struct{})}, netip.MustParseAddrPort("192.0.2.1:1"), 1)
		defer func() {
			// Not the lingering close, which waits on acknowledgements the
			// deaf socket never brings.
			s.fail(errClosed)
			s.Close()
		}()
		for len(data) >= 5 {
			kind := data[0]
			seq := uint32(data[1])<<24 | uint32(data[2])<<16 | uint32(data[3])<<8 | uint32(data[4])
			data = data[5:]
			n := 0
			if len(data) > 0 {
				n = min(int(data[0]%8), len(data)-1)
				data = data[1:]
			}
			payload := data[:n]
			data = data[n:]
			if kind == 0xff {
				// One of its own writes, where the window allows.
				s.mu.Lock()
				room := len(s.sent) < window
				s.mu.Unlock()
				if room {
					_, _ = s.Write([]byte{byte(seq)})
				}
				continue
			}
			s.mu.Lock()
			s.handle(kind, seq, payload)
			if s.acked > s.next || uint32(len(s.sent)) != s.next-s.acked {
				t.Fatalf("acked %d, next %d, %d segments in flight", s.acked, s.next, len(s.sent))
			}
			if len(s.early) > window || len(s.rbuf) > maxBuffered {
				t.Fatalf("%d early segments, %d buffered bytes", len(s.early), len(s.rbuf))
			}
			for k := range s.early {
				if k <= s.expect || k-s.expect >= window {
					t.Fatalf("early segment %d held at expect %d", k, s.expect)
				}
			}
			s.mu.Unlock()
		}
	})
}

// A peer holding the session id, while the application is not reading (the
// host waiting on an admin), must not grow what the stream holds: a segment
// held early and then skipped, because the buffer was full when its turn
// came, is let go once the stream moves past it.
func TestSkippedEarlySegmentsAreLetGo(t *testing.T) {
	s := newStream(&deaf{closed: make(chan struct{})}, netip.MustParseAddrPort("192.0.2.1:1"), 1)
	defer func() {
		s.fail(errClosed)
		s.Close()
	}()
	big := make([]byte, maxSegment)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rbuf = make([]byte, maxBuffered-2*len(big)+1)
	for range 1000 {
		s.handle(pktData, s.expect+1, big)     // held early
		s.handle(pktData, s.expect, []byte{1}) // its turn; it does not fit
		s.handle(pktData, s.expect, []byte{1}) // and the stream moves past it
		s.rbuf = s.rbuf[:len(s.rbuf)-2]
	}
	if len(s.early) > 1 {
		t.Fatalf("%d early segments held after the stream moved past them", len(s.early))
	}
}

// counting is a socket that never answers and counts what is sent.
type counting struct {
	deaf
	sent atomic.Int64
}

func (c *counting) WriteTo(b []byte, _ net.Addr) (int, error) { c.sent.Add(1); return len(b), nil }

// Unanswered, a stream sends its window less and less often, so an address
// a stranger pointed it at does not get it every few hundred milliseconds
// for as long as the session lasts.
func TestAnUnansweredWindowBacksOff(t *testing.T) {
	c := &counting{deaf: deaf{closed: make(chan struct{})}}
	s := newStream(c, netip.MustParseAddrPort("192.0.2.1:1"), 1)
	defer func() {
		s.fail(errClosed)
		s.Close()
	}()
	if _, err := s.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * time.Second)
	// At a fixed 400 ms it would be ten sends; backing off, four or so.
	if n := c.sent.Load(); n > 6 {
		t.Fatalf("an unanswered segment was sent %d times in 4s", n)
	}
}
