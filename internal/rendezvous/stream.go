package rendezvous

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// The wire format on a punched path. Every packet names the session, a random
// id the two sides agreed through the DHT, so a stray datagram on the port is
// ignored rather than read. Nothing here is authenticated: the enrollment
// protocol running over the stream is, so an injected packet can break a
// session, as a rewritten TCP segment could, but not admit anyone. A stream
// carries only link sessions, and a bad link confirmation voids nothing.
//
// A stream follows its peer to wherever the last packet of the session came
// from, as WireGuard follows a roaming peer. Each side takes the first path
// it hears on, and the two need not pick the same pair of addresses — one may
// hear the other's LAN address first, the other its public one — so a stream
// bound to its first address could drop everything the peer sends. Following
// costs nothing an address check would have bought: the session id is known
// only to holders of the link and to whoever is on the path, and the latter
// could as well rewrite a TCP connection.
const (
	pktPunch byte = 1 // also the keepalive
	pktData  byte = 2
	pktAck   byte = 3
	pktFin   byte = 4

	headerLen  = 1 + 4 + 4
	maxSegment = 1100 // fits any path MTU a UDP datagram will cross

	window       = 64
	retransmitIn = 400 * time.Millisecond
	maxRTO       = 8 * time.Second
	tick         = 100 * time.Millisecond
	keepaliveIn  = 10 * time.Second
	peerSilence  = 90 * time.Second
	maxBuffered  = 8 << 20
)

var errClosed = errors.New("rendezvous: the stream is closed")

func packet(kind byte, id, seq uint32, payload []byte) []byte {
	b := make([]byte, headerLen, headerLen+len(payload))
	b[0] = kind
	binary.BigEndian.PutUint32(b[1:5], id)
	binary.BigEndian.PutUint32(b[5:9], seq)
	return append(b, payload...)
}

func parsePacket(b []byte) (kind byte, id, seq uint32, payload []byte, ok bool) {
	if len(b) < headerLen {
		return 0, 0, 0, nil, false
	}
	return b[0], binary.BigEndian.Uint32(b[1:5]), binary.BigEndian.Uint32(b[5:9]), b[headerLen:], true
}

// A stream is a reliable, ordered byte stream to one peer over a UDP socket
// it owns: a fixed window and cumulative acknowledgements, with the receiver
// holding segments that arrive early and the sender resending the first
// missing one on a third duplicate acknowledgement, as TCP's NewReno does. It
// has no congestion control beyond the window, which an enrollment's few
// hundred kilobytes do not need.
type stream struct {
	pc net.PacketConn
	id uint32

	mu      sync.Mutex
	peer    *net.UDPAddr // where the session was last heard from
	cond    *sync.Cond
	next    uint32   // sequence number the next segment gets
	acked   uint32   // every segment below this is acknowledged
	sent    [][]byte // segments acked..next-1, as sent
	last    time.Time
	rto     time.Duration // the wait before the window is sent again
	dups    int           // duplicate acknowledgements of acked in a row
	repair  uint32        // while nonzero, a loss is being repaired up to here
	expect  uint32
	early   map[uint32][]byte // segments past a gap, held until it fills
	rbuf    []byte
	fin     bool
	err     error
	closing bool // a Close is waiting for the last acknowledgements
	closed  bool
	heard   time.Time

	readDeadline, writeDeadline time.Time
	done                        chan struct{}
}

// newStream starts a stream on a socket already punched to peer.
func newStream(pc net.PacketConn, peer netip.AddrPort, id uint32) *stream {
	s := &stream{pc: pc, peer: net.UDPAddrFromAddrPort(peer), id: id, heard: time.Now(),
		early: make(map[uint32][]byte), done: make(chan struct{})}
	s.cond = sync.NewCond(&s.mu)
	go s.readLoop()
	go s.timerLoop()
	return s
}

// send writes one packet to the peer, with s.mu held.
func (s *stream) send(kind byte, seq uint32, payload []byte) {
	_, _ = s.pc.WriteTo(packet(kind, s.id, seq, payload), s.peer)
}

func (s *stream) readLoop() {
	buf := make([]byte, 64<<10)
	for {
		n, from, err := s.pc.ReadFrom(buf)
		if err != nil {
			s.fail(err)
			return
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		kind, id, seq, payload, ok := parsePacket(buf[:n])
		if !ok || id != s.id {
			continue
		}
		s.mu.Lock()
		// Followed only to where a punch could go: a stranger holding the
		// session id cannot point the stream at loopback or a group.
		if (!ua.IP.Equal(s.peer.IP) || ua.Port != s.peer.Port) && punchable(ua.AddrPort()) {
			s.peer = ua
		}
		s.handle(kind, seq, payload)
		s.mu.Unlock()
	}
}

// handle takes one packet of the session, with s.mu held.
func (s *stream) handle(kind byte, seq uint32, payload []byte) {
	s.heard = time.Now()
	switch kind {
	case pktData:
		s.receive(seq, payload)
		// A duplicate or a gap is answered with where the stream is,
		// which is what tells the sender what is missing.
		s.send(pktAck, s.expect, nil)
	case pktAck:
		s.acknowledged(seq)
	case pktPunch:
		// The peer is still punching: it has not heard from this side
		// yet, and a reply is what tells it the path is open.
		if seq == 0 {
			s.send(pktPunch, 1, nil)
		}
	case pktFin:
		s.fin = true
		s.cond.Broadcast()
	}
}

// receive takes a data segment, with s.mu held.
//
// What it holds for later is bounded by the window: an empty or oversized
// segment is not one a sender of this package writes and is dropped, and the
// early map loses every entry the stream has moved past, so a peer that
// knows the session id cannot grow it by sending segments the stream then
// skips.
func (s *stream) receive(seq uint32, payload []byte) {
	if len(payload) == 0 || len(payload) > maxSegment {
		return
	}
	switch {
	case seq == s.expect:
		if len(s.rbuf)+len(payload) > maxBuffered {
			return // the reader is behind; the sender will resend
		}
		s.rbuf = append(s.rbuf, payload...)
		s.expect++
		for {
			seg, ok := s.early[s.expect]
			if !ok || len(s.rbuf)+len(seg) > maxBuffered {
				break
			}
			delete(s.early, s.expect)
			s.rbuf = append(s.rbuf, seg...)
			s.expect++
		}
		for k := range s.early {
			if k < s.expect || k-s.expect >= window {
				delete(s.early, k)
			}
		}
		s.cond.Broadcast()
	case seq > s.expect && seq-s.expect < window:
		if _, ok := s.early[seq]; !ok {
			s.early[seq] = bytes.Clone(payload)
		}
	}
}

// acknowledged takes a cumulative acknowledgement, with s.mu held.
func (s *stream) acknowledged(seq uint32) {
	switch {
	case seq > s.acked && seq <= s.next:
		s.sent = s.sent[seq-s.acked:]
		s.acked = seq
		s.dups = 0
		s.last = time.Now()
		s.rto = retransmitIn
		// A partial acknowledgement during a repair points at the next
		// segment lost from the same window.
		if s.repair != 0 && seq < s.repair && len(s.sent) > 0 {
			s.send(pktData, s.acked, s.sent[0])
		} else {
			s.repair = 0
		}
		s.cond.Broadcast()
	case seq == s.acked && len(s.sent) > 0:
		s.dups++
		if s.dups == 3 && s.repair == 0 {
			s.repair = s.next
			s.send(pktData, s.acked, s.sent[0])
			s.last = time.Now()
		}
	}
}

func (s *stream) timerLoop() {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-t.C:
			s.mu.Lock()
			switch {
			case now.Sub(s.heard) > peerSilence:
				s.err = errors.New("rendezvous: the peer went silent")
			case len(s.sent) > 0 && now.Sub(s.last) > max(s.rto, retransmitIn):
				for i, seg := range s.sent {
					s.send(pktData, s.acked+uint32(i), seg)
				}
				s.last, s.dups, s.repair = now, 0, 0
				// Unanswered, the window is sent less and less often: to a
				// peer that is gone, or to an address a stranger pointed the
				// stream at, it would otherwise be sent every tick for as
				// long as the session lasts.
				s.rto = min(2*max(s.rto, retransmitIn), maxRTO)
			case now.Sub(s.last) > keepaliveIn:
				s.send(pktPunch, 0, nil)
				s.last = now
			}
			// Wakes waiters so they notice deadlines, which a condition
			// variable cannot time out on by itself.
			s.cond.Broadcast()
			s.mu.Unlock()
		}
	}
}

func (s *stream) fail(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.cond.Broadcast()
	s.mu.Unlock()
}

func past(deadline time.Time) bool { return !deadline.IsZero() && time.Now().After(deadline) }

func (s *stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.rbuf) == 0 {
		switch {
		case s.closed:
			return 0, errClosed
		case s.fin:
			return 0, io.EOF
		case s.err != nil:
			return 0, s.err
		case past(s.readDeadline):
			return 0, os.ErrDeadlineExceeded
		}
		s.cond.Wait()
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}

func (s *stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	written := 0
	for written < len(p) {
		for len(s.sent) >= window {
			switch {
			case s.closed:
				return written, errClosed
			case s.err != nil:
				return written, s.err
			case past(s.writeDeadline):
				return written, os.ErrDeadlineExceeded
			}
			s.cond.Wait()
		}
		if s.closed {
			return written, errClosed
		}
		if s.err != nil {
			return written, s.err
		}
		n := min(maxSegment, len(p)-written)
		seg := append([]byte(nil), p[written:written+n]...)
		if len(s.sent) == 0 {
			s.last = time.Now()
		}
		s.sent = append(s.sent, seg)
		s.send(pktData, s.next, seg)
		s.next++
		written += n
	}
	return written, nil
}

// Close ends the stream once what was written has been acknowledged, or
// after a few seconds, and releases the socket.
//
// Only the first call does that; one made while it waits returns at once,
// since the wait releases the lock and two teardowns would close done twice.
func (s *stream) Close() error {
	s.mu.Lock()
	if s.closed || s.closing {
		s.mu.Unlock()
		return nil
	}
	s.closing = true
	deadline := time.Now().Add(3 * time.Second)
	for len(s.sent) > 0 && s.err == nil && time.Now().Before(deadline) {
		s.cond.Wait()
	}
	s.closed = true
	for range 3 {
		s.send(pktFin, 0, nil)
	}
	s.cond.Broadcast()
	s.mu.Unlock()
	close(s.done)
	return s.pc.Close()
}

func (s *stream) LocalAddr() net.Addr { return s.pc.LocalAddr() }
func (s *stream) RemoteAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peer
}

func (s *stream) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline, s.writeDeadline = t, t
	s.mu.Unlock()
	return nil
}

func (s *stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.mu.Unlock()
	return nil
}

func (s *stream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.writeDeadline = t
	s.mu.Unlock()
	return nil
}

var _ net.Conn = (*stream)(nil)
