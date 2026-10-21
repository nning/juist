package daemon

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

// listenOverlay listens for gossip on this device's overlay addresses only,
// so log sync is reachable through the tunnel and from nowhere else. An
// address that cannot be bound is skipped, as the IPv6 half is where the host
// lacks IPv6; none at all is an error.
func listenOverlay(addrs []netip.Prefix, port uint16) (net.Listener, error) {
	return asListener(listenEach(func(ap netip.AddrPort) (net.Listener, error) { return net.Listen("tcp", ap.String()) }, addrs, port))
}

// asListener is m as a net.Listener, nil where it is.
func asListener(m *multiListener, err error) (net.Listener, error) {
	if err != nil {
		return nil, err
	}
	return m, nil
}

// listenEach is listenOverlay by listen.
func listenEach(listen func(netip.AddrPort) (net.Listener, error), addrs []netip.Prefix, port uint16) (*multiListener, error) {
	var slots []*slot
	var errs []error
	for _, p := range addrs {
		ap := netip.AddrPortFrom(p.Addr(), port)
		ln, err := listen(ap)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if port == 0 {
			// Every address on one port, the one the announcement names.
			port = uint16(portOf(ln.Addr()))
			ap = netip.AddrPortFrom(p.Addr(), port)
		}
		slots = append(slots, &slot{at: ap, ln: ln})
	}
	if len(slots) == 0 {
		return nil, fmt.Errorf("listening on the overlay addresses: %w", errors.Join(errs...))
	}
	m := &multiListener{lns: slots, listen: listen, port: port, conns: make(chan net.Conn),
		errs: make(chan error, len(slots)), closed: make(chan struct{})}
	m.start()
	return m, nil
}

// How long a listener waits after a failed accept, at first and at most,
// and at most before it tries again to bind an address rebind could not.
const (
	acceptRetry    = 50 * time.Millisecond
	acceptRetryMax = time.Second
	bindRetryMax   = 30 * time.Second
)

// A multiListener accepts from several listeners as one.
type multiListener struct {
	conns  chan net.Conn
	errs   chan error
	closed chan struct{}
	once   sync.Once

	// listen opens a listener at an address, for one taken down and for
	// rebind, nil for never; port is the one every address shares.
	listen func(netip.AddrPort) (net.Listener, error)
	port   uint16

	mu  sync.Mutex
	lns []*slot
}

// A slot is one listener of a multiListener's, and where it listens.
type slot struct {
	at   netip.AddrPort
	ln   net.Listener // nil until it could be bound
	gone bool         // rebind dropped it, under the multiListener's mu
}

func (m *multiListener) start() {
	for _, s := range m.lns {
		go m.accept(s)
	}
}

// accept takes s's connections. An accept that fails is reported, and
// accepting goes on: an error such as running out of descriptors passes, and
// a listener that stopped here would end log sync for good. A listener the
// system took down, as Android destroys the sockets of a VPN device it
// replaces, fails with EINVAL from then on, and is opened again.
func (m *multiListener) accept(s *slot) {
	wait := acceptRetry
	for {
		m.mu.Lock()
		ln, gone := s.ln, s.gone
		m.mu.Unlock()
		if gone {
			return
		}
		if ln == nil {
			select {
			case <-m.closed:
				return
			case <-time.After(wait):
			}
			wait = min(2*wait, bindRetryMax)
			if nl, err := m.listen(s.at); err == nil {
				m.mu.Lock()
				if s.gone || m.isClosed() {
					nl.Close()
				} else {
					s.ln, wait = nl, acceptRetry
				}
				m.mu.Unlock()
			}
			continue
		}
		c, err := ln.Accept()
		if err != nil {
			closed := errors.Is(err, net.ErrClosed)
			m.mu.Lock()
			gone = s.gone
			m.mu.Unlock()
			if gone || closed && m.listen == nil {
				return
			}
			if !closed {
				select {
				case m.errs <- err:
				default:
				}
			}
			select {
			case <-m.closed:
				return
			case <-time.After(wait):
			}
			wait = min(2*wait, acceptRetryMax)
			// Closed, where a reopen failed, or taken down.
			if m.listen != nil && (closed || errors.Is(err, syscall.EINVAL)) {
				m.replace(s, ln)
			}
			continue
		}
		wait = acceptRetry
		select {
		case m.conns <- c:
		case <-m.closed:
			c.Close()
			return
		}
	}
}

// replace listens again in place of ln, s's listener, unless the
// multiListener closed or dropped s meanwhile. Where it cannot, ln stays
// closed, and the next accept tries again.
func (m *multiListener) replace(s *slot, ln net.Listener) {
	ln.Close()
	nl, err := m.listen(s.at)
	if err != nil {
		select {
		case m.errs <- fmt.Errorf("listening again: %w", err):
		default:
		}
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-m.closed:
		nl.Close()
	default:
		if s.gone {
			nl.Close()
			return
		}
		s.ln = nl
	}
}

// rebind listens at addrs on the shared port, opening the new ones before it
// closes those no longer named. One that cannot be opened yet is reported,
// and tried again until it can.
func (m *multiListener) rebind(addrs []netip.Prefix) error {
	if m.listen == nil {
		return errors.New("this listener cannot listen elsewhere")
	}
	m.mu.Lock()
	have := map[netip.AddrPort]bool{}
	for _, s := range m.lns {
		have[s.at] = true
	}
	m.mu.Unlock()
	want := map[netip.AddrPort]bool{}
	var added []*slot
	var errs []error
	for _, p := range addrs {
		ap := netip.AddrPortFrom(p.Addr(), m.port)
		want[ap] = true
		if have[ap] {
			continue
		}
		ln, err := m.listen(ap)
		if err != nil {
			errs = append(errs, err)
		}
		added = append(added, &slot{at: ap, ln: ln})
	}
	m.mu.Lock()
	select {
	case <-m.closed:
		m.mu.Unlock()
		for _, s := range added {
			if s.ln != nil {
				s.ln.Close()
			}
		}
		return net.ErrClosed
	default:
	}
	var kept []*slot
	for _, s := range m.lns {
		if want[s.at] {
			kept = append(kept, s)
			continue
		}
		s.gone = true
		if s.ln != nil {
			s.ln.Close()
		}
	}
	m.lns = append(kept, added...)
	m.mu.Unlock()
	for _, s := range added {
		go m.accept(s)
	}
	return errors.Join(errs...)
}

func (m *multiListener) Accept() (net.Conn, error) {
	select {
	case c := <-m.conns:
		return c, nil
	case err := <-m.errs:
		return nil, err
	case <-m.closed:
		return nil, net.ErrClosed
	}
}

func (m *multiListener) Close() error {
	var err error
	m.once.Do(func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		close(m.closed)
		for _, s := range m.lns {
			if s.ln != nil {
				err = errors.Join(err, s.ln.Close())
			}
		}
	})
	return err
}

// Addr is the first listener's: every one shares the port.
func (m *multiListener) Addr() net.Addr {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.lns {
		if s.ln != nil {
			return s.ln.Addr()
		}
	}
	return &net.TCPAddr{Port: int(m.port)}
}

// isClosed reports whether Close ran.
func (m *multiListener) isClosed() bool {
	select {
	case <-m.closed:
		return true
	default:
		return false
	}
}
