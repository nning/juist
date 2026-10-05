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
	return listenEach(func(ap netip.AddrPort) (net.Listener, error) { return net.Listen("tcp", ap.String()) }, addrs, port)
}

// listenEach is listenOverlay by listen.
func listenEach(listen func(netip.AddrPort) (net.Listener, error), addrs []netip.Prefix, port uint16) (net.Listener, error) {
	var lns []net.Listener
	var aps []netip.AddrPort
	var errs []error
	for _, p := range addrs {
		ap := netip.AddrPortFrom(p.Addr(), port)
		ln, err := listen(ap)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		lns = append(lns, ln)
		if port == 0 {
			// Every address on one port, the one the announcement names.
			port = uint16(portOf(ln.Addr()))
		}
		aps = append(aps, netip.AddrPortFrom(p.Addr(), port))
	}
	if len(lns) == 0 {
		return nil, fmt.Errorf("listening on the overlay addresses: %w", errors.Join(errs...))
	}
	m := newMultiListener(lns)
	m.reopen = func(i int) (net.Listener, error) { return listen(aps[i]) }
	m.start()
	return m, nil
}

// How long a listener waits after a failed accept, at first and at most.
const (
	acceptRetry    = 50 * time.Millisecond
	acceptRetryMax = time.Second
)

// A multiListener accepts from several listeners as one.
type multiListener struct {
	conns  chan net.Conn
	errs   chan error
	closed chan struct{}
	once   sync.Once

	// reopen listens again in place of listener i, nil for never.
	reopen func(i int) (net.Listener, error)

	mu  sync.Mutex
	lns []net.Listener
}

// newMultiListener accepts from lns once started.
func newMultiListener(lns []net.Listener) *multiListener {
	return &multiListener{lns: lns, conns: make(chan net.Conn), errs: make(chan error, len(lns)),
		closed: make(chan struct{})}
}

func (m *multiListener) start() {
	for i := range m.lns {
		go m.accept(i)
	}
}

// accept takes listener i's connections. An accept that fails is reported, and
// accepting goes on: an error such as running out of descriptors passes, and
// a listener that stopped here would end log sync for good. A listener the
// system took down, as Android destroys the sockets of a VPN device it
// replaces, fails with EINVAL from then on, and is opened again.
func (m *multiListener) accept(i int) {
	wait := acceptRetry
	for {
		m.mu.Lock()
		ln := m.lns[i]
		m.mu.Unlock()
		c, err := ln.Accept()
		if err != nil {
			gone := errors.Is(err, net.ErrClosed)
			if gone && m.reopen == nil {
				return
			}
			if !gone {
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
			if m.reopen != nil && (gone || errors.Is(err, syscall.EINVAL)) {
				m.replace(i, ln)
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

// replace listens again in place of ln, listener i, unless the multiListener
// closed meanwhile. Where it cannot, ln stays closed, and the next accept
// tries again.
func (m *multiListener) replace(i int, ln net.Listener) {
	ln.Close()
	nl, err := m.reopen(i)
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
		m.lns[i] = nl
	}
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
		for _, ln := range m.lns {
			err = errors.Join(err, ln.Close())
		}
	})
	return err
}

// Addr is the first listener's: every one shares the port.
func (m *multiListener) Addr() net.Addr {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lns[0].Addr()
}
