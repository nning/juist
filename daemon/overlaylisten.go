package daemon

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
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
	var errs []error
	for _, p := range addrs {
		ln, err := listen(netip.AddrPortFrom(p.Addr(), port))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		lns = append(lns, ln)
		if port == 0 {
			// Every address on one port, the one the announcement names.
			port = uint16(portOf(ln.Addr()))
		}
	}
	if len(lns) == 0 {
		return nil, fmt.Errorf("listening on the overlay addresses: %w", errors.Join(errs...))
	}
	return newMultiListener(lns), nil
}

// acceptRetry is how long a listener waits after a failed accept.
const acceptRetry = 50 * time.Millisecond

// A multiListener accepts from several listeners as one.
type multiListener struct {
	lns    []net.Listener
	conns  chan net.Conn
	errs   chan error
	closed chan struct{}
	once   sync.Once
}

func newMultiListener(lns []net.Listener) *multiListener {
	m := &multiListener{lns: lns, conns: make(chan net.Conn), errs: make(chan error, len(lns)),
		closed: make(chan struct{})}
	for _, ln := range lns {
		go func() {
			for {
				c, err := ln.Accept()
				if errors.Is(err, net.ErrClosed) {
					return
				}
				if err != nil {
					// Reported, and accepting goes on: an error such as
					// running out of descriptors passes, and a listener
					// that stopped here would end log sync for good.
					select {
					case m.errs <- err:
					default:
					}
					select {
					case <-m.closed:
						return
					case <-time.After(acceptRetry):
					}
					continue
				}
				select {
				case m.conns <- c:
				case <-m.closed:
					c.Close()
					return
				}
			}
		}()
	}
	return m
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
		close(m.closed)
		for _, ln := range m.lns {
			err = errors.Join(err, ln.Close())
		}
	})
	return err
}

// Addr is the first listener's: every one shares the port.
func (m *multiListener) Addr() net.Addr { return m.lns[0].Addr() }
