package relay

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/time/rate"
	"tailscale.com/net/stun"
	"tailscale.com/types/logger"

	"github.com/nning/juist/internal/admit"
)

// stunResponder answers STUN binding requests, so a member learns its own
// reflexive address from another member rather than from a public STUN server.
// That is what [docs/04-architecture.md] means by member disco reflection
// being primary.
//
// It is open by construction: a binding request carries no identity, so this
// cannot be membership-authenticated the way DERP is. What it discloses is the
// querier's own address, back to the querier.
type stunResponder struct {
	v4, v6 *stunSocket
	logf   logger.Logf

	// answers bounds the reply rate in all, and perSource from one host. A
	// binding response is about twice its request, so an open responder is a
	// weak reflector; the caps are far above what netcheck asks of one relay
	// and low enough that the reflector is not worth using, and one host's
	// flood does not spend the others' answers.
	answers *rate.Limiter

	perSource *admit.Rates[netip.Prefix]

	mu     sync.Mutex // guards closed
	closed bool
}

const (
	// stunAnswersPerSecond is the sustained answer rate, and stunBurst the
	// depth. A member's netcheck asks a few times per five minutes.
	stunAnswersPerSecond = 200
	stunBurst            = 400

	// stunPerSource is one host's sustained answer rate, its burst twice
	// that, and stunSources the hosts tracked; past them the host seen
	// longest ago starts over, and the rate in all still bounds a flood from
	// spoofed sources.
	stunPerSource = 20
	stunSources   = 4096
)

// listenSTUN binds the responder on both families. port zero picks one, and
// the second family is bound at whatever the first got: a relay announces one
// port, so the two must agree. A family that will not bind is logged and left
// out rather than failing the relay.
func listenSTUN(port uint16, logf logger.Logf) (*stunResponder, error) {
	s := &stunResponder{logf: logf, answers: rate.NewLimiter(stunAnswersPerSecond, stunBurst),
		perSource: newSTUNRates()}
	v4, err := listenSTUNFamily("udp4", port, logf)
	if err != nil {
		return nil, err
	}
	s.v4 = v4
	if port == 0 {
		port = v4.port()
	}
	if v6, err := listenSTUNFamily("udp6", port, logf); err != nil {
		logf("relay: no IPv6 STUN responder: %v", err)
	} else {
		s.v6 = v6
	}
	go s.serve(s.v4)
	if s.v6 != nil {
		go s.serve(s.v6)
	}
	return s, nil
}

// stunSocket is one family's socket, told to report which of this host's
// addresses each request arrived at.
//
// That is the whole reason this is not a plain UDPConn. A wildcard socket
// replies from whichever source the route table picks, which on a multi-homed
// relay is often not the address the request was sent to — and a reply from an
// address the querier never wrote to is dropped by its own NAT, so the answer
// is lost exactly for the querier who most needed it.
type stunSocket struct {
	uc *net.UDPConn
	p4 *ipv4.PacketConn
	p6 *ipv6.PacketConn
}

func listenSTUNFamily(network string, port uint16, logf logger.Logf) (*stunSocket, error) {
	uc, err := net.ListenUDP(network, &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, fmt.Errorf("relay: binding %s port %d for STUN: %w", network, port, err)
	}
	s := &stunSocket{uc: uc}
	if network == "udp4" {
		s.p4 = ipv4.NewPacketConn(uc)
		if err := s.p4.SetControlMessage(ipv4.FlagDst, true); err != nil {
			// Answering from the wrong address is better than not answering,
			// and on a single-homed host the two are the same address.
			logf("relay: STUN replies may use the wrong source address: %v", err)
			s.p4 = nil
		}
		return s, nil
	}
	s.p6 = ipv6.NewPacketConn(uc)
	if err := s.p6.SetControlMessage(ipv6.FlagDst, true); err != nil {
		logf("relay: STUN replies may use the wrong source address: %v", err)
		s.p6 = nil
	}
	return s, nil
}

func (s *stunSocket) port() uint16 {
	if ua, ok := s.uc.LocalAddr().(*net.UDPAddr); ok {
		return uint16(ua.Port)
	}
	return 0
}

// read returns one datagram, the address it came from, and the address of
// this host it was sent to, which is zero where the socket could not be told
// to report it.
func (s *stunSocket) read(buf []byte) (n int, from netip.AddrPort, to netip.Addr, err error) {
	switch {
	case s.p4 != nil:
		n, cm, src, err := s.p4.ReadFrom(buf)
		if err != nil {
			return 0, netip.AddrPort{}, netip.Addr{}, err
		}
		if cm != nil {
			to, _ = netip.AddrFromSlice(cm.Dst)
		}
		return n, addrPortOf(src), to.Unmap(), nil
	case s.p6 != nil:
		n, cm, src, err := s.p6.ReadFrom(buf)
		if err != nil {
			return 0, netip.AddrPort{}, netip.Addr{}, err
		}
		if cm != nil {
			to, _ = netip.AddrFromSlice(cm.Dst)
		}
		return n, addrPortOf(src), to, nil
	}
	n, src, err := s.uc.ReadFromUDPAddrPort(buf)
	if err != nil {
		return 0, netip.AddrPort{}, netip.Addr{}, err
	}
	return n, netip.AddrPortFrom(src.Addr().Unmap(), src.Port()), netip.Addr{}, nil
}

// write sends a reply, from the address the request arrived at where that is
// known.
func (s *stunSocket) write(b []byte, to netip.AddrPort, from netip.Addr) error {
	dst := net.UDPAddrFromAddrPort(to)
	switch {
	case s.p4 != nil:
		var cm *ipv4.ControlMessage
		if from.Is4() {
			cm = &ipv4.ControlMessage{Src: from.AsSlice()}
		}
		_, err := s.p4.WriteTo(b, cm, dst)
		return err
	case s.p6 != nil:
		var cm *ipv6.ControlMessage
		if from.Is6() {
			cm = &ipv6.ControlMessage{Src: from.AsSlice()}
		}
		_, err := s.p6.WriteTo(b, cm, dst)
		return err
	}
	_, err := s.uc.WriteToUDPAddrPort(b, to)
	return err
}

func (s *stunSocket) close() { s.uc.Close() }

func addrPortOf(a net.Addr) netip.AddrPort {
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	ap := ua.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// port reports where the responder answers. Both families share it.
func (s *stunResponder) port() uint16 { return s.v4.port() }

func (s *stunResponder) close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.v4.close()
	if s.v6 != nil {
		s.v6.close()
	}
}

func (s *stunResponder) serve(sock *stunSocket) {
	buf := make([]byte, 1500)
	for {
		n, from, to, err := sock.read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			s.logf("relay: STUN read: %v", err)
			continue
		}
		pkt := buf[:n]
		if !stun.Is(pkt) {
			continue
		}
		txid, err := stun.ParseBindingRequest(pkt)
		if err != nil {
			continue
		}
		if !s.allow(from.Addr()) {
			continue
		}
		if err := sock.write(stun.Response(txid, from), from, to); err != nil {
			s.logf("relay: STUN write to %v: %v", from, err)
		}
	}
}

// allow reports whether a request from a is answered, by the rates from its
// host, an IPv6 address's /64, and in all.
func (s *stunResponder) allow(a netip.Addr) bool {
	return s.perSource.Allow(admit.Host(a)) && s.answers.Allow()
}

func newSTUNRates() *admit.Rates[netip.Prefix] {
	return admit.NewRates[netip.Prefix](stunPerSource, 2*stunPerSource, stunSources)
}
