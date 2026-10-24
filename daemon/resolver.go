package daemon

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/dnsfwd"
	"github.com/nning/juist/internal/names"
	"github.com/nning/juist/internal/netstack"
	"github.com/nning/juist/types"
)

// A Resolver is how juistd's resolver in the tunnel reaches the resolvers it
// asks: Dial opens a connection to one over network, udp or tcp.
type Resolver struct {
	Dial func(ctx context.Context, network string, to netip.AddrPort) (net.Conn, error)
}

// withResolver has connect build the data plane with a stack of its own at
// the network's resolver address, which the daemon keeps to answer on.
func (d *Daemon) withResolver(connect func(conn.Options) (conn.Manager, error)) func(conn.Options) (conn.Manager, error) {
	return func(o conn.Options) (conn.Manager, error) {
		at := types.ResolverAddr(d.ula)
		dev, stack, err := netstack.New([]netip.Addr{at}, netstackMTU)
		if err != nil {
			return nil, err
		}
		o.Local, o.LocalAddrs = dev, []netip.Addr{at}
		m, err := connect(o)
		if err != nil {
			dev.Close()
			return nil, err
		}
		d.resolver = stack
		return m, nil
	}
}

// resolverMaxUDP is the longest answer the resolver's stack carries in one
// UDP datagram over IPv6, which it does not fragment.
const resolverMaxUDP = netstackMTU - 40 - 8

// resolverNames answers the host in the resolver's stack, which the host's
// own packets alone reach, asking upstream by dial, and failing at once what
// it cannot ask.
func (d *Daemon) resolverNames(dial func(context.Context, string, netip.AddrPort) (net.Conn, error)) NamesServer {
	return func(addr netip.AddrPort, answer func([]byte) []byte, upstream func([]byte) ([]netip.AddrPort, error)) (io.Closer, error) {
		stack := d.resolver
		if stack == nil {
			return nil, errors.New("daemon: no stack for the resolver")
		}
		listen := func(ap netip.AddrPort) (net.PacketConn, net.Listener, error) {
			pc, err := stack.ListenUDPAddrPort(ap)
			if err != nil {
				return nil, nil, err
			}
			ln, err := stack.ListenTCPAddrPort(ap)
			if err != nil {
				pc.Close()
				return nil, nil, err
			}
			return pc, ln, nil
		}
		none := func() []netip.AddrPort { return nil }
		return dnsfwd.Start(dnsfwd.Options{Addrs: []netip.Addr{addr.Addr()}, Port: addr.Port(), Listen: listen,
			Local: true, Answer: answer, Upstream: none, UpstreamFor: upstream, Dial: dial, FailFast: true,
			MaxTTL: names.TTL, Capped: d.namesCapped, MaxUDP: resolverMaxUDP})
	}
}

// namesCapped reports whether q asks for a name the network may yet answer
// itself: one under its public domain, or one it points at a member.
func (d *Daemon) namesCapped(q []byte) bool {
	z := d.zone.Load()
	if z == nil {
		return false
	}
	name, ok := names.Question(q)
	if !ok {
		return false
	}
	return z.Public != "" && (name == z.Public || strings.HasSuffix(name, "."+z.Public)) || z.Overridden(q)
}
