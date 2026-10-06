package daemon

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/netstack"
	"tailscale.com/net/netns"
)

// netstackMTU is the overlay's MTU, as a device's.
const netstackMTU = 1280

// onNetstack has connect build the data plane on a network stack of its own
// on this node's overlay addresses, which the daemon keeps to listen and dial
// on. It turns netns off for the process: with no device to loop through,
// sockets bound to the default route's interface would miss every other LAN.
func (d *Daemon) onNetstack(connect func(conn.Options) (conn.Manager, error)) func(conn.Options) (conn.Manager, error) {
	return func(o conn.Options) (conn.Manager, error) {
		netns.SetEnabled(false)
		addrs := make([]netip.Addr, 0, len(o.Self.Addrs))
		for _, p := range o.Self.Addrs {
			addrs = append(addrs, p.Addr())
		}
		dev, stack, err := netstack.New(addrs, netstackMTU)
		if err != nil {
			return nil, err
		}
		o.Tun = dev
		m, err := connect(o)
		if err != nil {
			dev.Close()
			return nil, err
		}
		d.stack = stack
		return m, nil
	}
}

// gossipDial is dial, else a dial on the network stack where there is one,
// nil for the gossip's own.
func (d *Daemon) gossipDial(dial func(context.Context, netip.AddrPort) (net.Conn, error)) func(context.Context, netip.AddrPort) (net.Conn, error) {
	if dial != nil || d.stack == nil {
		return dial
	}
	return func(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
		return d.stack.DialContextTCPAddrPort(ctx, ap)
	}
}

// ListenOverlayUDP takes datagrams at addr as [Daemon.ListenOverlay]
// listens for TCP.
func (d *Daemon) ListenOverlayUDP(addr string) (net.PacketConn, error) {
	if d.stack == nil {
		return nil, errors.New("daemon: no network stack of its own")
	}
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}
	return d.stack.ListenUDPAddrPort(ap)
}

// ListenOverlay listens for TCP at addr, one of this node's overlay
// addresses and a port, on the network stack where the daemon runs on one.
func (d *Daemon) ListenOverlay(addr string) (net.Listener, error) {
	if d.stack == nil {
		return nil, errors.New("daemon: no network stack of its own")
	}
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}
	return d.stack.ListenTCPAddrPort(ap)
}
