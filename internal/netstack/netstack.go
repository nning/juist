/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 *
 * Adapted from wireguard-go's tun/netstack to TCP and UDP alone, and to the
 * gVisor Tailscale pins, whose packet buffers wireguard-go's copy no longer
 * builds against.
 */

// Package netstack is a TUN device whose other end is a TCP/IP stack in this
// process: what reaches its addresses reaches the process alone, which
// listens and dials there.
package netstack

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"tailscale.com/net/packet"
	"tailscale.com/wgengine/netstack/gro"
)

// batchSize is how many packets a Read or Write takes at most.
const batchSize = 128

// TCP's buffer bounds, tailscaled's: what a path of high bandwidth and delay
// needs in flight.
const (
	rxBufMax = 8 << 20
	txBufMax = 6 << 20
)

// A Device is the TUN end, and Net the stack's.
type Device struct {
	ep       *link
	stack    *stack.Stack
	events   chan tun.Event
	incoming chan *buffer.View
	pending  *buffer.View // read and not yet given, as it did not fit
	mtu      int

	closeOnce sync.Once
	closed    chan struct{}
}

// Net listens and dials on the stack's addresses.
type Net struct{ d *Device }

var _ tun.Device = (*Device)(nil)

// A link is the stack's NIC, which keeps the dispatcher the stack attaches,
// for what is written to go to it through GRO.
type link struct {
	*channel.Endpoint
	d atomic.Pointer[stack.NetworkDispatcher]
}

func (l *link) Attach(d stack.NetworkDispatcher) {
	l.Endpoint.Attach(d)
	if d == nil {
		l.d.Store(nil)
		return
	}
	l.d.Store(&d)
}

// New is a device of mtu with addrs, and the stack behind it.
func New(addrs []netip.Addr, mtu int) (*Device, *Net, error) {
	d := &Device{
		ep: &link{Endpoint: channel.New(1024, uint32(mtu), "")},
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
			HandleLocal:        true,
		}),
		events:   make(chan tun.Event, 10),
		incoming: make(chan *buffer.View, 4*batchSize),
		mtu:      mtu,
		closed:   make(chan struct{}),
	}
	// Write validates every checksum the stack would, before GRO.
	d.ep.LinkEPCapabilities |= stack.CapabilityRXChecksumOffload
	sack := tcpip.TCPSACKEnabled(true)
	cubic := tcpip.CongestionControlOption("cubic")
	rx := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultReceiveBufferSize, Max: rxBufMax}
	tx := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultSendBufferSize, Max: txBufMax}
	for _, o := range []tcpip.SettableTransportProtocolOption{&sack, &cubic, &rx, &tx} {
		if err := d.stack.SetTransportProtocolOption(tcp.ProtocolNumber, o); err != nil {
			return nil, nil, fmt.Errorf("netstack: setting TCP's %T: %v", o, err)
		}
	}
	d.ep.AddNotify(d)
	if err := d.stack.CreateNIC(1, d.ep); err != nil {
		return nil, nil, fmt.Errorf("netstack: creating the NIC: %v", err)
	}
	var v4, v6 bool
	for _, a := range addrs {
		proto := ipv6.ProtocolNumber
		if a.Is4() {
			proto, v4 = ipv4.ProtocolNumber, true
		} else {
			v6 = true
		}
		pa := tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddrFromSlice(a.AsSlice()).WithPrefix()}
		if err := d.stack.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
			return nil, nil, fmt.Errorf("netstack: adding %v: %v", a, err)
		}
	}
	if v4 {
		d.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if v6 {
		d.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}
	d.events <- tun.EventUp
	return d, &Net{d}, nil
}

func (d *Device) Name() (string, error)    { return "netstack", nil }
func (d *Device) File() *os.File           { return nil }
func (d *Device) Events() <-chan tun.Event { return d.events }
func (d *Device) MTU() (int, error)        { return d.mtu, nil }
func (d *Device) BatchSize() int           { return batchSize }

// Read is the packets the stack sends, as many as wait and fit. It is called
// by one goroutine at a time.
func (d *Device) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	v := d.pending
	d.pending = nil
	if v == nil {
		select {
		case v = <-d.incoming:
		case <-d.closed:
			return 0, os.ErrClosed
		}
	}
	n, off := 0, tun.ReadPacketSpacing
	for {
		size := int(v.Size())
		if off+size+tun.ReadPacketSpacing > len(slab) {
			if n == 0 {
				v.Release()
				return 0, tun.ErrTooManySegments
			}
			d.pending = v
			return n, nil
		}
		m, _ := v.Read(slab[off : off+size])
		v.Release()
		packets[n] = tun.ReadPacket{Offset: off, Size: m}
		n, off = n+1, off+m+tun.ReadPacketSpacing
		if n == len(packets) {
			return n, nil
		}
		select {
		case v = <-d.incoming:
		default:
			return n, nil
		}
	}
}

// Write hands packets to the stack, a flow's segments coalesced, and drops
// what is no IP packet or fails a checksum.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	disp := d.ep.d.Load()
	if disp == nil {
		return 0, os.ErrClosed
	}
	g := gro.NewGRO()
	g.SetDispatcher(*disp)
	var p packet.Parsed
	for _, b := range bufs {
		if len(b) <= offset {
			continue
		}
		p.Decode(b[offset:])
		if p.IPVersion == 4 || p.IPVersion == 6 {
			g.Enqueue(&p)
		}
	}
	g.Flush()
	return len(bufs), nil
}

// WriteNotify is the stack saying it has a packet to send.
func (d *Device) WriteNotify() {
	pkt := d.ep.Read()
	if pkt == nil {
		return
	}
	v := pkt.ToView()
	pkt.DecRef()
	select {
	case d.incoming <- v:
	case <-d.closed:
		v.Release()
	}
}

// Close takes the stack down, with its listeners and connections.
func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
		d.stack.RemoveNIC(1)
		close(d.events)
		d.ep.Close()
		// Ends what listens and dials on the stack, which removing the NIC
		// leaves waiting.
		d.stack.Close()
	})
	return nil
}

func fullAddr(ap netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	proto := ipv6.ProtocolNumber
	if ap.Addr().Is4() {
		proto = ipv4.ProtocolNumber
	}
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ap.Addr().AsSlice()), Port: ap.Port()}, proto
}

// ListenTCPAddrPort listens at ap, one of the stack's addresses.
func (n *Net) ListenTCPAddrPort(ap netip.AddrPort) (*gonet.TCPListener, error) {
	fa, proto := fullAddr(ap)
	if n.d.stack.CheckLocalAddress(0, proto, fa.Addr) == 0 {
		return nil, fmt.Errorf("netstack: %v is none of the stack's addresses", ap.Addr())
	}
	return gonet.ListenTCP(n.d.stack, fa, proto)
}

// ListenUDPAddrPort takes datagrams at ap, one of the stack's addresses.
func (n *Net) ListenUDPAddrPort(ap netip.AddrPort) (*gonet.UDPConn, error) {
	fa, proto := fullAddr(ap)
	if n.d.stack.CheckLocalAddress(0, proto, fa.Addr) == 0 {
		return nil, fmt.Errorf("netstack: %v is none of the stack's addresses", ap.Addr())
	}
	return gonet.DialUDP(n.d.stack, &fa, nil, proto)
}

// DialContextTCPAddrPort dials ap from the stack.
func (n *Net) DialContextTCPAddrPort(ctx context.Context, ap netip.AddrPort) (*gonet.TCPConn, error) {
	fa, proto := fullAddr(ap)
	return gonet.DialContextTCP(ctx, n.d.stack, fa, proto)
}
