/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 *
 * Adapted from wireguard-go's tun/netstack to TCP alone, and to the gVisor
 * Tailscale pins, whose packet buffers wireguard-go's copy no longer builds
 * against.
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
	"syscall"

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
)

// A Device is the TUN end, and Net the stack's.
type Device struct {
	ep       *channel.Endpoint
	stack    *stack.Stack
	events   chan tun.Event
	incoming chan *buffer.View
	mtu      int

	closeOnce sync.Once
	closed    chan struct{}
}

// Net listens and dials on the stack's addresses.
type Net struct{ d *Device }

var _ tun.Device = (*Device)(nil)

// New is a device of mtu with addrs, and the stack behind it.
func New(addrs []netip.Addr, mtu int) (*Device, *Net, error) {
	d := &Device{
		ep: channel.New(1024, uint32(mtu), ""),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
			HandleLocal:        true,
		}),
		events:   make(chan tun.Event, 10),
		incoming: make(chan *buffer.View),
		mtu:      mtu,
		closed:   make(chan struct{}),
	}
	sack := tcpip.TCPSACKEnabled(true)
	if err := d.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, nil, fmt.Errorf("netstack: enabling SACK: %v", err)
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
func (d *Device) BatchSize() int           { return 1 }

// Read is a packet the stack sends.
func (d *Device) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	select {
	case v := <-d.incoming:
		n, err := v.Read(slab[tun.ReadPacketSpacing : len(slab)-tun.ReadPacketSpacing])
		v.Release()
		if err != nil {
			return 0, err
		}
		packets[0] = tun.ReadPacket{Offset: tun.ReadPacketSpacing, Size: n}
		return 1, nil
	case <-d.closed:
		return 0, os.ErrClosed
	}
}

// Write hands packets to the stack.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		p := b[offset:]
		if len(p) == 0 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
		switch p[0] >> 4 {
		case 4:
			d.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			d.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			pkb.DecRef()
			return 0, syscall.EAFNOSUPPORT
		}
		pkb.DecRef()
	}
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

// DialContextTCPAddrPort dials ap from the stack.
func (n *Net) DialContextTCPAddrPort(ctx context.Context, ap netip.AddrPort) (*gonet.TCPConn, error) {
	fa, proto := fullAddr(ap)
	return gonet.DialContextTCP(ctx, n.d.stack, fa, proto)
}
