package netstack

import (
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Closing the device ends what listens on its stack, so that a listener of
// a stack replaced is known to have ended.
func TestClosingTheDeviceEndsItsListeners(t *testing.T) {
	dev, stack, err := New([]netip.Addr{netip.MustParseAddr("100.64.0.1")}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := stack.ListenTCPAddrPort(netip.MustParseAddrPort("100.64.0.1:443"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()
	dev.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Error("accepted on a closed stack")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a listener of a closed stack still waits")
	}
}

// The stack listens on its own addresses alone.
func TestTheStackListensOnItsAddressesAlone(t *testing.T) {
	dev, stack, err := New([]netip.Addr{netip.MustParseAddr("100.64.0.1")}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if ln, err := stack.ListenTCPAddrPort(netip.MustParseAddrPort("10.0.0.1:443")); err == nil {
		ln.Close()
		t.Error("the stack listens on an address of another's")
	}
	ln, err := stack.ListenTCPAddrPort(netip.MustParseAddrPort("100.64.0.1:443"))
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
}

// udp4 is an IPv4 datagram from src to dst carrying payload, its checksums
// right unless broken.
func udp4(src, dst netip.AddrPort, payload []byte, broken bool) []byte {
	b := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(b)), TTL: 64, Protocol: uint8(header.UDPProtocolNumber),
		SrcAddr: tcpip.AddrFrom4(src.Addr().As4()), DstAddr: tcpip.AddrFrom4(dst.Addr().As4())})
	ip.SetChecksum(^ip.CalculateChecksum())
	u := header.UDP(b[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{SrcPort: src.Port(), DstPort: dst.Port(), Length: uint16(len(u))})
	copy(u.Payload(), payload)
	sum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(u)))
	u.SetChecksum(^u.CalculateChecksum(checksum.Checksum(payload, sum)))
	if broken {
		u.SetChecksum(u.Checksum() + 1)
	}
	return b
}

// The stack takes UDP at its addresses, as HTTP/3 on a service member
// needs, and drops a datagram whose checksum fails.
func TestTheStackTakesUDP(t *testing.T) {
	self := netip.MustParseAddrPort("100.64.0.1:443")
	dev, stack, err := New([]netip.Addr{self.Addr()}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	c, err := stack.ListenUDPAddrPort(self)
	if err != nil {
		t.Fatalf("listening for UDP: %v", err)
	}
	defer c.Close()
	from := netip.MustParseAddrPort("100.64.0.2:5000")
	for _, tc := range []struct {
		payload string
		broken  bool
	}{{"broken", true}, {"whole", false}} {
		if _, err := dev.Write([][]byte{udp4(from, self, []byte(tc.payload), tc.broken)}, 0); err != nil {
			t.Fatal(err)
		}
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 64)
	n, _, err := c.ReadFrom(b)
	if err != nil || string(b[:n]) != "whole" {
		t.Fatalf("read %q, %v; want the whole datagram alone", b[:n], err)
	}
}
