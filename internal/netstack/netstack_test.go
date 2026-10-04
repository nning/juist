package netstack

import (
	"net/netip"
	"testing"
	"time"
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
