package underlay

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
)

func TestASocketIsProtectedBeforeItIsUsed(t *testing.T) {
	var n atomic.Int64
	ProtectWith(func(uintptr) error { n.Add(1); return nil })
	t.Cleanup(func() { ProtectWith(nil) })
	pc, err := ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc.Close()
	if n.Load() != 1 {
		t.Errorf("%d sockets protected, want 1", n.Load())
	}
	ProtectWith(func(uintptr) error { return errors.New("refused") })
	if _, err := Dialer(0).Dial("udp", pc.LocalAddr().String()); err == nil {
		t.Error("a socket the platform refused to protect was used")
	}
	ProtectWith(nil)
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
