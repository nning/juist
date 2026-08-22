package conn

import (
	"io"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
)

// echoTUN is a test-only tun.Device that answers ICMPv4 and ICMPv6 echo
// requests and drops every other packet. It stands in for a host network
// stack, which the engine's RespondToPing scaffolding cannot: that helper
// (wgengine's echoRespondToAll) calls ICMP4Header unconditionally and panics
// on an ICMPv6 echo, so v6 overlay reachability can only be asserted with a
// device like this one.
//
// Unlike RespondToPing — which injects the reply directly into the engine,
// after the inbound filter but before the TUN — this device sits below the
// tstun.Wrapper, so the echo request traverses the full inbound path
// (WireGuard decrypt, source check, packet filter, Wrapper.Write) and the
// reply traverses the full outbound path (Wrapper.Read, outbound filter,
// WireGuard encrypt). That makes it a slightly stronger reachability probe
// than the scaffolding it replaces.
type echoTUN struct {
	events  chan tun.Event
	replies chan []byte // marshaled IP packets waiting to be Read

	closeOnce sync.Once
	closed    chan struct{}
}

func newEchoTUN() *echoTUN {
	return &echoTUN{
		events:  make(chan tun.Event),
		replies: make(chan []byte, 64),
		closed:  make(chan struct{}),
	}
}

var _ tun.Device = (*echoTUN)(nil)

func (d *echoTUN) File() *os.File           { panic("echoTUN.File called, which makes no sense") }
func (d *echoTUN) MTU() (int, error)        { return 1500, nil }
func (d *echoTUN) Name() (string, error)    { return "echoTUN", nil }
func (d *echoTUN) Events() <-chan tun.Event { return d.events }

// BatchSize must not change over the device's lifetime; the tstun.Wrapper
// sizes its read vectors from it once, at Wrap time.
func (d *echoTUN) BatchSize() int { return 1 }

func (d *echoTUN) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed) // unblocks Read
		close(d.events)
	})
	return nil
}

// Read blocks until an echo reply is queued or the device is closed. The
// packet is written at bufs[i][offset:], per the tun.Device contract; the
// caller (tstun.Wrapper.pollVector) reserves offset bytes of headroom for
// WireGuard's transport header.
func (d *echoTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-d.replies:
		if len(bufs) < 1 || len(bufs[0]) < offset+len(pkt) {
			return 0, io.ErrShortBuffer
		}
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	case <-d.closed:
		return 0, io.EOF
	}
}

// Write receives the packets the engine delivers to the "host": each begins
// at bufs[i][offset:]. Echo requests of either family are answered with the
// mirrored reply; everything else is silently dropped, like a host with no
// listeners.
func (d *echoTUN) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-d.closed:
		return 0, tstun.ErrClosed
	default:
	}
	var p packet.Parsed
	for _, buf := range bufs {
		p.Decode(buf[offset:])
		if !p.IsEchoRequest() {
			continue
		}
		var reply []byte
		switch p.IPVersion {
		case 4:
			h := p.ICMP4Header()
			h.ToResponse()
			// ICMP4Header.Marshal writes the ICMP checksum itself.
			reply = packet.Generate(&h, p.Payload())
		case 6:
			h := p.ICMP6Header()
			h.ToResponse()
			// ICMP6Header implements HeaderChecksummer, so Generate calls
			// WriteChecksum and the ICMPv6 pseudo-header checksum — computed
			// over the already-swapped Src/Dst — comes out correct.
			reply = packet.Generate(&h, p.Payload())
		default:
			continue
		}
		select {
		case d.replies <- reply:
		case <-d.closed:
			return 0, tstun.ErrClosed
		default:
			// Reply queue full; drop, as a congested network would.
		}
	}
	return len(bufs), nil
}

// newEchoNode is newNode, except the engine gets an echoTUN instead of
// RespondToPing, so both address families answer overlay pings.
func newEchoNode(t *testing.T, id uint64, v4, v6 string) *node {
	t.Helper()
	return startNode(t, id, v4, v6, func(o *Options) {
		o.Tun = newEchoTUN()
		o.RespondToPing = false
	})
}

// TestTwoNodeOverlayPingBothFamilies asserts overlay reachability on both
// address families: two nodes whose TUNs echo ICMP answer each other's pings
// on the v4 and the v6 overlay address, direct-only. The v6 address goes
// first so it is the one that primes disco and the WireGuard handshake.
func TestTwoNodeOverlayPingBothFamilies(t *testing.T) {
	a := newEchoNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newEchoNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")

	if err := a.mgr.SetPeers([]Peer{b.peer()}); err != nil {
		t.Fatalf("a.SetPeers: %v", err)
	}
	if err := b.mgr.SetPeers([]Peer{a.peer()}); err != nil {
		t.Fatalf("b.SetPeers: %v", err)
	}

	for _, addr := range []netip.Addr{b.addrs[1].Addr(), b.addrs[0].Addr()} {
		res, ok := pingUntil(t, a, addr, 30*time.Second)
		if !ok {
			t.Fatalf("a could not ping b at %v over the overlay", addr)
		}
		t.Logf("a -> b (%v): %v", addr, res.Latency)
	}
}
