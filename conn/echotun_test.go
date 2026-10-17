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
// requests and drops everything else. The engine's RespondToPing scaffolding
// cannot stand in for it: that helper panics on an ICMPv6 echo. Sitting below
// the tstun.Wrapper also makes it a stronger probe, since the request and
// reply traverse the full inbound and outbound paths.
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
// packet goes at bufs[i][offset:], per the tun.Device contract: the caller
// reserves that headroom for WireGuard's transport header.
func (d *echoTUN) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	select {
	case pkt := <-d.replies:
		if len(slab) < 2*tun.ReadPacketSpacing+len(pkt) {
			return 0, io.ErrShortBuffer
		}
		packets[0] = tun.ReadPacket{Offset: tun.ReadPacketSpacing, Size: copy(slab[tun.ReadPacketSpacing:], pkt)}
		return 1, nil
	case <-d.closed:
		return 0, io.EOF
	}
}

// Write receives the packets the engine delivers to the "host", each at
// bufs[i][offset:]. Echo requests of either family are mirrored back;
// everything else is dropped, like a host with no listeners.
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
// families, direct-only. The v6 address goes first, so it is the one that
// primes disco and the handshake.
func TestTwoNodeOverlayPingBothFamilies(t *testing.T) {
	t.Parallel()
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
