package conn

import (
	"net/netip"
	"slices"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/netstack/gro"
)

// takeLocal has what w's device sends to addrs go to dev instead of the
// engine, and what dev sends go to w's device, until dev is closed. It must
// run before w starts, since the hook is a plain field the packet path reads.
func takeLocal(w *tstun.Wrapper, dev tun.Device, addrs []netip.Addr, running *sync.WaitGroup) {
	next := w.PreFilterPacketOutboundToWireGuardNetstackIntercept
	w.PreFilterPacketOutboundToWireGuardNetstackIntercept = func(p *packet.Parsed, w *tstun.Wrapper, g *gro.GRO) (filter.Response, *gro.GRO) {
		if slices.Contains(addrs, p.Dst.Addr()) {
			dev.Write([][]byte{p.Buffer()}, 0)
			return filter.DropSilently, g
		}
		if next != nil {
			return next(p, w, g)
		}
		return filter.Accept, g
	}
	running.Add(1)
	go func() {
		defer running.Done()
		// Room for a batch of the stack's packets, each at most its MTU.
		slab := make([]byte, 1<<16)
		packets := make([]tun.ReadPacket, dev.BatchSize())
		for {
			n, err := dev.Read(slab, packets)
			if err != nil && n == 0 {
				if err == tun.ErrTooManySegments {
					continue
				}
				return
			}
			for _, p := range packets[:n] {
				w.InjectInboundCopy(slab[p.Offset : p.Offset+p.Size])
			}
		}
	}()
}
