package conn

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"

	"tailscale.com/net/netmon"
	"tailscale.com/net/portmapper"
	"tailscale.com/net/portmapper/portmappertype"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
	"tailscale.com/util/eventbus"
)

// The engine asks for its port mapper while it is built, through a hook the
// whole process shares: [New] holds engineMu across that, so that the
// hook takes the switch of the engine being built.
var (
	engineMu    sync.Mutex
	buildingOff *atomic.Bool

	// portMapperBuilt is told the switch each port mapper takes; tests only.
	portMapperBuilt = func(off *atomic.Bool) {}
)

func init() {
	portmappertype.HookNewPortMapper.Set(newPortMapper)
}

func newPortMapper(logf logger.Logf, bus *eventbus.Bus, netMon *netmon.Monitor, disableUPnP, onlyTCP443 func() bool) portmappertype.Client {
	off := buildingOff
	if off == nil {
		off = new(atomic.Bool)
		off.Store(true)
	}
	portMapperBuilt(off)
	pm := portmapper.NewClient(portmapper.Config{
		EventBus: bus,
		Logf:     logf,
		NetMon:   netMon,
		DebugKnobs: &portmapper.DebugKnobs{
			DisableAll: func() bool {
				return off.Load() || onlyTCP443 != nil && onlyTCP443()
			},
			DisableUPnPFunc: disableUPnP,
		},
	})
	pm.SetGatewayLookupFunc(netMon.GatewayAndSelfIP)
	return pm
}

// Underlay is what the data plane's last measurement found of the networks
// beneath it. The zero value is no measurement yet.
type Underlay struct {
	Measured bool

	// UDP says a STUN server answered; IPv4 and IPv6 that one did over each.
	UDP, IPv4, IPv6 bool

	// PortPerPeer says IPv4's NAT gave this node another public port for
	// each server it sent to, which no peer can punch; Mapping says the
	// measurement could tell either way.
	PortPerPeer, Mapping bool

	// Offered names the port mapping protocols the router answered:
	// "UPnP", "NAT-PMP", "PCP".
	Offered []string

	// Mapped is the public address a port mapping on the router holds for
	// this node, invalid where none does.
	Mapped netip.AddrPort

	// PortMapOff says this node asks the router for no mapping.
	PortMapOff bool
}

// Underlay is what the last netcheck report found, and the port mapping
// held.
func (m *tsManager) Underlay() Underlay {
	u := Underlay{PortMapOff: m.portMapOff.Load()}
	if p := m.mapped.Load(); p != nil {
		u.Mapped = *p
	}
	r := m.magic.GetLastNetcheckReport(context.Background())
	if r == nil {
		return u
	}
	u.Measured, u.UDP, u.IPv4, u.IPv6 = true, r.UDP, r.IPv4, r.IPv6
	if v, ok := r.MappingVariesByDestIP.Get(); ok {
		u.Mapping, u.PortPerPeer = true, v
	}
	for _, p := range []struct {
		name string
		b    opt.Bool
	}{{"UPnP", r.UPnP}, {"NAT-PMP", r.PMP}, {"PCP", r.PCP}} {
		if v, _ := p.b.Get(); v {
			u.Offered = append(u.Offered, p.name)
		}
	}
	return u
}

// portMapped is the endpoint among eps a port mapping holds, invalid where
// none does.
func portMapped(eps []tailcfg.Endpoint) netip.AddrPort {
	for _, e := range eps {
		if e.Type == tailcfg.EndpointPortmapped && e.Addr.IsValid() {
			return netip.AddrPortFrom(e.Addr.Addr().Unmap(), e.Addr.Port())
		}
	}
	return netip.AddrPort{}
}
