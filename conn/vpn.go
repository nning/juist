package conn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/router"

	"github.com/nning/juist/internal/plumber"
	"github.com/nning/juist/types"
)

// A VPN brings the device up as Android's VpnService does: its addresses,
// routes and DNS given at once, and all of them again on every change.
type VPN interface {
	// Establish brings up a device as c says and returns its descriptor,
	// non-blocking and of raw IP packets, which the caller then owns. The
	// device it replaces stops carrying packets.
	Establish(c VPNConfig) (*os.File, error)
}

// A VPNConfig is a device as [VPN.Establish] brings it up: DNS, where set,
// takes all of the host's lookups, trying Search for a name without a dot.
type VPNConfig struct {
	Addrs  []netip.Prefix
	Routes []netip.Prefix
	DNS    []netip.Addr
	Search []string
	MTU    int
}

func (c VPNConfig) equal(o VPNConfig) bool {
	return slices.Equal(c.Addrs, o.Addrs) && slices.Equal(c.Routes, o.Routes) && slices.Equal(c.DNS, o.DNS) &&
		slices.Equal(c.Search, o.Search) && c.MTU == o.MTU
}

// errOnVPN refuses what a VPN app may not do to its host.
var errOnVPN = errors.New("conn: a VPN device serves nothing")

// VPNDial is a TCP dial into the overlay for p, a [VPNHub.Plumber]'s, as
// [VPNDialer]'s.
func VPNDial(p Plumber) func(context.Context, netip.AddrPort) (net.Conn, error) {
	dial := VPNDialer(p)
	return func(ctx context.Context, to netip.AddrPort) (net.Conn, error) { return dial(ctx, "tcp", to) }
}

// VPNDialer dials into the overlay for p, a [VPNHub.Plumber]'s, over network,
// tcp or udp: from the network's own address of the far end's family, so
// that it leaves by the device alone, and failing while no device carries it.
func VPNDialer(p Plumber) func(ctx context.Context, network string, to netip.AddrPort) (net.Conn, error) {
	vp, _ := p.(*vpnPlumber)
	return func(ctx context.Context, network string, to netip.AddrPort) (net.Conn, error) {
		from, ok := vp.source(to.Addr())
		if !ok {
			return nil, errNoVPNDevice
		}
		var local net.Addr = &net.TCPAddr{IP: from.AsSlice()}
		if network == "udp" {
			local = &net.UDPAddr{IP: from.AsSlice()}
		}
		d := net.Dialer{LocalAddr: local}
		return d.DialContext(ctx, network, to.String())
	}
}

var errNoVPNDevice = errors.New("conn: no VPN device is established to dial through")

// A vpnPlumber is one network's on a hub, in its slot.
type vpnPlumber struct {
	hub   *VPNHub
	slot  int
	cover func() []netip.Prefix
}

// VPNCoverChanged establishes p's device again where the network's prefixes
// its cover names are no longer those it was established with, as after a
// join, before which the cover named none. p is a [VPNHub.Plumber]'s.
func VPNCoverChanged(p Plumber) error {
	vp, ok := p.(*vpnPlumber)
	if !ok {
		return nil
	}
	r := vp.hub.router(vp.slot)
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.establishLocked()
}

// source is the network's own address of to's family, where the device
// last established carries it.
func (p *vpnPlumber) source(to netip.Addr) (netip.Addr, bool) {
	return p.hub.source(p.slot, to.Unmap().Is4())
}

func (p *vpnPlumber) OpenTUN(string, int) (*os.File, error) {
	return nil, errors.New("conn: a VPN device is established with its addresses, by its router")
}

func (p *vpnPlumber) SetAddrs(string, []netip.Prefix) error { return nil }

func (p *vpnPlumber) SetRoutes(string, []netip.Prefix, netip.Addr) error { return nil }

// SetGuard does nothing: a VPN service's device is the app's alone.
func (p *vpnPlumber) SetGuard(string, plumber.GuardSpec) error { return nil }

func (p *vpnPlumber) SetServe(_ string, s plumber.ServeSpec) error {
	if len(s.Sources) > 0 || s.DNSPort != 0 {
		return errOnVPN
	}
	return nil
}

// SetEgress takes what leaves the host directly alone: the router routes the
// internet into the tunnel, refused there or carried, as the exit node's use
// is set on it.
func (p *vpnPlumber) SetEgress(string, plumber.EgressSpec) error { return nil }

// SetDNS has the device take the host's lookups to servers, searching
// search, or none.
func (p *vpnPlumber) SetDNS(_ string, servers []netip.Addr, search []string) error {
	r := p.hub.router(p.slot)
	if r == nil {
		if len(servers) > 0 {
			return errors.New("conn: no VPN device is up to take the host's DNS")
		}
		return nil
	}
	return r.setDNS(servers, search)
}

func (p *vpnPlumber) Answers(string) (string, error) { return "", nil }

func (p *vpnPlumber) Destroy(string) error { return nil }

// newVPNPlumbed is the device of p's network on its hub and its router,
// which establish the hub's device once given addresses.
func newVPNPlumbed(p *vpnPlumber, name string, mtu int, logf logger.Logf) (tun.Device, router.Router) {
	d := &vpnTUN{name: name, mtu: mtu, hub: p.hub, slot: p.slot, events: make(chan tun.Event, 1),
		in: make(chan *[]byte, vpnQueue), done: make(chan struct{})}
	d.events <- tun.EventUp
	r := &vpnRouter{p: p, cover: p.cover, mtu: mtu, logf: logger.WithPrefix(logf, "router: ")}
	p.hub.attach(p.slot, d, r)
	return d, r
}

// vpnQueue is how many packets wait for a network's engine before more are
// dropped, as a full NIC queue drops them.
const vpnQueue = 256

// A vpnTUN is one network's device on a hub: it reads what the hub sends its
// way, and writes through the hub.
type vpnTUN struct {
	name   string
	mtu    int
	hub    *VPNHub
	slot   int
	events chan tun.Event
	in     chan *[]byte
	done   chan struct{}
	once   sync.Once
}

func (d *vpnTUN) File() *os.File           { return d.hub.file() }
func (d *vpnTUN) MTU() (int, error)        { return d.mtu, nil }
func (d *vpnTUN) Name() (string, error)    { return d.name, nil }
func (d *vpnTUN) Events() <-chan tun.Event { return d.events }
func (d *vpnTUN) BatchSize() int           { return 1 }

// deliver queues b, from the packet pool, for the engine, dropping it where
// the queue is full or the device closed.
func (d *vpnTUN) deliver(b *[]byte) {
	select {
	case <-d.done:
		putPacket(b)
		return
	default:
	}
	select {
	case d.in <- b:
	default:
		putPacket(b)
	}
}

func (d *vpnTUN) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	select {
	case b := <-d.in:
		n := copy(slab[tun.ReadPacketSpacing:len(slab)-tun.ReadPacketSpacing], *b)
		putPacket(b)
		packets[0] = tun.ReadPacket{Offset: tun.ReadPacketSpacing, Size: n}
		return 1, nil
	case <-d.done:
		return 0, os.ErrClosed
	}
}

// Write drops what comes before the hub's first descriptor, as a device
// that is down would.
func (d *vpnTUN) Write(bufs [][]byte, offset int) (int, error) { return d.hub.write(d, bufs, offset) }

// Close detaches the device from the hub, whose own device stays up for
// the other networks and for this one's next mesh.
func (d *vpnTUN) Close() error {
	d.once.Do(func() {
		close(d.done)
		close(d.events)
		d.hub.detach(d)
	})
	return nil
}

// What the manager finds a VPN's router can by a type assertion, held at
// compile time.
var (
	_ exitRouter = (*vpnRouter)(nil)
	_ hostRouter = (*vpnRouter)(nil)
)

// A vpnRouter has the hub establish its device again whenever what its
// network routes changes: the network's addresses, the overlay's routes, the
// internet while an exit node is chosen, and the host's DNS.
type vpnRouter struct {
	p     *vpnPlumber
	cover func() []netip.Prefix
	mtu   int
	logf  logger.Logf

	mu             sync.Mutex
	own            []netip.Addr   // the addresses as the engine last gave them, in its order
	addrs, overlay []netip.Prefix // as the engine last set them
	internet       bool           // routed into the tunnel, for an exit node
	dns            []netip.Addr
	search         []string
}

func (r *vpnRouter) Up() error { return nil }

// Set takes the addresses and routes cfg gives. A config without addresses
// keeps the device as it is: a VPN cannot be established without one.
func (r *vpnRouter) Set(cfg *router.Config) error {
	if cfg == nil || len(cfg.LocalAddrs) == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.own = r.own[:0]
	for _, a := range cfg.LocalAddrs {
		r.own = append(r.own, a.Addr().Unmap())
	}
	r.addrs, r.overlay = sortedPrefixes(cfg.LocalAddrs), slices.Clone(cfg.Routes)
	return r.establishLocked()
}

func (r *vpnRouter) setDNS(servers []netip.Addr, search []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dns, r.search = slices.Clone(servers), nil
	if len(servers) > 0 {
		r.search = slices.Clone(search)
	}
	return r.establishLocked()
}

// setEgress routes the internet into the tunnel unless e leaves it direct:
// carried there by the exit node, or refused where it cannot be used, so
// that nothing leaves directly instead. Both families go in; what no exit
// node carries is refused there.
func (r *vpnRouter) setEgress(e Egress, _ tunnelled) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.internet = e != EgressDirect
	return r.establishLocked()
}

func (r *vpnRouter) setServe(s Serve) error {
	if s.serving() {
		return errOnVPN
	}
	return nil
}

func (r *vpnRouter) lans() ([]netip.Prefix, []netip.Addr) { return nil, nil }

func (r *vpnRouter) hostRoutes() []netip.Prefix { return r.p.hub.hostRoutes() }

func (r *vpnRouter) watchHostRoutes(changed func()) { r.p.hub.watchHostRoutes(r.p.slot, changed) }

func (r *vpnRouter) answersThrough() string { return "" }

// establishLocked hands the hub what the network routes, which establishes
// its device again where that changed it.
func (r *vpnRouter) establishLocked() error {
	if len(r.addrs) == 0 {
		return nil
	}
	var cover []netip.Prefix
	if r.cover != nil {
		cover = r.cover()
	}
	// A route to an address of the device's own is the device's already, and
	// one inside the network's prefixes is theirs.
	routes := append(slices.DeleteFunc(slices.Clone(r.overlay), func(p netip.Prefix) bool {
		return p.IsSingleIP() && slices.ContainsFunc(r.addrs, func(a netip.Prefix) bool { return a.Addr() == p.Addr() }) ||
			slices.ContainsFunc(cover, func(c netip.Prefix) bool { return c.Bits() <= p.Bits() && c.Contains(p.Addr()) })
	}), cover...)
	c, err := r.p.hub.set(r.p.slot, r, &vpnPart{
		addrs: r.addrs, own: slices.Clone(r.own), routes: sortedPrefixes(routes),
		overlay: append(slices.Clone(cover), r.overlay...), internet: r.internet,
		dns: r.dns, search: r.search, mtu: r.mtu,
	})
	if c != nil {
		r.logf("established: %d routes, DNS %v", len(c.Routes), c.DNS)
	}
	return err
}

func (r *vpnRouter) Close() error { return nil }

func sortedPrefixes(ps []netip.Prefix) []netip.Prefix {
	out := slices.Clone(ps)
	slices.SortFunc(out, types.ComparePrefix)
	return slices.Compact(out)
}
