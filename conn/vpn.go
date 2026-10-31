package conn

import (
	"context"
	"errors"
	"io"
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

// NewVPNPlumber is the [Plumber] for v. It serves nothing, and sends the
// host's traffic outside the overlay into the tunnel only where an exit node
// is chosen, with the host's DNS then. Where cover names the network's
// prefixes, they are routed whole, rather than one route per member:
// establishing again replaces the device, and with it every connection
// through it, as Android does, so it is kept to changes of the device's own
// addresses and of the exit node's use.
func NewVPNPlumber(v VPN, cover func() []netip.Prefix) Plumber {
	return &vpnPlumber{v: v, cover: cover}
}

// VPNDial is a TCP dial into the overlay for p, a [NewVPNPlumber]'s, as
// [VPNDialer]'s.
func VPNDial(p Plumber) func(context.Context, netip.AddrPort) (net.Conn, error) {
	dial := VPNDialer(p)
	return func(ctx context.Context, to netip.AddrPort) (net.Conn, error) { return dial(ctx, "tcp", to) }
}

// VPNDialer dials into the overlay for p, a [NewVPNPlumber]'s, over network,
// tcp or udp: from the device's own address of the far end's family, so that
// it leaves by the device alone, and failing while no device is established.
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

type vpnPlumber struct {
	v     VPN
	cover func() []netip.Prefix

	mu  sync.Mutex
	rtr *vpnRouter // the router of the device the last mesh made, nil before
}

func (p *vpnPlumber) router() *vpnRouter {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rtr
}

// source is the device's address of to's family, as last established.
func (p *vpnPlumber) source(to netip.Addr) (netip.Addr, bool) {
	r := p.router()
	if r == nil {
		return netip.Addr{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.everEstablished {
		return netip.Addr{}, false
	}
	for _, a := range r.established.Addrs {
		if a.Addr().Is4() == to.Unmap().Is4() {
			return a.Addr(), true
		}
	}
	return netip.Addr{}, false
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
	r := p.router()
	if r == nil {
		if len(servers) > 0 {
			return errors.New("conn: no VPN device is up to take the host's DNS")
		}
		return nil
	}
	return r.setDNS(servers, search)
}

func (p *vpnPlumber) Answers(string) (string, error) { return "", nil }

func (p *vpnPlumber) Destroy(string) error {
	if r := p.router(); r != nil {
		return r.dev.Close()
	}
	return nil
}

// newVPNPlumbed is the device p establishes, without a descriptor until its
// router is first given addresses, and that router.
func newVPNPlumbed(p *vpnPlumber, name string, mtu int, logf logger.Logf) (tun.Device, router.Router) {
	d := &vpnTUN{name: name, mtu: mtu, events: make(chan tun.Event, 1), swapped: make(chan struct{})}
	d.events <- tun.EventUp
	r := &vpnRouter{v: p.v, cover: p.cover, dev: d, logf: logger.WithPrefix(logf, "router: ")}
	p.mu.Lock()
	p.rtr = r
	p.mu.Unlock()
	return d, r
}

// A vpnTUN is the device on whichever descriptor was established last. Read
// waits for the first, and moves to each new one.
type vpnTUN struct {
	name   string
	mtu    int
	events chan tun.Event

	mu      sync.Mutex
	f       *os.File
	swapped chan struct{} // closed and replaced whenever f changes
	closed  bool
	once    sync.Once
}

// swap makes f the device's descriptor and closes the one it replaces, which
// ends a Read waiting on it.
func (d *vpnTUN) swap(f *os.File) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		f.Close()
		return os.ErrClosed
	}
	old := d.f
	d.f = f
	close(d.swapped)
	d.swapped = make(chan struct{})
	d.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}

// current is the descriptor, waiting for the first.
func (d *vpnTUN) current() (*os.File, error) {
	for {
		d.mu.Lock()
		f, closed, swapped := d.f, d.closed, d.swapped
		d.mu.Unlock()
		if closed {
			return nil, os.ErrClosed
		}
		if f != nil {
			return f, nil
		}
		<-swapped
	}
}

func (d *vpnTUN) File() *os.File {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.f
}

func (d *vpnTUN) MTU() (int, error)        { return d.mtu, nil }
func (d *vpnTUN) Name() (string, error)    { return d.name, nil }
func (d *vpnTUN) Events() <-chan tun.Event { return d.events }
func (d *vpnTUN) BatchSize() int           { return 1 }

func (d *vpnTUN) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	for {
		f, err := d.current()
		if err != nil {
			return 0, err
		}
		n, err := f.Read(slab[tun.ReadPacketSpacing : len(slab)-tun.ReadPacketSpacing])
		if err != nil {
			if d.File() != f {
				continue // established again
			}
			return 0, err
		}
		if n == 0 {
			continue
		}
		packets[0] = tun.ReadPacket{Offset: tun.ReadPacketSpacing, Size: n}
		return 1, nil
	}
}

// Write drops what comes before the first descriptor, as a device that is
// down would.
func (d *vpnTUN) Write(bufs [][]byte, offset int) (int, error) {
	f := d.File()
	if f == nil {
		return len(bufs), nil
	}
	for i, buf := range bufs {
		if len(buf) <= offset {
			return i, io.ErrShortBuffer
		}
		if _, err := f.Write(buf[offset:]); err != nil {
			if d.File() != f {
				return len(bufs), nil // established again; these are lost as on any change
			}
			return i, err
		}
	}
	return len(bufs), nil
}

func (d *vpnTUN) Close() error {
	var err error
	d.once.Do(func() {
		d.mu.Lock()
		f := d.f
		d.f, d.closed = nil, true
		close(d.swapped)
		d.mu.Unlock()
		close(d.events)
		if f != nil {
			err = f.Close()
		}
	})
	return err
}

// What the manager finds a VPN's router can by a type assertion, held at
// compile time.
var _ exitRouter = (*vpnRouter)(nil)

// A vpnRouter establishes the device again whenever what it routes changes:
// the device's addresses, the overlay's routes, the internet while an exit
// node is chosen, and the host's DNS.
type vpnRouter struct {
	v     VPN
	cover func() []netip.Prefix
	dev   *vpnTUN
	logf  logger.Logf

	mu              sync.Mutex
	addrs, overlay  []netip.Prefix // as the engine last set them
	internet        bool           // routed into the tunnel, for an exit node
	dns             []netip.Addr
	search          []string
	established     VPNConfig // as last established
	everEstablished bool
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

func (r *vpnRouter) answersThrough() string { return "" }

// establishLocked establishes the device again where its config changed.
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
	if r.internet {
		routes = append(routes, Internet(true, true, append(slices.Clone(cover), r.overlay...))...)
	}
	// The servers taking the host's lookups are in the tunnel, juistd's own
	// resolver among them, which no member's route covers.
	for _, a := range r.dns {
		if !slices.ContainsFunc(routes, func(p netip.Prefix) bool { return p.Contains(a) }) {
			routes = append(routes, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	c := VPNConfig{Addrs: r.addrs, Routes: sortedPrefixes(routes), DNS: r.dns, Search: r.search, MTU: r.dev.mtu}
	if r.everEstablished && c.equal(r.established) {
		return nil
	}
	f, err := r.v.Establish(c)
	if err != nil {
		return err
	}
	if err := r.dev.swap(f); err != nil {
		return err
	}
	r.established, r.everEstablished = c, true
	return nil
}

func (r *vpnRouter) Close() error { return nil }

func sortedPrefixes(ps []netip.Prefix) []netip.Prefix {
	out := slices.Clone(ps)
	slices.SortFunc(out, types.ComparePrefix)
	return slices.Compact(out)
}
