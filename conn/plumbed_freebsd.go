package conn

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"syscall"

	"github.com/tailscale/wireguard-go/tun"
	"go4.org/netipx"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/router"

	"github.com/nning/juist/internal/plumber"
)

// tunNeeds is what creating a device takes here: juistd started as root
// keeps root for its helper alone.
const tunNeeds = "root"

// newPlumbed is the device p creates and the router that has p route it.
// wireguard-go's own FreeBSD device will not do: it sets its MTU itself,
// which only root may.
func newPlumbed(p Plumber, name string, inst, mtu int, logf logger.Logf) (tun.Device, router.Router, error) {
	f, err := p.OpenTUN(name, mtu)
	if err != nil {
		return nil, nil, err
	}
	d := &plumbedTUN{p: p, f: f, name: name, mtu: mtu, events: make(chan tun.Event, 1)}
	d.events <- tun.EventUp
	return d, &plumbedRouter{p: p, dev: name, inst: inst, logf: logger.WithPrefix(logf, "router: "),
		done: make(chan struct{})}, nil
}

// A plumbedTUN is a FreeBSD TUN device on a descriptor the helper opened,
// each packet behind a four-byte address family, as TUNSIFHEAD has it.
type plumbedTUN struct {
	p      Plumber
	f      *os.File
	name   string
	mtu    int
	events chan tun.Event
	once   sync.Once
}

func (d *plumbedTUN) File() *os.File           { return d.f }
func (d *plumbedTUN) MTU() (int, error)        { return d.mtu, nil }
func (d *plumbedTUN) Name() (string, error)    { return d.name, nil }
func (d *plumbedTUN) Events() <-chan tun.Event { return d.events }
func (d *plumbedTUN) BatchSize() int           { return 1 }

func (d *plumbedTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if offset < 4 {
		return 0, io.ErrShortBuffer
	}
	n, err := d.f.Read(bufs[0][offset-4:])
	if n < 4 {
		return 0, err
	}
	sizes[0] = n - 4
	return 1, err
}

func (d *plumbedTUN) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 4 {
		return 0, io.ErrShortBuffer
	}
	for i, buf := range bufs {
		buf = buf[offset-4:]
		if len(buf) < 5 {
			return i, io.ErrShortBuffer
		}
		buf[0], buf[1], buf[2] = 0, 0, 0
		switch buf[4] >> 4 {
		case 4:
			buf[3] = unix.AF_INET
		case 6:
			buf[3] = unix.AF_INET6
		default:
			return i, unix.EAFNOSUPPORT
		}
		if _, err := d.f.Write(buf); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

// Close destroys the device, and with it its addresses and routes.
func (d *plumbedTUN) Close() error {
	var err error
	d.once.Do(func() {
		close(d.events)
		err = errors.Join(d.f.Close(), d.p.Destroy(d.name))
	})
	return err
}

// A plumbedRouter has the helper give the device the node's addresses and its
// peers' routes. The host's one table holds them: instances are kept apart
// by their prefixes, as the IPv4 yield of [InstanceHoldings] keeps them.
type plumbedRouter struct {
	p    Plumber
	dev  string
	inst int
	logf logger.Logf
	done chan struct{} // closes with the router, ending the watch of routes
	once sync.Once

	mu    sync.Mutex
	addrs []netip.Prefix // the device's, as last set
}

func (r *plumbedRouter) Up() error { return nil }

func (r *plumbedRouter) Set(cfg *router.Config) error {
	if cfg == nil {
		cfg = &router.Config{}
	}
	var errs []error
	errs = append(errs, r.p.SetAddrs(r.dev, cfg.LocalAddrs))
	r.mu.Lock()
	r.addrs = slices.Clone(cfg.LocalAddrs)
	r.mu.Unlock()
	// A route to an address of the device's own is the device's already.
	routes := slices.DeleteFunc(slices.Clone(cfg.Routes), func(p netip.Prefix) bool {
		return slices.ContainsFunc(cfg.LocalAddrs, func(a netip.Prefix) bool { return a.Addr() == p.Addr() && p.IsSingleIP() })
	})
	errs = append(errs, r.p.SetRoutes(r.dev, routes, preferredSrc4(cfg.LocalAddrs)))
	return errors.Join(errs...)
}

// setServe has the helper serve s through the device: its addresses the ones
// DNS is asked on.
func (r *plumbedRouter) setServe(s Serve) error {
	if !s.serving() {
		return r.p.SetServe(r.dev, plumber.ServeSpec{})
	}
	r.mu.Lock()
	var addrs []netip.Addr
	for _, a := range r.addrs {
		addrs = append(addrs, a.Addr())
	}
	r.mu.Unlock()
	return r.p.SetServe(r.dev, plumber.ServeSpec{Sources: s.Sources, Addrs: addrs, DNSPort: s.DNS, Local: offTunnel()})
}

// setEgress has the helper send the host's internet traffic as e asks: into
// the device, less what the host keeps and routers carry, the families no
// exit node carries refused, as on Linux.
func (r *plumbedRouter) setEgress(e Egress, t tunnelled) error {
	spec := plumber.EgressSpec{Mode: plumber.EgressDirect}
	if e != EgressDirect {
		r.mu.Lock()
		v6 := slices.ContainsFunc(r.addrs, func(p netip.Prefix) bool { return p.Addr().Is6() })
		r.mu.Unlock()
		mode := plumber.EgressTunnel
		if e == EgressRefused {
			mode = plumber.EgressRefused
		}
		spec = plumber.EgressSpec{Mode: mode, V4: t.v4, V6: t.v6, Subnets: t.subnets, Local: offTunnel(),
			Capture: lessOf(Internet(true, v6, nil), t.subnets), Isolate: t.answers}
	}
	return r.p.SetEgress(r.dev, spec)
}

// lessOf is ps without what take holds.
func lessOf(ps, take []netip.Prefix) []netip.Prefix {
	var b netipx.IPSetBuilder
	for _, p := range ps {
		b.AddPrefix(p)
	}
	for _, p := range take {
		b.RemovePrefix(p)
	}
	s, _ := b.IPSet()
	return s.Prefixes()
}

func (r *plumbedRouter) lans() ([]netip.Prefix, []netip.Addr) { return attached(r.dev) }

func (r *plumbedRouter) answersThrough() string {
	why, err := r.p.Answers(r.dev)
	if err != nil {
		return err.Error()
	}
	return why
}

// Close leaves the routes to the device's destruction.
func (r *plumbedRouter) Close() error {
	r.once.Do(func() { close(r.done) })
	return nil
}

// hostRoutes is what the host reaches but by its default routes: the routes
// of the one table but those into this device, a higher instance's or the
// loopback, and those a redirect made, which anyone on the LAN can send.
func (r *plumbedRouter) hostRoutes() []netip.Prefix {
	skip, err := r.notTheHosts()
	if err != nil {
		return nil
	}
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || skip[rm.Index] || !hostsOwn(rm.Flags) {
			continue
		}
		if p, ok := routeDst(rm); ok && p.Bits() > 0 && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// hostsOwn reports whether a route of flags is the host's own: none an ICMP
// redirect made or changed, nor one that drops what it takes.
func hostsOwn(flags int) bool {
	return flags&(syscall.RTF_DYNAMIC|syscall.RTF_MODIFIED|syscall.RTF_REJECT|syscall.RTF_BLACKHOLE) == 0
}

// notTheHosts is the devices whose routes are not the host's own: this one,
// a higher instance's, and the loopback, by index.
func (r *plumbedRouter) notTheHosts() (map[int]bool, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	skip := map[int]bool{}
	for _, ifc := range ifs {
		inst, juist := deviceInstance(ifc.Name)
		if ifc.Name == r.dev || ifc.Flags&net.FlagLoopback != 0 || juist && inst >= r.inst {
			skip[ifc.Index] = true
		}
	}
	return skip, nil
}

// watchHostRoutes calls changed, from a goroutine of its own, whenever a route
// of the host's comes, goes or changes, until the router closes: the network
// monitor hears devd's interface events alone.
func (r *plumbedRouter) watchHostRoutes(changed func()) {
	// Non-blocking, so that closing it ends the read.
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.AF_UNSPEC)
	if err != nil {
		r.logf("watching the host's routes: %v", err)
		return
	}
	f := os.NewFile(uintptr(fd), "route")
	go func() {
		<-r.done
		f.Close()
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := f.Read(buf)
			if err != nil {
				return
			}
			// rt_msghdr: length, version, type, then the device's index.
			if n < 6 {
				continue
			}
			switch buf[3] {
			case unix.RTM_ADD, unix.RTM_DELETE, unix.RTM_CHANGE:
				skip, err := r.notTheHosts()
				if err == nil && !skip[int(binary.NativeEndian.Uint16(buf[4:6]))] {
					changed()
				}
			}
		}
	}()
}
