package resolved

import (
	"context"
	"net/netip"
	"strings"

	"github.com/godbus/dbus/v5"
)

// A Routing is where resolved asks each name, by its links' servers and
// domains as they were read, but for one link's.
type Routing struct {
	Scopes []Scope
}

// A Scope is one link's servers, or the global ones at Ifindex 0, with its
// Domains, lowercase without a final dot, "" for ".", and whether it takes
// every name no other link's domain claims.
type Scope struct {
	Ifindex      int
	Servers      []netip.AddrPort
	Domains      []string
	DefaultRoute bool
}

// Routing reads how resolved routes names to every link but skip's, and to
// its global servers.
func (c *Client) Routing(skip int) (Routing, error) {
	var servers []struct {
		Ifindex int32
		Family  int32
		Address []byte
		Port    uint16
		Name    string
	}
	if err := c.property(c.obj, manager, "DNSEx", &servers); err != nil {
		return Routing{}, err
	}
	var domains []struct {
		Ifindex   int32
		Domain    string
		RouteOnly bool
	}
	if err := c.property(c.obj, manager, "Domains", &domains); err != nil {
		return Routing{}, err
	}
	byLink := map[int]*Scope{}
	var order []int
	at := func(i int) *Scope {
		if s, ok := byLink[i]; ok {
			return s
		}
		s := &Scope{Ifindex: i, DefaultRoute: i == 0}
		byLink[i] = s
		order = append(order, i)
		return s
	}
	for _, s := range servers {
		a, ok := netip.AddrFromSlice(s.Address)
		if int(s.Ifindex) == skip || !ok {
			continue
		}
		sc := at(int(s.Ifindex))
		sc.Servers = append(sc.Servers, netip.AddrPortFrom(a.Unmap(), cmpPort(s.Port)))
	}
	for _, d := range domains {
		if sc, ok := byLink[int(d.Ifindex)]; ok {
			sc.Domains = append(sc.Domains, strings.ToLower(strings.Trim(d.Domain, ".")))
		}
	}
	var r Routing
	for _, i := range order {
		sc := byLink[i]
		if i != 0 {
			path, err := c.linkPath(i)
			if err != nil {
				return Routing{}, err
			}
			if err := c.property(c.conn.Object(busName, path), busName+".Link", "DefaultRoute", &sc.DefaultRoute); err != nil {
				return Routing{}, err
			}
		}
		r.Scopes = append(r.Scopes, *sc)
	}
	return r, nil
}

func cmpPort(p uint16) uint16 {
	if p == 0 {
		return 53
	}
	return p
}

func (c *Client) linkPath(ifindex int) (dbus.ObjectPath, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	var path dbus.ObjectPath
	err := c.obj.CallWithContext(ctx, manager+".GetLink", 0, int32(ifindex)).Store(&path)
	return path, err
}

func (c *Client) property(obj dbus.BusObject, iface, name string, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	var v dbus.Variant
	if err := obj.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, iface, name).Store(&v); err != nil {
		return err
	}
	return v.Store(out)
}

// Servers are those resolved asks name of, as it routes it: the links whose
// domain matching it is longest, else those that take every name, in the
// order they were read; none where no link would be asked.
func (r Routing) Servers(name string) []netip.AddrPort {
	name = strings.ToLower(strings.Trim(name, "."))
	best := -1
	var out []netip.AddrPort
	for _, sc := range r.Scopes {
		n := -1
		for _, d := range sc.Domains {
			if l := matches(name, d); l > n {
				n = l
			}
		}
		switch {
		case n > best:
			best, out = n, append([]netip.AddrPort{}, sc.Servers...)
		case n == best && n >= 0:
			out = append(out, sc.Servers...)
		}
	}
	if best >= 0 {
		return out
	}
	out = []netip.AddrPort{}
	for _, sc := range r.Scopes {
		if sc.DefaultRoute {
			out = append(out, sc.Servers...)
		}
	}
	return out
}

// matches is how many labels of domain, "" for the root, name is under, -1
// where it is under none of it.
func matches(name, domain string) int {
	switch {
	case domain == "":
		return 0
	case name == domain || strings.HasSuffix(name, "."+domain):
		return strings.Count(domain, ".") + 1
	}
	return -1
}
