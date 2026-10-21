package conn

import (
	"net/netip"
	"os"

	"github.com/nning/juist/internal/plumber"
)

// A Plumber creates this node's device and sets its addresses and routes, as
// FreeBSD's helper running as root does for a daemon that does not.
type Plumber interface {
	// OpenTUN creates the device, up and with mtu, and returns its
	// descriptor.
	OpenTUN(name string, mtu int) (*os.File, error)
	SetAddrs(dev string, addrs []netip.Prefix) error
	// SetRoutes routes exactly routes into dev, from src4 for IPv4.
	SetRoutes(dev string, routes []netip.Prefix, src4 netip.Addr) error
	// SetServe has the host serve through dev, or no longer where s serves
	// nothing.
	SetServe(dev string, s plumber.ServeSpec) error
	// SetEgress sends the host's traffic outside the overlay as e asks.
	SetEgress(dev string, e plumber.EgressSpec) error
	// SetDNS makes servers, on port 53, the host's resolvers by dev, with
	// search its search domains, or no longer where there are none.
	SetDNS(dev string, servers []netip.Addr, search []string) error
	// Answers says why answers to what comes in by another device would not
	// leave by it, "" where they would.
	Answers(dev string) (string, error)
	Destroy(dev string) error
}

// preferredSrc4 is the first IPv4 address among addrs. With two, as while a
// renumbering is under way, it is the one every peer still accepts, and the
// kernel would otherwise choose by the order the addresses were added in.
func preferredSrc4(addrs []netip.Prefix) netip.Addr {
	for _, p := range addrs {
		if p.Addr().Is4() {
			return p.Addr()
		}
	}
	return netip.Addr{}
}

// HostControl is what juistd does to the host's egress while no mesh runs:
// refusing it, where an exit node is chosen, and clearing that. By Plumber
// where it plumbs Dev, as on FreeBSD; by the kernel's routing and nftables
// on Linux; nothing elsewhere.
type HostControl struct {
	Instance int
	Plumber  Plumber
	Dev      string
}

// RefuseEgress refuses egress as [RefuseEgress] or [RefuseEgressBy] do.
func (h HostControl) RefuseEgress(isolate bool) error {
	if h.Plumber != nil {
		return RefuseEgressBy(h.Plumber, h.Dev, isolate)
	}
	return RefuseEgress(h.Instance, isolate)
}

// ClearEgress clears what RefuseEgress refused.
func (h HostControl) ClearEgress() error {
	if h.Plumber != nil {
		return ClearEgressBy(h.Plumber, h.Dev)
	}
	return ClearEgress(h.Instance)
}

// RefuseEgressBy and ClearEgressBy are [RefuseEgress] and [ClearEgress] where
// p plumbs dev, as on FreeBSD: refused, nothing but local space leaves the
// host, and juistd's own traffic, and answers but with isolate, until a
// router of dev's takes over.
func RefuseEgressBy(p Plumber, dev string, isolate bool) error {
	return p.SetEgress(dev, plumber.EgressSpec{Mode: plumber.EgressRefused, Local: offTunnel(), Isolate: isolate})
}

func ClearEgressBy(p Plumber, dev string) error {
	return p.SetEgress(dev, plumber.EgressSpec{Mode: plumber.EgressDirect})
}
