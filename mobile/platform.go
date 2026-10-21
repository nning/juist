package mobile

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"

	"golang.org/x/sys/unix"
	"tailscale.com/net/netmon"

	"github.com/nning/juist/conn"
)

type sealer struct{ p Platform }

func (s sealer) Seal(plain []byte) ([]byte, error)  { return s.p.Seal(plain) }
func (s sealer) Open(sealed []byte) ([]byte, error) { return s.p.Open(sealed) }

// noPlatform is the platform while no core runs: it refuses everything.
type noPlatform struct{}

func (noPlatform) Protect(int32) bool              { return false }
func (noPlatform) Establish(string) (int32, error) { return -1, errNoCore }
func (noPlatform) Interfaces() (string, error)     { return "", errNoCore }
func (noPlatform) Seal([]byte) ([]byte, error)     { return nil, errNoCore }
func (noPlatform) Open([]byte) ([]byte, error)     { return nil, errNoCore }
func (noPlatform) Log(string)                      {}

// establish is what [Platform.Establish] brings the interface up with: its
// addresses and the routes into it, as prefixes, the DNS servers that take
// all of the phone's lookups, where any, and its MTU.
type establish struct {
	Addrs  []string `json:"addrs"`
	Routes []string `json:"routes"`
	DNS    []string `json:"dns,omitempty"`
	MTU    int      `json:"mtu"`
}

type vpn struct{ p Platform }

func (v vpn) Establish(c conn.VPNConfig) (*os.File, error) {
	e := establish{Addrs: prefixStrings(c.Addrs), Routes: prefixStrings(c.Routes), MTU: c.MTU}
	for _, a := range c.DNS {
		e.DNS = append(e.DNS, a.String())
	}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	fd, err := v.p.Establish(string(b))
	if err != nil {
		return nil, err
	}
	if fd < 0 {
		return nil, fmt.Errorf("mobile: VpnService gave no descriptor")
	}
	// Non-blocking, so that closing it, when established again, ends a read.
	if err := unix.SetNonblock(int(fd), true); err != nil {
		unix.Close(int(fd))
		return nil, err
	}
	return os.NewFile(uintptr(fd), "tun"), nil
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

// An iface is one network interface as [Platform.Interfaces] lists it,
// its addresses as prefixes.
type iface struct {
	Name      string   `json:"name"`
	Index     int      `json:"index"`
	MTU       int      `json:"mtu"`
	Up        bool     `json:"up"`
	Loopback  bool     `json:"loopback"`
	Multicast bool     `json:"multicast"`
	Addrs     []string `json:"addrs"`
}

func interfaces(p Platform) ([]netmon.Interface, error) {
	s, err := p.Interfaces()
	if err != nil {
		return nil, err
	}
	return parseInterfaces(s)
}

func parseInterfaces(s string) ([]netmon.Interface, error) {
	var list []iface
	if err := json.Unmarshal([]byte(s), &list); err != nil {
		return nil, fmt.Errorf("mobile: the interface list: %w", err)
	}
	out := make([]netmon.Interface, 0, len(list))
	for _, l := range list {
		ifi := &net.Interface{Index: l.Index, MTU: l.MTU, Name: l.Name}
		if l.Up {
			ifi.Flags |= net.FlagUp | net.FlagRunning
		}
		if l.Loopback {
			ifi.Flags |= net.FlagLoopback
		}
		if l.Multicast {
			ifi.Flags |= net.FlagMulticast
		}
		addrs := []net.Addr{}
		for _, a := range l.Addrs {
			p, err := netip.ParsePrefix(a)
			if err != nil {
				continue
			}
			addrs = append(addrs, &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())})
		}
		out = append(out, netmon.Interface{Interface: ifi, AltAddrs: addrs})
	}
	return out, nil
}
