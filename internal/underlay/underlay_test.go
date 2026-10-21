package underlay

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/net/netmon"
)

// TestInternalInterface: what leads only into this host is left out of what a
// device announces, and what may carry its LAN address is not.
func TestInternalInterface(t *testing.T) {
	for name, want := range map[string]bool{
		"juist0":          true,
		"tailscale0":      true,
		"ztabcdef12":      true,
		"docker0":         true,
		"br-3f2a9c0d1e4b": true,
		"veth1a2b3c":      true,
		"virbr0":          true,
		"lxcbr0":          true,
		"podman0":         true,
		"eth0":            false,
		"enp3s0":          false,
		"wlp2s0":          false,
		"br0":             false,
		"br-lan":          false,
		"br-3F2A9C0D1E4B": false,
	} {
		if got := InternalInterface(name); got != want {
			t.Errorf("InternalInterface(%q) = %v, want %v", name, got, want)
		}
	}
}

// phoneInterfaces registers a lister of interfaces no host has, as the
// Android app does, so a scan that reads net.Interfaces finds none of them.
func phoneInterfaces(t *testing.T) {
	ifc := func(name string, flags net.Flags, addrs ...string) netmon.Interface {
		var as []net.Addr
		for _, a := range addrs {
			p := netip.MustParsePrefix(a)
			as = append(as, &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())})
		}
		return netmon.Interface{Interface: &net.Interface{Index: 9000, Name: name, Flags: flags}, AltAddrs: as}
	}
	up := net.FlagUp | net.FlagRunning
	netmon.RegisterInterfaceGetter(func() ([]netmon.Interface, error) {
		return []netmon.Interface{
			ifc("phonelo", up|net.FlagLoopback, "127.0.0.1/8"),
			ifc("phonewlan", up, "192.168.77.23/24", "fe80::77/64"),
			ifc("phonedown", 0, "10.77.0.5/16"),
			ifc("juist77", up, "100.77.0.1/32"),
		}, nil
	})
	t.Cleanup(func() { netmon.RegisterInterfaceGetter(nil) })
}

func names(ifs []Interface) []string {
	var out []string
	for _, i := range ifs {
		out = append(out, i.Name)
	}
	return out
}

func TestInterfacesAreNetmonsAndFiltered(t *testing.T) {
	phoneInterfaces(t)
	for _, c := range []struct {
		f    Filter
		want []string
	}{
		{Filter{}, []string{"phonelo", "phonewlan", "phonedown", "juist77"}},
		{Filter{Up: true}, []string{"phonelo", "phonewlan", "juist77"}},
		{Filter{NoLoopback: true}, []string{"phonewlan", "phonedown", "juist77"}},
		{Filter{Up: true, NoLoopback: true, Skip: "juist77"}, []string{"phonewlan"}},
	} {
		if got := names(Interfaces(c.f)); !slices.Equal(got, c.want) {
			t.Errorf("Interfaces(%+v) = %v, want %v", c.f, got, c.want)
		}
	}
	got := Interfaces(Filter{Skip: "phonelo"})[0].Prefixes
	want := []netip.Prefix{netip.MustParsePrefix("192.168.77.23/24"), netip.MustParsePrefix("fe80::77/64")}
	if !slices.Equal(got, want) {
		t.Errorf("phonewlan's prefixes = %v, want %v", got, want)
	}
	addrs, internal := Scan()
	if w := []netip.Addr{netip.MustParseAddr("192.168.77.23"), netip.MustParseAddr("fe80::77")}; !slices.Equal(addrs, w) {
		t.Errorf("Scan's addrs = %v, want %v", addrs, w)
	}
	if w := []netip.Addr{netip.MustParseAddr("100.77.0.1")}; !slices.Equal(internal, w) {
		t.Errorf("Scan's internal = %v, want %v", internal, w)
	}
}
