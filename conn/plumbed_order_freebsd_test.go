package conn

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"testing"

	"tailscale.com/wgengine/router"

	"github.com/nning/juist/internal/plumber"
)

// orderPlumber records the addresses and routes it is asked to set, in order.
type orderPlumber struct{ calls []string }

func (p *orderPlumber) OpenTUN(string, int) (*os.File, error) { return nil, nil }
func (p *orderPlumber) SetAddrs(_ string, a []netip.Prefix) error {
	p.calls = append(p.calls, fmt.Sprint("addrs ", a))
	return nil
}
func (p *orderPlumber) SetRoutes(_ string, _ []netip.Prefix, src netip.Addr) error {
	p.calls = append(p.calls, fmt.Sprint("routes from ", src))
	return nil
}
func (p *orderPlumber) SetServe(string, plumber.ServeSpec) error    { return nil }
func (p *orderPlumber) SetGuard(string, plumber.GuardSpec) error    { return nil }
func (p *orderPlumber) SetEgress(string, plumber.EgressSpec) error  { return nil }
func (p *orderPlumber) SetDNS(string, []netip.Addr, []string) error { return nil }
func (p *orderPlumber) Answers(string) (string, error)              { return "", nil }
func (p *orderPlumber) Destroy(string) error                        { return nil }

// An address the device takes is on it before a route's source names it,
// whether or not one goes, and one that goes comes off after.
func TestAPlumbedRouterAddsAddressesBeforeRoutes(t *testing.T) {
	p := &orderPlumber{}
	r := &plumbedRouter{p: p, dev: "juist0", done: make(chan struct{})}
	v4, v6 := netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("fd7a:115c:a1e0::1/128")
	moved := netip.MustParsePrefix("10.7.0.1/32")
	routes := []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}
	for _, step := range []struct {
		addrs []netip.Prefix
		want  []string
	}{
		{[]netip.Prefix{v4, v6}, []string{"addrs [100.64.0.1/32 fd7a:115c:a1e0::1/128]", "routes from 100.64.0.1",
			"addrs [100.64.0.1/32 fd7a:115c:a1e0::1/128]"}},
		{[]netip.Prefix{v6}, []string{"routes from invalid IP", "addrs [fd7a:115c:a1e0::1/128]"}},
		{[]netip.Prefix{v6, v4}, []string{"addrs [fd7a:115c:a1e0::1/128 100.64.0.1/32]", "routes from 100.64.0.1",
			"addrs [fd7a:115c:a1e0::1/128 100.64.0.1/32]"}},
		{[]netip.Prefix{moved, v6}, []string{"addrs [10.7.0.1/32 fd7a:115c:a1e0::1/128 100.64.0.1/32]", "routes from 10.7.0.1",
			"addrs [10.7.0.1/32 fd7a:115c:a1e0::1/128]"}},
	} {
		p.calls = nil
		if err := r.Set(&router.Config{LocalAddrs: step.addrs, Routes: routes}); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(p.calls, step.want) {
			t.Errorf("to %v: %q, want %q", step.addrs, p.calls, step.want)
		}
	}
}
