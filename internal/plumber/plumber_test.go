//go:build unix

package plumber

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeHost records what the helper does, handing out a pipe as the device.
type fakeHost struct {
	mu        sync.Mutex
	calls     []string
	destroyed []string
	// onePath refuses a second route to a prefix, as a kernel without
	// multipath routing does; routes are those held then.
	onePath bool
	routes  map[netip.Prefix]int
	// held are the host's addresses and gateways.
	held []netip.Addr
}

func (h *fakeHost) record(format string, a ...any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, fmt.Sprintf(format, a...))
}

func (h *fakeHost) OpenTUN(name string, mtu int) (*os.File, func() error, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	w.Close()
	h.record("open %s %d", name, mtu)
	return r, func() error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.destroyed = append(h.destroyed, name)
		return nil
	}, nil
}

func (h *fakeHost) AddAddr(dev string, p netip.Prefix) error {
	h.record("addr+ %s %v", dev, p)
	return nil
}

func (h *fakeHost) DelAddr(dev string, p netip.Prefix) error {
	h.record("addr- %s %v", dev, p)
	return nil
}

func (h *fakeHost) AddRoute(dev string, p netip.Prefix, src netip.Addr) error {
	h.mu.Lock()
	if h.routes == nil {
		h.routes = map[netip.Prefix]int{}
	}
	if h.onePath && h.routes[p] > 0 {
		h.mu.Unlock()
		return unix.EEXIST
	}
	h.routes[p]++
	h.mu.Unlock()
	h.record("route+ %s %v %v", dev, p, src)
	return nil
}

func (h *fakeHost) DelRoute(dev string, p netip.Prefix, _ netip.Addr) error {
	h.mu.Lock()
	h.routes[p]--
	h.mu.Unlock()
	h.record("route- %s %v", dev, p)
	return nil
}

// inOrder is what the helper did since the last look, in order.
func (h *fakeHost) inOrder() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.calls
	h.calls = nil
	return c
}

func (h *fakeHost) SetServe(dev string, s ServeSpec) error {
	h.record("serve %s %v dns %d", dev, s.Sources, s.DNSPort)
	return nil
}

func (h *fakeHost) SetEgress(dev string, e EgressSpec, uid int) error {
	h.record("egress %s %s uid %d", dev, e.Mode, uid)
	return nil
}

func (h *fakeHost) ListenHTTPS(a netip.Addr) (*os.File, error) {
	h.record("listen %v", a)
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	return ln.File()
}

func (h *fakeHost) Free(string) bool { return true }

func (h *fakeHost) HostAddrs() []netip.Addr { return h.held }

func (h *fakeHost) SetGuard(dev string, g GuardSpec) error {
	h.record("guard %s %v %v", dev, g.Own, g.Overlay)
	return nil
}
func (h *fakeHost) Answers() string { return "the host's rules" }

func (h *fakeHost) SetDNS(dev string, servers []netip.Addr, search []string) error {
	if len(search) > 0 {
		h.record("dns %s %v search %v", dev, servers, search)
		return nil
	}
	h.record("dns %s %v", dev, servers)
	return nil
}

func (h *fakeHost) ListenDNS(a netip.Addr, proto string) (*os.File, error) {
	h.record("listen dns %v %s", a, proto)
	if proto == "udp" {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return nil, err
		}
		defer c.Close()
		return c.File()
	}
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	return ln.File()
}

func (h *fakeHost) took() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := slices.Clone(h.calls)
	h.calls = nil
	slices.Sort(c)
	return c
}

// pair is a client on one end of a socket pair and the helper serving the
// other, which returns into done.
func pair(t *testing.T, h Host) (*Client, chan error) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	c, err := NewClient(os.NewFile(uintptr(fds[0]), "daemon"))
	if err != nil {
		t.Fatal(err)
	}
	fc, err := net.FileConn(os.NewFile(uintptr(fds[1]), "helper"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		destroy, err := Serve(fc.(*net.UnixConn), h, 870, "juist0", t.Logf)
		destroy()
		done <- err
	}()
	t.Cleanup(func() { c.Close() })
	return c, done
}

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// The daemon gets its device's descriptor, and the helper sets exactly the
// addresses and routes asked, from the source asked for IPv4, changing only
// what changed; hung up on, it destroys the device.
func TestTheHelperPlumbsWhatItIsAsked(t *testing.T) {
	h := &fakeHost{}
	c, done := pair(t, h)
	f, err := c.OpenTUN("juist0", 1280)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if got := h.took(); !slices.Equal(got, []string{"open juist0 1280"}) {
		t.Errorf("opening: %q", got)
	}
	if err := c.SetAddrs("juist0", prefixes("10.11.11.11/32", "fd90::1/128")); err != nil {
		t.Fatal(err)
	}
	if err := c.SetRoutes("juist0", prefixes("10.11.11.12/32", "fd90::2/128"), netip.MustParseAddr("10.11.11.11")); err != nil {
		t.Fatal(err)
	}
	want := []string{"addr+ juist0 10.11.11.11/32", "addr+ juist0 fd90::1/128",
		"route+ juist0 10.11.11.12/32 10.11.11.11", "route+ juist0 fd90::2/128 invalid IP"}
	if got := h.took(); !slices.Equal(got, want) {
		t.Errorf("plumbing: %q, want %q", got, want)
	}
	// Renumbered: the old address goes, and the IPv4 route takes the new
	// source; the IPv6 one stays.
	if err := c.SetAddrs("juist0", prefixes("10.11.12.11/32", "fd90::1/128")); err != nil {
		t.Fatal(err)
	}
	if err := c.SetRoutes("juist0", prefixes("10.11.11.12/32", "fd90::2/128"), netip.MustParseAddr("10.11.12.11")); err != nil {
		t.Fatal(err)
	}
	want = []string{"addr+ juist0 10.11.12.11/32", "addr- juist0 10.11.11.11/32",
		"route+ juist0 10.11.11.12/32 10.11.12.11", "route- juist0 10.11.11.12/32"}
	if got := h.took(); !slices.Equal(got, want) {
		t.Errorf("renumbering: %q, want %q", got, want)
	}
	c.Close()
	if err := <-done; err != nil {
		t.Errorf("serving: %v", err)
	}
	if !slices.Equal(h.destroyed, []string{"juist0"}) {
		t.Errorf("hung up on, the helper destroyed %q", h.destroyed)
	}
}

// A route taking a new source goes in before the old one goes, where the
// kernel holds both, so the prefix is never without a route; where it holds
// one, the old goes first.
func TestARouteFromANewSourceGoesInFirst(t *testing.T) {
	for _, onePath := range []bool{false, true} {
		h := &fakeHost{onePath: onePath}
		c, _ := pair(t, h)
		f, err := c.OpenTUN("juist0", 1280)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		peer := prefixes("10.11.11.12/32")
		if err := c.SetAddrs("juist0", prefixes("10.11.11.11/32", "10.11.12.11/32")); err != nil {
			t.Fatal(err)
		}
		if err := c.SetRoutes("juist0", peer, netip.MustParseAddr("10.11.11.11")); err != nil {
			t.Fatal(err)
		}
		h.inOrder()
		if err := c.SetRoutes("juist0", peer, netip.MustParseAddr("10.11.12.11")); err != nil {
			t.Fatalf("one path %v: %v", onePath, err)
		}
		want := []string{"route+ juist0 10.11.11.12/32 10.11.12.11", "route- juist0 10.11.11.12/32"}
		if onePath {
			want[0], want[1] = want[1], want[0]
		}
		if got := h.inOrder(); !slices.Equal(got, want) {
			t.Errorf("one path %v: %q, want %q", onePath, got, want)
		}
	}
}

// Nothing but juist's own devices, opened here, is touched, and no default
// route goes in this way.
func TestTheHelperTouchesNothingElse(t *testing.T) {
	h := &fakeHost{}
	c, _ := pair(t, h)
	for _, tc := range []struct {
		name string
		err  func() error
		want string
	}{
		{"another device", func() error { _, err := c.OpenTUN("em0", 1280); return err }, "no device of juist's"},
		{"a tiny MTU", func() error { _, err := c.OpenTUN("juist0", 576); return err }, "MTU"},
		{"a device not opened", func() error { return c.SetAddrs("juist0", prefixes("10.0.0.1/32")) }, "not opened here"},
		{"its destruction", func() error { return c.Destroy("juist0") }, "not opened here"},
	} {
		if err := tc.err(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	f, err := c.OpenTUN("juist0", 1280)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := c.OpenTUN("juist0", 1280); err == nil {
		t.Error("a device opened twice")
	}
	err = c.SetRoutes("juist0", prefixes("0.0.0.0/0", "10.1.0.0/16"), netip.Addr{})
	if err == nil || !strings.Contains(err.Error(), "default route") {
		t.Errorf("a default route: %v", err)
	}
	if got := h.took(); !slices.Equal(got, []string{"open juist0 1280", "route+ juist0 10.1.0.0/16 invalid IP"}) {
		t.Errorf("the host saw %q", got)
	}
}

// A route set bigger than the socket's buffer goes whole, and the calls
// after it are answered: a network of many members routes on FreeBSD, whose
// buffers hold 8 KiB.
func TestALargeRouteSetGoesWhole(t *testing.T) {
	h := &fakeHost{}
	c, _ := pair(t, h)
	f, err := c.OpenTUN("juist0", 1280)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	var routes []netip.Prefix
	for i := range 60000 {
		routes = append(routes, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 32))
	}
	if err := c.SetRoutes("juist0", routes, netip.Addr{}); err != nil {
		t.Fatalf("a large route set: %v", err)
	}
	if err := c.SetAddrs("juist0", prefixes("10.11.11.11/32")); err != nil {
		t.Fatalf("the call after it: %v", err)
	}
	if got := len(h.took()); got != 60000+2 {
		t.Errorf("the host saw %d calls", got)
	}
}

// An address wider than one host is refused: it would route the rest of its
// prefix into the device.
func TestAnAddressIsOneHost(t *testing.T) {
	h := &fakeHost{}
	c, _ := pair(t, h)
	f, err := c.OpenTUN("juist0", 1280)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	err = c.SetAddrs("juist0", prefixes("fd90::1/1", "10.0.0.1/1", "10.11.11.11/32"))
	if err == nil || !strings.Contains(err.Error(), "more than one host") {
		t.Errorf("wide addresses: %v", err)
	}
	if got := h.took(); !slices.Equal(got, []string{"addr+ juist0 10.11.11.11/32", "open juist0 1280"}) {
		t.Errorf("the host saw %q", got)
	}
}

// A link-local address is taken where it is a member's own: fe80::/64 and
// the low half of one of the device's overlay IPv6 addresses.
func TestALinkLocalAddressIsTheDevicesOwn(t *testing.T) {
	h := &fakeHost{}
	c, _ := pair(t, h)
	f, err := c.OpenTUN("juist0", 1280)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := c.SetAddrs("juist0", prefixes("fd90::1:2:3:4/128", "fe80::1:2:3:4/128")); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"fe80::9/128", "fe80:1::1:2:3:4/128", "fe80::1:2:3:4/64", "fe81::1:2:3:4/128"} {
		err := c.SetAddrs("juist0", prefixes("fd90::1:2:3:4/128", bad))
		if err == nil || !strings.Contains(err.Error(), "outside any network's space") && !strings.Contains(err.Error(), "more than one host") {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if got := h.took(); !slices.Contains(got, "addr+ juist0 fe80::1:2:3:4/128") || slices.ContainsFunc(got, func(c string) bool {
		return strings.HasPrefix(c, "addr+") && strings.Contains(c, "fe8") && !strings.HasSuffix(c, "fe80::1:2:3:4/128")
	}) {
		t.Errorf("the host saw %q", got)
	}
}

// slowHost takes longer than a call may over every route.
type slowHost struct{ fakeHost }

func (h *slowHost) AddRoute(dev string, p netip.Prefix, src netip.Addr) error {
	// Well past the deadline, which a slow machine's timers may miss by
	// a little.
	time.Sleep(2 * time.Second)
	return h.fakeHost.AddRoute(dev, p, src)
}

// A call the helper does not answer in time breaks the client for good,
// rather than have the next call read its answer.
func TestALateAnswerIsNoOtherCallsAnswer(t *testing.T) {
	was := callTimeout
	callTimeout = 200 * time.Millisecond
	t.Cleanup(func() { callTimeout = was })
	c, _ := pair(t, &slowHost{})
	f, err := c.OpenTUN("juist0", 1280)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := c.SetRoutes("juist0", prefixes("0.0.0.0/0", "10.1.0.0/16"), netip.Addr{}); err == nil {
		t.Fatal("a late answer came in time")
	}
	select {
	case <-c.Broken():
	default:
		t.Error("the client is not broken")
	}
	time.Sleep(2500 * time.Millisecond)
	err = c.SetAddrs("juist0", prefixes("10.11.11.11/32"))
	if err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("the call after a late answer: %v", err)
	}
}

// Egress goes by the daemon's user as the helper started it, not the
// socket's creator, the helper itself.
func TestEgressIsTheDaemonsUser(t *testing.T) {
	h := &fakeHost{}
	c, _ := pair(t, h)
	f, err := c.OpenTUN("juist0", 1280)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := c.SetEgress("juist0", EgressSpec{Mode: EgressRefused}); err != nil {
		t.Fatal(err)
	}
	if got := h.took(); !slices.Contains(got, "egress juist0 refused uid 870") {
		t.Errorf("the host saw %q", got)
	}
}

// What serving writes into pf's rules is the device's own addresses alone:
// one with a zone could carry rules of the daemon's own.
func TestServingTakesTheDevicesAddressesAlone(t *testing.T) {
	h := &fakeHost{}
	c, _ := pair(t, h)
	f, err := c.OpenTUN("juist0", 1280)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := c.SetAddrs("juist0", prefixes("198.19.44.1/32")); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"fe80::1%x\npass in quick all", "198.19.44.2"} {
		err := c.SetServe("juist0", ServeSpec{Sources: prefixes("198.19.44.0/22"), Addrs: []netip.Addr{netip.MustParseAddr(a)}, DNSPort: 41646})
		if err == nil || !strings.Contains(err.Error(), "no address of juist0") {
			t.Errorf("serving on %q: %v", a, err)
		}
	}
	if err := c.SetServe("juist0", ServeSpec{Sources: prefixes("198.19.44.0/22"),
		Addrs: []netip.Addr{netip.MustParseAddr("198.19.44.1")}, DNSPort: 41646}); err != nil {
		t.Errorf("serving on its own: %v", err)
	}
	if got := h.took(); slices.ContainsFunc(got, func(s string) bool { return strings.Contains(s, "pass in") }) {
		t.Errorf("the host saw %q", got)
	}
}

// What a guard writes into pf's rules is addresses in the overlay's space
// alone: a LAN host's would keep it from the LAN.
func TestAGuardTakesTheOverlaysAddressesAlone(t *testing.T) {
	h := &fakeHost{}
	c, _ := pair(t, h)
	f, err := c.OpenTUN("juist0", 1280)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := c.SetAddrs("juist0", prefixes("198.19.44.1/32", "fd12::1/128")); err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddr
	for _, tc := range []struct {
		g    GuardSpec
		want string
	}{
		{GuardSpec{Own: []netip.Addr{a("203.0.113.9")}}, "outside any network's space"},
		{GuardSpec{Overlay: []netip.Addr{a("192.0.2.7")}}, "outside any network's space"},
		{GuardSpec{Overlay: []netip.Addr{a("fd12::2%x\npass in quick all")}}, "outside any network's space"},
	} {
		if err := c.SetGuard("juist0", tc.g); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("guarding %v: %v, want %q", tc.g, err, tc.want)
		}
	}
	if err := c.SetGuard("juist0", GuardSpec{Own: []netip.Addr{a("198.19.44.1"), a("fd12::1")},
		Overlay: []netip.Addr{a("198.19.44.2"), a("fd12::2")}}); err != nil {
		t.Errorf("guarding its own and its peers': %v", err)
	}
	if got := h.took(); !slices.Contains(got, "guard juist0 [198.19.44.1 fd12::1] [198.19.44.2 fd12::2]") {
		t.Errorf("the host saw %q", got)
	}
}

// No route into the device takes the host's own address or a gateway of its
// routes, so not its LAN whole; a part of a wider network it is on, which a
// subnet may be, it does take.
func TestTheHelperRoutesNothingOverTheHostsOwnLAN(t *testing.T) {
	h := &fakeHost{held: []netip.Addr{netip.MustParseAddr("10.20.0.7"), netip.MustParseAddr("10.20.0.1"),
		netip.MustParseAddr("fe80::1%em0")}}
	c, _ := pair(t, h)
	f, err := c.OpenTUN("juist0", 1280)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	for _, p := range []string{"10.20.0.0/24", "10.20.0.1/32", "10.0.0.0/8", "10.20.0.7/32"} {
		err := c.SetRoutes("juist0", prefixes(p), netip.Addr{})
		if err == nil || !strings.Contains(err.Error(), "over the host's own LAN") {
			t.Errorf("a route to %s: %v", p, err)
		}
	}
	if err := c.SetRoutes("juist0", prefixes("10.20.0.128/25", "10.30.0.0/16"), netip.Addr{}); err != nil {
		t.Errorf("a subnet beside the host's: %v", err)
	}
	if got := h.took(); slices.ContainsFunc(got, func(s string) bool {
		return strings.Contains(s, "route+ juist0 10.20.0.0/24") || strings.Contains(s, "route+ juist0 10.0.0.0/8")
	}) {
		t.Errorf("the host saw %q", got)
	}
}

// A helper plumbs its own daemon's device alone: another network's daemon,
// taken over, lifts no refusal of this one's while it is stopped, nor sets
// its DNS or opens its device.
func TestTheHelperPlumbsItsDaemonsDeviceAlone(t *testing.T) {
	h := &fakeHost{}
	c, _ := pair(t, h)
	for what, err := range map[string]error{
		"lifting a refusal": c.SetEgress("juist1", EgressSpec{Mode: EgressDirect}),
		"giving DNS back":   c.SetDNS("juist1", nil, nil),
		"opening":           func() error { _, err := c.OpenTUN("juist1", 1280); return err }(),
	} {
		if err == nil || !strings.Contains(err.Error(), "no device of this juistd's") {
			t.Errorf("%s on another's device: %v", what, err)
		}
	}
	if got := h.took(); len(got) != 0 {
		t.Errorf("the host saw %q", got)
	}
}

// The daemon asks whether answers leave the way they came, before any device.
func TestTheHelperSaysWhereAnswersGo(t *testing.T) {
	c, _ := pair(t, &fakeHost{})
	got, err := c.Answers("juist0")
	if err != nil || got != "the host's rules" {
		t.Errorf("answers: %q, %v", got, err)
	}
}

// The daemon takes no address of the internet's or the LAN's for its device,
// masquerades or blocks no source outside the overlay, and captures neither
// what the host keeps to itself and its links nor anything for a device it
// has not opened; without one it gives the host's DNS back, and sets none.
func TestTheHelperKeepsToTheNetworksSpace(t *testing.T) {
	h := &fakeHost{}
	c, _ := pair(t, h)
	if err := c.SetDNS("juist0", []netip.Addr{netip.MustParseAddr("198.19.44.1")}, nil); err == nil {
		t.Error("DNS set for a device not opened")
	}
	if err := c.SetDNS("juist0", nil, nil); err != nil {
		t.Errorf("DNS given back without a device: %v", err)
	}
	e := EgressSpec{Mode: EgressRefused, Capture: prefixes("8.0.0.0/7")}
	if err := c.SetEgress("juist0", e); err == nil {
		t.Error("captured into a device not opened")
	}
	f, err := c.OpenTUN("juist0", 1280)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	for _, a := range []string{"8.8.8.8/32", "127.0.0.2/32", "fe80::1/128", "2001:4860::1/128"} {
		if err := c.SetAddrs("juist0", prefixes(a)); err == nil {
			t.Errorf("took %s for the device", a)
		}
	}
	if err := c.SetAddrs("juist0", prefixes("198.19.44.1/32", "fd7a:115c:a1e0::1/128")); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{"0.0.0.0/0", "8.8.8.0/24", "10.0.0.0/7"} {
		if err := c.SetServe("juist0", ServeSpec{Sources: prefixes(src)}); err == nil {
			t.Errorf("served the source %s", src)
		}
	}
	for _, p := range []string{"0.0.0.0/0", "192.168.1.0/24", "8.0.0.0/4", "::/0", "fe80::/64", "8.8.8.1/24"} {
		e := EgressSpec{Mode: EgressTunnel, Capture: []netip.Prefix{netip.MustParsePrefix(p)}}
		if err := c.SetEgress("juist0", e); err == nil {
			t.Errorf("captured %s", p)
		}
	}
	if err := c.SetEgress("juist0", EgressSpec{Mode: EgressTunnel, Capture: prefixes("8.0.0.0/7", "2000::/4")}); err != nil {
		t.Errorf("the internet not captured: %v", err)
	}
	for _, p := range []string{"0.0.0.0/1", "128.0.0.0/1", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
		"0.0.0.0/8", "::/1", "8000::/1", "::1/128", "fe80::/64", "ff02::/16"} {
		if err := c.SetRoutes("juist0", prefixes(p), netip.Addr{}); err == nil {
			t.Errorf("routed %s", p)
		}
	}
	if err := c.SetRoutes("juist0", prefixes("10.1.0.0/16", "203.0.113.0/24", "fd7a:115c:a1e0::/48"), netip.Addr{}); err != nil {
		t.Errorf("a member's routes refused: %v", err)
	}
	for _, a := range []string{"8.8.8.8", "127.0.0.1", "192.0.2.53", "fe80::1", "2001:4860:4860::8888"} {
		if err := c.SetDNS("juist0", []netip.Addr{netip.MustParseAddr(a)}, nil); err == nil {
			t.Errorf("took the resolver %s", a)
		}
	}
	if err := c.SetDNS("juist0", []netip.Addr{netip.MustParseAddr("198.19.44.2")}, nil); err != nil {
		t.Errorf("the exit node's resolver refused: %v", err)
	}
	for _, call := range h.took() {
		if strings.Contains(call, "8.8.8.8") || strings.Contains(call, "0.0.0.0/0") || strings.HasPrefix(call, "dns juist1 [198") ||
			strings.Contains(call, "/1 ") || strings.Contains(call, "127.0.0") || strings.Contains(call, "fe80::") {
			t.Errorf("the host was asked %q", call)
		}
	}
}

// The relay's daemon is handed a listener on 443 at an address of the host's,
// and only of its own device's, never on loopback, a link or the device's
// own addresses or another juist device's, which terminators serve.
func TestTheHelperBindsTheRelaysPortAtAHostsAddress(t *testing.T) {
	h := &fakeHost{}
	c, _ := pair(t, h)
	if _, err := c.ListenHTTPS("juist0", netip.MustParseAddr("192.0.2.7")); err == nil {
		t.Error("443 was bound for a device not opened")
	}
	f, err := c.OpenTUN("juist0", 1280)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := c.SetAddrs("juist0", prefixes("198.18.0.1/32")); err != nil {
		t.Fatal(err)
	}
	h.took()
	ln, err := c.ListenHTTPS("juist0", netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	if got := h.took(); !slices.Equal(got, []string{"listen 192.0.2.7"}) {
		t.Errorf("the host did %q", got)
	}
	defer func(f func() []netip.Addr) { juistAddrs = f }(juistAddrs)
	juistAddrs = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("10.20.0.5")} }
	for _, a := range []string{"127.0.0.1", "::1", "fe80::1", "169.254.1.1", "224.0.0.1", "198.18.0.1", "::ffff:192.0.2.7",
		"10.20.0.5"} {
		if _, err := c.ListenHTTPS("juist0", netip.MustParseAddr(a)); err == nil {
			t.Errorf("443 was bound at %s", a)
		}
	}
	if got := h.took(); len(got) != 0 {
		t.Errorf("the host did %q", got)
	}
}

// The daemon's own resolver is handed 53 at an address of its device's
// alone; resolv.conf takes its search domains only where they are domains;
// and once the daemon is gone, the host's resolvers are given back where they
// were the daemon's own, and an exit node's are kept.
func TestTheHelperServesTheDaemonsOwnResolver(t *testing.T) {
	h := &fakeHost{}
	c, done := pair(t, h)
	f, err := c.OpenTUN("juist0", 1280)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := c.SetAddrs("juist0", prefixes("198.18.0.1/32")); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"192.0.2.7", "127.0.0.1", "198.18.0.2"} {
		if _, _, err := c.ListenDNS("juist0", netip.MustParseAddr(a)); err == nil {
			t.Errorf("53 was bound at %s", a)
		}
	}
	h.took()
	pc, ln, err := c.ListenDNS("juist0", netip.MustParseAddr("198.18.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	pc.Close()
	ln.Close()
	if got := h.took(); !slices.Equal(got, []string{"listen dns 198.18.0.1 tcp", "listen dns 198.18.0.1 udp"}) {
		t.Errorf("the host did %q", got)
	}
	own := []netip.Addr{netip.MustParseAddr("198.18.0.1")}
	for _, s := range []string{"a b", "lan\nnameserver 8.8.8.8", "-lan", "lan.", "LAN", ""} {
		if err := c.SetDNS("juist0", own, []string{s}); err == nil {
			t.Errorf("searched %q", s)
		}
	}
	if err := c.SetDNS("juist0", own, []string{"home.juist", "lan"}); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := h.took(); !slices.Equal(got, []string{"dns juist0 [198.18.0.1] search [home.juist lan]", "dns juist0 []"}) {
		t.Errorf("the host did %q", got)
	}

	h = &fakeHost{}
	c, done = pair(t, h)
	if f, err = c.OpenTUN("juist0", 1280); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := c.SetAddrs("juist0", prefixes("198.18.0.1/32")); err != nil {
		t.Fatal(err)
	}
	if err := c.SetDNS("juist0", []netip.Addr{netip.MustParseAddr("198.18.0.2")}, nil); err != nil {
		t.Fatal(err)
	}
	c.Close()
	<-done
	if got := h.took(); slices.Contains(got, "dns juist0 []") {
		t.Errorf("the exit node's resolvers were given back: %q", got)
	}
}
