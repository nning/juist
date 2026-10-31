package conn

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"tailscale.com/wgengine/router"

	"github.com/nning/juist/internal/plumber"
)

// requireRoot skips without root, which FreeBSD's helper needs, unless the
// OS plumbing is required, as make test-freebsd requires it.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		if os.Getenv("JUIST_REQUIRE_OS_PLUMBING") != "" {
			t.Fatal("needs root, and JUIST_REQUIRE_OS_PLUMBING is set")
		}
		t.Skip("needs root")
	}
}

// helperPair is a client of a real helper for dev, as juistd's split makes
// one.
func helperPair(t *testing.T, dev string) *plumber.Client {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := plumber.NewClient(os.NewFile(uintptr(fds[0]), "daemon"))
	if err != nil {
		t.Fatal(err)
	}
	fc, err := net.FileConn(os.NewFile(uintptr(fds[1]), "helper"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		destroy, err := plumber.Serve(fc.(*net.UnixConn), plumber.FreeBSD{}, os.Getuid(), dev, t.Logf)
		destroy()
		done <- err
	}()
	t.Cleanup(func() {
		c.Close()
		if err := <-done; err != nil {
			t.Errorf("serving: %v", err)
		}
	})
	return c
}

// A device the helper made carries this node's addresses and its peers'
// routes, from the source the router pins, reaches the node through its
// descriptor, is another instance's holding, and goes with its routes.
func TestAPlumbedDeviceCarriesTheOverlay(t *testing.T) {
	requireRoot(t)
	c := helperPair(t, "juist9")
	dev, rtr, err := newPlumbed(c, "juist9", 9, 1280, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	old, renumbered := netip.MustParsePrefix("198.18.200.1/32"), netip.MustParsePrefix("198.18.201.1/32")
	self6 := netip.MustParsePrefix("fd00:aa::1/128")
	peer := netip.MustParsePrefix("198.18.200.2/32")
	routes := []netip.Prefix{peer, netip.MustParsePrefix("fd00:aa::2/128"), old}
	if err := rtr.Set(&router.Config{LocalAddrs: []netip.Prefix{old, self6}, Routes: routes}); err != nil {
		t.Fatal(err)
	}
	// Renumbering, the new address comes first: it is the one every peer
	// accepts, and the kernel would choose the one it had before. The route
	// from it goes in before the one from the old address goes.
	changes := watchRoutes(t, peer.Addr())
	if err := rtr.Set(&router.Config{LocalAddrs: []netip.Prefix{renumbered, old, self6}, Routes: routes}); err != nil {
		t.Fatal(err)
	}
	if got := changes(); len(got) == 0 || got[0] != syscall.RTM_ADD {
		t.Errorf("the peer's route changed by %v, want an addition first", got)
	}
	out, err := exec.Command("/sbin/route", "-n", "get", peer.Addr().String()).CombinedOutput()
	if err != nil || !slices.Contains(fieldsOf(out), "juist9") {
		t.Fatalf("the peer is not routed into the device (%v):\n%s", err, out)
	}

	// A ping to the peer comes out of the descriptor, from the pinned
	// source.
	ping := exec.Command("/sbin/ping", "-c", "3", "-i", "0.2", "-t", "2", peer.Addr().String())
	if err := ping.Start(); err != nil {
		t.Fatal(err)
	}
	defer ping.Wait()
	got := make(chan netip.Addr, 1)
	go func() {
		slab := make([]byte, 2000+2*tun.ReadPacketSpacing)
		packets := make([]tun.ReadPacket, 1)
		for {
			n, err := dev.Read(slab, packets)
			if err != nil || n == 0 {
				return
			}
			pkt := slab[packets[0].Offset : packets[0].Offset+packets[0].Size]
			if len(pkt) >= 20 && pkt[0]>>4 == 4 {
				got <- netip.AddrFrom4([4]byte(pkt[12:16]))
				return
			}
		}
	}()
	select {
	case src := <-got:
		if src != renumbered.Addr() {
			t.Errorf("the ping left from %v, want %v", src, renumbered.Addr())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("nothing came out of the device")
	}

	held, err := InstanceHoldings(1, "")
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(held, func(h Holding) bool { return h.Instance == 9 })
	if i < 0 || !slices.Contains(held[i].Prefixes, peer) || !slices.Contains(held[i].Prefixes, old) {
		t.Errorf("instance 9 holds %+v", held)
	}
	if mine, _ := InstanceHoldings(9, "juist9"); slices.ContainsFunc(mine, func(h Holding) bool { return h.Instance == 9 }) {
		t.Error("an instance holds against itself")
	}

	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := net.InterfaceByName("juist9"); err == nil {
		t.Error("the device outlived its closing")
	}
	if out, _ := exec.Command("/sbin/route", "-n", "get", peer.Addr().String()).CombinedOutput(); slices.Contains(fieldsOf(out), "juist9") {
		t.Errorf("the peer's route outlived the device:\n%s", out)
	}
}

func fieldsOf(b []byte) []string { return strings.Fields(string(b)) }

// watchRoutes follows the routing socket for additions and deletions of
// routes to dst; the function returned stops and reports them in order.
func watchRoutes(t *testing.T, dst netip.Addr) func() []int {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.AF_UNSPEC)
	if err != nil {
		t.Fatal(err)
	}
	// Closing does not wake a read; a timeout does.
	tv := syscall.Timeval{Usec: 100_000}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		t.Fatal(err)
	}
	var got []int
	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 1<<16)
		for !stop.Load() {
			n, err := syscall.Read(fd, b)
			if err != nil || n == 0 {
				continue
			}
			msgs, err := route.ParseRIB(route.RIBTypeRoute, b[:n])
			if err != nil {
				continue
			}
			for _, m := range msgs {
				rm, ok := m.(*route.RouteMessage)
				if !ok || rm.Type != syscall.RTM_ADD && rm.Type != syscall.RTM_DELETE || len(rm.Addrs) <= syscall.RTAX_DST {
					continue
				}
				if a, ok := rm.Addrs[syscall.RTAX_DST].(*route.Inet4Addr); ok && netip.AddrFrom4(a.IP) == dst {
					got = append(got, rm.Type)
				}
			}
		}
	}()
	return func() []int {
		time.Sleep(200 * time.Millisecond)
		stop.Store(true)
		<-done
		syscall.Close(fd)
		return got
	}
}

// A packet the node writes into its device reaches the host, whose answer
// comes back out of it.
func TestAPlumbedDeviceTakesWhatTheNodeWrites(t *testing.T) {
	requireRoot(t)
	c := helperPair(t, "juist8")
	dev, rtr, err := newPlumbed(c, "juist8", 8, 1280, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	self, peer := netip.MustParseAddr("198.18.220.1"), netip.MustParsePrefix("198.18.220.2/32")
	if err := rtr.Set(&router.Config{LocalAddrs: []netip.Prefix{netip.PrefixFrom(self, 32)},
		Routes: []netip.Prefix{peer}}); err != nil {
		t.Fatal(err)
	}
	// An echo request from the peer to this node, as the tunnel would
	// deliver it.
	req := []byte{0x45, 0, 0, 28, 0x12, 0x34, 0, 0, 64, 1, 0, 0}
	req = append(req, peer.Addr().AsSlice()...)
	req = append(req, self.AsSlice()...)
	req = append(req, 8, 0, 0, 0, 0xab, 0xcd, 0, 1)
	sum := func(b []byte) uint16 {
		var s uint32
		for i := 0; i+1 < len(b); i += 2 {
			s += uint32(b[i])<<8 | uint32(b[i+1])
		}
		for s > 0xffff {
			s = s&0xffff + s>>16
		}
		return ^uint16(s)
	}
	cs := sum(req[:20])
	req[10], req[11] = byte(cs>>8), byte(cs)
	cs = sum(req[20:])
	req[22], req[23] = byte(cs>>8), byte(cs)
	buf := append(make([]byte, 4), req...)
	if _, err := dev.Write([][]byte{buf}, 4); err != nil {
		t.Fatalf("writing: %v", err)
	}
	got := make(chan bool, 1)
	go func() {
		slab, packets := make([]byte, 2000+2*tun.ReadPacketSpacing), make([]tun.ReadPacket, 1)
		for {
			if n, err := dev.Read(slab, packets); err != nil || n == 0 {
				return
			}
			p := slab[packets[0].Offset : packets[0].Offset+packets[0].Size]
			if len(p) >= 28 && p[9] == 1 && p[20] == 0 && netip.AddrFrom4([4]byte(p[16:20])) == peer.Addr() {
				got <- true
				return
			}
		}
	}()
	select {
	case <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("the host did not answer what the node wrote")
	}
}

// The router reads the host's own routes, not its device's, and hears of a
// new one.
func TestAPlumbedRouterKnowsTheHostsRoutes(t *testing.T) {
	requireRoot(t)
	c := helperPair(t, "juist8")
	dev, rtr, err := newPlumbed(c, "juist8", 8, 1280, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	defer rtr.Close()
	peer := netip.MustParsePrefix("198.18.221.2/32")
	if err := rtr.Set(&router.Config{LocalAddrs: []netip.Prefix{netip.MustParsePrefix("198.18.221.1/32")},
		Routes: []netip.Prefix{peer}}); err != nil {
		t.Fatal(err)
	}
	pr := rtr.(*plumbedRouter)
	heard := make(chan struct{}, 256)
	pr.watchHostRoutes(func() { heard <- struct{}{} })
	time.Sleep(200 * time.Millisecond)
	// The device's own routes are no news: routing a peer set would have
	// the daemon reconcile once a route.
	var more []netip.Prefix
	for i := range 20 {
		more = append(more, netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18, 223, byte(i + 1)}), 32))
	}
	if err := rtr.Set(&router.Config{LocalAddrs: []netip.Prefix{netip.MustParsePrefix("198.18.221.1/32")},
		Routes: append(more, peer)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if n := len(heard); n > 0 {
		t.Errorf("the device's own routes were heard %d times", n)
	}
	out, _ := exec.Command("/sbin/route", "-n", "get", "default").Output()
	gw := ""
	for _, l := range strings.Split(string(out), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "gateway:" {
			gw = f[1]
		}
	}
	if gw == "" {
		t.Skip("no default gateway to route through")
	}
	own := netip.MustParsePrefix("198.18.222.0/24")
	if out, err := exec.Command("/sbin/route", "-q", "-n", "add", "-net", own.String(), gw).CombinedOutput(); err != nil {
		t.Fatalf("a route of the host's: %v: %s", err, out)
	}
	defer exec.Command("/sbin/route", "-q", "-n", "delete", "-net", own.String()).Run()
	select {
	case <-heard:
	case <-time.After(5 * time.Second):
		t.Error("a new route of the host's went unheard")
	}
	routes := pr.hostRoutes()
	if slices.Contains(routes, peer) {
		t.Errorf("the device's own route is the host's: %v", routes)
	}
	if !slices.Contains(routes, own) {
		t.Errorf("the host's route %v is missing: %v", own, routes)
	}
	if slices.ContainsFunc(routes, func(p netip.Prefix) bool { return p.Addr().IsLoopback() || p.Bits() == 0 }) {
		t.Errorf("loopback or default routes count: %v", routes)
	}
}

// A route an ICMP redirect made or changed, which anyone on the LAN can
// send, or one that drops what it takes, is not the host's own.
func TestARedirectsRouteIsNotTheHosts(t *testing.T) {
	if !hostsOwn(syscall.RTF_UP | syscall.RTF_STATIC | syscall.RTF_GATEWAY) {
		t.Error("a static route is not the host's")
	}
	for _, f := range []int{syscall.RTF_DYNAMIC, syscall.RTF_MODIFIED, syscall.RTF_REJECT, syscall.RTF_BLACKHOLE} {
		if hostsOwn(syscall.RTF_UP | syscall.RTF_GATEWAY | f) {
			t.Errorf("a route of flags %#x is the host's", f)
		}
	}
}
