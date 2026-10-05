package conn

import (
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
	"tailscale.com/wgengine/router"

	"github.com/nning/juist/internal/plumber"
)

// fakeVPN establishes a datagram socket pair per call, keeping the far ends.
type fakeVPN struct {
	t  *testing.T
	mu sync.Mutex
	// far are the ends the host would hold, one per establish, and given
	// what each was established with.
	far   []*os.File
	given []VPNConfig
}

func (v *fakeVPN) Establish(c VPNConfig) (*os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	if err := unix.SetNonblock(fds[0], true); err != nil {
		return nil, err
	}
	far := os.NewFile(uintptr(fds[1]), "far")
	v.t.Cleanup(func() { far.Close() })
	v.mu.Lock()
	defer v.mu.Unlock()
	v.far = append(v.far, far)
	v.given = append(v.given, c)
	return os.NewFile(uintptr(fds[0]), "tun"), nil
}

func (v *fakeVPN) established() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.far)
}

func readPacket(t *testing.T, d tun.Device) chan []byte {
	t.Helper()
	got := make(chan []byte, 4)
	go func() {
		slab := make([]byte, 2048)
		packets := make([]tun.ReadPacket, 1)
		for {
			n, err := d.Read(slab, packets)
			if err != nil {
				close(got)
				return
			}
			for _, p := range packets[:n] {
				got <- slices.Clone(slab[p.Offset : p.Offset+p.Size])
			}
		}
	}()
	return got
}

func TestAVPNDeviceMovesToEachEstablishedDescriptor(t *testing.T) {
	v := &fakeVPN{t: t}
	dev, rtr := newVPNPlumbed(NewVPNPlumber(v, nil).(*vpnPlumber), "juist0", 1280, t.Logf)
	got := readPacket(t, dev)
	recv := func(what string) []byte {
		t.Helper()
		select {
		case b := <-got:
			return b
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: nothing read", what)
			return nil
		}
	}

	self := []netip.Prefix{netip.MustParsePrefix("fd00::2/128"), netip.MustParsePrefix("10.0.0.2/32")}
	peers := []netip.Prefix{netip.MustParsePrefix("10.0.0.3/32"), netip.MustParsePrefix("10.0.0.2/32")}
	if err := rtr.Set(&router.Config{Routes: peers}); err != nil || v.established() != 0 {
		t.Fatalf("a config without addresses: %v, %d established", err, v.established())
	}
	if err := rtr.Set(&router.Config{LocalAddrs: self, Routes: peers}); err != nil {
		t.Fatal(err)
	}
	if want := []netip.Prefix{netip.MustParsePrefix("10.0.0.3/32")}; !slices.Equal(v.given[0].Routes, want) {
		t.Errorf("routes established: %v, want %v, without the device's own address", v.given[0].Routes, want)
	}
	if _, err := v.far[0].Write([]byte("in one")); err != nil {
		t.Fatal(err)
	}
	if b := recv("the first device"); string(b) != "in one" {
		t.Errorf("read %q", b)
	}
	if n, err := dev.Write([][]byte{[]byte("xxout one")}, 2); n != 1 || err != nil {
		t.Fatalf("writing: %d, %v", n, err)
	}
	buf := make([]byte, 64)
	if n, err := v.far[0].Read(buf); err != nil || string(buf[:n]) != "out one" {
		t.Errorf("the host read %q, %v", buf[:n], err)
	}

	if err := rtr.Set(&router.Config{LocalAddrs: slices.Clone(self[1:]), Routes: peers}); err != nil {
		t.Fatal(err)
	}
	if err := rtr.Set(&router.Config{LocalAddrs: self[1:], Routes: []netip.Prefix{peers[1], peers[0]}}); err != nil {
		t.Fatal(err)
	}
	if v.established() != 2 {
		t.Fatalf("%d established, want one more for the address gone and none for the same config again", v.established())
	}
	if _, err := v.far[1].Write([]byte("in two")); err != nil {
		t.Fatal(err)
	}
	if b := recv("the device established again"); string(b) != "in two" {
		t.Errorf("read %q", b)
	}
	if _, err := v.far[0].Write([]byte("stale")); err == nil {
		t.Error("the device replaced still took packets")
	}

	dev.Close()
	select {
	case _, open := <-got:
		if open {
			t.Error("read after closing")
		}
	case <-time.After(5 * time.Second):
		t.Error("closing did not end a read")
	}
}

func TestAVPNPlumberServesNothing(t *testing.T) {
	p := NewVPNPlumber(&fakeVPN{t: t}, nil)
	if err := p.SetEgress("juist0", plumber.EgressSpec{Mode: plumber.EgressDirect}); err != nil {
		t.Errorf("leaving the host's traffic as it is: %v", err)
	}
	if err := p.SetServe("juist0", plumber.ServeSpec{DNSPort: 53}); err == nil {
		t.Error("a VPN device served")
	}
	if err := p.SetDNS("juist0", []netip.Addr{netip.MustParseAddr("10.0.0.1")}); err == nil {
		t.Error("DNS was taken with no device up")
	}
	if err := p.SetDNS("juist0", nil); err != nil {
		t.Errorf("setting no DNS: %v", err)
	}
}

func TestAVPNRoutesTheNetworkWholeAndIsNotEstablishedAgainForAMember(t *testing.T) {
	v := &fakeVPN{t: t}
	network := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/22"), netip.MustParsePrefix("fd00:1:2::/48")}
	dev, rtr := newVPNPlumbed(NewVPNPlumber(v, func() []netip.Prefix { return network }).(*vpnPlumber), "juist0", 1280, t.Logf)
	defer dev.Close()
	self := []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32"), netip.MustParsePrefix("fd00:1:2::2/128")}
	peers := []netip.Prefix{netip.MustParsePrefix("10.0.0.3/32"), netip.MustParsePrefix("fd00:1:2::3/128"),
		netip.MustParsePrefix("192.0.2.0/24")}
	if err := rtr.Set(&router.Config{LocalAddrs: self, Routes: peers}); err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{network[0], netip.MustParsePrefix("192.0.2.0/24"), network[1]}
	if !slices.Equal(v.given[0].Routes, want) {
		t.Errorf("routes established: %v, want %v", v.given[0].Routes, want)
	}
	if err := rtr.Set(&router.Config{LocalAddrs: self, Routes: append(peers, netip.MustParsePrefix("10.0.1.9/32"))}); err != nil {
		t.Fatal(err)
	}
	if v.established() != 1 {
		t.Errorf("a member more established the device again, %d times in all", v.established())
	}
}

func routes(rs []netip.Prefix, a string) bool {
	return slices.ContainsFunc(rs, func(p netip.Prefix) bool { return p.Contains(netip.MustParseAddr(a)) })
}

func TestAVPNRoutesTheInternetToAnExitNodeAndItsDNS(t *testing.T) {
	v := &fakeVPN{t: t}
	network := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/22"), netip.MustParsePrefix("fd00:1:2::/48")}
	p := NewVPNPlumber(v, func() []netip.Prefix { return network }).(*vpnPlumber)
	dev, rtr := newVPNPlumbed(p, "juist0", 1280, t.Logf)
	defer dev.Close()
	self := []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32"), netip.MustParsePrefix("fd00:1:2::2/128")}
	if err := rtr.Set(&router.Config{LocalAddrs: self, Routes: []netip.Prefix{netip.MustParsePrefix("10.0.0.3/32")}}); err != nil {
		t.Fatal(err)
	}
	exits := rtr.(exitRouter)
	if err := exits.setEgress(EgressRefused, tunnelled{}); err != nil {
		t.Fatal(err)
	}
	last := func() VPNConfig { return v.given[len(v.given)-1] }
	for _, a := range []string{"8.8.8.8", "2606:4700::1111"} {
		if !routes(last().Routes, a) {
			t.Errorf("%s is not routed into the tunnel while the exit node is refused", a)
		}
	}
	for _, a := range []string{"192.168.1.1", "10.1.0.1", "fe80::1", "224.0.0.251"} {
		if routes(last().Routes, a) {
			t.Errorf("%s, no internet address, is routed into the tunnel", a)
		}
	}
	if !routes(last().Routes, "10.0.0.3") {
		t.Error("the network is no longer routed")
	}
	dns := []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	if err := p.SetDNS("juist0", dns); err != nil || !slices.Equal(last().DNS, dns) {
		t.Errorf("DNS established: %v, %v", last().DNS, err)
	}
	if err := exits.setEgress(EgressDirect, tunnelled{}); err != nil {
		t.Fatal(err)
	}
	if routes(last().Routes, "8.8.8.8") {
		t.Error("the internet is still routed into the tunnel with no exit node")
	}
	n := v.established()
	if err := p.SetDNS("juist0", dns); err != nil || v.established() != n {
		t.Errorf("the same DNS again established the device again: %v", err)
	}
	if err := exits.setServe(Serve{Routes: Internet(true, true, nil)}); err == nil {
		t.Error("a VPN device served as an exit node")
	}
}

// A dial into the overlay leaves from the device's own address, and not at
// all before the device is established, when it would leave by the LAN.
func TestAVPNDialLeavesByTheDeviceAlone(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	to := netip.MustParseAddrPort(ln.Addr().String())
	p := NewVPNPlumber(&fakeVPN{t: t}, nil)
	dial := VPNDial(p)
	if c, err := dial(t.Context(), to); err == nil {
		c.Close()
		t.Fatal("a dial before the device is established was made")
	}
	dev, rtr := newVPNPlumbed(p.(*vpnPlumber), "juist0", 1280, t.Logf)
	defer dev.Close()
	self := []netip.Prefix{netip.MustParsePrefix("127.0.0.2/32"), netip.MustParsePrefix("fd00:1:2::2/128")}
	if err := rtr.Set(&router.Config{LocalAddrs: self}); err != nil {
		t.Fatal(err)
	}
	c, err := dial(t.Context(), to)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if from := netip.MustParseAddrPort(c.LocalAddr().String()).Addr(); from != self[0].Addr() {
		t.Errorf("the dial left from %v, want %v", from, self[0].Addr())
	}
}
