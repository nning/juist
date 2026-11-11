//go:build unix

package plumber

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/sys/unix"
)

const fuzzUID = 870

// fuzzHeld are the host's addresses, which no route may cover.
var fuzzHeld = []netip.Addr{netip.MustParseAddr("192.168.178.20"), netip.MustParseAddr("2001:db8::20")}

// FuzzServe speaks to the helper as a compromised daemon could, in frames as
// on the wire: whatever it sends, the helper does to the host only what its
// rules allow, to its daemon's device alone, and destroys what it made once
// hung up on.
func FuzzServe(f *testing.F) {
	for _, seq := range seedRequests() {
		f.Add(framed(f, seq...))
	}
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 1, 0xa0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		h := &rulesHost{open: map[string]bool{}, addrs: map[netip.Addr]bool{}}
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		unix.CloseOnExec(fds[0])
		unix.CloseOnExec(fds[1])
		helper, daemon := unixConn(t, fds[0]), unixConn(t, fds[1])
		served := make(chan error, 1)
		go func() {
			destroy, err := Serve(helper, h, fuzzUID, "juist0", func(string, ...any) {})
			destroy()
			helper.Close()
			served <- err
		}()
		wrote := make(chan struct{})
		go func() {
			defer close(wrote)
			_, _ = daemon.Write(data)
			_ = daemon.CloseWrite()
		}()
		for {
			body, fd, err := readFrame(daemon, true)
			if fd != nil {
				fd.Close()
			}
			if err != nil {
				break
			}
			var resp response
			if err := decMode.Unmarshal(body, &resp); err != nil {
				h.wrong("an answer that does not decode: %v", err)
			}
		}
		<-served
		<-wrote
		daemon.Close()
		if len(h.open) > 0 {
			h.wrong("devices left after the daemon hung up: %v", h.open)
		}
		if len(h.violations) > 0 {
			t.Fatalf("the helper did what its rules forbid:\n%v", h.violations)
		}
	})
}

func unixConn(t *testing.T, fd int) *net.UnixConn {
	f := os.NewFile(uintptr(fd), "socket")
	defer f.Close()
	c, err := net.FileConn(f)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*net.UnixConn)
}

func framed(t testing.TB, reqs ...request) []byte {
	var out []byte
	for _, r := range reqs {
		b, err := cbor.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		out = append(binary.BigEndian.AppendUint32(out, uint32(len(b))), b...)
	}
	return out
}

func seedRequests() [][]request {
	a := netip.MustParseAddr
	p := netip.MustParsePrefix
	return [][]request{
		{
			{Op: opOpen, Device: "juist0", MTU: 1280},
			{Op: opAddrs, Device: "juist0", Addrs: []netip.Prefix{p("10.7.0.1/32"), p("fd7a:1:2:3::1/128"), p("fe80::1/128")}},
			{Op: opRoutes, Device: "juist0", Routes: []netip.Prefix{p("10.8.0.0/16"), p("fd7a:1:2:4::/64")}, Src4: a("10.7.0.1")},
			{Op: opServe, Device: "juist0", Serve: &ServeSpec{Sources: []netip.Prefix{p("10.7.0.0/16")}, Addrs: []netip.Addr{a("10.7.0.1")}, DNSPort: 53}},
			{Op: opGuard, Device: "juist0", Guard: &GuardSpec{Own: []netip.Addr{a("10.7.0.1")}, Overlay: []netip.Addr{a("10.7.0.2")}}},
			{Op: opEgress, Device: "juist0", Egress: &EgressSpec{Mode: EgressTunnel, V4: true, Capture: []netip.Prefix{p("8.8.8.0/24")}}},
			{Op: opDNS, Device: "juist0", DNS: []netip.Addr{a("10.7.0.1")}, Search: []string{"home.juist"}},
			{Op: opDNS53, Device: "juist0", Listen: a("10.7.0.1"), Proto: "udp"},
			{Op: opListen, Device: "juist0", Listen: a("203.0.113.7")},
			{Op: opAnswers},
			{Op: opDestroy, Device: "juist0"},
		},
		{
			{Op: opOpen, Device: "juist1", MTU: 1280},
			{Op: opRoutes, Device: "juist0", Routes: []netip.Prefix{p("10.8.0.0/16")}},
			{Op: opOpen, Device: "juist0", MTU: 9000},
			{Op: opAddrs, Device: "juist0", Addrs: []netip.Prefix{p("192.168.178.0/24"), p("8.8.8.8/32")}},
			{Op: opRoutes, Device: "juist0", Routes: []netip.Prefix{p("0.0.0.0/0"), p("192.168.0.0/16"), p("fe80::/10")}},
			{Op: opListen, Device: "juist0", Listen: a("127.0.0.1")},
		},
		{
			{Op: opEgress, Device: "juist0", Egress: &EgressSpec{Mode: EgressRefused}},
			{Op: opDNS, Device: "juist0"},
		},
	}
}

// rulesHost checks every call the helper makes against what the helper may
// do to a host.
type rulesHost struct {
	mu         sync.Mutex
	open       map[string]bool
	addrs      map[netip.Addr]bool
	violations []string
}

func (h *rulesHost) wrong(format string, a ...any) {
	h.violations = append(h.violations, fmt.Sprintf(format, a...))
}

// device checks that dev is the daemon's, and open where it must be.
func (h *rulesHost) device(dev string, mustBeOpen bool) {
	if dev != "juist0" {
		h.wrong("a call for %q", dev)
	}
	if mustBeOpen && !h.open[dev] {
		h.wrong("a call for %q, which is not open", dev)
	}
}

func (h *rulesHost) inOverlay(a netip.Addr) bool {
	return a.IsValid() && a.Zone() == "" && within(netip.PrefixFrom(a, a.BitLen()), overlaySpace)
}

func (h *rulesHost) OpenTUN(name string, mtu int) (*os.File, func() error, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.device(name, false)
	if h.open[name] {
		h.wrong("%s opened twice", name)
	}
	if mtu < 1280 || mtu > 65535 {
		h.wrong("an MTU of %d", mtu)
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	w.Close()
	h.open[name] = true
	return r, func() error {
		h.mu.Lock()
		defer h.mu.Unlock()
		if !h.open[name] {
			h.wrong("%s destroyed twice", name)
		}
		delete(h.open, name)
		clear(h.addrs)
		return nil
	}, nil
}

func (h *rulesHost) AddAddr(dev string, p netip.Prefix) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.device(dev, true)
	a := p.Addr()
	ll := a.Is6() && a.Zone() == "" && netip.MustParsePrefix("fe80::/64").Contains(a)
	if !p.IsSingleIP() || !(h.inOverlay(a) || ll) {
		h.wrong("an address %v", p)
	}
	h.addrs[a] = true
	return nil
}

func (h *rulesHost) DelAddr(dev string, p netip.Prefix) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.device(dev, true)
	delete(h.addrs, p.Addr())
	return nil
}

func (h *rulesHost) AddRoute(dev string, p netip.Prefix, src netip.Addr) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.device(dev, true)
	if !p.IsValid() || p.Bits() == 0 ||
		slices.ContainsFunc(linkSpace, func(s netip.Prefix) bool { return s.Overlaps(p) }) ||
		slices.ContainsFunc(fuzzHeld, p.Contains) {
		h.wrong("a route %v", p)
	}
	if src.IsValid() && (!src.Is4() || !p.Addr().Is4() || !h.addrs[src]) {
		h.wrong("a route %v from %v", p, src)
	}
	return nil
}

func (h *rulesHost) DelRoute(dev string, p netip.Prefix, src netip.Addr) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.device(dev, true)
	return nil
}

func (h *rulesHost) SetServe(dev string, s ServeSpec) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.device(dev, true)
	for _, p := range s.Sources {
		if !within(p, overlaySpace) {
			h.wrong("serving from %v", p)
		}
	}
	for _, a := range s.Addrs {
		if !h.addrs[a] {
			h.wrong("serving at %v, no address of the device", a)
		}
	}
	for _, p := range s.Local {
		if !p.IsValid() {
			h.wrong("serving an invalid local prefix")
		}
	}
	return nil
}

func (h *rulesHost) SetEgress(dev string, e EgressSpec, uid int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.device(dev, e.Mode == EgressTunnel || len(e.Capture) > 0)
	if uid != fuzzUID {
		h.wrong("egress for uid %d", uid)
	}
	if e.Mode != EgressDirect && e.Mode != EgressTunnel && e.Mode != EgressRefused {
		h.wrong("an egress %q", e.Mode)
	}
	for _, p := range e.Capture {
		if !p.IsValid() || p.Bits() == 0 || slices.ContainsFunc(hostSpace, func(s netip.Prefix) bool { return s.Overlaps(p) }) {
			h.wrong("a capture of %v", p)
		}
	}
	return nil
}

func (h *rulesHost) SetDNS(dev string, servers []netip.Addr, search []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.device(dev, len(servers) > 0)
	if len(servers) > 3 || len(search) > 6 {
		h.wrong("%d resolvers and %d search domains", len(servers), len(search))
	}
	for _, s := range servers {
		if !h.inOverlay(s) {
			h.wrong("a resolver %v", s)
		}
	}
	for _, d := range search {
		if !searchDomain.MatchString(d) || len(d) > 253 {
			h.wrong("a search domain %q", d)
		}
	}
	return nil
}

func (h *rulesHost) SetGuard(dev string, g GuardSpec) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.device(dev, true)
	for _, a := range slices.Concat(g.Own, g.Overlay) {
		if !h.inOverlay(a) {
			h.wrong("guarding %v", a)
		}
	}
	return nil
}

func (h *rulesHost) HostAddrs() []netip.Addr { return fuzzHeld }

func (h *rulesHost) Free(string) bool { return true }

func (h *rulesHost) Answers() string { return "" }

func (h *rulesHost) ListenHTTPS(a netip.Addr) (*os.File, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.device("juist0", true)
	if !a.IsValid() || a.Zone() != "" || a.Is4In6() || h.addrs[a] ||
		slices.ContainsFunc(linkSpace, func(s netip.Prefix) bool { return s.Contains(a) }) {
		h.wrong("443 at %v", a)
	}
	return descriptorStandIn()
}

func (h *rulesHost) ListenDNS(a netip.Addr, proto string) (*os.File, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.device("juist0", true)
	if !h.addrs[a] || (proto != "udp" && proto != "tcp") {
		h.wrong("53/%s at %v", proto, a)
	}
	return descriptorStandIn()
}

// descriptorStandIn is a descriptor to hand the daemon in place of a socket.
func descriptorStandIn() (*os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	w.Close()
	return r, nil
}
