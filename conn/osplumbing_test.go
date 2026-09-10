package conn

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// TestTunNameYieldsToInjectedDevice pins the precedence in Options: a
// caller-supplied Tun wins over TunName, so no test triggers the real-device
// path by accident. The name is a valid one, so the precedence rule is the
// only reason no device appears.
func TestTunNameYieldsToInjectedDevice(t *testing.T) {
	const name = "juistnocreate"
	mgr, err := New(Options{
		Self: Self{
			ID:       1,
			NodeKey:  key.NewNode(),
			DiscoKey: key.NewDisco(),
			Addrs:    []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		},
		Tun:     newEchoTUN(),
		TunName: name,
		Logf:    logger.WithPrefix(t.Logf, "n1: "),
	})
	if err != nil {
		t.Fatalf("New with an injected Tun and a TunName: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })

	if _, err := net.InterfaceByName(name); err == nil {
		t.Fatal("New created an OS device from TunName even though Tun was supplied")
	}
}

// TestCheckTunName covers the names conn.New refuses before the kernel sees
// them: one over IFNAMSIZ comes back as a bare EINVAL, and one containing %
// is expanded by kernel templating into a device nobody named.
func TestCheckTunName(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"juist0", true},
		{"juist-abc", true},
		{"abcdefghijklmno", true},   // 15 bytes, the longest Linux accepts
		{"abcdefghijklmnop", false}, // 16
		{"", false},
		{"juist%d", false},
		{"juist 0", false},
		{"juist/0", false},
		{".", false},
		{"..", false},
	} {
		err := checkTunName(tc.name)
		if tc.ok && err != nil {
			t.Errorf("checkTunName(%q) = %v, want nil", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("checkTunName(%q) = nil, want an error", tc.name)
		}
	}
}

// TestRealDevicePlumbsOverlayIntoHost checks that a real router.Router, wired
// at engine construction, programs this node's overlay addresses onto the
// interface and its peers' prefixes as routes into it. The fake router the
// other tests use discards both.
//
// It needs CAP_NET_ADMIN and /dev/net/tun, and skips without them unless
// JUIST_REQUIRE_OS_PLUMBING is set, which the privileged CI job does so that a
// runner that cannot create a device turns red rather than green.
func TestRealDevicePlumbsOverlayIntoHost(t *testing.T) {
	if os.Geteuid() != 0 {
		skipUnlessRequired(t, "needs CAP_NET_ADMIN to create a TUN device and program routes")
	}
	// Decided here rather than inside ifaceRoutes, so the test is
	// all-or-nothing: a skip half-way through reads as "not run" while
	// quietly dropping the route assertions.
	ipCmd, err := exec.LookPath("ip")
	if err != nil {
		skipUnlessRequired(t, "iproute2 not installed; cannot read the programmed routes")
	}

	// Within IFNAMSIZ, and unique enough that a stale device from an
	// interrupted run does not collide with a live one.
	name := fmt.Sprintf("juisttest%d", os.Getpid()%10000)
	selfV4 := netip.MustParsePrefix("100.64.0.1/32")
	selfV6 := netip.MustParsePrefix("fd7a:115c:a1e0::1/128")
	peerV4 := netip.MustParsePrefix("100.64.0.2/32")
	peerV6 := netip.MustParsePrefix("fd7a:115c:a1e0::2/128")

	mgr, err := New(Options{
		Self: Self{
			ID:       1,
			NodeKey:  key.NewNode(),
			DiscoKey: key.NewDisco(),
			Addrs:    []netip.Prefix{selfV4, selfV6},
		},
		TunName: name,
		Logf:    logger.WithPrefix(t.Logf, "n1: "),
	})
	if err != nil {
		// euid 0 without CAP_NET_ADMIN (some containers), or no /dev/net/tun:
		// the wiring is what is under test, not this host's capabilities.
		if strings.Contains(err.Error(), "not permitted") ||
			strings.Contains(err.Error(), "permission denied") ||
			strings.Contains(err.Error(), "does not exist") {
			skipUnlessRequired(t, "cannot create a TUN device here: %v", err)
		}
		t.Fatalf("New with a real device %q: %v", name, err)
	}
	t.Cleanup(func() { mgr.Close() })

	peer := Peer{
		ID:       2,
		NodeKey:  key.NewNode().Public(),
		DiscoKey: key.NewDisco().Public(),
		Addrs:    []netip.Prefix{peerV4, peerV6},
	}
	if err := mgr.SetPeers([]Peer{peer}); err != nil {
		t.Fatalf("SetPeers: %v", err)
	}

	// router.Set runs inside Reconfig; give the interface a moment to settle.
	// Only the v4 address must appear: the Linux router silently skips IPv6
	// where the kernel has none, so the v6 half is asserted only where it got
	// as far as the interface.
	deadline := time.Now().Add(5 * time.Second)
	for !ifaceHasAddrs(t, name, selfV4.Addr()) {
		if time.Now().After(deadline) {
			t.Fatalf("interface %q never carried overlay address %v", name, selfV4.Addr())
		}
		time.Sleep(100 * time.Millisecond)
	}
	want := []netip.Prefix{peerV4}
	if ifaceHasAddrs(t, name, selfV6.Addr()) {
		want = append(want, peerV6)
	} else {
		t.Logf("no usable IPv6 on this host; asserting the v4 half only")
	}

	routes := ifaceRoutes(t, []string{ipCmd}, name)
	for _, w := range want {
		if !slices.Contains(routes, w) {
			t.Errorf("peer route %v not programmed into %q; have %v", w, name, routes)
		}
	}
	// Default-deny reaches the router: an address of no member gets no route
	// into the device. This holds because peerRoutes is built only from the
	// peer set, but assert it against the real device so a regression shows.
	for _, absent := range []netip.Prefix{
		netip.MustParsePrefix("100.64.0.9/32"),
		netip.MustParsePrefix("fd7a:115c:a1e0::9/128"),
	} {
		if slices.Contains(routes, absent) {
			t.Errorf("non-member prefix %v was routed into %q", absent, name)
		}
	}
}

// requireOSPlumbingEnv is the environment variable that makes the real-device
// test fail where it would otherwise skip.
const requireOSPlumbingEnv = "JUIST_REQUIRE_OS_PLUMBING"

// skipUnlessRequired skips the test with the given reason, or fails it when
// JUIST_REQUIRE_OS_PLUMBING is set.
func skipUnlessRequired(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv(requireOSPlumbingEnv) != "" {
		t.Fatalf("%s is set, but: %s", requireOSPlumbingEnv, fmt.Sprintf(format, args...))
	}
	t.Skipf(format, args...)
}

// ifaceHasAddrs reports whether the named interface carries every given
// address.
func ifaceHasAddrs(t *testing.T, name string, want ...netip.Addr) bool {
	t.Helper()
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	have := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				have = append(have, ip.Unmap())
			}
		}
	}
	for _, w := range want {
		if !slices.Contains(have, w) {
			return false
		}
	}
	return true
}

// ifaceRoutes returns the destination prefixes routed through the named
// interface, by shelling out to iproute2. ipArgv is how to invoke it: the
// netns harness prepends "-n <namespace>".
//
// "table all" is load-bearing: the Linux router puts peer routes in table 52
// wherever policy routing is available, so reading the main table alone would
// report no peer routes at all. Lines whose first field is a route type rather
// than a destination are skipped.
func ifaceRoutes(t *testing.T, ipArgv []string, name string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, family := range []string{"-4", "-6"} {
		argv := append(slices.Clone(ipArgv), family, "route", "show", "table", "all", "dev", name)
		cmd := exec.Command(argv[0], argv[1:]...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		raw, err := cmd.Output()
		if err != nil {
			// Print the command and what iproute2 said: an ExitError on its
			// own is "exit status 2", which says nothing about which argument
			// this build of ip did not like.
			t.Fatalf("%s: %v: %s", cmd, err, strings.TrimSpace(stderr.String()))
		}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			dst := fields[0]
			if p, err := netip.ParsePrefix(dst); err == nil {
				out = append(out, p)
			} else if a, err := netip.ParseAddr(dst); err == nil {
				out = append(out, netip.PrefixFrom(a, a.BitLen()))
			}
		}
	}
	return out
}
