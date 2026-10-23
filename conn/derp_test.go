package conn

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"tailscale.com/net/netmon"
)

func testRelay() Relay {
	return Relay{
		Region:   7,
		HostName: "abcdefgh.relay.juist.invalid",
		Addrs: []netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.10:4443"),
			netip.MustParseAddrPort("[2001:db8::1]:4443"),
		},
		STUNPort: 4443,
		CertHash: [32]byte{1, 2, 3},
	}
}

// TestDERPMapNeverResolvesAHostName is the property the announcement depends
// on: the relay's name is a TLS server name and nothing else. A node with an
// address field left empty would fall back to a DNS lookup of a .invalid name,
// which fails — and on a host with a wildcard resolver, fails by connecting
// somewhere else.
func TestDERPMapNeverResolvesAHostName(t *testing.T) {
	dm, _ := derpMap([]Relay{testRelay()}, nil, false, false, Networks{})
	if dm == nil {
		t.Fatal("no map built")
	}
	if !dm.OmitDefaultRegions {
		t.Error("the map admits Tailscale's own regions; a relay must be a member")
	}
	reg, ok := dm.Regions[7]
	if !ok {
		t.Fatalf("region 7 missing; have %v", dm.RegionIDs())
	}
	if len(reg.Nodes) != 2 {
		t.Fatalf("region has %d nodes, want one per announced address", len(reg.Nodes))
	}
	for _, n := range reg.Nodes {
		if n.IPv4 == "" || n.IPv6 == "" {
			t.Errorf("node %q leaves an address family empty, so it would be resolved in DNS: %+v",
				n.Name, n)
		}
		if n.CertName != "sha256-raw:0102030000000000000000000000000000000000000000000000000000000000" {
			t.Errorf("node %q does not pin the announced certificate: %q", n.Name, n.CertName)
		}
		if n.HostName != "abcdefgh.relay.juist.invalid" {
			t.Errorf("node %q has host name %q", n.Name, n.HostName)
		}
		if n.DERPPort != 4443 || n.STUNPort != 4443 {
			t.Errorf("node %q has ports derp=%d stun=%d, want 4443/4443", n.Name, n.DERPPort, n.STUNPort)
		}
	}
	v4, v6 := reg.Nodes[0], reg.Nodes[1]
	if v4.IPv4 != "192.0.2.10" || v4.IPv6 != "none" {
		t.Errorf("the v4 node is %+v", v4)
	}
	if v6.IPv6 != "2001:db8::1" || v6.IPv4 != "none" {
		t.Errorf("the v6 node is %+v", v6)
	}

	// A relay that does not reflect must not be probed for STUN, or every
	// netcheck spends its timeout on a port nothing answers.
	quiet := testRelay()
	quiet.STUNPort = 0
	if dm, _ := derpMap([]Relay{quiet}, nil, false, false, Networks{}); dm.Regions[7].Nodes[0].STUNPort != -1 {
		got := dm.Regions[7].Nodes[0].STUNPort
		t.Errorf("STUNPort %d for a relay that does not reflect, want -1 (disabled)", got)
	}

	// No relays is direct-only, which is a nil map rather than an empty one:
	// an empty map is a change the engine would act on.
	if dm, _ := derpMap(nil, nil, false, false, Networks{}); dm != nil {
		t.Error("an empty relay set produced a map")
	}
}

// TestSetRelaysRejectsWhatCannotBeUsed. Each of these would install a region
// that silently fails rather than refusing: an unauthenticated relay, two
// relays sharing an identifier, or one nothing can be dialled at.
func TestSetRelaysRejectsWhatCannotBeUsed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spoil func(*Relay)
	}{
		{"no certificate hash", func(r *Relay) { r.CertHash = [32]byte{} }},
		{"no host name", func(r *Relay) { r.HostName = "" }},
		{"no addresses", func(r *Relay) { r.Addrs = nil }},
		{"region zero", func(r *Relay) { r.Region = 0 }},
		{"region past 16 bits", func(r *Relay) { r.Region = MaxRegionID + 1 }},
		{"port zero", func(r *Relay) {
			r.Addrs = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), 0)}
		}},
		{"v4-mapped address", func(r *Relay) {
			r.Addrs = []netip.AddrPort{netip.MustParseAddrPort("[::ffff:192.0.2.1]:4443")}
		}},
	} {
		r := testRelay()
		tc.spoil(&r)
		if err := validateRelays([]Relay{r}); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
	a, b := testRelay(), testRelay()
	if err := validateRelays([]Relay{a, b}); err == nil {
		t.Error("two relays sharing a region were accepted")
	}
	if err := validateRelays([]Relay{testRelay()}); err != nil {
		t.Errorf("a usable relay was refused: %v", err)
	}
}

// TestSameRelaysIgnoresNothing: an unchanged set must compare equal, since
// installing one restarts the data plane's latency probes, and every field
// that can change must make it compare unequal.
func TestSameRelaysIgnoresNothing(t *testing.T) {
	if !sameRelays([]Relay{testRelay()}, []Relay{testRelay()}) {
		t.Fatal("two identical relay sets compare unequal")
	}
	for _, tc := range []struct {
		name  string
		alter func(*Relay)
	}{
		{"region", func(r *Relay) { r.Region++ }},
		{"host name", func(r *Relay) { r.HostName += "x" }},
		{"stun port", func(r *Relay) { r.STUNPort++ }},
		{"certificate", func(r *Relay) { r.CertHash[0]++ }},
		{"addresses", func(r *Relay) { r.Addrs = r.Addrs[:1] }},
	} {
		other := testRelay()
		tc.alter(&other)
		if sameRelays([]Relay{testRelay()}, []Relay{other}) {
			t.Errorf("a changed %s compared equal, so the change would never be installed", tc.name)
		}
	}
	if sameRelays(nil, []Relay{testRelay()}) {
		t.Error("an empty set compared equal to a populated one")
	}
}

// TestRelaysReachTheDataPlane: a manager with no relays is direct-only and
// reports no home region, and installing a set it cannot use leaves it as it
// was rather than half-configured.
func TestRelaysReachTheDataPlane(t *testing.T) {
	n := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	if got := n.mgr.HomeRelay(); got != 0 {
		t.Errorf("home relay %d with no relays installed", got)
	}
	if got := n.mgr.LocalEndpoints(); len(got) != 0 {
		// Not a hard failure: an engine that learned endpoints another way
		// would be fine. What must not happen is a claim without a relay.
		t.Logf("the data plane reports endpoints without a relay: %v", got)
	}
	if err := n.mgr.SetRelays([]Relay{testRelay()}); err != nil {
		t.Fatalf("installing a relay: %v", err)
	}
	bad := testRelay()
	bad.CertHash = [32]byte{}
	if err := n.mgr.SetRelays([]Relay{bad}); err == nil {
		t.Error("a relay with nothing to authenticate it was installed")
	}
	if err := n.mgr.SetRelays(nil); err != nil {
		t.Fatalf("returning to direct-only: %v", err)
	}
}

// TestRelayDialOrderPutsPublicFirst: the data plane tries a region's nodes in
// order with a short timeout each, and a relay-capable member announces every
// address it holds. A private one no other member can reach would otherwise
// cost every connection the seconds it takes to fail.
func TestRelayDialOrderPutsPublicFirst(t *testing.T) {
	in := []netip.AddrPort{
		netip.MustParseAddrPort("10.0.0.1:4443"),
		netip.MustParseAddrPort("198.51.100.7:4443"),
		netip.MustParseAddrPort("192.168.1.5:4443"),
		netip.MustParseAddrPort("[2001:db8::1]:4443"),
	}
	got := relayDialOrder(in, Networks{})
	if len(got) != len(in) {
		t.Fatalf("reordering dropped addresses: %v", got)
	}
	for i, ap := range got[:2] {
		if isPrivateAddr(ap.Addr()) {
			t.Errorf("address %d is %v, a private one ahead of a public", i, ap)
		}
	}
	for _, ap := range got[2:] {
		if !isPrivateAddr(ap.Addr()) {
			t.Errorf("a public address %v was ordered behind a private one", ap)
		}
	}
	// Stable within each group, so an unchanged announcement yields an
	// unchanged map and the engine recognizes the no-op.
	if got[0] != netip.MustParseAddrPort("198.51.100.7:4443") {
		t.Errorf("first address is %v, want the announcement's first public one", got[0])
	}
}

// Site-local IPv6 and the carriers' shared IPv4 are routed between no
// networks, and go behind the public addresses as private ones do: netcheck
// probes a region's first three nodes alone.
func TestUnroutedAddressesGoBehindThePublicOnes(t *testing.T) {
	in := []netip.AddrPort{
		netip.MustParseAddrPort("[fec0::5054:ff:fe12:3456]:4443"),
		netip.MustParseAddrPort("100.64.3.2:4443"),
		netip.MustParseAddrPort("203.0.113.9:4443"),
	}
	if got := relayDialOrder(in, Networks{}); got[0] != in[2] {
		t.Errorf("order %v, want the public address first", got)
	}
}

// A relay seen from this host's own public address, as one behind the same
// router, is dialled first on a network of this host's: netcheck, once it
// has measured, probes a region's first node or two alone. Elsewhere its
// public addresses come first, a private network at another site often
// numbered as this host's own. An address this host holds itself, as every
// Docker host holds 172.17.0.1, is none.
func TestAnAddressOnThisHostsNetworkComesFirstAtOneSite(t *testing.T) {
	local := Networks{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.77.0.1/24"), netip.MustParsePrefix("172.17.0.1/16")},
		Public: []netip.Addr{netip.MustParseAddr("203.0.113.9")}}
	in := []netip.AddrPort{
		netip.MustParseAddrPort("10.0.3.15:4443"),
		netip.MustParseAddrPort("10.77.0.3:4443"),
		netip.MustParseAddrPort("172.17.0.1:4443"),
		netip.MustParseAddrPort("203.0.113.9:4443"),
	}
	if got, want := relayDialOrder(in, local), []netip.AddrPort{in[1], in[3], in[0], in[2]}; !slices.Equal(got, want) {
		t.Errorf("at one site, order %v, want %v", got, want)
	}
	elsewhere := slices.Clone(in)
	elsewhere[3] = netip.MustParseAddrPort("198.51.100.4:4443")
	if got, want := relayDialOrder(elsewhere, local), []netip.AddrPort{elsewhere[3], elsewhere[0], elsewhere[1], elsewhere[2]}; !slices.Equal(got, want) {
		t.Errorf("elsewhere, order %v, want %v", got, want)
	}
}

// This device's own relay leads with an address this host holds: behind a
// NAT that does not hairpin, its public address answers this host nothing,
// and netcheck, once it has measured, probes a region's first node alone, so
// the relay could not be this device's home.
func TestThisDevicesOwnRelayLeadsWithAnAddressItHolds(t *testing.T) {
	local := Networks{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.77.0.3/24")},
		Public: []netip.Addr{netip.MustParseAddr("203.0.113.9")}}
	r := testRelay()
	r.Addrs = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:4443"), netip.MustParseAddrPort("10.77.0.3:4443")}
	r.Own = true
	dm, _ := derpMap([]Relay{r}, nil, false, false, local)
	if n := dm.Regions[7].Nodes[0]; n.IPv4 != "10.77.0.3" {
		t.Errorf("this device's own relay is dialled first at %s, want the address it holds", n.IPv4)
	}
	r.Own = false
	dm, _ = derpMap([]Relay{r}, nil, false, false, local)
	if n := dm.Regions[7].Nodes[0]; n.IPv4 != "203.0.113.9" {
		t.Errorf("another's relay is dialled first at %s, an address this host holds", n.IPv4)
	}
}

// A relay's name is dialled at its public addresses, never at a private one,
// though one on this host's network comes first among its own port's.
func TestANamedRelaysAddressesArePublic(t *testing.T) {
	r := namedRelay()
	r.Addrs = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:4443"), netip.MustParseAddrPort("10.0.0.1:4443")}
	local := Networks{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")}, Public: []netip.Addr{netip.MustParseAddr("192.0.2.10")}}
	dm, _ := derpMap([]Relay{r}, nil, true, false, local)
	for _, n := range dm.Regions[7].Nodes {
		if n.IPv4 == "10.0.0.1" {
			t.Errorf("the name is dialled at a private address: %+v", n)
		}
	}
	if len(dm.Regions[7].Nodes) != 2 {
		t.Errorf("%d nodes, want the name in DNS and at the public address", len(dm.Regions[7].Nodes))
	}
}

// TestSTUNServersNeverBecomeRelays: public STUN servers are asked for this
// node's reflexive address and nothing else. They are STUN-only, least
// preferred as a home by far, and never take a member relay's region.
func TestSTUNServersNeverBecomeRelays(t *testing.T) {
	r := testRelay()
	r.Region = MaxRegionID
	dm, stunRegions := derpMap([]Relay{r}, []string{"stun.example:3478", "[2001:db8::1]:19302"}, false, false, Networks{})
	if dm.Regions[MaxRegionID].Nodes[0].STUNOnly {
		t.Fatal("a STUN server took a member relay's region")
	}
	if len(stunRegions) != 1 {
		t.Fatalf("STUN regions %v, want one for both servers", stunRegions)
	}
	for id := range stunRegions {
		reg := dm.Regions[id]
		if len(reg.Nodes) != 2 || !reg.Nodes[0].STUNOnly || !reg.Nodes[1].STUNOnly || reg.Nodes[0].DERPPort != 0 {
			t.Errorf("region %d is not the STUN-only nodes: %+v", id, reg.Nodes)
		}
		if dm.HomeParams.RegionScore[id] < 1000 {
			t.Errorf("region %d could win the home relay on latency", id)
		}
	}
	if !dm.OmitDefaultRegions {
		t.Fatal("the map lets Tailscale's own regions in")
	}
	if _, err := parseSTUNServer("no-port"); err == nil {
		t.Fatal("accepted a STUN server without a port")
	}
}

// TestTheHomeRelayMayChange: magicsock changes its home relay only while it
// believes a control plane will tell peers, and keeps the first one it picked
// otherwise. With no control plane that first pick is the only one: a node
// started before any relay existed homed on a STUN server and never used the
// relay granted later.
func TestTheHomeRelayMayChange(t *testing.T) {
	n := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	if !n.mgr.(*tsManager).health.GetInPollNetMap() {
		t.Error("the data plane believes it cannot announce a new home relay, so it will keep its first")
	}
}

// A relay's name is a public DNS name and nothing else: an address, a host's
// own name or a label a CA would not sign is never dialled.
func TestARelayNameIsAPublicName(t *testing.T) {
	for _, name := range []string{"relay.example.org", "xn--bcher-kva.example"} {
		if !validRelayName(name) {
			t.Errorf("%s refused", name)
		}
	}
	for _, name := range []string{"127.0.0.1", "10.0.0.1", "localhost", "relay.localhost", "-relay.example.org",
		"relay-.example.org", "relay.example.org:443", "relay.example.org.", "Relay.example.org", "relay",
		strings.Repeat("a", 64) + ".example.org"} {
		if validRelayName(name) {
			t.Errorf("%s taken", name)
		}
	}
}

// TestHostScannersReadTheAppsInterfaces: on Android only the app's own
// interface lister works, so the relay order and an exit node's networks must
// come from netmon's. Run apart, as the lister is the process's.
func TestHostScannersReadTheAppsInterfaces(t *testing.T) {
	if os.Getenv("JUIST_TEST_APP_INTERFACES") == "" {
		cmd := exec.Command(os.Args[0], "-test.run", "^TestHostScannersReadTheAppsInterfaces$", "-test.count", "1")
		cmd.Env = append(os.Environ(), "JUIST_TEST_APP_INTERFACES=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return
	}
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
			ifc("phonewlan", up, "192.168.77.23/24"),
			ifc("phonedown", 0, "10.77.0.5/16"),
			ifc("juist77", up, "100.77.0.1/32", "fd77::1/64"),
		}, nil
	})
	pfx := func(ss ...string) (out []netip.Prefix) {
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	if got, want := hostNetworks("juist77"), pfx("127.0.0.1/8", "192.168.77.23/24"); !slices.Equal(got, want) {
		t.Errorf("hostNetworks = %v, want %v", got, want)
	}
	nets, hosts := attached("juist77")
	if want := pfx("192.168.77.0/24", "10.77.0.0/16"); !slices.Equal(nets, want) {
		t.Errorf("attached's networks = %v, want %v", nets, want)
	}
	if want := []netip.Addr{netip.MustParseAddr("192.168.77.23"), netip.MustParseAddr("10.77.0.5")}; !slices.Equal(hosts, want) {
		t.Errorf("attached's hosts = %v, want %v", hosts, want)
	}
}
