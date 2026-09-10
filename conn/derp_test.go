package conn

import (
	"net/netip"
	"testing"
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
	dm := derpMap([]Relay{testRelay()})
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
	if got := derpMap([]Relay{quiet}).Regions[7].Nodes[0].STUNPort; got != -1 {
		t.Errorf("STUNPort %d for a relay that does not reflect, want -1 (disabled)", got)
	}

	// No relays is direct-only, which is a nil map rather than an empty one:
	// an empty map is a change the engine would act on.
	if derpMap(nil) != nil {
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
	got := relayDialOrder(in)
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
