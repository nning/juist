//go:build unix

package plumber

import (
	"net/netip"
	"strings"
	"testing"
)

// Serving masquerades each family's sources onto each uplink's address of
// that family, redirects DNS on the device's own addresses to the forwarder,
// takes overlay sources and the forwarder by the tunnel alone, and lets
// nothing from the internet into the overlay unasked; the tunnel's states
// hold on the tunnel alone.
func TestServingRules(t *testing.T) {
	s := ServeSpec{
		Sources: prefixes("198.19.44.0/22", "fdc6:6d7a:fd03::/48"),
		Addrs:   []netip.Addr{netip.MustParseAddr("198.19.44.1"), netip.MustParseAddr("fdc6:6d7a:fd03::1")},
		DNSPort: 41646,
		Local:   prefixes("10.0.0.0/8", "fc00::/7"),
	}
	ups := []uplink{
		{name: "vtnet0", addr4: netip.MustParseAddr("10.0.2.15"), addr6: netip.MustParseAddr("2001:db8::15")},
		{name: "vtnet1", addr4: netip.MustParseAddr("10.77.0.1")},
	}
	got := serveRules("juist0", s, ups)
	for _, want := range []string{
		"table <juist_local> const { 10.0.0.0/8, fc00::/7 }",
		"nat on vtnet0 inet from { 198.19.44.0/22 } to any -> 10.0.2.15",
		"nat on vtnet0 inet6 from { fdc6:6d7a:fd03::/48 } to any -> 2001:db8::15",
		"nat on vtnet1 inet from { 198.19.44.0/22 } to any -> 10.77.0.1",
		"rdr on juist0 inet proto { tcp udp } from any to 198.19.44.1 port 53 -> 198.19.44.1 port 41646",
		"rdr on juist0 inet6 proto { tcp udp } from any to fdc6:6d7a:fd03::1 port 53 -> fdc6:6d7a:fd03::1 port 41646",
		"block in quick on { vtnet0 vtnet1 } from { 198.19.44.0/22, fdc6:6d7a:fd03::/48 }",
		"block in quick on { vtnet0 vtnet1 } proto { tcp udp } to { 198.19.44.1, fdc6:6d7a:fd03::1 } port { 53 41646 }",
		"pass in on juist0 all flags any keep state (if-bound)",
		"block out quick on juist0 from ! <juist_local>",
		"pass out on juist0 all keep state (if-bound)",
	} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("the rules lack %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "vtnet1 inet6") {
		t.Errorf("an uplink without IPv6 masquerades IPv6:\n%s", got)
	}
	if got := serveRules("juist0", ServeSpec{Sources: s.Sources, Local: s.Local}, ups); strings.Contains(got, "rdr") ||
		strings.Contains(got, "port { 53") {
		t.Errorf("without DNS, DNS is redirected:\n%s", got)
	}
}

// Using an exit node, juistd's own traffic goes by the host's gateway from
// the gateway device's address, a family no exit node carries is refused at
// once but for routed subnets, and nothing else leaves by another device but
// local space, DHCP and neighbour discovery.
func TestEgressRules(t *testing.T) {
	e := EgressSpec{Mode: EgressTunnel, V4: true, Subnets: prefixes("2a01:4f8:1::/48"),
		Local: prefixes("10.0.0.0/8", "fc00::/7")}
	gw4 := gateway{dev: "vtnet0", hop: netip.MustParseAddr("10.0.2.2"), addr: netip.MustParseAddr("10.0.2.15")}
	got := egressRules("juist0", e, 800, gw4, gateway{})
	for _, want := range []string{
		"table <juist_carried> const { 10.0.0.0/8, 2a01:4f8:1::/48, fc00::/7 }",
		"nat on vtnet0 inet tagged juist_self -> 10.0.2.15",
		"pass out quick on juist0 route-to (vtnet0 10.0.2.2) inet proto { tcp udp } from any to ! <juist_local> user 800 no state tag juist_self",
		"block return out quick on juist0 inet6 to ! <juist_carried>",
		"pass out quick on juist0 all no state",
		"pass out quick proto { tcp udp } all user 800 no state",
		"pass out quick to <juist_local> no state",
		"block drop out quick all",
	} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("the rules lack %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "juist0 inet to !") || strings.Contains(got, "inet6 tagged") {
		t.Errorf("a family carried is refused, or one without a gateway is taken back:\n%s", got)
	}
	if strings.Index(got, "block return") > strings.Index(got, "pass out quick on juist0 all no state") {
		t.Errorf("the refusal comes after the tunnel's pass:\n%s", got)
	}
	refused := egressRules("juist0", EgressSpec{Mode: EgressRefused, V4: true, V6: true, Local: e.Local}, 800, gw4, gateway{})
	if !strings.Contains(refused, "block return out quick on juist0 inet to ! <juist_carried>") {
		t.Errorf("refused, IPv4 goes in:\n%s", refused)
	}
}

// Answers to what came in by another device leave by it, back to its gateway,
// in rules that are not quick, so that the host's own decide; isolated, they
// go into the tunnel with the rest.
func TestAnswersLeaveTheWayTheyCame(t *testing.T) {
	gw4 := gateway{dev: "vtnet0", hop: netip.MustParseAddr("10.0.2.2"), addr: netip.MustParseAddr("10.0.2.15")}
	e := EgressSpec{Mode: EgressTunnel, V4: true, Local: prefixes("10.0.0.0/8")}
	got := egressRules("juist0", e, 800, gw4, gateway{})
	for _, want := range []string{
		"pass in on ! juist0 from ! <juist_local> flags any keep state (sloppy)",
		"pass in on vtnet0 reply-to (vtnet0 10.0.2.2) inet from ! <juist_local> to (vtnet0) flags any keep state (sloppy)",
	} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("the rules lack %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "pass in quick") || strings.Contains(got, "inet6 from") || strings.Contains(got, "pass in from") {
		t.Errorf("answers pass quick, by a gateway there is none of, or by the tunnel's device:\n%s", got)
	}
	e.Isolate = true
	if got := egressRules("juist0", e, 800, gw4, gateway{}); strings.Contains(got, "pass in") {
		t.Errorf("isolated, answers leave by another device:\n%s", got)
	}
}

// The host's own pf rules must call juist's anchors, and pass nothing quick
// before the filter's, which would pass what the guard drops.
func TestTheHostsRulesCallTheAnchorsFirst(t *testing.T) {
	nat := "nat-anchor \"juist/*\" all\nrdr-anchor \"juist/*\" all\n"
	for _, tc := range []struct {
		nat, rules string
		want       bool
	}{
		{nat, "anchor \"juist/*\" all\npass quick on em0 all\n", true},
		{nat, "block drop in quick on em0 from 192.0.2.0/24 to any\nanchor \"juist/*\" all\n", true},
		{nat, "pass out quick on em0 all flags S/SA keep state\nanchor \"juist/*\" all\n", false},
		{nat, "pass in all\n", false},
		{"rdr-anchor \"juist/*\" all\n", "anchor \"juist/*\" all\n", false},
	} {
		if got := callsAnchors(tc.nat, tc.rules); got != tc.want {
			t.Errorf("%q: %v, want %v", tc.rules, got, tc.want)
		}
	}
}
