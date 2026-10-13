//go:build unix

package plumber

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// A ServeSpec is what a device serves its peers as an exit node or subnet
// router: their traffic from Sources, masqueraded onto the host's networks,
// and, where DNSPort is set, their DNS on port 53 of Addrs, the device's own,
// redirected to the forwarder there. Local is what may reach into the
// overlay unasked: every private and special range.
type ServeSpec struct {
	Sources []netip.Prefix `cbor:"1,keyasint,omitempty"`
	Addrs   []netip.Addr   `cbor:"2,keyasint,omitempty"`
	DNSPort uint16         `cbor:"3,keyasint,omitempty"`
	Local   []netip.Prefix `cbor:"4,keyasint,omitempty"`
}

// An uplink is a device of the host's but juist's and the loopback, with
// the address served traffic leaving by it is masqueraded to, a global one,
// in each family it has.
type uplink struct {
	name         string
	addr4, addr6 netip.Addr
}

// serveRules is the pf anchor serving dev as s asks, beside the host's other
// devices, uplinks.
func serveRules(dev string, s ServeSpec, uplinks []uplink) string {
	var b strings.Builder
	list := func(ps []netip.Prefix, v6 bool) string {
		var out []string
		for _, p := range ps {
			if p.Addr().Is6() == v6 {
				out = append(out, p.String())
			}
		}
		return strings.Join(out, ", ")
	}
	fmt.Fprintf(&b, "table <juist_local> const { %s }\n", strings.Join(prefixStrings(s.Local), ", "))
	for _, u := range uplinks {
		for _, fam := range []struct {
			v6   bool
			name string
			addr netip.Addr
		}{{false, "inet", u.addr4}, {true, "inet6", u.addr6}} {
			if src := list(s.Sources, fam.v6); src != "" && fam.addr.IsValid() {
				fmt.Fprintf(&b, "nat on %s %s from { %s } to any -> %s\n", u.name, fam.name, src, fam.addr)
			}
		}
	}
	if s.DNSPort != 0 {
		for _, a := range s.Addrs {
			fam := "inet"
			if a.Is6() {
				fam = "inet6"
			}
			fmt.Fprintf(&b, "rdr on %s %s proto { tcp udp } from any to %s port 53 -> %s port %d\n", dev, fam, a, a, s.DNSPort)
		}
	}
	// Overlay sources by juist's devices alone, and the forwarder through
	// this one alone: others could claim to be members. The loopback is the
	// host's own, and named by none.
	var others []string
	for _, u := range uplinks {
		others = append(others, u.name)
	}
	if len(others) > 0 {
		on := strings.Join(others, " ")
		fmt.Fprintf(&b, "block in quick on { %s } from { %s }\n", on, strings.Join(prefixStrings(s.Sources), ", "))
		if s.DNSPort != 0 && len(s.Addrs) > 0 {
			var addrs []string
			for _, a := range s.Addrs {
				addrs = append(addrs, a.String())
			}
			fmt.Fprintf(&b, "block in quick on { %s } proto { tcp udp } to { %s } port { 53 %d }\n", on,
				strings.Join(addrs, ", "), s.DNSPort)
		}
	}
	// Nothing from the internet reaches into the overlay unasked; answers
	// to what peers sent follow the state it takes coming in, which the
	// NAT's, taken going out, is not for the device. Not quick: the host's
	// own rules on the device still have their say.
	fmt.Fprintf(&b, "pass in on %s all flags any keep state\n", dev)
	fmt.Fprintf(&b, "block out quick on %s from ! <juist_local>\n", dev)
	// What the host opens through the device takes its state going out: one
	// taken from the answer knows no window scaling, and pf drops the
	// segments past the window it assumes.
	fmt.Fprintf(&b, "pass out on %s all keep state\n", dev)
	return b.String()
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	slices.Sort(out)
	return out
}

// callsAnchors reports whether a ruleset, as pfctl lists it, calls juist's
// anchors, with no rule passing quick before the filter's.
func callsAnchors(nat, rules string) bool {
	if !strings.Contains(nat, `nat-anchor "juist/*"`) || !strings.Contains(nat, `rdr-anchor "juist/*"`) {
		return false
	}
	for _, l := range strings.Split(rules, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, `anchor "juist/*"`) {
			return true
		}
		if strings.HasPrefix(l, "pass") && strings.Contains(" "+l+" ", " quick ") {
			return false
		}
	}
	return false
}
