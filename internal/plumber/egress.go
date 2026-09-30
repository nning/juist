//go:build unix

package plumber

import (
	"fmt"
	"net/netip"
	"strings"
)

// Egress modes: the host's routes, the tunnel, or refused, as while the exit
// node chosen cannot be used.
const (
	EgressDirect  = "direct"
	EgressTunnel  = "tunnel"
	EgressRefused = "refused"
)

// An EgressSpec is where the host's traffic outside the overlay goes. Capture
// is routed into the device, the internet less what the host keeps; in the
// tunnel, V4 and V6 say which families an exit node carries, and Subnets
// what routers do, the rest refused at once. Local may leave outside it, and
// answers to connections that came in by another device, but with Isolate.
type EgressSpec struct {
	Mode    string         `cbor:"1,keyasint"`
	V4      bool           `cbor:"2,keyasint,omitempty"`
	V6      bool           `cbor:"3,keyasint,omitempty"`
	Subnets []netip.Prefix `cbor:"4,keyasint,omitempty"`
	Local   []netip.Prefix `cbor:"5,keyasint,omitempty"`
	Capture []netip.Prefix `cbor:"6,keyasint,omitempty"`
	Isolate bool           `cbor:"7,keyasint,omitempty"`
}

// A gateway is the host's default route in one family: its device, next hop
// and the device's address that juistd's own traffic leaves with.
type gateway struct {
	dev  string
	hop  netip.Addr
	addr netip.Addr
}

// egressRules is the pf anchor for dev's egress as e asks, the host's own
// gateways gw4 and gw6 taking the traffic of uid, juistd's, where valid.
func egressRules(dev string, e EgressSpec, uid int, gw4, gw6 gateway) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table <juist_local> const { %s }\n", strings.Join(prefixStrings(e.Local), ", "))
	fmt.Fprintf(&b, "table <juist_carried> const { %s }\n", strings.Join(prefixStrings(append(append(
		[]netip.Prefix(nil), e.Local...), e.Subnets...)), ", "))
	user := fmt.Sprint(uid)
	for _, g := range []struct {
		fam string
		gw  gateway
	}{{"inet", gw4}, {"inet6", gw6}} {
		if !g.gw.hop.IsValid() || !g.gw.addr.IsValid() {
			continue
		}
		// What juistd sends goes by the host's routes, as on Linux its user
		// is routed by main: out of the tunnel, from the device's address.
		fmt.Fprintf(&b, "nat on %s %s tagged juist_self -> %s\n", g.gw.dev, g.fam, g.gw.addr)
		fmt.Fprintf(&b, "pass out quick on %s route-to (%s %s) %s proto { tcp udp } from any to ! <juist_local> user %s no state tag juist_self\n",
			dev, g.gw.dev, g.gw.hop, g.fam, user)
	}
	if !e.Isolate {
		// Answers to what comes in by another device leave by it: its
		// state passes them by the guard, and reply-to sends them back to a
		// gateway, not into the tunnel. Not quick: the host's rules decide.
		// Any packet takes state, sloppily, so that a connection older than
		// the anchor, as the ssh session choosing the exit node, is kept.
		fmt.Fprintf(&b, "pass in on ! %s from ! <juist_local> flags any keep state (sloppy)\n", dev)
		for _, g := range []struct {
			fam string
			gw  gateway
		}{{"inet", gw4}, {"inet6", gw6}} {
			if g.gw.hop.IsValid() {
				fmt.Fprintf(&b, "pass in on %s reply-to (%s %s) %s from ! <juist_local> to (%s) flags any keep state (sloppy)\n",
					g.gw.dev, g.gw.dev, g.gw.hop, g.fam, g.gw.dev)
			}
		}
	}
	for _, fam := range []struct {
		name    string
		carried bool
	}{{"inet", e.V4}, {"inet6", e.V6}} {
		if e.Mode == EgressRefused || !fam.carried {
			fmt.Fprintf(&b, "block return out quick on %s %s to ! <juist_carried>\n", dev, fam.name)
		}
	}
	// Without state, as Linux's guard: a stateful pass takes a TCP
	// connection by its SYN alone, and would drop what answers one that
	// came in, as sshd's does.
	fmt.Fprintf(&b, "pass out quick on %s all no state\n", dev)
	b.WriteString("pass out quick on lo0 all no state\n")
	fmt.Fprintf(&b, "pass out quick proto { tcp udp } all user %s no state\n", user)
	b.WriteString("pass out quick inet proto udp from port 68 to port 67 no state\n")
	b.WriteString("pass out quick inet6 proto udp from port 546 to port 547 no state\n")
	b.WriteString("pass out quick inet6 proto icmp6 icmp6-type { routersol, neighbrsol, neighbradv } no state\n")
	b.WriteString("pass out quick to <juist_local> no state\n")
	b.WriteString("block drop out quick all\n")
	return b.String()
}
