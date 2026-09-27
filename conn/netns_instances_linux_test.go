//go:build linux

package conn

import (
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestNetnsAHostInTwoNetworks is M5's exit criteria (1) and (3)
// (docs/05-roadmap.md) as the data plane sees them: one host runs two
// instances, each in a network of its own, and reaches the members of both
// over IPv4 and IPv6; no route into either device covers the other network's
// addresses; the other network's member is reached through its own instance
// alone; and one network removing the host, or either instance stopping and
// starting again, leaves the other's tunnel as it was. That the rules stay is
// TestNetnsInstancesLeaveEachOtherAlone's, which looks at once rather than
// after a ping that the restore would have outwaited.
func TestNetnsAHostInTwoNetworks(t *testing.T) {
	lab := newNetnsLab(t)
	home := lab.addNode("h", 1) // instance 0, in network "home" with x
	work := lab.addInstance(home, "w", 21, 3)
	x := lab.addNode("x", 2)
	y := lab.addNode("y", 3)
	// The two networks' ranges, apart, so that a route covering one of them
	// shows up as such rather than only an exact address.
	homeNets := []netip.Prefix{netip.MustParsePrefix("100.64.0.0/24"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")}
	workNets := []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24"), netip.MustParsePrefix("fd7a:115c:b000::/48")}
	for _, n := range []*netnsNode{work, y} {
		n.addrs = []netip.Prefix{
			netip.MustParsePrefix(fmt.Sprintf("10.9.0.%d/32", n.id)),
			netip.MustParsePrefix(fmt.Sprintf("fd7a:115c:b000::%d/128", n.id)),
		}
	}

	home.start([]*netnsNode{x}, 0)
	work.start([]*netnsNode{y}, 0)
	x.start([]*netnsNode{home}, 0)
	y.start([]*netnsNode{work}, 0)

	reach := func(when string, from, to *netnsNode) {
		t.Helper()
		for _, p := range to.addrs {
			if err := from.pingUntil(p.Addr(), 60*time.Second); err != nil {
				t.Fatalf("%s: %s cannot reach %s at %v: %v", when, from.name, to.name, p.Addr(), err)
			}
		}
	}
	apart := func(when string) {
		t.Helper()
		for _, c := range []struct {
			dev   *netnsNode
			other []netip.Prefix
		}{{home, workNets}, {work, homeNets}} {
			for _, r := range c.dev.routes() {
				for _, o := range c.other {
					if r.Overlaps(o) {
						t.Errorf("%s: %v, over the other network's %v, is routed into %s", when, r, o, c.dev.tun)
					}
				}
			}
		}
	}
	reach("both running", home, x)
	reach("both running", work, y)
	reach("both running", x, home)
	reach("both running", y, work)
	apart("both running")

	// y is reached through work's instance and no other: with it stopped,
	// nothing on the host routes to y at all.
	work.stop()
	if err := home.ping(y.addrs[0].Addr()); err == nil {
		t.Fatalf("with work's instance stopped, %v of work is still reached", y.addrs[0].Addr())
	}
	reach("work stopped", home, x)
	work.restart(work.addrs, []*netnsNode{y})
	reach("work restarted", work, y)

	// Work removes the host: its peer set empties, and home does not notice.
	work.setPeers("none")
	if err := work.ping(y.addrs[0].Addr()); err == nil {
		t.Errorf("removed from work, the host still reaches %v", y.addrs[0].Addr())
	}
	reach("removed from work", home, x)
	reach("removed from work", x, home)
	work.setPeers("all")
	reach("readmitted to work", work, y)

	home.stop()
	reach("home stopped", work, y)
	home.restart(home.addrs, []*netnsNode{x})
	reach("home restarted", home, x)
	reach("home restarted", work, y)
	apart("after the restarts")
}

// TestNetnsRenumberingKeepsEveryPairReachable is M5's exit criteria (5) and
// (6) as the data plane sees them. The network moves from 100.64.0.0/24 to
// 10.7.0.0/24 while c is offline: a and b hold both addresses, and send from
// the old one, which c still expects; c returns on its old log and reaches
// both, then learns the move; past the deadline only the new addresses
// remain. Then c alone moves once more, and is reached at both of its
// addresses until that deadline, and at the new one only after it.
func TestNetnsRenumberingKeepsEveryPairReachable(t *testing.T) {
	lab := newNetnsLab(t)
	a, b, c := lab.addNode("a", 1), lab.addNode("b", 2), lab.addNode("c", 3)
	oldV4 := func(n *netnsNode) netip.Prefix { return netip.MustParsePrefix(fmt.Sprintf("100.64.0.%d/32", n.id)) }
	newV4 := func(n *netnsNode) netip.Prefix { return netip.MustParsePrefix(fmt.Sprintf("10.7.0.%d/32", n.id)) }
	lastV4 := func(n *netnsNode) netip.Prefix { return netip.MustParsePrefix(fmt.Sprintf("10.7.0.%d/32", 30+n.id)) }
	v6 := func(n *netnsNode) netip.Prefix {
		return netip.MustParsePrefix(fmt.Sprintf("fd7a:115c:a1e0::%d/128", n.id))
	}
	// The daemon's order: IPv6, the retiring address, the new one. The first
	// IPv4 is the one sent from.
	before := func(n *netnsNode) []netip.Prefix { return []netip.Prefix{v6(n), oldV4(n)} }
	moving := func(n *netnsNode) []netip.Prefix { return []netip.Prefix{v6(n), oldV4(n), newV4(n)} }
	after := func(n *netnsNode) []netip.Prefix { return []netip.Prefix{v6(n), newV4(n)} }
	views := func(addrs func(*netnsNode) []netip.Prefix, ns ...*netnsNode) []*netnsNode {
		out := make([]*netnsNode, len(ns))
		for i, n := range ns {
			out[i] = viewOf(n, addrs(n)...)
		}
		return out
	}
	reach := func(when string, from, to *netnsNode, addrs ...netip.Prefix) {
		t.Helper()
		for _, p := range addrs {
			if err := from.pingUntil(p.Addr(), 60*time.Second); err != nil {
				t.Fatalf("%s: %s cannot reach %s at %v: %v", when, from.name, to.name, p.Addr(), err)
			}
		}
	}
	// everyPair reaches every node from every other at the addresses holds
	// gives it, the way the sender's view has them.
	everyPair := func(when string, holds func(from, to *netnsNode) []netip.Prefix) {
		t.Helper()
		for _, from := range []*netnsNode{a, b, c} {
			for _, to := range []*netnsNode{a, b, c} {
				if from != to {
					reach(when, from, to, holds(from, to)...)
				}
			}
		}
	}

	a.addrs, b.addrs, c.addrs = before(a), before(b), before(c)
	a.start(views(before, b, c), 0)
	b.start(views(before, a, c), 0)
	c.start(views(before, a, b), 0)
	everyPair("before", func(_, to *netnsNode) []netip.Prefix { return before(to) })

	// The renumbering applies on a and b; c is offline and misses it.
	c.stop()
	a.restart(moving(a), views(moving, b, c))
	b.restart(moving(b), views(moving, a, c))
	reach("moving", a, b, moving(b)...)
	reach("moving", b, a, moving(a)...)

	// c returns on its old log: it knows nobody's new address, and a and b
	// reach it at the one it holds, from the ones it expects.
	c.restart(before(c), views(before, a, b))
	everyPair("c returned, behind", func(from, to *netnsNode) []netip.Prefix { return before(to) })

	// c learns the move.
	c.restart(moving(c), views(moving, a, b))
	everyPair("c caught up", func(_, to *netnsNode) []netip.Prefix { return moving(to) })

	// Past the deadline the old addresses retire everywhere.
	restartAll := func(addrs func(*netnsNode) []netip.Prefix) {
		t.Helper()
		for _, n := range []*netnsNode{a, b, c} {
			others := slices.DeleteFunc([]*netnsNode{a, b, c}, func(o *netnsNode) bool { return o == n })
			n.restart(addrs(n), views(addrs, others...))
		}
	}
	restartAll(after)
	everyPair("after the deadline", func(_, to *netnsNode) []netip.Prefix { return after(to) })
	for _, n := range []*netnsNode{a, b, c} {
		if held := n.deviceAddrs(); slices.Contains(held, oldV4(n).Addr()) || !slices.Contains(held, newV4(n).Addr()) {
			t.Errorf("after the deadline %s's device holds %v", n.name, held)
		}
	}

	// c alone moves on (criterion 6): both of its addresses work until the
	// deadline, the new one only after it.
	cMoving := func(n *netnsNode) []netip.Prefix {
		if n == c {
			return []netip.Prefix{v6(c), newV4(c), lastV4(c)}
		}
		return after(n)
	}
	restartAll(cMoving)
	reach("c moving", a, c, cMoving(c)...)
	reach("c moving", b, c, cMoving(c)...)
	reach("c moving", c, a, after(a)...)
	cMoved := func(n *netnsNode) []netip.Prefix {
		if n == c {
			return []netip.Prefix{v6(c), lastV4(c)}
		}
		return after(n)
	}
	restartAll(cMoved)
	everyPair("c moved", func(_, to *netnsNode) []netip.Prefix { return cMoved(to) })
	if held := c.deviceAddrs(); slices.Contains(held, newV4(c).Addr()) {
		t.Errorf("past its deadline c's device still holds %v: %v", newV4(c).Addr(), held)
	}
}

// deviceAddrs lists the addresses on the node's overlay device.
func (n *netnsNode) deviceAddrs() []netip.Addr {
	t := n.lab.t
	t.Helper()
	out, err := exec.Command(n.lab.ip, "-n", n.ns, "-o", "addr", "show", "dev", n.tun).CombinedOutput()
	if err != nil {
		t.Fatalf("listing %s's addresses: %v: %s", n.tun, err, strings.TrimSpace(string(out)))
	}
	var addrs []netip.Addr
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "inet" || f[i] == "inet6" {
				if p, err := netip.ParsePrefix(f[i+1]); err == nil {
					addrs = append(addrs, p.Addr())
				}
			}
		}
	}
	return addrs
}
