//go:build linux

package conn

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fullGroupDatagram and fullGroupDatagram6 fill the device's MTU, so that
// wrapped they are 20 and 40 bytes past it.
const (
	fullGroupDatagram  = 1280 - 28
	fullGroupDatagram6 = 1280 - 48
)

// A labSend is what sendGroupUntil sends: the family, the sizes, and
// whether by the host's routes rather than on the device.
type labSend struct {
	family string
	sizes  []int
	routed bool
}

// sendGroupUntil has from send group datagrams as s says until every one
// of to has heard each from src.
func sendGroupUntil(from *netnsNode, to []*netnsNode, src netip.Addr, s labSend, within time.Duration) error {
	return heardUntil(to, "HEARD", src, s.sizes, within, func() {
		for _, size := range s.sizes {
			cmd := "SEND " + s.family + " " + strconv.Itoa(size)
			if s.routed {
				cmd += " routed"
			}
			from.command(cmd, "OK")
		}
	})
}

// heardUntil runs again until each of nodes says, asked what, that it heard
// each of sizes from src.
func heardUntil(nodes []*netnsNode, what string, src netip.Addr, sizes []int, within time.Duration, again func()) error {
	deadline := time.Now().Add(within)
	for {
		var missing []string
		for _, n := range nodes {
			heard := strings.Split(strings.TrimPrefix(n.command(what, what), what+" "), ",")
			for _, size := range sizes {
				if want := fmt.Sprintf("%v/%d", src, size); !slices.Contains(heard, want) {
					missing = append(missing, n.name+" "+want)
				}
			}
		}
		if len(missing) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("not heard: %s", strings.Join(missing, ", "))
		}
		again()
		time.Sleep(500 * time.Millisecond)
	}
}

func multicastNodes(nodes ...*netnsNode) {
	for _, n := range nodes {
		n.env = append(n.env, envMulticast+"=1")
	}
}

// pingGroupUntil pings ff02::1 on n's device until each of from answers.
func (n *netnsNode) pingGroupUntil(from []netip.Addr, within time.Duration) error {
	deadline := time.Now().Add(within)
	for {
		out, _ := n.lab.exec(n, "ping", "-6", "-n", "-c", "2", "-i", "0.5", "-W", "2", "-I", n.tun, "ff02::1").CombinedOutput()
		missing := slices.DeleteFunc(slices.Clone(from), func(a netip.Addr) bool {
			return strings.Contains(string(out), "from "+a.String()+"%") || strings.Contains(string(out), "from "+a.String()+":")
		})
		if len(missing) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s: no answer from %v: %s", n.name, missing, strings.TrimSpace(string(out)))
		}
	}
}

// A group datagram sent on one member's device reaches listeners joined on
// the other members' devices, from the sender's overlay address, over IPv6
// its link-local one, full-sized too; and an answer goes back unicast to it,
// as SSDP's does; a ping to ff02::1 is answered by every member.
func TestNetnsAGroupDatagramReachesEveryMember(t *testing.T) {
	t.Parallel()
	lab := newNetnsLab(t)
	a, b, c := lab.addNode("a", 1), lab.addNode("b", 2), lab.addNode("c", 3)
	multicastNodes(a, b, c)
	a.start([]*netnsNode{b, c}, 0)
	b.start([]*netnsNode{a, c}, 0)
	c.start([]*netnsNode{a, b}, 0)
	b.command("JOIN 4", "OK")
	c.command("JOIN 4", "OK")
	b.command("JOIN 6 answer", "OK")
	c.command("JOIN 6", "OK")
	both := []*netnsNode{b, c}
	if err := sendGroupUntil(a, both, a.addrs[0].Addr(), labSend{"4", []int{64, fullGroupDatagram}, false}, 60*time.Second); err != nil {
		t.Fatal(err)
	}
	llA := linkLocal(a.addrs[1].Addr())
	if err := sendGroupUntil(a, both, llA, labSend{"6", []int{64, fullGroupDatagram6}, false}, 60*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := heardUntil([]*netnsNode{a}, "ANSWERS", linkLocal(b.addrs[1].Addr()), []int{len("answer")}, 10*time.Second, func() {
		a.command("SEND 6 64", "OK")
	}); err != nil {
		t.Fatalf("the answer to a's link-local: %v", err)
	}
	if err := a.pingGroupUntil([]netip.Addr{linkLocal(b.addrs[1].Addr()), linkLocal(c.addrs[1].Addr())}, 30*time.Second); err != nil {
		t.Fatalf("a ping to ff02::1: %v", err)
	}
}

// Under an access that passes groups and pings both ways, a ping to ff02::1
// is answered by every member, through a firewall that drops what
// conntrack takes for invalid, as firewalld does.
func TestNetnsAGroupPingIsAnsweredUnderAnAccess(t *testing.T) {
	t.Parallel()
	lab := newNetnsLab(t)
	a, b, c := lab.addNode("a", 1), lab.addNode("b", 2), lab.addNode("c", 3)
	multicastNodes(a, b, c)
	a.start([]*netnsNode{b, c}, 0)
	b.start([]*netnsNode{a, c}, 0)
	c.start([]*netnsNode{a, b}, 0)
	for _, n := range []*netnsNode{a, b, c} {
		n.command("GROUPACCESS", "OK")
	}
	lab.must(lab.exec(a, "nft", "add table inet fw; add chain inet fw input { type filter hook input priority filter; }; add rule inet fw input ct state invalid drop"))
	if err := a.pingUntil(b.addrs[1].Addr(), 60*time.Second); err != nil {
		t.Fatalf("control: %v", err)
	}
	if err := a.pingGroupUntil([]netip.Addr{linkLocal(b.addrs[1].Addr()), linkLocal(c.addrs[1].Addr())}, 30*time.Second); err != nil {
		t.Fatalf("a ping to ff02::1: %v", err)
	}
}

// Through a relay alone, too.
func TestNetnsAGroupDatagramCrossesARelay(t *testing.T) {
	t.Parallel()
	lab := newNATLab(t)
	relayNode := lab.addNode("r", 10)
	a := lab.addNATNode("a", 21, natPortRestricted)
	b := lab.addNATNode("b", 22, natPortRestricted)
	spec := lab.startRelayNode(relayNode, []*netnsNode{a, b})
	lab.blockUDP(a)
	for _, n := range []*netnsNode{a, b} {
		n.env = append(n.env, envRelays+"="+spec.encode(), envNoEndpoints+"=1")
	}
	multicastNodes(a, b)
	a.start([]*netnsNode{b}, 0)
	b.start([]*netnsNode{a}, 0)
	a.waitHome(120 * time.Second)
	b.waitHome(90 * time.Second)
	if err := a.pingUntil(b.addrs[0].Addr(), 120*time.Second); err != nil {
		t.Fatalf("control: a does not reach b through the relay: %v", err)
	}
	b.command("JOIN 4", "OK")
	b.command("JOIN 6", "OK")
	if err := sendGroupUntil(a, []*netnsNode{b}, a.addrs[0].Addr(), labSend{"4", []int{64, fullGroupDatagram}, false}, 60*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := sendGroupUntil(a, []*netnsNode{b}, linkLocal(a.addrs[1].Addr()), labSend{"6", []int{64, fullGroupDatagram6}, false}, 60*time.Second); err != nil {
		t.Fatal(err)
	}
}

// An app that sends a routed group by the host's routes, and one listening
// for it on the host's default interface, reach each other through the
// network, not the LAN: the datagram comes from the sender's overlay
// address.
func TestNetnsARoutedGroupReachesTheDefaultInterface(t *testing.T) {
	t.Parallel()
	lab := newNetnsLab(t)
	a, b := lab.addNode("a", 1), lab.addNode("b", 2)
	multicastNodes(a, b)
	for _, n := range []*netnsNode{a, b} {
		n.env = append(n.env, envGroups+"="+testGroup.Addr().String())
	}
	a.start([]*netnsNode{b}, 0)
	b.start([]*netnsNode{a}, 0)
	b.command("JOIN 4 "+b.veth, "OK")
	if err := sendGroupUntil(a, []*netnsNode{b}, a.addrs[0].Addr(), labSend{"4", []int{64}, true}, 60*time.Second); err != nil {
		t.Fatal(err)
	}
}
