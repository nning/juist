//go:build linux

package conn

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fullGroupDatagram fills the device's MTU, so that wrapped it is 20 bytes
// past it.
const fullGroupDatagram = 1280 - 28

// sendGroupUntil has from send a group datagram of each size until every
// one of to has heard each from from's overlay IPv4 address.
func sendGroupUntil(from *netnsNode, to []*netnsNode, sizes []int, within time.Duration) error {
	src := from.addrs[0].Addr()
	deadline := time.Now().Add(within)
	for {
		var missing []string
		for _, n := range to {
			heard := strings.Split(strings.TrimPrefix(n.command("HEARD", "HEARD"), "HEARD "), ",")
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
		for _, size := range sizes {
			from.command("SEND "+strconv.Itoa(size), "OK")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// A group datagram sent on one member's device reaches listeners joined on
// the other members' devices, from the sender's overlay address, a full-sized
// one too.
func TestNetnsAGroupDatagramReachesEveryMember(t *testing.T) {
	t.Parallel()
	lab := newNetnsLab(t)
	a, b, c := lab.addNode("a", 1), lab.addNode("b", 2), lab.addNode("c", 3)
	for _, n := range []*netnsNode{a, b, c} {
		n.env = append(n.env, envMulticast+"=1")
	}
	a.start([]*netnsNode{b, c}, 0)
	b.start([]*netnsNode{a, c}, 0)
	c.start([]*netnsNode{a, b}, 0)
	b.command("JOIN", "OK")
	c.command("JOIN", "OK")
	if err := sendGroupUntil(a, []*netnsNode{b, c}, []int{64, fullGroupDatagram}, 60*time.Second); err != nil {
		t.Fatal(err)
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
		n.env = append(n.env, envRelays+"="+spec.encode(), envNoEndpoints+"=1", envMulticast+"=1")
	}
	a.start([]*netnsNode{b}, 0)
	b.start([]*netnsNode{a}, 0)
	a.waitHome(120 * time.Second)
	b.waitHome(90 * time.Second)
	if err := a.pingUntil(b.addrs[0].Addr(), 120*time.Second); err != nil {
		t.Fatalf("control: a does not reach b through the relay: %v", err)
	}
	b.command("JOIN", "OK")
	if err := sendGroupUntil(a, []*netnsNode{b}, []int{64, fullGroupDatagram}, 60*time.Second); err != nil {
		t.Fatal(err)
	}
}
