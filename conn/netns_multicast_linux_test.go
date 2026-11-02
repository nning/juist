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
	if err := sendGroupUntil(a, both, a.addrs[0].Addr(), labSend{"4", []int{64, 65, fullGroupDatagram}, false}, 60*time.Second); err != nil {
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
	if err := sendGroupUntil(a, []*netnsNode{b}, a.addrs[0].Addr(), labSend{"4", []int{64, 65, fullGroupDatagram}, false}, 60*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := sendGroupUntil(a, []*netnsNode{b}, linkLocal(a.addrs[1].Addr()), labSend{"6", []int{64, fullGroupDatagram6}, false}, 60*time.Second); err != nil {
		t.Fatal(err)
	}
}

// A copied group reaches a listener joined on the default interface.

func TestNetnsACopiedGroupReachesTheDefaultInterface(t *testing.T) {
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

func TestNetnsDiscoveryKeepsTheLAN(t *testing.T) {
	for _, family := range []string{"4", "4-list", "minecraft", "ssdp", "broadcast", "broadcast-directed"} {
		t.Run(family, func(t *testing.T) {
			lab := newNetnsLab(t)
			a, b, c := lab.addNode("a", 1), lab.addNode("b", 2), lab.addNode("c", 3)
			multicastNodes(a, b)
			group, port := testGroup.Addr().String(), "45353"
			if family == "minecraft" {
				group, port = "224.0.2.60", "4445"
			}
			if family == "ssdp" {
				group, port = "239.255.255.250", "1900"
			}
			if family == "4-list" {
				for _, n := range []*netnsNode{a, b} {
					n.env = append(n.env, envGroups+"="+group)
				}
			}
			a.start([]*netnsNode{b}, 0)
			b.start([]*netnsNode{a}, 0)
			c.start(nil, 0)
			b.command("JOIN "+family+" "+b.veth+" answer", "OK")
			c.command("JOIN "+family+" "+c.veth, "OK")
			lab.must(lab.exec(a, "nft", "add table ip marks; add chain ip marks before { type filter hook output priority 9; }; add chain ip marks after { type filter hook output priority 11; }; add rule ip marks before oifname \""+a.veth+"\" udp dport "+port+" meta mark set 0x1234; add rule ip marks after oifname \""+a.veth+"\" udp dport "+port+" meta mark != 0x1234 drop"))
			lab.must(lab.exec(b, "nft", "add table ip lan; add chain ip lan pre { type filter hook prerouting priority -300; }; add rule ip lan pre iifname \""+b.veth+"\" udp dport "+port+" drop"))
			if err := a.pingUntil(b.addrs[0].Addr(), 60*time.Second); err != nil {
				t.Fatal(err)
			}
			if err := sendGroupUntil(a, []*netnsNode{b}, a.addrs[0].Addr(), labSend{family, []int{64, 65, fullGroupDatagram}, true}, 15*time.Second); err != nil {
				for _, n := range []*netnsNode{a, b} {
					out, _ := lab.exec(n, "sh", "-c", "nft list ruleset; ip route show table all; ip route get "+b.addrs[0].Addr().String()+" oif "+a.tun).CombinedOutput()
					t.Logf("%s rules: %s", n.name, out)
				}
				t.Fatal(err)
			}
			if err := sendGroupUntil(a, []*netnsNode{c}, a.underlay, labSend{family, []int{64, 65, fullGroupDatagram, 1300}, true}, 10*time.Second); err != nil {
				t.Fatalf("LAN original: %v", err)
			}
			if err := heardUntil([]*netnsNode{a}, "ANSWERS", b.addrs[0].Addr(), []int{len("answer")}, 10*time.Second, func() { a.command("SEND "+family+" 64 routed", "OK") }); err != nil {
				t.Fatalf("unicast answer: %v", err)
			}
			if heard := b.command("HEARD", "HEARD"); strings.Contains(heard, "/1300") {
				t.Fatalf("oversized discovery crossed: %s", heard)
			}
			a.setPeers("none")
			out, err := lab.exec(a, "nft", "list tables").CombinedOutput()
			if err != nil || strings.Contains(string(out), "discovery") {
				t.Fatalf("discovery without peers: %s (%v)", out, err)
			}
			a.setPeers("all")
			if err := sendGroupUntil(a, []*netnsNode{b}, a.addrs[0].Addr(), labSend{family, []int{80}, true}, 15*time.Second); err != nil {
				t.Fatalf("restored peer: %v", err)
			}
			a.stop()
			out, err = lab.exec(a, "nft", "list tables").CombinedOutput()
			if err != nil || strings.Contains(string(out), "discovery") {
				t.Fatalf("discovery rules left after stop: %s (%v)", out, err)
			}
		})
	}
}

func TestNetnsAutomaticGroupsCanBeDisabled(t *testing.T) {
	lab := newNetnsLab(t)
	a, b := lab.addNode("a", 1), lab.addNode("b", 2)
	multicastNodes(a, b)
	a.env = append(a.env, envGroups+"=none")
	a.start([]*netnsNode{b}, 0)
	b.start([]*netnsNode{a}, 0)
	b.command("JOIN minecraft "+b.veth, "OK")
	lab.must(lab.exec(b, "nft", "add table ip lan; add chain ip lan pre { type filter hook prerouting priority -300; }; add rule ip lan pre iifname "+b.veth+" udp dport 4445 drop"))
	if err := a.pingUntil(b.addrs[0].Addr(), 60*time.Second); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		a.command("SEND minecraft 64 routed", "OK")
	}
	time.Sleep(500 * time.Millisecond)
	if heard := b.command("HEARD", "HEARD"); strings.Contains(heard, "/64") {
		t.Fatalf("disabled copies crossed: %s", heard)
	}
	if err := sendGroupUntil(a, []*netnsNode{b}, a.addrs[0].Addr(), labSend{"minecraft", []int{80}, false}, 15*time.Second); err != nil {
		t.Fatalf("native multicast was disabled too: %v", err)
	}
}

func TestNetnsUnderlayGroupsAreNotCopied(t *testing.T) {
	lab := newNetnsLab(t)
	a, b := lab.addNode("a", 1), lab.addNode("b", 2)
	multicastNodes(a, b)
	a.start([]*netnsNode{b}, 0)
	b.start([]*netnsNode{a}, 0)
	b.command("JOIN minecraft "+b.veth, "OK")
	lab.must(lab.exec(b, "nft", "add table ip lan; add chain ip lan pre { type filter hook prerouting priority -300; }; add rule ip lan pre iifname "+b.veth+" udp dport 4445 drop"))
	if err := a.pingUntil(b.addrs[0].Addr(), 60*time.Second); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		a.command("SEND minecraft 64 underlay", "OK")
	}
	time.Sleep(500 * time.Millisecond)
	if heard := b.command("HEARD", "HEARD"); strings.Contains(heard, "/64") {
		t.Fatalf("underlay packet copied: %s", heard)
	}
	if err := sendGroupUntil(a, []*netnsNode{b}, a.addrs[0].Addr(), labSend{"minecraft", []int{80}, true}, 15*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestNetnsDiscoveryFollowsMulticastAccess(t *testing.T) {
	for _, off := range []bool{false, true} {
		t.Run(strconv.FormatBool(off), func(t *testing.T) {
			lab := newNetnsLab(t)
			a, b := lab.addNode("a", 1), lab.addNode("b", 2)
			if off {
				multicastNodes(b)
			} else {
				multicastNodes(a, b)
			}
			a.start([]*netnsNode{b}, 0)
			b.start([]*netnsNode{a}, 0)
			b.command("JOIN minecraft "+b.veth, "OK")
			b.command("JOIN broadcast", "OK")
			lab.must(lab.exec(b, "nft", "add table ip lan; add chain ip lan pre { type filter hook prerouting priority -300; }; add rule ip lan pre iifname "+b.veth+" udp dport { 4445, 45353 } drop"))
			if err := a.pingUntil(b.addrs[0].Addr(), 60*time.Second); err != nil {
				t.Fatal(err)
			}
			table := func(want bool) {
				t.Helper()
				out, err := lab.exec(a, "nft", "list table ip juist0discovery").CombinedOutput()
				if (err == nil) != want {
					t.Fatalf("copy table present=%v, want %v: %s", err == nil, want, out)
				}
			}
			a.command("ACCESS 22", "OK")
			table(false)
			a.command("GROUPACCESS", "OK")
			b.command("GROUPACCESS", "OK")
			table(!off)
			for _, family := range []string{"minecraft", "broadcast"} {
				if off {
					a.command("SEND "+family+" 64 routed", "OK")
				} else if err := sendGroupUntil(a, []*netnsNode{b}, a.addrs[0].Addr(), labSend{family, []int{64}, true}, 15*time.Second); err != nil {
					t.Fatal(err)
				}
			}
			if off {
				time.Sleep(500 * time.Millisecond)
				if heard := b.command("HEARD", "HEARD"); strings.Contains(heard, "/64") {
					t.Fatalf("policy overrode multicast off: %s", heard)
				}
			}
			a.command("ACCESS 22", "OK")
			table(false)
		})
	}
}

func TestNetnsBroadcastCopiesOrdinaryUDPPorts(t *testing.T) {
	for _, port := range []uint16{137, 138} {
		t.Run(strconv.Itoa(int(port)), func(t *testing.T) {
			lab := newNetnsLab(t)
			a, b, c := lab.addNode("a", 1), lab.addNode("b", 2), lab.addNode("c", 3)
			multicastNodes(a, b)
			a.start([]*netnsNode{b}, 0)
			b.start([]*netnsNode{a}, 0)
			c.start(nil, 0)
			family := "broadcast:" + strconv.Itoa(int(port))
			b.command("JOIN "+family+" "+b.veth, "OK")
			c.command("JOIN "+family+" "+c.veth, "OK")
			lab.must(lab.exec(b, "nft", "add table ip lan; add chain ip lan pre { type filter hook prerouting priority -300; }; add rule ip lan pre iifname "+b.veth+" udp dport "+strconv.Itoa(int(port))+" drop"))
			if err := a.pingUntil(b.addrs[0].Addr(), 60*time.Second); err != nil {
				t.Fatal(err)
			}
			send := func() { a.command("SEND "+family+" 64 routed "+strconv.Itoa(int(port)), "OK") }
			if err := heardUntil([]*netnsNode{b}, "HEARD", a.addrs[0].Addr(), []int{64}, 15*time.Second, send); err != nil {
				rules, _ := lab.exec(a, "nft", "list table ip juist0discovery").CombinedOutput()
				t.Fatalf("overlay: %v; sender rules: %s", err, rules)
			}
			if err := heardUntil([]*netnsNode{c}, "HEARD", netip.MustParseAddr("10.77.0.1"), []int{64}, 15*time.Second, send); err != nil {
				t.Fatalf("LAN: %v", err)
			}
		})
	}
}
