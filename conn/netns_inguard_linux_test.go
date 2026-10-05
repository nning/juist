//go:build linux

package conn

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A device's overlay addresses are its tunnel's: a host on its LAN reaches
// neither them nor, with a member's address as the source, the device at all.
func TestNetnsTheLANReachesNoOverlayAddress(t *testing.T) {
	lab := newNetnsLab(t)
	a := lab.addNode("a", 1)
	b := lab.addNode("b", 2)
	lan := lab.addNode("x", 9) // no member, only on the LAN
	v6 := func(n *netnsNode) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("fd00:77::%d", n.id)) }
	for _, n := range []*netnsNode{a, lan} {
		lab.runIn(n, "addr", "add", v6(n).String()+"/64", "dev", n.veth, "nodad")
	}
	// Strict reverse-path filtering, which a namespace may inherit, would
	// drop the forged sources below whatever juist does.
	lab.must(lab.exec(a, "sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=0",
		"net.ipv4.conf."+a.veth+".rp_filter=0"))
	defer func() {
		if t.Failed() {
			lab.dump(a, []string{"nft", "list", "ruleset"}, []string{"ip", "addr"})
			lab.dump(lan, []string{"ip", "route"}, []string{"ip", "-6", "route"})
		}
	}()

	a.start([]*netnsNode{b}, 0)
	b.start([]*netnsNode{a}, 0)
	for _, p := range b.addrs {
		if err := a.pingUntil(p.Addr(), 60*time.Second); err != nil {
			t.Fatalf("over the overlay: %v", err)
		}
	}
	for _, p := range a.addrs {
		if err := a.ping(p.Addr()); err != nil {
			t.Errorf("a cannot reach its own overlay address: %v", err)
		}
	}

	under := map[bool]netip.Addr{false: a.underlay, true: v6(a)}
	for _, p := range a.addrs {
		lab.runIn(lan, "route", "add", p.String(), "via", under[p.Addr().Is6()].String(), "dev", lan.veth)
		if err := lan.ping(p.Addr()); err == nil {
			t.Errorf("the LAN reached a's overlay address %v", p.Addr())
		}
	}

	for _, p := range b.addrs {
		fam := p.Addr().Is6()
		before := echosIn(t, a, fam)
		if err := lan.ping(under[fam]); err != nil {
			t.Fatalf("the LAN cannot reach a at all: %v", err)
		}
		forged := echosIn(t, a, fam)
		if forged <= before {
			t.Fatalf("a counted no echo request from the LAN: %d, then %d", before, forged)
		}
		lab.runIn(lan, "addr", "add", p.String(), "dev", lan.veth, "nodad")
		lab.exec(lan, "ping", "-n", "-q", "-c", "3", "-i", "0.2", "-W", "1", "-I", p.Addr().String(),
			under[fam].String()).Run()
		if after := echosIn(t, a, fam); after != forged {
			t.Errorf("a took %d echo requests from the LAN sent as b's %v", after-forged, p.Addr())
		}
	}
}

// echosIn is how many ICMP echo requests n's stack has taken in a family.
func echosIn(t *testing.T, n *netnsNode, v6 bool) int {
	t.Helper()
	file := map[bool]string{false: "/proc/net/snmp", true: "/proc/net/snmp6"}[v6]
	out, err := n.lab.exec(n, "cat", file).Output()
	if err != nil {
		t.Fatalf("reading %s in %s: %v", file, n.name, err)
	}
	if v6 {
		for _, line := range strings.Split(string(out), "\n") {
			if f := strings.Fields(line); len(f) == 2 && f[0] == "Icmp6InEchos" {
				v, err := strconv.Atoi(f[1])
				if err == nil {
					return v
				}
			}
		}
		t.Fatalf("%s holds no Icmp6InEchos", file)
	}
	// "Icmp: names…" and then "Icmp: values…".
	var names []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || f[0] != "Icmp:" {
			continue
		}
		if names == nil {
			names = f
			continue
		}
		for i, name := range names {
			if name == "InEchos" && i < len(f) {
				if v, err := strconv.Atoi(f[i]); err == nil {
					return v
				}
			}
		}
		break
	}
	t.Fatalf("%s holds no Icmp InEchos", file)
	return 0
}
