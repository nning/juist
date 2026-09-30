package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

func (m *peersManager) onlyPeerSubnets(t *testing.T) []netip.Prefix {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.peers) != 1 {
		t.Fatalf("%d peers, want 1", len(m.peers))
	}
	return m.peers[0].Subnets
}

func prefixes(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range s {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

// A subnet an admin grants, and its router's operator agrees to route, every
// member reaches through the router, less what it reaches by routes of its
// own; its owner may turn subnets off, and a revoke ends it.
func TestASubnetFromGrantToRevoke(t *testing.T) {
	exitNodesHere(t)
	t.Parallel()
	laptop, vps := homeAndVPS(t)
	mustContain(t, laptop.mustRun("subnet"), "no subnets", "juist grant DEVICE 192.168.1.0/24")

	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"grant", "vps", "192.168.50.1/24"}, []string{"192.168.50.1/24 has host bits set", "hint: 192.168.50.0/24"}},
		{[]string{"grant", "vps", "0.0.0.0/0"}, []string{"0.0.0.0/0 is the internet", "hint: juist grant vps exit"}},
		{[]string{"grant", "vps", "198.18.4.0/24"}, []string{"overlaps the network's own addresses"}},
		{[]string{"grant", "vps", "192.168/16"}, []string{`"192.168/16" is no prefix`}},
		{[]string{"revoke", "vps", "10.0.0.0/8"}, []string{"vps does not route 10.0.0.0/8", "hint: juist subnet"}},
	} {
		out, err := laptop.run(tc.args...)
		if err == nil {
			t.Errorf("%v succeeded:\n%s", tc.args, out)
			continue
		}
		mustContain(t, out+err.Error(), tc.want...)
	}

	mustContain(t, laptop.mustRun("grant", "vps", "192.168.50.0/24"), "vps: routes 192.168.50.0/24")
	mustContain(t, laptop.mustRun("grant", "vps", "192.168.50.0/24"), "vps: unchanged")
	out, err := laptop.run("grant", "laptop", "192.168.0.0/16")
	if err == nil || !strings.Contains(err.Error(), "overlaps 192.168.50.0/24, which vps routes") {
		t.Fatalf("a second router for the same addresses (%v):\n%s", err, out)
	}
	mustContain(t, laptop.mustRun("grant", "laptop", "203.0.114.0/24"),
		"warning: 203.0.114.0/24 is public space: every member reaches it through laptop")
	laptop.mustRun("revoke", "laptop", "203.0.114.0/24")

	eventually(t, "laptop lists the subnet, not routed yet", func() bool {
		out, err := laptop.run("subnet")
		return err == nil && strings.Contains(out, "192.168.50.0/24") &&
			strings.Contains(out, "its router's operator has not agreed")
	})
	eventually(t, "vps hears of its grant", func() bool {
		out, err := vps.run("subnet", "serve")
		return err == nil && strings.Contains(out, "routing 192.168.50.0/24")
	})
	if _, s := vps.mgr.exitState(); !slices.Equal(s.Subnets, prefixes("192.168.50.0/24")) || len(s.Routes) > 0 {
		t.Fatalf("vps serves %+v", s)
	}
	mustContain(t, vps.mustRun("status"), "Subnets", "this device routes 192.168.50.0/24")
	mustContain(t, vps.mustRun("subnet"), "192.168.50.0/24", "vps (this device)", "routed")

	eventually(t, "laptop routes the subnet through vps", func() bool {
		return slices.Equal(laptop.mgr.onlyPeerSubnets(t), prefixes("192.168.50.0/24"))
	})
	mustContain(t, laptop.mustRun("subnet"), "in use")
	// Once seen flipping to "not in use" for a moment under make check's
	// load, cause unknown: the reason is logged where it does not settle.
	eventually(t, "laptop's status says the subnet is in use", func() bool {
		if out := laptop.mustRun("status"); strings.Contains(out, "Subnets") && strings.Contains(out, "1 in use") {
			return true
		}
		t.Logf("laptop's subnets: %+v", statusOfDaemon(t, laptop).Subnets)
		return false
	})

	// Part of it on this host's own LAN stays there.
	laptop.mgr.mu.Lock()
	laptop.mgr.host = prefixes("192.168.50.128/25")
	laptop.mgr.mu.Unlock()
	eventually(t, "laptop leaves its own LAN to it", func() bool {
		return slices.Equal(laptop.mgr.onlyPeerSubnets(t), prefixes("192.168.50.0/25"))
	})
	mustContain(t, laptop.mustRun("subnet"), "in use, but for 192.168.50.128/25, which this device reaches by a route of its own")

	mustContain(t, laptop.mustRun("subnet", "off"), "subnets off")
	if s := laptop.mgr.onlyPeerSubnets(t); len(s) != 0 {
		t.Fatalf("subnets off, laptop routes %v", s)
	}
	mustContain(t, laptop.mustRun("subnet", "off"), "unchanged: subnets off")
	mustContain(t, laptop.mustRun("status"), "off on this device")
	mustContain(t, laptop.mustRun("subnet", "on"), "subnets on")
	if s := laptop.mgr.onlyPeerSubnets(t); len(s) == 0 {
		t.Fatal("subnets on, laptop routes none")
	}

	mustContain(t, laptop.mustRun("revoke", "vps", "192.168.50.0/24"), "vps: no roles")
	if s := laptop.mgr.onlyPeerSubnets(t); len(s) != 0 {
		t.Fatalf("after the revoke, laptop routes %v", s)
	}
	eventually(t, "vps stops routing", func() bool {
		_, s := vps.mgr.exitState()
		return len(s.Subnets) == 0
	})
	mustContain(t, vps.mustRun("subnet", "serve", "--stop"), "stopped routing")
	mustContain(t, vps.mustRun("subnet", "serve", "--stop"), "unchanged: not routing")
}

// Forwarding set up for a device stays while it serves either way, and goes
// with the last.
func TestForwardingStaysWhileEitherServes(t *testing.T) {
	exitNodesHere(t)
	if helperSetsUpHost {
		t.Skip("exit-node.sh's; FreeBSD's helper holds forwarding per device, as TestServingSetsTheHostUpAndBack shows")
	}
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	calls := filepath.Join(t.TempDir(), "calls")
	h.layout.exitScript = filepath.Join(t.TempDir(), "exit-node.sh")
	if err := os.WriteFile(h.layout.exitScript, []byte("#!/bin/sh\necho \"$*\" >> "+calls+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.cli.system = map[string]string{exitSysctl: "# for: juist0\n",
		"/proc/sys/net/ipv4/conf/all/forwarding": "1\n", "/proc/sys/net/ipv6/conf/all/forwarding": "1\n"}
	on := true
	for _, req := range []ipc.Request{{Command: ipc.CmdExit, Serve: &on}, {Command: ipc.CmdSubnet, ServeSubnets: &on}} {
		if _, err := ipc.Call(h.layout.socket(0), req); err != nil {
			t.Fatal(err)
		}
	}
	mustContain(t, h.mustRun("exit", "serve", "--stop"), "stopped serving")
	if b, _ := os.ReadFile(calls); len(b) != 0 {
		t.Fatalf("forwarding was undone while subnets are routed: %q", b)
	}
	mustContain(t, h.mustRun("subnet", "serve", "--stop"), "stopped routing")
	if b, _ := os.ReadFile(calls); string(b) != "off juist0\n" {
		t.Errorf("the setup script ran %q, want off juist0", b)
	}
}

// The status says DNS goes through the exit node where it does, and the
// warning why not where it does not, with what to do where resolved refused.
func TestTheStatusSaysWhereDNSGoes(t *testing.T) {
	id := types.Identity{1}
	st := &ipc.Status{InNetwork: true, Derived: ipc.Derived{NetworkName: "home",
		Exit: &ipc.Exit{Node: id, Name: "vps", DNS: true}}}
	found := false
	for _, l := range statusOf(st, time.Now(), func(_, s string) string { return s }).head {
		found = found || l.label == "Exit node" && l.text == "vps, DNS too"
	}
	if !found {
		t.Error("the status does not say DNS goes through vps")
	}
	st.Exit.Partly = "IPv6 refused: vps carries IPv4 alone"
	found = false
	for _, l := range statusOf(st, time.Now(), func(_, s string) string { return s }).head {
		found = found || l.label == "Exit node" && l.text == "vps, DNS too; IPv6 refused: vps carries IPv4 alone"
	}
	if !found {
		t.Error("the status does not say vps refuses IPv6")
	}
	c := newCLI(t)
	part := &ipc.Exit{Node: id, Name: "vps", Partly: "IPv6 refused: vps carries IPv4 alone"}
	out := &syncBuffer{}
	a := c.app(out, "")
	if got := a.inUse(part); got != "in use, IPv6 refused: vps carries IPv4 alone" {
		t.Errorf("the list says %q", got)
	}
	a.warnPartly(part)
	mustContain(t, out.String(), "warning: IPv6 refused: vps carries IPv4 alone")
	c.system = map[string]string{"/etc/resolv.conf": "nameserver 192.168.1.1\n"}
	out = &syncBuffer{}
	a = c.app(out, "")
	a.warnDNS(&ipc.Exit{Node: id, Name: "vps", DNSNot: "systemd-resolved refused juistd"}, nil)
	mustContain(t, out.String(), "warning: DNS goes to 192.168.1.1, outside the tunnel: systemd-resolved refused juistd",
		"hint: the package's polkit rule allows juistd that")
	out = &syncBuffer{}
	a = c.app(out, "")
	a.warnDNS(&ipc.Exit{Node: id, Name: "vps",
		DNSNot: "/etc/resolv.conf lists every link's servers, systemd-resolved's uplink mode, not its stub"}, nil)
	mustContain(t, out.String(), "hint: "+asRoot("ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf"))
	out = &syncBuffer{}
	a = c.app(out, "")
	a.warnDNS(&ipc.Exit{Node: id, Name: "vps", DNS: true}, nil)
	if out.String() != "" {
		t.Errorf("DNS through vps, still warned:\n%s", out.String())
	}
}

// Routing a prefix that holds a Docker network warns that Docker drops what
// is routed to its containers; one beside it does not.
func TestRoutingADockerNetworkIsWarnedOf(t *testing.T) {
	c := newCLI(t)
	out := &syncBuffer{}
	a := c.app(out, "")
	a.host = &hostLayout{dockerNets: func() map[string][]netip.Prefix {
		return map[string][]netip.Prefix{"br-494bc3342646": {netip.MustParsePrefix("172.21.0.0/16")}}
	}}
	a.warnDocker([]netip.Prefix{netip.MustParsePrefix("192.168.77.0/24")})
	if out.String() != "" {
		t.Errorf("warned of a prefix beside docker's:\n%s", out.String())
	}
	a.warnDocker([]netip.Prefix{netip.MustParsePrefix("192.168.77.0/24"), netip.MustParsePrefix("172.21.0.0/16")})
	mustContain(t, out.String(),
		"warning: docker shields its containers on br-494bc3342646 (172.21.0.0/16) from routed traffic",
		"hint: docker lets it through on a network with gateway_mode_ipv4=nat-unprotected")
}
