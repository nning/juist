//go:build linux

package conn

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestNetnsExitNode is M6a exit criterion (3) (docs/05-roadmap.md): with a
// full tunnel up, a capture on the client's only link sees nothing but LAN
// traffic, while the internet is reached through the exit node and the LAN
// directly — also against routes a hostile LAN pushes, a socket bound to the
// link and an exit table someone flushed; the exit node's own public network
// is not reached through it; and with the exit node gone or refused, the
// internet is unreachable rather than reached directly.
func TestNetnsExitNode(t *testing.T) {
	lab := newNetnsLab(t)
	client := lab.addNode("c", 1)
	exit := lab.addNode("x", 2)
	// web is the internet: a host only the exit node has a route to.
	web := lab.addNode("w", 9)
	internet := netip.MustParseAddr("1.1.1.1")
	lab.runIn(web, "addr", "add", internet.String()+"/32", "dev", "lo")
	lab.runIn(exit, "route", "add", internet.String()+"/32", "via", web.underlay.String(), "dev", exit.veth)
	// A public network the exit node is on, as a VPS provider's or a LAN
	// with global IPv6 is: its members are no internet the exit node opens.
	exitsNet, neighbour := "45.83.0.2/24", netip.MustParseAddr("45.83.0.9")
	lab.runIn(exit, "addr", "add", exitsNet, "dev", exit.veth)
	lab.runIn(web, "addr", "add", neighbour.String()+"/24", "dev", web.veth)
	lab.forwardBoth(exit)
	// IPv6 has a way out as IPv4 does, so that a leak of it would reach the
	// wire rather than fail for want of a route.
	lab.runIn(client, "-6", "neigh", "add", "fe80::fe", "lladdr", gatewayMAC, "dev", client.veth, "nud", "permanent")
	lab.runIn(client, "-6", "route", "add", "default", "via", "fe80::fe", "dev", client.veth)

	exit.carries = Internet(true, true, nil)
	exit.env = append(exit.env, envServe+"=100.64.0.0/24,fd7a:115c:a1e0::/48")
	client.env = append(client.env, envEgress+"="+EgressTunnel.String())
	defer func() {
		if t.Failed() {
			lab.dump(client, []string{"ip", "rule"}, []string{"ip", "-6", "rule"},
				[]string{"ip", "route", "show", "table", "all"}, []string{"ip", "-6", "route", "show", "table", "all"},
				[]string{"nft", "list", "ruleset"})
			lab.dump(exit, []string{"nft", "list", "ruleset"}, []string{"sysctl", "net.ipv4.conf.all.forwarding"},
				[]string{"ip", "route"})
		}
	}()

	tap := lab.tapEgress(client)
	exit.start([]*netnsNode{client}, 0)
	client.start([]*netnsNode{exit}, 0)
	if err := client.pingUntil(internet, 60*time.Second); err != nil {
		t.Fatalf("the internet, through the exit node: %v", err)
	}
	if err := client.ping(web.underlay); err != nil {
		t.Errorf("the LAN, directly: %v", err)
	}
	if err := client.ping(neighbour); err == nil {
		t.Errorf("the exit node's own network, %v, answered through it", neighbour)
	}
	// Into the tunnel, where the exit node has no IPv6 route to give it.
	_ = client.ping(netip.MustParseAddr("2606:4700::1111"))
	// Routes a hostile DHCP server pushes (option 121) take nothing out of
	// the tunnel.
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		lab.runIn(client, "route", "add", half, "via", lab.gateway().String(), "dev", client.veth)
	}
	if err := client.ping(internet); err != nil {
		t.Errorf("with a hostile LAN's routes, the internet through the exit node: %v", err)
	}
	// Nor does a socket bound to the link.
	_ = lab.exec(client, "ping", "-n", "-q", "-c", "1", "-W", "1", "-I", client.veth, internet.String()).Run()
	if s := tap.strangers(); len(s) > 0 {
		t.Errorf("with the tunnel up, the client sent %v outside it", s)
	}
	// Nor an exit table someone flushed: the guard holds.
	tap = lab.tapEgress(client)
	lab.runIn(client, "route", "flush", "table", strconv.Itoa(exitTable(client.inst)))
	_ = client.ping(internet)
	if s := tap.strangers(); len(s) > 0 {
		t.Errorf("with the exit table flushed, the client sent %v outside the tunnel", s)
	}
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		lab.runIn(client, "route", "del", half)
	}
	client.egress(EgressTunnel) // installs the table again, as every reconcile does
	if err := client.pingUntil(internet, 10*time.Second); err != nil {
		t.Errorf("the table given again, the internet through the exit node: %v", err)
	}

	tap = lab.tapEgress(client)
	exit.stop()
	if err := client.ping(internet); err == nil {
		t.Error("the internet answered with the exit node gone")
	}
	client.egress(EgressRefused)
	for _, dst := range []netip.Addr{internet, netip.MustParseAddr("2606:4700::1111")} {
		// Rejected, the ping says so in its statistics under -q.
		if err := client.ping(dst); err == nil ||
			!regexp.MustCompile(`nreachable|No route|\+1 errors|not permitted`).MatchString(err.Error()) {
			t.Errorf("refused, %v: %v; want it rejected", dst, err)
		}
	}
	if err := client.ping(web.underlay); err != nil {
		t.Errorf("refused, the LAN: %v", err)
	}
	if s := tap.strangers(); len(s) > 0 {
		t.Errorf("with the exit node gone, the client sent %v outside the tunnel", s)
	}

	// Direct, the same ping leaves by the LAN's gateway: the tap sees a leak
	// where there is one.
	tap = lab.tapEgress(client)
	client.egress(EgressDirect)
	_ = client.ping(internet)
	if s := tap.strangers(); !slices.Contains(s, internet) {
		t.Errorf("direct, the tap saw %v and not %v", s, internet)
	}
}

// TestNetnsAFamilyNoExitNodeCarriesIsRefused: an exit node carrying IPv4
// alone leaves the client's IPv6 rejected at once, as a program falling back
// to IPv4 needs, rather than dropped unsaid, and outside the tunnel still. An
// unmarked exit rule an earlier build left is replaced by the marked one.
func TestNetnsAFamilyNoExitNodeCarriesIsRefused(t *testing.T) {
	lab := newNetnsLab(t)
	client := lab.addNode("c", 1)
	exit := lab.addNode("x", 2)
	web := lab.addNode("w", 9)
	internet := netip.MustParseAddr("1.1.1.1")
	lab.runIn(web, "addr", "add", internet.String()+"/32", "dev", "lo")
	lab.runIn(exit, "route", "add", internet.String()+"/32", "via", web.underlay.String(), "dev", exit.veth)
	lab.forwardBoth(exit)
	lab.runIn(client, "-6", "neigh", "add", "fe80::fe", "lladdr", gatewayMAC, "dev", client.veth, "nud", "permanent")
	lab.runIn(client, "-6", "route", "add", "default", "via", "fe80::fe", "dev", client.veth)

	exit.carries = Internet(true, false, nil)
	exit.env = append(exit.env, envServe+"=100.64.0.0/24")
	client.env = append(client.env, envEgress+"="+EgressTunnel.String())
	defer func() {
		if t.Failed() {
			lab.dump(client, []string{"ip", "-6", "rule"}, []string{"ip", "-6", "route", "show", "table", "all"},
				[]string{"nft", "list", "ruleset"})
		}
	}()
	pref := strconv.Itoa(juistRulePrefBase + exitRuleExit + client.inst)
	lab.runIn(client, "rule", "add", "pref", pref, "lookup", strconv.Itoa(exitTable(client.inst)))
	tap := lab.tapEgress(client)
	exit.start([]*netnsNode{client}, 0)
	client.start([]*netnsNode{exit}, 0)
	if err := client.pingUntil(internet, 60*time.Second); err != nil {
		t.Fatalf("IPv4, through the exit node: %v", err)
	}
	// Not "not permitted", which a drop leaving by the LAN would give.
	if err := client.ping(netip.MustParseAddr("2606:4700::1111")); err == nil ||
		!regexp.MustCompile(`nreachable|No route|\+1 errors`).MatchString(err.Error()) {
		t.Errorf("IPv6, which the exit node does not carry: %v; want it rejected", err)
	}
	out, err := lab.exec(client, "ip", "rule", "list", "pref", pref).CombinedOutput()
	if lines := strings.Split(strings.TrimSpace(string(out)), "\n"); err != nil || len(lines) != 1 ||
		!strings.Contains(lines[0], "not ") || !strings.Contains(lines[0], "fwmark 0x80000") {
		t.Errorf("the exit rules at %s: %v\n%s", pref, err, out)
	}
	if s := tap.strangers(); len(s) > 0 {
		t.Errorf("the client sent %v outside the tunnel", s)
	}
}

// forwardBoth turns forwarding on in n for both families, which the helper
// serves, as the packaged exit-node script does.
func (l *netnsLab) forwardBoth(n *netnsNode) {
	l.t.Helper()
	l.must(l.exec(n, "sh", "-c",
		"echo 1 >/proc/sys/net/ipv4/conf/all/forwarding && echo 1 >/proc/sys/net/ipv6/conf/all/forwarding"))
}

// TestNetnsAStrictReversePathFilterIsFound: firewalld's strict IPv6
// reverse-path rule, as nft writes it, is read as strict, and its loose one
// as loose, from the kernel's own encoding.
func TestNetnsAStrictReversePathFilterIsFound(t *testing.T) {
	lab := newNetnsLab(t)
	n := lab.addNode("r", 1)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		fib  string
		want string
	}{
		{"fib saddr . mark . iif oif missing drop", "RPFILTER true <nil>"},
		{"fib saddr . mark oif missing drop", "RPFILTER false <nil>"},
	} {
		ruleset := "table inet firewalld {\n chain filter_PREROUTING {\n  type filter hook prerouting priority filter + 10; policy accept;\n" +
			"  meta nfproto ipv6 " + tc.fib + "\n }\n}\n"
		lab.must(lab.exec(n, "nft", "flush", "ruleset"))
		cmd := lab.exec(n, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(ruleset)
		lab.must(cmd)
		helper := lab.exec(n, self, "-test.run", "^TestHelperNetnsRPFilter$", "-test.timeout", "1m")
		helper.Env = append(os.Environ(), netnsHelperEnv+"=rpfilter")
		out, err := helper.CombinedOutput()
		if err != nil || !strings.Contains(string(out), protoPrefix+tc.want) {
			t.Errorf("%s: want %q, the helper said (%v):\n%s", tc.fib, tc.want, err, out)
		}
	}
}

// egress sets the node's egress.
func (n *netnsNode) egress(e Egress) {
	n.lab.t.Helper()
	if _, err := n.stdin.Write([]byte("EGRESS " + e.String() + "\n")); err != nil {
		n.lab.t.Fatalf("node %s: sending EGRESS: %v", n.name, err)
	}
	n.expect("OK", 30*time.Second)
}

// dump logs what each command says in n's namespace, for a failure to be
// read without another run.
func (l *netnsLab) dump(n *netnsNode, argvs ...[]string) {
	for _, argv := range argvs {
		out, err := l.exec(n, argv...).CombinedOutput()
		l.t.Logf("%s: %s (%v):\n%s", n.name, strings.Join(argv, " "), err, out)
	}
}

// TestNetnsARefusingClientHearsItsExitNode: under loose reverse-path
// filtering, systemd's default, a client refusing the internet still takes
// the answers of an exit node at a public address, so that its tunnel comes
// up and the refusal can end. The kernel checks an answer's source by a
// lookup without juistd's mark or user, which lands in the exit table.
func TestNetnsARefusingClientHearsItsExitNode(t *testing.T) {
	lab := newNetnsLab(t)
	client := lab.addNode("c", 1)
	exit := lab.addNode("x", 2)
	public := netip.MustParseAddr("45.83.0.2")
	lab.runIn(exit, "addr", "add", public.String()+"/32", "dev", exit.veth)
	lab.runIn(client, "route", "add", public.String()+"/32", "via", exit.underlay.String(), "dev", client.veth)
	// The exit node answers from its public address, and the client hears
	// it there alone: a path over the LAN's private addresses would pass
	// the check whatever the exit table holds.
	lab.runIn(exit, "route", "add", client.underlay.String()+"/32", "dev", exit.veth, "src", public.String())
	iptables, err := exec.LookPath("iptables")
	if err != nil {
		skipUnlessRequired(t, "iptables not installed; the test keeps the exit node's LAN address from the client with it")
	}
	lab.must(lab.exec(client, iptables, "-A", "INPUT", "-p", "udp", "-s", exit.underlay.String(), "-j", "DROP"))
	lab.must(lab.exec(client, "sh", "-c", "for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 2 >$f; done"))
	defer func() {
		if t.Failed() {
			lab.dump(client, []string{"ip", "rule"}, []string{"ip", "route", "show", "table", "all"},
				[]string{"nft", "list", "ruleset"}, []string{"sh", "-c", "grep . /proc/sys/net/ipv4/conf/*/rp_filter"})
		}
	}()

	exit.carries = Internet(true, true, nil)
	exit.env = append(exit.env, envServe+"=100.64.0.0/24,fd7a:115c:a1e0::/48")
	lab.forwardBoth(exit)
	client.env = append(client.env, envEgress+"="+EgressRefused.String())
	seen := viewOf(exit, exit.addrs...)
	seen.underlay, seen.carries = public, exit.carries
	exit.start([]*netnsNode{client}, 0)
	client.start([]*netnsNode{seen}, 0)
	if err := client.pingUntil(exit.addrs[0].Addr(), 60*time.Second); err != nil {
		t.Fatalf("refusing, the exit node at %v over the tunnel: %v", public, err)
	}
	client.egress(EgressTunnel)
	if err := client.pingUntil(exit.addrs[0].Addr(), 30*time.Second); err != nil {
		t.Errorf("through the exit node, the exit node over the tunnel: %v", err)
	}
}

// TestNetnsASubnetThroughItsRouter is M6b exit criterion (2)
// (docs/05-roadmap.md): a subnet a router serves is reached through it from a
// member, and nothing of it leaves the member outside the tunnel; without the
// route, it is not reached at all. The member knows nothing of the subnet but
// what its router's peer entry says.
func TestNetnsASubnetThroughItsRouter(t *testing.T) {
	lab := newNetnsLab(t)
	client := lab.addNode("c", 1)
	router := lab.addNode("r", 2)
	// host is on the router's subnet alone, which only the router is on too.
	host := lab.addNode("h", 9)
	subnet, hostAddr := netip.MustParsePrefix("10.99.0.0/24"), netip.MustParseAddr("10.99.0.9")
	lab.runIn(router, "addr", "add", "10.99.0.2/24", "dev", router.veth)
	lab.runIn(host, "addr", "add", hostAddr.String()+"/24", "dev", host.veth)
	lab.forwardBoth(router)
	defer func() {
		if t.Failed() {
			lab.dump(client, []string{"ip", "rule"}, []string{"ip", "route", "show", "table", "all"},
				[]string{"ip", "route", "get", "10.99.0.9"})
			lab.dump(router, []string{"nft", "list", "ruleset"}, []string{"ip", "route"},
				[]string{"sh", "-c", "grep . /proc/sys/net/ipv*/conf/all/forwarding"})
		}
	}()

	router.subnets = []netip.Prefix{subnet}
	router.env = append(router.env, envServe+"=100.64.0.0/24,fd7a:115c:a1e0::/48", envSubnets+"="+subnet.String())
	router.start([]*netnsNode{client}, 0)
	client.start([]*netnsNode{router}, 0)
	if err := client.pingUntil(hostAddr, 60*time.Second); err != nil {
		t.Fatalf("the subnet through its router: %v", err)
	}
	if routes := client.routes(); !slices.Contains(routes, subnet) {
		t.Errorf("the subnet is not routed into the tunnel: %v", routes)
	}
	// Tapped once the route is in: before it, the subnet goes by the host's
	// routes, as no guard holds it in.
	tap := lab.tapEgress(client)
	if err := client.ping(hostAddr); err != nil {
		t.Errorf("the subnet through its router, again: %v", err)
	}
	if s := tap.strangers(); len(s) > 0 {
		t.Errorf("the client sent %v outside the tunnel", s)
	}

	// A route of the client's own inside the subnet is told of at once, so
	// that the daemon gives that part back without waiting for its tick.
	before := client.hostRouteChanges()
	lab.runIn(client, "route", "add", "10.99.0.128/25", "via", lab.gateway().String(), "dev", client.veth)
	deadline := time.Now().Add(5 * time.Second)
	for client.hostRouteChanges() == before {
		if time.Now().After(deadline) {
			t.Error("a route of the client's own inside the subnet went unnoticed")
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	lab.runIn(client, "route", "del", "10.99.0.128/25")

	client.setPeers("none")
	if err := client.ping(hostAddr); err == nil {
		t.Error("the subnet answered with its router's route withdrawn")
	}
}

// hostRouteChanges is how often n's data plane saw the host's routes change.
func (n *netnsNode) hostRouteChanges() int {
	n.lab.t.Helper()
	if _, err := io.WriteString(n.stdin, "HOSTROUTES\n"); err != nil {
		n.lab.t.Fatalf("node %s: sending HOSTROUTES: %v", n.name, err)
	}
	var count int
	if _, err := fmt.Sscanf(n.expect("HOSTROUTES", 10*time.Second), "HOSTROUTES %d", &count); err != nil {
		n.lab.t.Fatalf("node %s: %v", n.name, err)
	}
	return count
}

// dnsHelper is a resolver in n's namespace, taking ASK commands.
type dnsHelper struct {
	stdin io.WriteCloser
	lines chan string
}

// startDNS starts it answering at addr, port 53, from addr: a resolver on a
// wildcard address answers from whatever address routing gives, which a
// client asking addr drops.
func (l *netnsLab) startDNS(n *netnsNode, addr netip.Addr) *dnsHelper {
	t := l.t
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := l.exec(n, self, "-test.run", "^TestHelperNetnsDNS$", "-test.timeout", "5m")
	cmd.Env = append(os.Environ(), netnsHelperEnv+"=dns", envDNSListen+"="+netip.AddrPortFrom(addr, 53).String())
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); cmd.Process.Kill(); cmd.Wait() })
	h := &dnsHelper{stdin: stdin, lines: make(chan string, 16)}
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if rest, ok := strings.CutPrefix(sc.Text(), protoPrefix); ok {
				h.lines <- rest
			}
		}
	}()
	h.expect(t, "READY")
	return h
}

func (h *dnsHelper) expect(t *testing.T, want string) string {
	t.Helper()
	select {
	case line := <-h.lines:
		if !strings.HasPrefix(line, want) {
			t.Fatalf("the resolver said %q, want %q", line, want)
		}
		return line
	case <-time.After(30 * time.Second):
		t.Fatalf("the resolver said nothing of %q", want)
	}
	return ""
}

func (h *dnsHelper) ask(t *testing.T, at netip.AddrPort) string {
	t.Helper()
	io.WriteString(h.stdin, "ASK "+at.String()+"\n")
	return h.expect(t, "ASK")
}

// ask has n put a DNS query to at, saying "ASK ok" where it was answered.
func (n *netnsNode) ask(at netip.AddrPort) string {
	n.lab.t.Helper()
	io.WriteString(n.stdin, "ASK "+at.String()+"\n")
	return n.expect("ASK", 30*time.Second)
}

// TestNetnsExitNodeAnswersDNS is the data path of M6c exit criterion (1)
// (docs/05-roadmap.md): a member's query to its exit node's resolver is
// answered, by a resolver only the exit node reaches, and nothing of it
// leaves the member outside the tunnel; a host on the exit node's LAN that
// is no member is not answered, though it sends to the resolver's address.
// Pointing the host's resolver at it is systemd-resolved's, which runs one
// per host, not per namespace, and is checked by hand.
func TestNetnsExitNodeAnswersDNS(t *testing.T) {
	lab := newNetnsLab(t)
	client := lab.addNode("c", 1)
	exit := lab.addNode("x", 2)
	web := lab.addNode("w", 9)
	resolver := netip.MustParseAddr("1.1.1.1")
	lab.runIn(web, "addr", "add", resolver.String()+"/32", "dev", "lo")
	lab.runIn(exit, "route", "add", resolver.String()+"/32", "via", web.underlay.String(), "dev", exit.veth)
	lab.forwardBoth(exit)
	upstream := lab.startDNS(web, resolver)
	defer func() {
		if t.Failed() {
			lab.dump(exit, []string{"ss", "-ulpn"}, []string{"ip", "route"})
		}
	}()

	exit.carries = Internet(true, true, nil)
	exit.env = append(exit.env, envServe+"=100.64.0.0/24,fd7a:115c:a1e0::/48",
		envServeDNS+"="+netip.AddrPortFrom(resolver, 53).String())
	client.env = append(client.env, envEgress+"="+EgressTunnel.String())
	tap := lab.tapEgress(client)
	exit.start([]*netnsNode{client}, 0)
	client.start([]*netnsNode{exit}, 0)
	if err := client.pingUntil(exit.addrs[0].Addr(), 60*time.Second); err != nil {
		t.Fatalf("the exit node over the tunnel: %v", err)
	}
	// Apart from the forwarder: the exit node reaches its resolver itself.
	if got := exit.ask(netip.AddrPortFrom(resolver, 53)); got != "ASK ok" {
		t.Fatalf("the exit node's own query to %v: %s", resolver, got)
	}
	for _, a := range exit.addrs {
		// Port 53 too, redirected, as a resolver without ports asks.
		for _, port := range []uint16{dnsPort, 53} {
			if got := client.ask(netip.AddrPortFrom(a.Addr(), port)); got != "ASK ok" {
				t.Errorf("the exit node's resolver at %v port %d: %s", a.Addr(), port, got)
			}
		}
	}
	if s := tap.strangers(); len(s) > 0 {
		t.Errorf("the client sent %v outside the tunnel", s)
	}

	lab.runIn(web, "route", "add", exit.addrs[0].String(), "via", exit.underlay.String(), "dev", web.veth)
	if got := upstream.ask(t, netip.AddrPortFrom(exit.addrs[0].Addr(), dnsPort)); got == "ASK ok" {
		t.Error("a host on the exit node's LAN was answered")
	}
}
