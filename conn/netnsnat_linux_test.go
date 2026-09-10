//go:build linux

package conn

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/types/key"
)

// The NAT matrix is M3b exit criterion (1). It is the M3a lab with a router
// namespace in front of each node: the bridge is the "internet", each node
// sits on a private segment of its own, and its router translates. Nothing
// here simulates NAT — it is Linux netfilter doing the translation, which is
// the point, since an approximation would test the approximation.
//
// What each kind is, in the terms that decide whether a pair can be punched:
//
//   - a *cone* NAT maps one internal port to one external port whatever the
//     destination (endpoint-independent mapping), so a peer told that port can
//     reach it. The three cone kinds differ only in what they let in
//     unsolicited, which is a filtering rule and not a mapping one.
//   - a *symmetric* NAT picks a fresh external port per destination, so the
//     port a peer was told is not the port its packets will arrive on. Two of
//     these cannot be punched at all, which is what relays are for.
//
// The lab asserts the mapping property itself before testing anything about
// juist: a rule that quietly did not do what its name says would otherwise
// make the matrix pass for the wrong reason.

type natKind int

const (
	// natFullCone forwards anything arriving at the mapped port inward,
	// solicited or not.
	natFullCone natKind = iota

	// natRestricted admits inbound from an address this node has sent to,
	// on any port of it.
	natRestricted

	// natPortRestricted admits inbound only from the address *and* port that
	// was sent to. This is what Linux masquerading does on its own, and what
	// most home routers do.
	natPortRestricted

	// natSymmetric picks a new external port per destination.
	natSymmetric

	// natDoubleCGNAT is a port-restricted NAT behind a second one, the shape
	// a carrier-grade NAT gives a subscriber.
	natDoubleCGNAT
)

func (k natKind) String() string {
	switch k {
	case natFullCone:
		return "full-cone"
	case natRestricted:
		return "restricted-cone"
	case natPortRestricted:
		return "port-restricted-cone"
	case natSymmetric:
		return "symmetric"
	case natDoubleCGNAT:
		return "double-NAT (CGNAT)"
	}
	return fmt.Sprintf("nat?<%d>", int(k))
}

// endpointIndependent reports whether the kind keeps one external port
// whatever the destination, which is what decides punchability.
func (k natKind) endpointIndependent() bool { return k != natSymmetric }

// carrierLAN is the segment between a subscriber's own NAT and the carrier's,
// in the range carriers really use. A juist node never holds an address here —
// it is behind the inner NAT — which matters, because the interface scan
// deliberately refuses to announce a 100.64/10 address: that range is the
// overlay's own.
var carrierLAN = netip.MustParsePrefix("100.64.0.0/24")

// privateFor is the segment between a node and its own NAT router.
func privateFor(host int) netip.Prefix {
	return netip.MustParsePrefix(fmt.Sprintf("10.99.%d.0/24", host))
}

func privateAddr(host, last int) netip.Addr {
	return netip.MustParseAddr(fmt.Sprintf("10.99.%d.%d", host, last))
}

// addNATNode creates a node behind a NAT of the given kind and returns it, not
// yet started. host is the last octet of its router's public address, its
// private segment's index, and its node ID.
func (l *netnsLab) addNATNode(name string, host int, kind natKind) *netnsNode {
	t := l.t
	t.Helper()

	n := l.newDetachedNode(name, host)
	router := "jn" + name + l.tag
	l.run("netns", "add", router)
	l.routers = append(l.routers, router)

	// The router's public side, on the lab's bridge.
	pubPort, pubVeth := "jp"+name+l.tag, "jv"+name+l.tag
	l.run("link", "add", pubPort, "type", "veth", "peer", "name", pubVeth)
	l.run("link", "set", pubPort, "master", l.bridge, "up")
	l.run("link", "set", pubVeth, "netns", router)
	pubAddr := lanAddr(underlayLAN, host)
	l.runNS(router, "addr", "add", netip.PrefixFrom(pubAddr, underlayLAN.Bits()).String(), "dev", pubVeth)
	l.runNS(router, "link", "set", pubVeth, "up")
	l.runNS(router, "link", "set", "lo", "up")
	// The same resolvable next hop the M3a lab uses, so a packet aimed off
	// the lab's LAN reaches the wire instead of being swallowed by an
	// unanswered ARP.
	l.runNS(router, "neigh", "add", l.gateway().String(), "lladdr", gatewayMAC, "dev", pubVeth, "nud", "permanent")
	l.runNS(router, "route", "add", "default", "via", l.gateway().String(), "dev", pubVeth)

	// The private side, and the node behind it.
	inPort, inVeth := "ji"+name+l.tag, "jw"+name+l.tag
	priv := privateFor(host)
	l.run("link", "add", inPort, "type", "veth", "peer", "name", inVeth)
	l.run("link", "set", inPort, "netns", router)
	l.run("link", "set", inVeth, "netns", n.ns)
	gw, nodeAddr := privateAddr(host, 1), privateAddr(host, 2)
	l.runNS(router, "addr", "add", netip.PrefixFrom(gw, priv.Bits()).String(), "dev", inPort)
	l.runNS(router, "link", "set", inPort, "up")
	l.runIn(n, "addr", "add", netip.PrefixFrom(nodeAddr, priv.Bits()).String(), "dev", inVeth)
	l.runIn(n, "link", "set", inVeth, "up")
	l.runIn(n, "link", "set", "lo", "up")
	l.runIn(n, "route", "add", "default", "via", gw.String(), "dev", inVeth)

	n.underlay, n.veth = nodeAddr, inVeth
	n.public = pubAddr
	n.nat = kind
	n.router = router

	l.forward(router)
	if kind == natDoubleCGNAT {
		// A second translation in front of the first: the router's public
		// side moves onto a carrier segment, and a carrier router
		// masquerades that onto the lab's LAN.
		n.public = l.addCarrier(name, host, router, pubVeth, pubAddr)
		l.masquerade(router, pubVeth, natPortRestricted, nodeAddr)
	} else {
		l.masquerade(router, pubVeth, kind, nodeAddr)
	}
	return n
}

// addCarrier puts a second NAT in front of a subscriber's, and returns the
// address the pair is seen at from the lab's LAN.
func (l *netnsLab) addCarrier(name string, host int, subscriber, subVeth string, subPub netip.Addr) netip.Addr {
	t := l.t
	t.Helper()
	carrier := "jc" + name + l.tag
	l.run("netns", "add", carrier)
	l.routers = append(l.routers, carrier)

	// The subscriber router's outer side is re-addressed onto the carrier
	// segment; its default route now points at the carrier.
	l.runNS(subscriber, "route", "del", "default")
	l.runNS(subscriber, "addr", "del", netip.PrefixFrom(subPub, underlayLAN.Bits()).String(), "dev", subVeth)
	subCarrier := lanAddr(carrierLAN, host)
	carrierGW := lanAddr(carrierLAN, 1)
	l.runNS(subscriber, "addr", "add", netip.PrefixFrom(subCarrier, carrierLAN.Bits()).String(), "dev", subVeth)
	l.runNS(subscriber, "route", "add", "default", "via", carrierGW.String(), "dev", subVeth)

	// The subscriber's veth is currently plugged into the lab bridge; move
	// that end into the carrier namespace so the two routers are peers.
	inner := "jp" + name + l.tag
	l.run("link", "set", inner, "nomaster")
	l.run("link", "set", inner, "netns", carrier)
	l.runNS(carrier, "addr", "add", netip.PrefixFrom(carrierGW, carrierLAN.Bits()).String(), "dev", inner)
	l.runNS(carrier, "link", "set", inner, "up")
	l.runNS(carrier, "link", "set", "lo", "up")

	// And the carrier's own public side.
	pubPort, pubVeth := "jq"+name+l.tag, "jx"+name+l.tag
	l.run("link", "add", pubPort, "type", "veth", "peer", "name", pubVeth)
	l.run("link", "set", pubPort, "master", l.bridge, "up")
	l.run("link", "set", pubVeth, "netns", carrier)
	pub := lanAddr(underlayLAN, host+100)
	l.runNS(carrier, "addr", "add", netip.PrefixFrom(pub, underlayLAN.Bits()).String(), "dev", pubVeth)
	l.runNS(carrier, "link", "set", pubVeth, "up")
	l.runNS(carrier, "neigh", "add", l.gateway().String(), "lladdr", gatewayMAC, "dev", pubVeth, "nud", "permanent")
	l.runNS(carrier, "route", "add", "default", "via", l.gateway().String(), "dev", pubVeth)
	l.forward(carrier)
	l.masquerade(carrier, pubVeth, natPortRestricted, subCarrier)
	return pub
}

// forward turns a namespace into a router. Written through /proc rather than
// with sysctl(8), which is not always installed and buys nothing here.
func (l *netnsLab) forward(ns string) {
	l.t.Helper()
	l.must(l.execNS(ns, "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"))
}

// masquerade installs the translation rules for one kind. The cone kinds pin
// the external port to the internal one, which is what makes the mapping
// endpoint-independent; symmetric leaves the kernel to pick per destination.
//
// Every cone kind translates inbound packets to the node and then decides in
// the filter chain whether to let them through, rather than leaving unsolicited
// ones to land on the router itself. That is not cosmetic. A packet delivered
// to the router's own address creates a conntrack entry whose tuple is the
// mirror of the one the node's own outbound flow needs, and with the external
// port pinned there is no second port to fall back on — so the node's first
// punch packet is dropped by its own NAT, for ever. Filtered in FORWARD, the
// entry is never confirmed and nothing is poisoned.
func (l *netnsLab) masquerade(ns, outVeth string, kind natKind, inside netip.Addr) {
	t := l.t
	t.Helper()
	port := strconv.Itoa(underlayPort)
	nat := func(args ...string) {
		l.must(l.execNS(ns, append([]string{l.iptables, "-w", "5"}, args...)...))
	}
	switch kind {
	case natSymmetric:
		// A fresh mapping per destination. --random-fully is what stops the
		// kernel preferring the source port, which would leave the mapping
		// endpoint-independent by accident. No inbound rule: with the
		// external port varying there is no port to forward, which is the
		// whole difficulty of this kind.
		nat("-t", "nat", "-A", "POSTROUTING", "-o", outVeth, "-p", "udp", "-j", "MASQUERADE", "--random-fully")
	default:
		nat("-t", "nat", "-A", "POSTROUTING", "-o", outVeth, "-p", "udp",
			"-j", "MASQUERADE", "--to-ports", port)
		nat("-t", "nat", "-A", "PREROUTING", "-i", outVeth, "-p", "udp", "--dport", port,
			"-j", "DNAT", "--to-destination", inside.String()+":"+port)
	}
	// Everything else — TCP, ICMP — is translated the ordinary way, so the
	// relay's HTTPS and a ping to a third party still work.
	nat("-t", "nat", "-A", "POSTROUTING", "-o", outVeth, "!", "-p", "udp", "-j", "MASQUERADE")

	// The filtering rule, which is the whole of what separates the cone kinds.
	// It goes in before the catch-all below.
	switch kind {
	case natFullCone:
		// Nothing: unsolicited inbound is forwarded, which is the defining
		// property.
	case natRestricted:
		// Unsolicited inbound is admitted only from an address this node has
		// been talking to. The lab's LAN is that set here, which is wider
		// than a real restricted cone and narrower than a full one — the
		// distinction that decides traversal is the mapping, and that is
		// identical in both.
		nat("-A", "FORWARD", "-i", outVeth, "-p", "udp", "!", "-s", underlayLAN.String(),
			"-m", "conntrack", "--ctstate", "NEW", "-j", "DROP")
	default:
		// Address and port: only a packet conntrack recognizes as a reply
		// gets in, which is what a home router does.
		nat("-A", "FORWARD", "-i", outVeth, "-p", "udp",
			"-m", "conntrack", "--ctstate", "NEW", "-j", "DROP")
	}
	nat("-A", "FORWARD", "-j", "ACCEPT")
}

// blockUDP drops forwarded UDP on a node's router, leaving TCP alone: the
// network that forces relaying over TCP.
func (l *netnsLab) blockUDP(n *netnsNode) {
	l.t.Helper()
	l.must(l.execNS(n.router, l.iptables, "-w", "5", "-I", "FORWARD", "1", "-p", "udp", "-j", "DROP"))
}

// lanAddr is the address at a given host octet of a prefix.
func lanAddr(pfx netip.Prefix, host int) netip.Addr {
	octets := pfx.Addr().As4()
	octets[3] = byte(host)
	return netip.AddrFrom4(octets)
}

// lab_exec_ns runs a command inside a namespace by name, for the router
// namespaces the lab owns but does not model as nodes.
func (l *netnsLab) execNS(ns string, argv ...string) *exec.Cmd {
	return exec.Command(l.ip, append([]string{"netns", "exec", ns}, argv...)...)
}

// runNS is [netnsLab.runIn] for a namespace named directly.
func (l *netnsLab) runNS(ns string, args ...string) {
	l.t.Helper()
	l.must(exec.Command(l.ip, append([]string{"-n", ns}, args...)...))
}

// mappedPortVia asks a STUN reflector what source port it saw, from inside a
// node's namespace. Two reflectors and one socket is the whole of NAT
// classification: an endpoint-independent mapping answers with one port, a
// symmetric one with two.
func (n *netnsNode) mappedPortVia(t *testing.T, reflectors []netip.AddrPort) []uint16 {
	t.Helper()
	self := testBinary(t)
	cmd := n.lab.exec(n, self, "-test.run", "^TestHelperNetnsSTUN$", "-test.timeout", "2m")
	cmd.Env = append(cmd.Env, netnsHelperEnv+"=stun", envSTUNTargets+"="+joinAddrPorts(reflectors))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("classifying %s's NAT: %v\n%s", n.name, err, out)
	}
	var ports []uint16
	for _, line := range strings.Split(string(out), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), protoPrefix+"PORT ")
		if !ok {
			continue
		}
		p, err := strconv.ParseUint(strings.TrimSpace(rest), 10, 16)
		if err != nil {
			t.Fatalf("classifying %s's NAT: %q: %v", n.name, rest, err)
		}
		ports = append(ports, uint16(p))
	}
	if len(ports) != len(reflectors) {
		t.Fatalf("%s got %d mapped ports from %d reflectors:\n%s",
			n.name, len(ports), len(reflectors), out)
	}
	return ports
}

func joinAddrPorts(aps []netip.AddrPort) string {
	out := make([]string, 0, len(aps))
	for _, ap := range aps {
		out = append(out, ap.String())
	}
	return strings.Join(out, ",")
}

// relaySpec is how the lab tells a node where the relay is: what conn.Relay
// needs, in one line.
type relaySpec struct {
	region   int
	hostName string
	addr     netip.AddrPort
	stunPort uint16
	cert     [32]byte
}

func (r relaySpec) encode() string {
	return strings.Join([]string{
		strconv.Itoa(r.region), r.hostName, r.addr.String(),
		strconv.Itoa(int(r.stunPort)), hex.EncodeToString(r.cert[:]),
	}, "|")
}

func decodeRelaySpec(s string) (Relay, error) {
	f := strings.Split(s, "|")
	if len(f) != 5 {
		return Relay{}, fmt.Errorf("relay spec %q has %d fields, want 5", s, len(f))
	}
	region, err := strconv.Atoi(f[0])
	if err != nil {
		return Relay{}, fmt.Errorf("relay region %q: %w", f[0], err)
	}
	addr, err := netip.ParseAddrPort(f[2])
	if err != nil {
		return Relay{}, fmt.Errorf("relay address %q: %w", f[2], err)
	}
	stun, err := strconv.ParseUint(f[3], 10, 16)
	if err != nil {
		return Relay{}, fmt.Errorf("relay STUN port %q: %w", f[3], err)
	}
	cert, err := unrawHex(f[4])
	if err != nil {
		return Relay{}, fmt.Errorf("relay certificate hash: %w", err)
	}
	return Relay{
		Region: region, HostName: f[1], Addrs: []netip.AddrPort{addr},
		STUNPort: uint16(stun), CertHash: cert,
	}, nil
}

func testBinary(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locating this test binary: %v", err)
	}
	return self
}

// startRelayNode brings up a node on the lab's LAN that serves a relay, and
// returns where it listens.
func (l *netnsLab) startRelayNode(n *netnsNode, admit []*netnsNode) relaySpec {
	t := l.t
	t.Helper()
	keys := make([]string, 0, len(admit))
	for _, p := range admit {
		keys = append(keys, rawHex(rawNodePublic(p.nodeKey.Public())))
	}
	n.env = append(n.env,
		envServeRelay+"="+strconv.Itoa(relayPort),
		envRelayAdmit+"="+strings.Join(keys, ","),
	)
	n.start(nil, 0)
	line := n.expect("RELAY ", 60*time.Second)
	f := strings.Fields(strings.TrimPrefix(line, "RELAY "))
	if len(f) != 4 {
		t.Fatalf("relay node said %q, want 4 fields", line)
	}
	port, err := strconv.ParseUint(f[0], 10, 16)
	if err != nil {
		t.Fatalf("relay port %q: %v", f[0], err)
	}
	stunPort, err := strconv.ParseUint(f[1], 10, 16)
	if err != nil {
		t.Fatalf("relay STUN port %q: %v", f[1], err)
	}
	cert, err := unrawHex(f[3])
	if err != nil {
		t.Fatalf("relay certificate hash: %v", err)
	}
	return relaySpec{
		region:   1,
		hostName: f[2],
		addr:     netip.AddrPortFrom(n.public, uint16(port)),
		stunPort: uint16(stunPort),
		cert:     cert,
	}
}

// relayPort is where a lab relay listens, on TCP for DERP and UDP for STUN.
const relayPort = 44443

// rawNodePublic is a WireGuard public key in the form the log records it and
// the relay's admission check takes. AppendTo is the serialization the DERP
// wire format itself uses, and unlike Raw32 it is not deprecated.
func rawNodePublic(k key.NodePublic) [32]byte {
	return [32]byte(k.AppendTo(make([]byte, 0, 32)))
}

// newNATLab is the lab with the tools NAT needs checked for. It is a separate
// entry point from [newNetnsLab] so that the M3a tests keep skipping only on
// what they actually need.
func newNATLab(t *testing.T) *netnsLab {
	t.Helper()
	l := newNetnsLab(t)
	ipt, err := exec.LookPath("iptables")
	if err != nil {
		skipUnlessRequired(t, "iptables not installed; the lab translates with netfilter rather than simulating")
	}
	l.iptables = ipt
	return l
}

// waitHome waits for a node's data plane to settle on a relay region. Until it
// has, a peer reachable only through the relay has no path at all, so a test
// that pinged before this would be timing netcheck rather than traversal.
func (n *netnsNode) waitHome(within time.Duration) int {
	t := n.lab.t
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if _, err := io.WriteString(n.stdin, "HOME\n"); err != nil {
			t.Fatalf("node %s: asking for its home relay: %v", n.name, err)
		}
		line := n.expect("HOME ", 30*time.Second)
		region, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "HOME ")))
		if err != nil {
			t.Fatalf("node %s said %q", n.name, line)
		}
		if region != 0 {
			return region
		}
		if time.Now().After(deadline) {
			t.Fatalf("node %s settled on no relay within %v; without one it has no path to a peer "+
				"it cannot reach directly", n.name, within)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// endpoints asks a node where its data plane believes it can be reached.
func (n *netnsNode) endpoints() []netip.AddrPort {
	t := n.lab.t
	t.Helper()
	if _, err := io.WriteString(n.stdin, "ENDPOINTS\n"); err != nil {
		t.Fatalf("node %s: asking for its endpoints: %v", n.name, err)
	}
	line := strings.TrimSpace(strings.TrimPrefix(n.expect("ENDPOINTS", 30*time.Second), "ENDPOINTS"))
	var out []netip.AddrPort
	for _, f := range strings.Split(line, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		ap, err := netip.ParseAddrPort(f)
		if err != nil {
			t.Fatalf("node %s reported endpoint %q: %v", n.name, f, err)
		}
		out = append(out, ap)
	}
	return out
}

// requireReflexive waits for a node to learn an address on the lab's LAN —
// which, for a node behind NAT, can only have come from the relay's STUN
// responder. Without one there is nothing to punch to, so a matrix that did
// not check this would report "no direct path" for a reason that has nothing
// to do with NAT.
func (n *netnsNode) requireReflexive(within time.Duration) netip.AddrPort {
	t := n.lab.t
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		eps := n.endpoints()
		for _, ap := range eps {
			if underlayLAN.Contains(ap.Addr()) {
				t.Logf("%s learned its reflexive address %v", n.name, ap)
				return ap
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s learned no address on the lab's LAN within %v; it has %v, so its "+
				"peer has nothing to aim at", n.name, within, eps)
		}
		time.Sleep(time.Second)
	}
}

// hint tells a node where a peer is, the way a gossiped announcement reaching
// the reconciler would.
func (n *netnsNode) hint(peer *netnsNode, at netip.AddrPort) {
	t := n.lab.t
	t.Helper()
	if _, err := fmt.Fprintf(n.stdin, "HINT %d %s\n", peer.id, at); err != nil {
		t.Fatalf("node %s: hinting %s at %v: %v", n.name, peer.name, at, err)
	}
	n.expect("OK", 30*time.Second)
}

// keepWarm pings in both directions for the whole window, so that disco has
// live traffic to upgrade. Idle, magicsock stops probing, and a path that would
// have become direct never does — which would look exactly like a NAT that
// cannot be punched. Both directions, because punching a pair of
// port-restricted NATs needs each side to have sent to the other, and a node
// that only ever answers never originates anything.
func keepWarm(a, b *netnsNode, toA, toB netip.Addr, window time.Duration) {
	deadline := time.Now().Add(window)
	var wg sync.WaitGroup
	for _, p := range []struct {
		from *netnsNode
		to   netip.Addr
	}{{a, toB}, {b, toA}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				p.from.ping(p.to)
				time.Sleep(500 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
}

// natCase is one cell of the matrix.
type natCase struct {
	name   string
	a, b   natKind
	direct bool // whether a direct path is expected once the relay is gone
}

// natMatrix is M3b exit criterion (1) written out. The three cone kinds all
// punch, because each side can be told one port that stays put. Symmetric
// against a cone punches from the symmetric side: its packet reaches the cone
// NAT's fixed port, and the reply comes back to whatever port the symmetric
// NAT happened to pick, which its own conntrack is holding open. Symmetric
// against symmetric cannot be punched by anyone — neither side can be told
// where the other's next packet will come from — and is the case relays exist
// for.
//
// The pairing the roadmap calls "symmetric x easy" is symmetric against
// full-cone rather than against port-restricted. Port-restricted filtering
// rejects the symmetric side's packet for coming from a port it has not sent
// to, which leaves only port prediction, and a criterion should not be a
// probabilistic one.
var natMatrix = []natCase{
	{"full-cone x full-cone", natFullCone, natFullCone, true},
	{"restricted x restricted", natRestricted, natRestricted, true},
	{"port-restricted x port-restricted", natPortRestricted, natPortRestricted, true},
	{"symmetric x full-cone", natSymmetric, natFullCone, true},
	{"double-NAT x port-restricted", natDoubleCGNAT, natPortRestricted, true},
	{"symmetric x symmetric", natSymmetric, natSymmetric, false},
}

// TestNetnsNATMatrix is M3b exit criterion (1): direct connections across the
// NAT matrix, and relay fallback where no direct connection is possible.
//
// The relay is a member's own, running the embedded DERP server and the STUN
// responder that tells each node its own reflexive address. Neither node is
// given an address for the other: what a node behind NAT really holds is a
// peer's private address, which means something else on its own segment.
// Everything that follows is disco doing its job.
func TestNetnsNATMatrix(t *testing.T) {
	for _, tc := range natMatrix {
		t.Run(tc.name, func(t *testing.T) {
			lab := newNATLab(t)
			relayNode := lab.addNode("r", 10)
			// Two more addresses on the relay, used only for classifying the
			// NATs. Two are needed to tell an endpoint-independent mapping
			// from a per-destination one — and they are separate from the
			// address the DERP map names because a cone NAT here pins one
			// external port: a classification flow to the address magicsock
			// will STUN would hold exactly the mapping magicsock then needs,
			// and netfilter, having only that one port to give, would drop
			// its packets instead.
			classify := []netip.Addr{lanAddr(underlayLAN, 110), lanAddr(underlayLAN, 210)}
			for _, a := range classify {
				lab.runIn(relayNode, "addr", "add",
					netip.PrefixFrom(a, underlayLAN.Bits()).String(), "dev", relayNode.veth)
			}

			a := lab.addNATNode("a", 21, tc.a)
			b := lab.addNATNode("b", 22, tc.b)
			spec := lab.startRelayNode(relayNode, []*netnsNode{a, b})

			// The lab checks itself before it checks juist: a rule that did
			// not do what its name says would otherwise make a cell pass for
			// the wrong reason.
			reflectors := []netip.AddrPort{
				netip.AddrPortFrom(classify[0], spec.stunPort),
				netip.AddrPortFrom(classify[1], spec.stunPort),
			}
			for _, n := range []*netnsNode{a, b} {
				ports := n.mappedPortVia(t, reflectors)
				same := ports[0] == ports[1]
				if same != n.nat.endpointIndependent() {
					t.Fatalf("%s is configured as %v but maps one socket to ports %v: "+
						"the lab's translation is not what this case is about",
						n.name, n.nat, ports)
				}
				t.Logf("%s (%v) maps one socket to %v", n.name, n.nat, ports)
			}

			for _, n := range []*netnsNode{a, b} {
				n.env = append(n.env,
					envRelays+"="+spec.encode(), envNoEndpoints+"=1", envDebug+"=1")
			}
			a.start([]*netnsNode{b}, 0)
			b.start([]*netnsNode{a}, 0)
			a.waitHome(90 * time.Second)
			b.waitHome(90 * time.Second)

			// Both sides learn where they are from the relay's STUN
			// responder, and then each is told where the other is — which is
			// what a signed announcement carries and what gossip, LAN
			// discovery or the DHT delivers. Without it disco never starts:
			// magicsock asks a peer to punch back only after it has pinged
			// something, so a peer with no candidate at all is one it never
			// asks.
			ra := a.requireReflexive(60 * time.Second)
			rb := b.requireReflexive(60 * time.Second)
			a.hint(b, rb)
			b.hint(a, ra)

			target := b.addrs[0].Addr()
			if err := a.pingUntil(target, 120*time.Second); err != nil {
				t.Fatalf("a (%v) could not reach b (%v) over the overlay at all: %v",
					tc.a, tc.b, err)
			}
			// Live traffic for the whole window, so disco has something to
			// upgrade: what the relay's death proves is about the NATs, not
			// about how soon the question was asked.
			keepWarm(a, b, a.addrs[0].Addr(), target, 25*time.Second)
			t.Logf("a endpoints %v; b endpoints %v", a.endpoints(), b.endpoints())

			relayNode.stop()
			if tc.direct {
				if err := a.pingUntil(target, 30*time.Second); err != nil {
					t.Errorf("a (%v) and b (%v) lost each other when the relay stopped, "+
						"so the path was never direct: %v", tc.a, tc.b, err)
				}
				return
			}
			if err := unreachableWithin(a, target, 60*time.Second); err != nil {
				t.Errorf("two symmetric NATs kept reaching each other with no relay, "+
					"so this cell is not testing what it claims: %v", err)
			}
		})
	}
}

// TestNetnsRelayCarriesWhatUDPCannot is the last of criterion (1): a node whose
// network passes no UDP at all still reaches its peers, because DERP is HTTPS
// and the relay is a member. Everything that makes a direct path is gone here
// — no STUN answer, no disco probe, no hole to punch.
func TestNetnsRelayCarriesWhatUDPCannot(t *testing.T) {
	lab := newNATLab(t)
	relayNode := lab.addNode("r", 10)
	a := lab.addNATNode("a", 21, natPortRestricted)
	b := lab.addNATNode("b", 22, natPortRestricted)
	spec := lab.startRelayNode(relayNode, []*netnsNode{a, b})

	// After the relay is up, so its own start is unaffected.
	lab.blockUDP(a)

	for _, n := range []*netnsNode{a, b} {
		n.env = append(n.env, envRelays+"="+spec.encode(), envNoEndpoints+"=1")
	}
	a.start([]*netnsNode{b}, 0)
	b.start([]*netnsNode{a}, 0)
	a.waitHome(120 * time.Second)
	b.waitHome(90 * time.Second)

	target := b.addrs[0].Addr()
	if err := a.pingUntil(target, 120*time.Second); err != nil {
		t.Fatalf("a could not reach b with UDP blocked, so nothing fell back to TCP: %v", err)
	}

	// And the control: it really is the relay carrying this. Without it the
	// pair has nothing, since a's network passes no UDP.
	relayNode.stop()
	if err := unreachableWithin(a, target, 60*time.Second); err != nil {
		t.Errorf("a kept reaching b after the relay stopped, with UDP blocked: %v", err)
	}
}

// TestNATRelaySpecRoundTrips covers the lab's own wire format, which otherwise
// runs only in the privileged job: a typo there would show up as a node coming
// up with a relay it cannot authenticate.
func TestNATRelaySpecRoundTrips(t *testing.T) {
	want := relaySpec{
		region:   1,
		hostName: "abcdefgh.relay.juist.invalid",
		addr:     netip.MustParseAddrPort("10.77.0.10:44443"),
		stunPort: 44443,
		cert:     [32]byte{1, 2, 3, 255},
	}
	got, err := decodeRelaySpec(want.encode())
	if err != nil {
		t.Fatalf("decodeRelaySpec: %v", err)
	}
	if got.Region != want.region || got.HostName != want.hostName ||
		got.STUNPort != want.stunPort || got.CertHash != want.cert {
		t.Errorf("round trip gave %+v, want %+v", got, want)
	}
	if len(got.Addrs) != 1 || got.Addrs[0] != want.addr {
		t.Errorf("addresses %v, want [%v]", got.Addrs, want.addr)
	}
	// What the data plane will be handed has to be usable, or the lab would
	// be testing its own rejection path.
	if err := validateRelays([]Relay{got}); err != nil {
		t.Errorf("the lab builds a relay the data plane refuses: %v", err)
	}
	if _, err := decodeRelaySpec("1|host|10.0.0.1:1"); err == nil {
		t.Error("a truncated spec decoded")
	}
}

// TestNATKindsAreDistinct pins what the matrix is about: only the symmetric
// kind maps one socket to different ports, and every kind has a name a failure
// can be read by.
func TestNATKindsAreDistinct(t *testing.T) {
	names := map[string]bool{}
	for _, k := range []natKind{natFullCone, natRestricted, natPortRestricted, natSymmetric, natDoubleCGNAT} {
		if names[k.String()] {
			t.Errorf("two NAT kinds are called %q", k)
		}
		names[k.String()] = true
		if want := k != natSymmetric; k.endpointIndependent() != want {
			t.Errorf("%v: endpointIndependent = %v, want %v", k, k.endpointIndependent(), want)
		}
	}
	if privateFor(21) == privateFor(22) {
		t.Error("two nodes would share a private segment")
	}
	if underlayLAN.Overlaps(carrierLAN) || underlayLAN.Overlaps(privateFor(21)) {
		t.Error("the lab's segments overlap, so a route would be ambiguous")
	}
}
