//go:build linux

package conn

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/types/key"
)

// The netns lab is M3a's test harness: a bridge in the root namespace, one
// network namespace per node, and a real TUN device with a real router in
// each. Two nodes with real devices do not fit in one namespace, since both
// want their own overlay addresses and routing table.
//
// Each node runs in a re-executed copy of this test binary: a namespace is a
// property of a thread, so one process cannot hold two without pinning every
// goroutine that might touch the engine.

const (
	// netnsHelperEnv names the role a re-executed test binary is to play.
	// Unset, the helper tests skip, so an ordinary `go test` never enters them.
	netnsHelperEnv = "JUIST_NETNS_ROLE"

	// How a node helper is configured. All of it is passed by environment:
	// the helper's argv belongs to the test framework.
	envNodeID    = "JUIST_NETNS_ID"
	envNodeKey   = "JUIST_NETNS_NODEKEY"
	envDiscoKey  = "JUIST_NETNS_DISCOKEY"
	envAddrs     = "JUIST_NETNS_ADDRS"
	envTun       = "JUIST_NETNS_TUN"
	envPort      = "JUIST_NETNS_PORT"
	envPeers     = "JUIST_NETNS_PEERS"
	envTCPListen = "JUIST_NETNS_TCP_LISTEN"
	envInstance  = "JUIST_NETNS_INSTANCE"
	envTCPDial   = "JUIST_NETNS_TCP_DIAL"
	envTCPBytes  = "JUIST_NETNS_TCP_BYTES"

	// The NAT matrix adds three more. envServeRelay makes a node run a relay
	// and report where it listens; envRelays gives a node the relay set to
	// install; envNoEndpoints withholds the peer address hints the lab
	// otherwise hands out, which is what a node behind NAT really has — its
	// peer's private address is no use, and its public one is a mapping only
	// the NAT knows until disco discovers it.
	envServeRelay  = "JUIST_NETNS_SERVE_RELAY"
	envRelayAdmit  = "JUIST_NETNS_RELAY_ADMIT"
	envRelays      = "JUIST_NETNS_RELAYS"
	envNoEndpoints = "JUIST_NETNS_NO_ENDPOINTS"
	envSTUNTargets = "JUIST_NETNS_STUN"

	// envDebug turns on magicsock's NAT-traversal logging. The NAT matrix
	// sets it: a cell that fails is a question about disco, and disco says
	// nothing without it.
	envDebug = "JUIST_NETNS_DEBUG"

	// envEgress is the egress a node starts with, and envServe the overlay
	// sources it masquerades while serving the internet as an exit node.
	envEgress = "JUIST_NETNS_EGRESS"
	envServe  = "JUIST_NETNS_SERVE"
	// envSubnets are the subnets a node routes for its peers, with
	// envServe's sources.
	envSubnets = "JUIST_NETNS_SUBNETS"
	// envServeDNS is the resolver an exit node forwards its members' DNS
	// to, on its overlay addresses at [dnsPort].
	envServeDNS = "JUIST_NETNS_SERVE_DNS"
	dnsPort     = 41646
	// envDNSListen is where the DNS helper answers.
	envDNSListen = "JUIST_NETNS_DNS_LISTEN"

	// protoPrefix marks the helper's protocol lines, so they are separable
	// from the test framework's own output on the same stream.
	protoPrefix = "#juist "

	// underlayPort is the UDP port every node binds. The namespaces are
	// separate, so one port serves all of them, and a fixed one keeps the
	// endpoints the lab hands out true.
	underlayPort = 41641

	// tcpEchoPort is where a node helper echoes TCP, when asked to.
	tcpEchoPort = 45111
)

// underlayLAN is the simulated LAN the namespaces share. Every packet a node
// sends must stay inside it: that is what makes the egress tap meaningful.
var underlayLAN = netip.MustParsePrefix("10.77.0.0/24")

// netnsLab is one bridge and the namespaces plugged into it. Everything it
// creates carries a per-lab tag, so two labs — or a lab and the leftovers of
// an interrupted run — never collide.
type netnsLab struct {
	t      *testing.T
	ip     string // iproute2, resolved once
	tag    string
	bridge string
	nodes  []*netnsNode

	// iptables is resolved only where a test asks for NAT, and routers are
	// the namespaces that translate: they hold no juist node, so they are
	// torn down separately from the nodes.
	iptables string
	routers  []string
}

// netnsNode is one node: a namespace, its veth into the bridge, and the helper
// process holding its manager and its real TUN device.
type netnsNode struct {
	lab      *netnsLab
	name     string
	id       uint64
	ns       string
	veth     string // the namespace's end of the veth pair
	port     string // the root namespace's end, a bridge port
	tun      string
	underlay netip.Addr
	addrs    []netip.Prefix
	// carries is what the node's peers route through it, as a grant gives
	// it: the internet, and subnets.
	carries []netip.Prefix
	subnets []netip.Prefix

	// inst is the host instance the node is, which picks its routing table,
	// and udpPort its data plane's port, underlayPort where zero. sharesNS
	// is set on a second instance in another node's namespace, which that
	// node's cleanup deletes.
	inst     int
	udpPort  int
	sharesNS bool

	nodeKey   key.NodePrivate
	discoPriv [32]byte
	discoPub  [32]byte

	// router is the namespace translating for this node, empty when it is
	// on the lab's LAN directly, and nat what that router does.
	router string
	nat    natKind

	// env is extra environment for the helper, set by the NAT lab before
	// start: the relay set to install, whether to serve one, and whether to
	// withhold peer address hints.
	env []string

	// public is where this node is reached from the public segment: its own
	// address, or its outermost NAT router's.
	public netip.Addr

	cmd     *exec.Cmd
	stdin   io.WriteCloser
	lines   chan string   // protocol lines, prefix stripped
	exited  chan struct{} // closed once the helper is reaped
	waitErr error

	mu   sync.Mutex
	gone bool // the test is done with this node; stop logging through t
}

// newNetnsLab checks the privileges and tools the harness needs, then creates
// the bridge. Everything it makes is torn down by a cleanup registered here.
func newNetnsLab(t *testing.T) *netnsLab {
	t.Helper()
	if os.Geteuid() != 0 {
		skipUnlessRequired(t, "needs root to create network namespaces, devices and routes")
	}
	ipCmd, err := exec.LookPath("ip")
	if err != nil {
		skipUnlessRequired(t, "iproute2 not installed; the harness builds its topology with it")
	}
	if _, err := exec.LookPath("ping"); err != nil {
		skipUnlessRequired(t, "ping not installed; the criterion asks for ordinary host tools")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		skipUnlessRequired(t, "no /dev/net/tun: %v", err)
	}
	// The router programs IPv6 only where the kernel has it, and the overlay's
	// primary family is the v6 ULA: without it this harness would assert half
	// the criterion and report a pass.
	if _, err := os.Stat("/proc/sys/net/ipv6"); err != nil {
		skipUnlessRequired(t, "the kernel has no IPv6; the overlay's primary family cannot be asserted")
	}

	var seed [2]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatalf("drawing a lab tag: %v", err)
	}
	l := &netnsLab{t: t, ip: ipCmd, tag: hex.EncodeToString(seed[:])}
	l.bridge = "jbr" + l.tag
	// Root is not enough: a container can hold CAP_NET_ADMIN and still refuse
	// to create a namespace or a bridge. Probe both, so an incapable host
	// skips rather than failing half-way through a topology.
	probe := "jprobe" + l.tag
	if out, err := exec.Command(ipCmd, "netns", "add", probe).CombinedOutput(); err != nil {
		skipUnlessRequired(t, "cannot create a network namespace here: %v: %s",
			err, strings.TrimSpace(string(out)))
	}
	exec.Command(ipCmd, "netns", "del", probe).Run()
	if out, err := exec.Command(ipCmd, "link", "add", "name", l.bridge, "type", "bridge").CombinedOutput(); err != nil {
		skipUnlessRequired(t, "cannot create a bridge here: %v: %s",
			err, strings.TrimSpace(string(out)))
	}
	t.Cleanup(l.cleanup)
	l.run("link", "set", l.bridge, "up")
	return l
}

// gateway is the LAN address every node routes through. Nothing holds it: each
// namespace is given a permanent neighbour entry for it instead, so the packet
// is addressed to a MAC no one owns and lands on the bridge, where the egress
// tap sees it. The alternative — putting the address on the bridge in the root
// namespace — would give the host a second route for this prefix, and break
// its networking outright on a machine that already uses it.
func (l *netnsLab) gateway() netip.Addr {
	octets := underlayLAN.Addr().As4()
	octets[3] = 254
	return netip.AddrFrom4(octets)
}

// gatewayMAC is locally administered, so it cannot collide with real hardware.
const gatewayMAC = "02:00:00:00:00:fe"

// addNode creates a namespace holding one veth into the bridge and returns the
// node, not yet started. host is the last octet of every address it gets, on
// the underlay and the overlay, and its node ID.
func (l *netnsLab) addNode(name string, host int) *netnsNode {
	t := l.t
	t.Helper()
	n := l.newDetachedNode(name, host)
	l.run("link", "add", n.port, "type", "veth", "peer", "name", n.veth)
	l.run("link", "set", n.port, "master", l.bridge, "up")
	l.run("link", "set", n.veth, "netns", n.ns)
	l.runIn(n, "link", "set", "lo", "up")
	l.runIn(n, "addr", "add", netip.PrefixFrom(n.underlay, underlayLAN.Bits()).String(), "dev", n.veth)
	l.runIn(n, "link", "set", n.veth, "up")
	// A default route makes the namespace an ordinary host: the engine's
	// socket binding and the network monitor both consult one, and without it
	// a connection to a third party would have nowhere to go to be seen.
	//
	// It goes through a next hop rather than being on-link, and that next hop
	// is resolved in advance. On-link, the kernel would ARP for the third
	// party itself and never put the IP packet on the wire, so the egress tap
	// would be watching for a frame that cannot appear — and would pass. See
	// [netnsLab.gateway].
	l.runIn(n, "neigh", "add", l.gateway().String(), "lladdr", gatewayMAC,
		"dev", n.veth, "nud", "permanent")
	l.runIn(n, "route", "add", "default", "via", l.gateway().String(), "dev", n.veth)
	return n
}

// newDetachedNode creates a node's namespace, keys and addresses without
// attaching it to anything: [netnsLab.addNode] puts it on the lab's LAN, and
// [netnsLab.addNATNode] puts a router in front of it.
func (l *netnsLab) newDetachedNode(name string, host int) *netnsNode {
	t := l.t
	t.Helper()
	discoPriv, discoPub, err := NewDiscoKey()
	if err != nil {
		t.Fatalf("generating a disco key: %v", err)
	}
	// The lab's LAN is stated once, in underlayLAN, and every address on it
	// follows from that prefix and the host octet.
	octets := underlayLAN.Addr().As4()
	octets[3] = byte(host)
	n := &netnsNode{
		lab:  l,
		name: name,
		id:   uint64(host),
		// Interface names must fit IFNAMSIZ (15 bytes); these are 7.
		ns:        "juist" + name + l.tag,
		veth:      "jv" + name + l.tag,
		port:      "jp" + name + l.tag,
		tun:       "jt" + name + l.tag,
		underlay:  netip.AddrFrom4(octets),
		public:    netip.AddrFrom4(octets),
		nodeKey:   key.NewNode(),
		discoPriv: discoPriv,
		discoPub:  discoPub,
		addrs: []netip.Prefix{
			netip.MustParsePrefix(fmt.Sprintf("100.64.0.%d/32", host)),
			netip.MustParsePrefix(fmt.Sprintf("fd7a:115c:a1e0::%d/128", host)),
		},
		lines:  make(chan string, 16),
		exited: make(chan struct{}),
	}

	l.run("netns", "add", n.ns)
	// Recorded before anything else can fail, so cleanup deletes the
	// namespace — and with it the veth — whatever goes wrong below.
	l.nodes = append(l.nodes, n)
	return n
}

// listenPort is the UDP port the node's data plane binds.
func (n *netnsNode) listenPort() int {
	if n.udpPort != 0 {
		return n.udpPort
	}
	return underlayPort
}

// addInstance adds a node to host's namespace as another juist instance, as a
// host in two networks runs: a device, keys and port of its own, and inst's
// routing table. octet numbers its overlay addresses and node ID.
func (l *netnsLab) addInstance(host *netnsNode, name string, octet, inst int) *netnsNode {
	t := l.t
	t.Helper()
	discoPriv, discoPub, err := NewDiscoKey()
	if err != nil {
		t.Fatalf("generating a disco key: %v", err)
	}
	n := &netnsNode{
		lab: l, name: name, id: uint64(octet),
		ns: host.ns, veth: host.veth, port: host.port, underlay: host.underlay, public: host.public,
		tun:     "jt" + name + l.tag,
		nodeKey: key.NewNode(), discoPriv: discoPriv, discoPub: discoPub,
		addrs: []netip.Prefix{
			netip.MustParsePrefix(fmt.Sprintf("100.64.0.%d/32", octet)),
			netip.MustParsePrefix(fmt.Sprintf("fd7a:115c:a1e0::%d/128", octet)),
		},
		inst: inst, udpPort: underlayPort + 10*inst, sharesNS: true,
		lines: make(chan string, 16), exited: make(chan struct{}),
	}
	l.nodes = append(l.nodes, n)
	return n
}

// restart stops the node's helper and starts another on addrs, as a daemon
// restarts on new addresses.
func (n *netnsNode) restart(addrs []netip.Prefix, peers []*netnsNode) {
	n.lab.t.Helper()
	n.stop()
	n.mu.Lock()
	n.gone = false
	n.mu.Unlock()
	n.cmd, n.addrs = nil, addrs
	n.lines, n.exited, n.waitErr = make(chan string, 16), make(chan struct{}), nil
	n.start(peers, 0)
}

// viewOf is n as a peer that holds addrs for it sees it: what a member whose
// log is behind, or ahead, installs.
func viewOf(n *netnsNode, addrs ...netip.Prefix) *netnsNode {
	return &netnsNode{id: n.id, nodeKey: n.nodeKey, discoPub: n.discoPub, addrs: addrs,
		underlay: n.underlay, udpPort: n.udpPort}
}

// start runs the node's helper inside its namespace and waits for it to report
// a live manager. tcpEcho, when non-zero, is a TCP port the helper accepts and
// echoes on.
func (n *netnsNode) start(peers []*netnsNode, tcpEcho int) {
	t := n.lab.t
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locating this test binary: %v", err)
	}
	cmd := n.lab.exec(n, self, "-test.run", "^TestHelperNetnsNode$", "-test.timeout", "10m")
	cmd.Env = append(os.Environ(),
		netnsHelperEnv+"=node",
		envNodeID+"="+strconv.FormatUint(n.id, 10),
		envNodeKey+"="+rawHex(n.nodeKey.Raw32()),
		envDiscoKey+"="+rawHex(n.discoPriv),
		envAddrs+"="+joinPrefixes(n.addrs),
		envTun+"="+n.tun,
		envPort+"="+strconv.Itoa(n.listenPort()),
		envInstance+"="+strconv.Itoa(n.inst),
		envPeers+"="+encodePeers(peers),
	)
	cmd.Env = append(cmd.Env, n.env...)
	if tcpEcho != 0 {
		cmd.Env = append(cmd.Env, envTCPListen+"="+strconv.Itoa(tcpEcho))
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("node %s stdin: %v", n.name, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("node %s stdout: %v", n.name, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("node %s stderr: %v", n.name, err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting node %s: %v", n.name, err)
	}
	n.cmd, n.stdin = cmd, stdin

	// Wait must not run until both pipes are drained, so the reaper waits on
	// the readers first.
	var readers sync.WaitGroup
	readers.Add(2)
	go func() { defer readers.Done(); n.read(stdout) }()
	go func() { defer readers.Done(); n.read(stderr) }()
	go func() {
		readers.Wait()
		n.waitErr = cmd.Wait()
		close(n.exited)
	}()

	n.expect("READY", 60*time.Second)
}

// read forwards the helper's output: protocol lines to the caller, everything
// else — engine logs, test framework noise — to the test log.
func (n *netnsNode) read(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if rest, ok := strings.CutPrefix(line, protoPrefix); ok {
			select {
			case n.lines <- rest:
			default:
				n.logf("dropped protocol line %q", rest)
			}
			continue
		}
		n.logf("%s", line)
	}
}

// logf logs through the test, unless the test is already done with this node —
// t.Logf after that panics, and a helper being torn down still writes.
func (n *netnsNode) logf(format string, args ...any) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.gone {
		return
	}
	n.lab.t.Logf("%s: "+format, append([]any{n.name}, args...)...)
}

// expect waits for a protocol line starting with want, failing the test if the
// helper says something else, dies, or says nothing in time.
func (n *netnsNode) expect(want string, timeout time.Duration) string {
	t := n.lab.t
	t.Helper()
	select {
	case line := <-n.lines:
		if !strings.HasPrefix(line, want) {
			t.Fatalf("node %s: got %q, want a line starting %q", n.name, line, want)
		}
		return line
	case <-n.exited:
		t.Fatalf("node %s exited while waiting for %q: %v", n.name, want, n.waitErr)
	case <-time.After(timeout):
		t.Fatalf("node %s: nothing said %q within %v", n.name, want, timeout)
	}
	return ""
}

// setPeers replaces the node's peer set: "all" is the set it was started with,
// "none" is empty — a member removed from the log.
func (n *netnsNode) setPeers(which string) {
	t := n.lab.t
	t.Helper()
	if _, err := io.WriteString(n.stdin, "PEERS "+which+"\n"); err != nil {
		t.Fatalf("node %s: sending PEERS %s: %v", n.name, which, err)
	}
	n.expect("OK", 30*time.Second)
}

// stop asks the helper to shut down, which tears its device and routes down
// the way a clean daemon exit does, and kills it if it will not go.
func (n *netnsNode) stop() {
	if n.cmd == nil {
		return
	}
	io.WriteString(n.stdin, "EXIT\n")
	n.stdin.Close()
	select {
	case <-n.exited:
	case <-time.After(30 * time.Second):
		n.cmd.Process.Kill()
		<-n.exited
	}
	n.mu.Lock()
	n.gone = true
	n.mu.Unlock()
}

// ping runs the host's own ping inside the node's namespace, covering the
// whole path — kernel stack, real device, filter, tunnel — rather than the
// engine's internal ICMP, which answers without reaching a device.
func (n *netnsNode) ping(to netip.Addr) error {
	out, err := n.lab.exec(n, "ping", "-n", "-q", "-c", "1", "-W", "1", to.String()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s cannot ping %v: %v: %s", n.name, to, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// pingUntil retries: the first packet primes disco and a WireGuard handshake,
// so nothing is expected to answer immediately.
func (n *netnsNode) pingUntil(to netip.Addr, within time.Duration) error {
	deadline := time.Now().Add(within)
	for {
		err := n.ping(to)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// routes returns the prefixes routed into the node's overlay device. Reading
// "table all" is load-bearing: the Linux router keeps peer routes in its own
// table, juistRouteTable.
func (n *netnsNode) routes() []netip.Prefix {
	return ifaceRoutes(n.lab.t, []string{n.lab.ip, "-n", n.ns}, n.tun)
}

// run executes an iproute2 command in the root namespace.
func (l *netnsLab) run(args ...string) {
	l.t.Helper()
	l.must(exec.Command(l.ip, args...))
}

// runIn executes an iproute2 command inside a node's namespace.
func (l *netnsLab) runIn(n *netnsNode, args ...string) {
	l.t.Helper()
	l.must(exec.Command(l.ip, append([]string{"-n", n.ns}, args...)...))
}

// exec builds a command that runs inside a node's namespace.
func (l *netnsLab) exec(n *netnsNode, argv ...string) *exec.Cmd {
	return exec.Command(l.ip, append([]string{"netns", "exec", n.ns}, argv...)...)
}

func (l *netnsLab) must(cmd *exec.Cmd) {
	l.t.Helper()
	if out, err := cmd.CombinedOutput(); err != nil {
		l.t.Fatalf("%s: %v: %s", strings.Join(cmd.Args, " "), err, strings.TrimSpace(string(out)))
	}
}

// cleanup stops every helper before deleting the namespaces they live in, then
// the bridge. Failures are logged, not fatal: a cleanup that fails the test
// would hide whatever the test itself found.
func (l *netnsLab) cleanup() {
	for _, n := range l.nodes {
		n.stop()
	}
	for _, n := range l.nodes {
		if n.sharesNS {
			continue
		}
		if out, err := exec.Command(l.ip, "netns", "del", n.ns).CombinedOutput(); err != nil {
			l.t.Logf("deleting namespace %s: %v: %s", n.ns, err, strings.TrimSpace(string(out)))
		}
	}
	for _, ns := range l.routers {
		if out, err := exec.Command(l.ip, "netns", "del", ns).CombinedOutput(); err != nil {
			l.t.Logf("deleting router namespace %s: %v: %s", ns, err, strings.TrimSpace(string(out)))
		}
	}
	if out, err := exec.Command(l.ip, "link", "del", l.bridge).CombinedOutput(); err != nil {
		l.t.Logf("deleting bridge %s: %v: %s", l.bridge, err, strings.TrimSpace(string(out)))
	}
}

// encodePeers renders nodes as the peer records the receiving helper rebuilds:
// what the reconciler would hand [Manager.SetPeers], plus the underlay
// endpoint gossip would have carried.
func encodePeers(peers []*netnsNode) string {
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		out = append(out, strings.Join([]string{
			strconv.FormatUint(p.id, 10),
			p.nodeKey.Public().String(),
			rawHex(p.discoPub),
			joinPrefixes(p.addrs),
			netip.AddrPortFrom(p.underlay, uint16(p.listenPort())).String(),
			joinPrefixes(p.carries),
			joinPrefixes(p.subnets),
		}, "|"))
	}
	return strings.Join(out, ";")
}

// decodePeers is encodePeers' inverse, run in the helper.
func decodePeers(s string) ([]Peer, error) {
	if s == "" {
		return nil, nil
	}
	var peers []Peer
	for _, rec := range strings.Split(s, ";") {
		f := strings.Split(rec, "|")
		if len(f) != 7 {
			return nil, fmt.Errorf("peer record %q has %d fields, want 7", rec, len(f))
		}
		id, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("peer ID %q: %w", f[0], err)
		}
		var nodePub key.NodePublic
		if err := nodePub.UnmarshalText([]byte(f[1])); err != nil {
			return nil, fmt.Errorf("peer node key: %w", err)
		}
		discoPub, err := unrawHex(f[2])
		if err != nil {
			return nil, fmt.Errorf("peer disco key: %w", err)
		}
		addrs, err := splitPrefixes(f[3])
		if err != nil {
			return nil, err
		}
		ep, err := netip.ParseAddrPort(f[4])
		if err != nil {
			return nil, fmt.Errorf("peer endpoint %q: %w", f[4], err)
		}
		var routes, subnets []netip.Prefix
		if f[5] != "" {
			if routes, err = splitPrefixes(f[5]); err != nil {
				return nil, err
			}
		}
		if f[6] != "" {
			if subnets, err = splitPrefixes(f[6]); err != nil {
				return nil, err
			}
		}
		peers = append(peers, Peer{
			ID:        id,
			NodeKey:   nodePub,
			DiscoKey:  DiscoPublicFromRaw32(discoPub),
			Addrs:     addrs,
			Routes:    routes,
			Subnets:   subnets,
			Endpoints: []netip.AddrPort{ep},
		})
	}
	return peers, nil
}

func rawHex(b [32]byte) string { return hex.EncodeToString(b[:]) }

func unrawHex(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("got %d bytes, want 32", len(b))
	}
	return [32]byte(b), nil
}

func joinPrefixes(pfxs []netip.Prefix) string {
	out := make([]string, 0, len(pfxs))
	for _, p := range pfxs {
		out = append(out, p.String())
	}
	return strings.Join(out, ",")
}

func splitPrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, fmt.Errorf("address %q: %w", f, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// egressTap records every destination address seen on one node's bridge port:
// the M0 egress criterion in its stronger form, watching the only link the
// node has rather than inferring from this process's own sockets.
type egressTap struct {
	t    *testing.T
	stop chan struct{}
	done chan struct{}

	mu   sync.Mutex
	dsts map[netip.Addr]int
}

// tapEgress starts capturing on a node's bridge port. The port lives in the
// root namespace, so no namespace switching is needed to watch it.
func (l *netnsLab) tapEgress(n *netnsNode) *egressTap {
	t := l.t
	t.Helper()
	iface, err := net.InterfaceByName(n.port)
	if err != nil {
		t.Fatalf("looking up bridge port %s: %v", n.port, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		t.Fatalf("opening a packet socket: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iface.Index,
	}); err != nil {
		unix.Close(fd)
		t.Fatalf("binding the packet socket to %s: %v", n.port, err)
	}
	// A receive timeout, so the reader notices the stop signal without needing
	// a packet to arrive first.
	tv := unix.NsecToTimeval(int64(250 * time.Millisecond))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		t.Fatalf("setting the capture timeout: %v", err)
	}

	tap := &egressTap{t: t, stop: make(chan struct{}), done: make(chan struct{}), dsts: map[netip.Addr]int{}}
	go func() {
		defer close(tap.done)
		defer unix.Close(fd)
		buf := make([]byte, 2048)
		for {
			select {
			case <-tap.stop:
				return
			default:
			}
			nb, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				continue // the read timeout, or a signal
			}
			if dsts := frameDsts(buf[:nb]); len(dsts) > 0 {
				tap.mu.Lock()
				for _, dst := range dsts {
					tap.dsts[dst]++
				}
				tap.mu.Unlock()
			}
		}
	}()
	t.Cleanup(tap.close)
	return tap
}

// strangers reports the destinations seen that are neither on the lab's LAN
// nor link-local or multicast housekeeping — that is, any third party.
func (tp *egressTap) strangers() []netip.Addr {
	tp.close()
	tp.mu.Lock()
	defer tp.mu.Unlock()
	var out []netip.Addr
	for dst := range tp.dsts {
		if !dst.IsGlobalUnicast() || underlayLAN.Contains(dst) {
			continue
		}
		out = append(out, dst)
	}
	return out
}

func (tp *egressTap) close() {
	select {
	case <-tp.stop:
		return // already stopped
	default:
	}
	close(tp.stop)
	<-tp.done
}

// frameDsts returns the addresses an Ethernet frame is aimed at: the
// destination of an IPv4 or IPv6 packet, and the target of an ARP request or a
// neighbour solicitation. The last two matter because address resolution
// precedes the packet — a host that cannot resolve its next hop emits only the
// query, so a tap watching IP headers alone would see nothing at all and call
// that silence a pass.
func frameDsts(f []byte) []netip.Addr {
	if len(f) < 14 {
		return nil
	}
	switch binary.BigEndian.Uint16(f[12:14]) {
	case 0x0800:
		if len(f) < 34 {
			return nil
		}
		return []netip.Addr{netip.AddrFrom4([4]byte(f[30:34]))}
	case 0x86dd:
		if len(f) < 54 {
			return nil
		}
		out := []netip.Addr{netip.AddrFrom16([16]byte(f[38:54]))}
		// A neighbour solicitation: ICMPv6 type 135, whose target sits after
		// the 4-byte ICMPv6 header and 4 reserved bytes.
		if f[20] == 58 && len(f) >= 78 && f[54] == 135 {
			out = append(out, netip.AddrFrom16([16]byte(f[62:78])))
		}
		return out
	case 0x0806:
		// An ARP request for IPv4 over Ethernet: the target protocol address
		// is the last four bytes of the 28-byte payload.
		if len(f) < 42 || binary.BigEndian.Uint16(f[16:18]) != 0x0800 || f[19] != 4 {
			return nil
		}
		return []netip.Addr{netip.AddrFrom4([4]byte(f[38:42]))}
	}
	return nil
}

// htons puts a 16-bit value in network byte order, which is what AF_PACKET's
// protocol field is read in.
func htons(v uint16) uint16 { return v<<8 | v>>8 }
