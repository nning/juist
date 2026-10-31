//go:build linux

package conn

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/net/ipv4"
	"tailscale.com/net/stun"
	"tailscale.com/types/ipproto"

	"github.com/nning/juist/internal/dnsfwd"
	"github.com/nning/juist/internal/netstack"
	"github.com/nning/juist/internal/pipe"
	"github.com/nning/juist/relay"
)

// The two halves of a netns node that do not run in the test process. Both
// skip unless the lab re-executed this binary for them, so an ordinary
// `go test` never enters either.

// TestHelperNetnsNode is one node of the lab: a real TUN device, a real
// router, and the peer set the lab gave it. It reports READY on stdout once
// the manager is up, then takes commands on stdin until told to exit.
func TestHelperNetnsNode(t *testing.T) {
	if os.Getenv(netnsHelperEnv) != "node" {
		t.Skip("not a netns node helper invocation")
	}
	id, err := strconv.ParseUint(os.Getenv(envNodeID), 10, 64)
	if err != nil {
		t.Fatalf("node ID: %v", err)
	}
	nodeRaw, err := unrawHex(os.Getenv(envNodeKey))
	if err != nil {
		t.Fatalf("node key: %v", err)
	}
	discoRaw, err := unrawHex(os.Getenv(envDiscoKey))
	if err != nil {
		t.Fatalf("disco key: %v", err)
	}
	addrs, err := splitPrefixes(os.Getenv(envAddrs))
	if err != nil {
		t.Fatalf("overlay addresses: %v", err)
	}
	port, err := strconv.ParseUint(os.Getenv(envPort), 10, 16)
	if err != nil {
		t.Fatalf("listen port: %v", err)
	}
	peers, err := decodePeers(os.Getenv(envPeers))
	if err != nil {
		t.Fatalf("peer set: %v", err)
	}
	inst := 0
	if v := os.Getenv(envInstance); v != "" {
		if inst, err = strconv.Atoi(v); err != nil {
			t.Fatalf("instance: %v", err)
		}
	}

	// A relay comes up before the manager, so that it holds its ports before
	// anything else in this process binds. Where it listens is reported after
	// READY, because the lab reads the protocol in order and READY is what
	// every node says first.
	var relayLine string
	if p := os.Getenv(envServeRelay); p != "" {
		srv := serveRelay(t, p)
		defer srv.Close()
		sum := srv.CertHash()
		relayLine = fmt.Sprintf("RELAY %d %d %s %s",
			srv.Port(), srv.STUNPort(), srv.HostName(), hex.EncodeToString(sum[:]))
	}

	var hostRouteChanges atomic.Int64
	tunName, dev, stack := os.Getenv(envTun), tun.Device(nil), (*netstack.Net)(nil)
	if os.Getenv(envNetstack) != "" {
		var own []netip.Addr
		for _, p := range addrs {
			own = append(own, p.Addr())
		}
		if dev, stack, err = netstack.New(own, 1280); err != nil {
			t.Fatalf("netstack: %v", err)
		}
		tunName = ""
	}
	mgr, err := New(Options{
		OnHostRoutesChange: func() { hostRouteChanges.Add(1) },
		Self: Self{
			ID:       id,
			NodeKey:  NodeKeyFromRaw32(nodeRaw),
			DiscoKey: DiscoKeyFromRaw32(discoRaw),
			Addrs:    addrs,
		},
		ListenPort: uint16(port),
		Tun:        dev,
		TunName:    tunName,
		Instance:   inst,
		Multicast:  os.Getenv(envMulticast) != "",
		Debug:      os.Getenv(envDebug) != "",
		// Engine logs go to stderr as they happen. The test framework's own
		// log buffers until the test ends, which is far too late to explain a
		// node the lab is still waiting on.
		Logf: func(format string, args ...any) {
			fmt.Fprintln(os.Stderr, strings.TrimRight(fmt.Sprintf(format, args...), "\n"))
		},
	})
	if err != nil {
		t.Fatalf("starting the manager: %v", err)
	}
	defer mgr.Close()

	// Relays before peers: a peer whose only path is through one must find
	// it already installed, or its first probes go nowhere.
	if spec := os.Getenv(envRelays); spec != "" {
		r, err := decodeRelaySpec(spec)
		if err != nil {
			t.Fatalf("relay set: %v", err)
		}
		if err := mgr.SetRelays([]Relay{r}); err != nil {
			t.Fatalf("SetRelays: %v", err)
		}
		// One relay in the lab, so every peer is reachable through it.
		for i := range peers {
			peers[i].HomeRelay = r.Region
		}
	}
	if os.Getenv(envNoEndpoints) != "" {
		// What a node behind NAT actually holds: no usable address for its
		// peer. Its private one means something else here, and its public
		// one is a mapping only its NAT knows until disco finds it.
		for i := range peers {
			peers[i].Endpoints = nil
		}
	}
	if err := mgr.SetPeers(peers); err != nil {
		t.Fatalf("SetPeers: %v", err)
	}
	if v := os.Getenv(envServe); v != "" {
		srcs, err := splitPrefixes(v)
		if err != nil {
			t.Fatalf("serve sources: %v", err)
		}
		s := Serve{Sources: srcs}
		if sub := os.Getenv(envSubnets); sub != "" {
			if s.Subnets, err = splitPrefixes(sub); err != nil {
				t.Fatalf("subnets: %v", err)
			}
		} else {
			s.Routes = Internet(true, true, nil)
		}
		if os.Getenv(envServeDNS) != "" {
			s.DNS = dnsPort
		}
		if err := mgr.SetServe(s); err != nil {
			t.Fatalf("SetServe: %v", err)
		}
	}
	if up := os.Getenv(envServeDNS); up != "" {
		upstream := netip.MustParseAddrPort(up)
		var own []netip.Addr
		for _, p := range addrs {
			own = append(own, p.Addr())
		}
		fwd, err := dnsfwd.Start(dnsfwd.Options{Addrs: own, Port: dnsPort, Device: os.Getenv(envTun),
			Allowed: func(a netip.Addr) bool {
				return netip.MustParsePrefix("100.64.0.0/24").Contains(a) ||
					netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(a)
			},
			Upstream: func() []netip.AddrPort { return []netip.AddrPort{upstream} }})
		if err != nil {
			t.Fatalf("answering DNS: %v", err)
		}
		defer fwd.Close()
	}
	if v := os.Getenv(envEgress); v != "" {
		if err := setEgressByName(mgr, v); err != nil {
			t.Fatalf("egress %s: %v", v, err)
		}
	}
	if p := os.Getenv(envTCPListen); p != "" {
		serveTCPEcho(t, p)
	}
	if v := os.Getenv(envNetstack); v != "" {
		port, target, _ := strings.Cut(v, ">")
		for _, p := range addrs {
			ap := netip.AddrPortFrom(p.Addr(), uint16(mustAtoi(t, port)))
			ln, err := stack.ListenTCPAddrPort(ap)
			if err != nil {
				t.Fatalf("netstack: listening at %v: %v", ap, err)
			}
			defer ln.Close()
			go passOn(ln, target)
		}
	}

	say("READY %d", mgr.LocalPort())
	if relayLine != "" {
		say("%s", relayLine)
	}
	streams := map[string]*heldStream{}
	var heard *groupListener
	var psk [32]byte
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		cmd := strings.TrimSpace(sc.Text())
		// HINT is where a peer's address arrives, which in a daemon is a
		// gossiped announcement reaching the reconciler. Disco cannot start
		// without one: magicsock sends a CallMeMaybe only after it has
		// pinged something, so a peer with no candidate at all is one it
		// never asks to punch back.
		if rest, ok := strings.CutPrefix(cmd, "HINT "); ok {
			f := strings.Fields(rest)
			if len(f) != 2 {
				t.Fatalf("HINT wants a node ID and an address, got %q", rest)
			}
			id, err := strconv.ParseUint(f[0], 10, 64)
			if err != nil {
				t.Fatalf("HINT node ID %q: %v", f[0], err)
			}
			ap, err := netip.ParseAddrPort(f[1])
			if err != nil {
				t.Fatalf("HINT address %q: %v", f[1], err)
			}
			found := false
			for i := range peers {
				if peers[i].ID == id {
					peers[i].Endpoints = []netip.AddrPort{ap}
					found = true
				}
			}
			if !found {
				t.Fatalf("HINT names node %d, which is not a peer here", id)
			}
			if err := mgr.SetPeers(peers); err != nil {
				t.Fatalf("SetPeers after HINT: %v", err)
			}
			say("OK")
			continue
		}
		if size, ok := strings.CutPrefix(cmd, "SEND "); ok {
			if err := sendGroup(os.Getenv(envTun), mustAtoi(t, size)); err != nil {
				t.Fatalf("SEND: %v", err)
			}
			say("OK")
			continue
		}
		if at, ok := strings.CutPrefix(cmd, "ASK "); ok {
			say("%s", askDNS(at))
			continue
		}
		if name, ok := strings.CutPrefix(cmd, "EGRESS "); ok {
			if err := setEgressByName(mgr, name); err != nil {
				t.Fatalf("EGRESS %s: %v", name, err)
			}
			say("OK")
			continue
		}
		if rest, ok := strings.CutPrefix(cmd, "STREAM "); ok {
			name, to, _ := strings.Cut(rest, " ")
			streams[name] = startStream(t, to)
			say("OK")
			continue
		}
		if name, ok := strings.CutPrefix(cmd, "STREAMSTAT "); ok {
			say("STREAM %s", streams[name].stat())
			continue
		}
		if rest, ok := strings.CutPrefix(cmd, "SELF "); ok {
			hexKey, addrList, _ := strings.Cut(rest, " ")
			k, err := unrawHex(hexKey)
			if err != nil {
				t.Fatalf("SELF: %v", err)
			}
			if addrs, err = splitPrefixes(addrList); err != nil {
				t.Fatalf("SELF: %v", err)
			}
			if err := mgr.SetSelf(Self{ID: id, NodeKey: NodeKeyFromRaw32(k), DiscoKey: DiscoKeyFromRaw32(discoRaw), Addrs: addrs}); err != nil {
				t.Fatalf("SetSelf: %v", err)
			}
			say("OK")
			continue
		}
		if rest, ok := strings.CutPrefix(cmd, "PROXY "); ok {
			at, target, _ := strings.Cut(rest, " ")
			ln, err := net.Listen("tcp", at)
			if err != nil {
				t.Fatalf("PROXY: %v", err)
			}
			defer ln.Close()
			go passOn(ln, target)
			say("OK")
			continue
		}
		if port, ok := strings.CutPrefix(cmd, "ACCESS "); ok {
			for i := range peers {
				p := uint16(mustAtoi(t, port))
				peers[i].Access = &Access{Open: []Ports{{Proto: ipproto.TCP, First: p, Last: p}}}
			}
			if err := mgr.SetPeers(peers); err != nil {
				t.Fatalf("SetPeers: %v", err)
			}
			say("OK")
			continue
		}
		if enc, ok := strings.CutPrefix(cmd, "PEERSET "); ok {
			if peers, err = decodePeers(enc); err != nil {
				t.Fatalf("PEERSET: %v", err)
			}
			for i := range peers {
				peers[i].PSK = psk
			}
			if err := mgr.SetPeers(peers); err != nil {
				t.Fatalf("SetPeers: %v", err)
			}
			say("OK")
			continue
		}
		if hexKey, ok := strings.CutPrefix(cmd, "PSK "); ok {
			k, err := unrawHex(hexKey)
			if err != nil {
				t.Fatalf("PSK: %v", err)
			}
			psk = k
			for i := range peers {
				peers[i].PSK = k
			}
			if err := mgr.SetPeers(peers); err != nil {
				t.Fatalf("SetPeers after PSK: %v", err)
			}
			say("OK")
			continue
		}
		if srcs, ok := strings.CutPrefix(cmd, "SERVE "); ok {
			s := Serve{}
			if srcs != "none" {
				var err error
				if s.Sources, err = splitPrefixes(srcs); err != nil {
					t.Fatalf("SERVE: %v", err)
				}
				s.Routes = Internet(true, true, nil)
			}
			if err := mgr.SetServe(s); err != nil {
				t.Fatalf("SetServe: %v", err)
			}
			say("OK")
			continue
		}
		switch cmd {
		case "PEERS all":
			if err := mgr.SetPeers(peers); err != nil {
				t.Fatalf("SetPeers(all): %v", err)
			}
			say("OK")
		case "PEERS none":
			if err := mgr.SetPeers(nil); err != nil {
				t.Fatalf("SetPeers(none): %v", err)
			}
			say("OK")
		case "JOIN":
			if heard, err = joinGroup(os.Getenv(envTun)); err != nil {
				t.Fatalf("JOIN: %v", err)
			}
			defer heard.close()
			say("OK")
		case "HEARD":
			say("HEARD %s", heard.heard())
		case "HOSTROUTES":
			// How often the host's own routes were seen to change.
			say("HOSTROUTES %d", hostRouteChanges.Load())
		case "HOME":
			// What region the data plane settled on, once netcheck has run.
			// Zero means it has no relay yet, which the lab waits out.
			say("HOME %d", mgr.HomeRelay())
		case "ENDPOINTS":
			// Where the data plane believes this node can be reached,
			// including the reflexive address a relay's STUN responder told
			// it. Without one, nothing can punch to this node.
			eps := mgr.LocalEndpoints()
			out := make([]string, 0, len(eps))
			for _, ap := range eps {
				out = append(out, ap.String())
			}
			say("ENDPOINTS %s", strings.Join(out, ","))
		case "REKEY":
			// Each peer's next packet starts a handshake; the answer is how
			// long until every one completed, or that one did not in 15 s.
			start := time.Now()
			for _, p := range peers {
				mgr.(*tsManager).eng.MarkDevicePeerForHandshake(p.NodeKey)
			}
			done := func() bool {
				tun := mgr.Tunnels()
				for _, p := range peers {
					if !tun[p.ID].LastHandshake.After(start) {
						return false
					}
				}
				return true
			}
			for !done() && time.Since(start) < 15*time.Second {
				time.Sleep(50 * time.Millisecond)
			}
			if done() {
				say("REKEYED %d", time.Since(start).Milliseconds())
			} else {
				say("REKEYED none")
			}
		case "EXIT":
			return
		default:
			t.Fatalf("unknown command %q", cmd)
		}
	}
}

// dnsQuery is a query for example.com A.
var dnsQuery = []byte{0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
	7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}

// askDNS puts dnsQuery to at and says whether it was answered.
func askDNS(at string) string {
	c, err := net.Dial("udp", at)
	if err != nil {
		return "ASK fail " + err.Error()
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(dnsQuery); err != nil {
		return "ASK fail " + err.Error()
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	switch {
	case err != nil:
		return "ASK fail " + err.Error()
	case n < 2 || buf[0] != 0x12 || buf[1] != 0x34 || buf[2]&0x80 == 0:
		return "ASK fail no answer to the query"
	}
	return "ASK ok"
}

// TestHelperNetnsDNS is a resolver: it answers every query on UDP port 53
// with the query as its answer, and asks as the node helper does.
func TestHelperNetnsDNS(t *testing.T) {
	if os.Getenv(netnsHelperEnv) != "dns" {
		t.Skip("not a netns DNS helper invocation")
	}
	pc, err := net.ListenPacket("udp", os.Getenv(envDNSListen))
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			buf[2] |= 0x80
			pc.WriteTo(buf[:n], src)
		}
	}()
	say("READY")
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		if at, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "ASK "); ok {
			say("%s", askDNS(at))
		}
	}
}

func setEgressByName(mgr Manager, name string) error {
	for _, e := range []Egress{EgressDirect, EgressTunnel, EgressRefused} {
		if e.String() == name {
			return mgr.SetEgress(e, false)
		}
	}
	return fmt.Errorf("no egress %q", name)
}

// serveRelay starts this node's relay, admitting exactly the keys the lab
// named. Admitting everything would make the lab prove less than it looks
// like it does: relay/ is where refusing a non-member is tested, and a lab
// that ignored the check could not notice it had been lost.
func serveRelay(t *testing.T, port string) *relay.Server {
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatalf("relay port: %v", err)
	}
	admitted := map[[32]byte]bool{}
	for _, h := range strings.Split(os.Getenv(envRelayAdmit), ",") {
		if h == "" {
			continue
		}
		k, err := unrawHex(h)
		if err != nil {
			t.Fatalf("relay admit list: %v", err)
		}
		admitted[k] = true
	}
	srv, err := relay.New(relay.Options{
		Admit: func(k [32]byte) bool { return admitted[k] },
		Port:  uint16(p),
		Logf: func(format string, args ...any) {
			fmt.Fprintln(os.Stderr, strings.TrimRight(fmt.Sprintf(format, args...), "\n"))
		},
	})
	if err != nil {
		t.Fatalf("starting the relay: %v", err)
	}
	return srv
}

// TestHelperNetnsSTUN classifies this namespace's NAT: one socket, two
// reflectors, and the source ports they report back. One port means the
// mapping is endpoint-independent and the peer can be told where to aim; two
// means it is symmetric and nobody can.
func TestHelperNetnsSTUN(t *testing.T) {
	if os.Getenv(netnsHelperEnv) != "stun" {
		t.Skip("not a netns STUN helper invocation")
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	defer c.Close()
	for _, target := range strings.Split(os.Getenv(envSTUNTargets), ",") {
		ap, err := netip.ParseAddrPort(strings.TrimSpace(target))
		if err != nil {
			t.Fatalf("reflector %q: %v", target, err)
		}
		txid := stun.NewTxID()
		if _, err := c.WriteToUDPAddrPort(stun.Request(txid), ap); err != nil {
			t.Fatalf("asking %v: %v", ap, err)
		}
		if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1500)
		n, _, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("no answer from %v: %v", ap, err)
		}
		gotID, mapped, err := stun.ParseResponse(buf[:n])
		if err != nil {
			t.Fatalf("answer from %v: %v", ap, err)
		}
		if gotID != txid {
			t.Fatalf("answer from %v carries another transaction ID", ap)
		}
		say("PORT %d", mapped.Port())
	}
}

// serveTCPEcho accepts and echoes on the given port. The listener is a
// wildcard one: what proves the stream crossed the overlay is the address the
// client dials, not the one this binds.
func serveTCPEcho(t *testing.T, port string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		t.Fatalf("listening on TCP port %s: %v", port, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
}

// TestHelperNetnsTCP carries a TCP stream to an overlay address and checks
// every byte comes back. It is an ordinary Go network client: it knows nothing
// about juist, so what it exercises is the host's stack over the real device.
func TestHelperNetnsTCP(t *testing.T) {
	if os.Getenv(netnsHelperEnv) != "tcp" {
		t.Skip("not a netns TCP helper invocation")
	}
	target, err := netip.ParseAddrPort(os.Getenv(envTCPDial))
	if err != nil {
		t.Fatalf("dial target: %v", err)
	}
	size, err := strconv.Atoi(os.Getenv(envTCPBytes))
	if err != nil {
		t.Fatalf("stream size: %v", err)
	}

	c, err := net.DialTimeout("tcp", target.String(), 30*time.Second)
	if err != nil {
		t.Fatalf("dialing %v over the overlay: %v", target, err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(90 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	// The pattern is position modulo 256, and the block length is a multiple
	// of 256, so the expected byte at any offset is that offset's low byte —
	// which is what makes the check below a one-liner.
	block := make([]byte, 32*1024)
	for i := range block {
		block[i] = byte(i)
	}
	go func() {
		for sent := 0; sent < size; {
			n := min(len(block), size-sent)
			if _, err := c.Write(block[:n]); err != nil {
				return
			}
			sent += n
		}
		c.(*net.TCPConn).CloseWrite()
	}()

	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("reading the echo back after %d of %d bytes: %v", len(got), size, err)
	}
	if len(got) != size {
		t.Fatalf("echoed %d bytes, want %d", len(got), size)
	}
	for i, b := range got {
		if b != byte(i) {
			t.Fatalf("byte %d of the stream came back as %d, want %d", i, b, byte(i))
		}
	}
}

// say writes one protocol line to the lab.
func say(format string, args ...any) {
	fmt.Printf(protoPrefix+format+"\n", args...)
}

// TestHelperNetnsRPFilter says what [StrictRP6] makes of its namespace's
// ruleset.
func TestHelperNetnsRPFilter(t *testing.T) {
	if os.Getenv(netnsHelperEnv) != "rpfilter" {
		t.Skip("not a netns reverse-path helper invocation")
	}
	strict, err := StrictRP6()
	say("RPFILTER %v %v", strict, err)
}

// passOn joins what ln accepts to target, as a service member or an ingress
// passes a connection on.
func passOn(ln net.Listener, target string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			d, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				return
			}
			pipe.Join(context.Background(), c, d, time.Minute)
		}()
	}
}

func mustAtoi(t *testing.T, s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A heldStream is one TCP connection kept streaming to an echo server across
// whatever the lab changes meanwhile: how much came back, the longest wait
// for any of it, and what ended it, if anything did.
type heldStream struct {
	mu     sync.Mutex
	echoed int64
	gap    time.Duration
	last   time.Time
	err    error
}

// startStream dials to and writes 16 KiB every 10 ms, checking the echo.
func startStream(t *testing.T, to string) *heldStream {
	c, err := net.DialTimeout("tcp", to, 30*time.Second)
	if err != nil {
		t.Fatalf("STREAM: dialing %s: %v", to, err)
	}
	h := &heldStream{last: time.Now()}
	block := make([]byte, 16*1024)
	for i := range block {
		block[i] = byte(i)
	}
	go func() {
		for {
			if _, err := c.Write(block); err != nil {
				h.end(fmt.Errorf("writing: %w", err))
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	go func() {
		buf := make([]byte, 64*1024)
		var off int64
		for {
			n, err := c.Read(buf)
			for i := range n {
				if buf[i] != byte(off+int64(i)) {
					h.end(fmt.Errorf("byte %d came back as %d", off+int64(i), buf[i]))
					return
				}
			}
			off += int64(n)
			h.read(n)
			if err != nil {
				h.end(fmt.Errorf("reading: %w", err))
				return
			}
		}
	}()
	return h
}

func (h *heldStream) read(n int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	h.gap = max(h.gap, now.Sub(h.last))
	h.last = now
	h.echoed += int64(n)
}

func (h *heldStream) end(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.err == nil {
		h.err = err
	}
}

// stat is the stream's bytes echoed, its longest wait in milliseconds, the
// current wait included, and what ended it, "-" for nothing.
func (h *heldStream) stat() string {
	if h == nil {
		return "0 0 no-stream"
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	gap := max(h.gap, time.Since(h.last))
	why := "-"
	if h.err != nil {
		why = strings.ReplaceAll(h.err.Error(), " ", "_")
	}
	return fmt.Sprintf("%d %d %s", h.echoed, gap.Milliseconds(), why)
}

// testGroup is where the lab's group datagrams go: mDNS's group, on a port
// of its own.
var testGroup = netip.MustParseAddrPort("224.0.0.251:45353")

// A groupListener records the group datagrams a device delivers, each as
// source/size.
type groupListener struct {
	c    *net.UDPConn
	mu   sync.Mutex
	seen []string
}

func joinGroup(dev string) (*groupListener, error) {
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(testGroup.Port())})
	if err != nil {
		return nil, err
	}
	if err := ipv4.NewPacketConn(c).JoinGroup(ifi, &net.UDPAddr{IP: testGroup.Addr().AsSlice()}); err != nil {
		c.Close()
		return nil, err
	}
	l := &groupListener{c: c}
	go func() {
		b := make([]byte, 1<<16)
		for {
			n, from, err := c.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			l.mu.Lock()
			l.seen = append(l.seen, fmt.Sprintf("%v/%d", from.Addr().Unmap(), n))
			l.mu.Unlock()
		}
	}()
	return l, nil
}

func (l *groupListener) heard() string {
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.seen, ",")
}

func (l *groupListener) close() { l.c.Close() }

// sendGroup sends size bytes to testGroup on dev, as mDNS does: TTL 255.
func sendGroup(dev string, size int) error {
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		return err
	}
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return err
	}
	defer c.Close()
	p := ipv4.NewPacketConn(c)
	if err := p.SetMulticastInterface(ifi); err != nil {
		return err
	}
	if err := p.SetMulticastTTL(255); err != nil {
		return err
	}
	_, err = c.WriteToUDPAddrPort(make([]byte, size), testGroup)
	return err
}
