package conn

import (
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/relay"
	"tailscale.com/net/netcheck"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// wgKey is n's public key as a relay names its clients.
func wgKey(n *node) (k [32]byte) {
	copy(k[:], n.nodeKey.Public().AppendTo(nil))
	return k
}

// sameHome is the home mapping of a node that is not walled.
func sameHome(r int) int { return r }

// slowProxy forwards TCP to target, holding each chunk back by delay, so a
// relay reached through it is measured as far.
func slowProxy(t *testing.T, target netip.AddrPort, delay time.Duration) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp4", net.JoinHostPort(hostAddr(t).String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	pipe := func(dst, src net.Conn) {
		defer dst.Close()
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				time.Sleep(delay)
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				up, err := net.Dial("tcp", target.String())
				if err != nil {
					c.Close()
					return
				}
				go pipe(up, c)
				pipe(c, up)
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

// deadTCP is a TCP port on this host's address nothing listens at.
func deadTCP(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp4", net.JoinHostPort(hostAddr(t).String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	ap := netip.MustParseAddrPort(ln.Addr().String())
	ln.Close()
	return ap
}

// relayAt is s as region, reached at addr, with no STUN, which netcheck then
// measures by HTTPS alone, as on a network passing TCP alone.
func relayAt(s *relay.Server, region int, addr netip.AddrPort) Relay {
	return Relay{Region: region, HostName: s.HostName(), Addrs: []netip.AddrPort{addr}, CertHash: s.CertHash()}
}

// homeOf is the region n's data plane sends to p at.
func homeOf(n *node, p *node) int {
	return int(n.mgr.(*tsManager).state.Load().nodes[p.nodeKey.Public()].HomeDERP())
}

// A node that reaches one relay by TCP alone and not another is walled, and
// sends to a peer homed at the other at its own home; once it reaches that
// relay again it sends there.
func TestAWalledNodeSendsToItsOwnHome(t *testing.T) {
	t.Parallel()
	r8, r9 := startRelay(t, 0), startRelay(t, 0)
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	p := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	q := newNode(t, 3, "100.64.0.3/32", "fd7a:115c:a1e0::3/128")
	m := a.mgr.(*tsManager)
	live8 := relayAt(r8, 8, netip.AddrPortFrom(hostAddr(t), r8.Port()))
	if err := a.mgr.SetRelays([]Relay{live8, relayAt(r9, 9, deadTCP(t))}); err != nil {
		t.Fatal(err)
	}
	atP, atQ := p.peer(), q.peer()
	atP.Endpoints, atQ.Endpoints = nil, nil
	atP.HomeRelay, atQ.HomeRelay = 9, 8
	if err := a.mgr.SetPeers([]Peer{atP, atQ}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 45*time.Second, "a walled node homed at the relay it reaches", func() bool {
		return a.mgr.HomeRelay() == 8 && a.mgr.Walled()
	})
	if got := homeOf(a, p); got != 8 {
		t.Errorf("a peer homed at the relay out of reach is sent to at %d, want this node's home", got)
	}
	if got := homeOf(a, q); got != 8 {
		t.Errorf("a peer homed at this node's home is sent to at %d", got)
	}
	if got := m.state.Load().peers[p.nodeKey.Public()].HomeRelay; got != 9 {
		t.Errorf("the peer's own home reads %d, want what it announced", got)
	}

	if err := a.mgr.SetRelays([]Relay{live8, relayAt(r9, 9, netip.AddrPortFrom(hostAddr(t), r9.Port()))}); err != nil {
		t.Fatal(err)
	}
	// Within a report or two, not at the next look the walls take on their own.
	waitUntil(t, meetEvery/2, "the walls gone once every relay is reached", func() bool {
		return !a.mgr.Walled() && homeOf(a, p) == 9
	})
}

// meetAlwaysDERP marks the run of TestWalledNodesMeetAtAHome in a process
// whose data plane sends no UDP, so that no direct path forms beside the
// relays: magicsock reads the knob once per process.
const meetAlwaysDERP = "TS_DEBUG_ALWAYS_USE_DERP"

// A walled node and a member homed where it does not reach meet at the
// walled node's home: the member keeps its connection there, past the 60 s
// magicsock keeps an idle one, so the walled node reaches it first; one that
// keeps none is reached once it sends, and the home says it is not there
// until then.
func TestWalledNodesMeetAtAHome(t *testing.T) {
	if os.Getenv(meetAlwaysDERP) == "" {
		t.Parallel()
		cmd := exec.Command(os.Args[0], "-test.run", "^TestWalledNodesMeetAtAHome$", "-test.count", "1", "-test.v")
		cmd.Env = append(os.Environ(), meetAlwaysDERP+"=true")
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "\nmeeting: passed\n") {
			t.Fatalf("%v\n%s", err, out)
		}
		return
	}
	// With UDP off, magicsock's sockets never return from a read, so Close
	// hangs: the process exits before the cleanups.
	defer func() {
		if t.Failed() {
			fmt.Println("\nmeeting: failed")
			os.Exit(1)
		}
		fmt.Println("\nmeeting: passed")
		os.Exit(0)
	}()
	r8, r9 := startRelay(t, 0), startRelay(t, 0)
	at8, at9 := netip.AddrPortFrom(hostAddr(t), r8.Port()), netip.AddrPortFrom(hostAddr(t), r9.Port())
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	keeps := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	rests := newNode(t, 3, "100.64.0.3/32", "fd7a:115c:a1e0::3/128")
	if err := a.mgr.SetRelays([]Relay{relayAt(r8, 8, at8), relayAt(r9, 9, deadTCP(t))}); err != nil {
		t.Fatal(err)
	}
	// The members reach both, 8 far enough that they home at 9.
	slow8 := slowProxy(t, at8, 50*time.Millisecond)
	for _, b := range []*node{keeps, rests} {
		if err := b.mgr.SetRelays([]Relay{relayAt(r8, 8, slow8), relayAt(r9, 9, at9)}); err != nil {
			t.Fatal(err)
		}
	}
	waitUntil(t, 45*time.Second, "homes at 8 for the walled node and 9 for the members", func() bool {
		return a.mgr.HomeRelay() == 8 && a.mgr.Walled() &&
			keeps.mgr.HomeRelay() == 9 && !keeps.mgr.Walled() && rests.mgr.HomeRelay() == 9 && !rests.mgr.Walled()
	})
	bare := func(n *node, home int, walled bool) Peer {
		p := n.peer()
		p.Endpoints, p.HomeRelay, p.Walled = nil, home, walled
		return p
	}
	rests.mgr.SetSaving(true)
	if err := a.mgr.SetPeers([]Peer{bare(keeps, 9, false), bare(rests, 9, false)}); err != nil {
		t.Fatal(err)
	}
	if err := keeps.mgr.SetPeers([]Peer{bare(a, 8, true)}); err != nil {
		t.Fatal(err)
	}
	if err := rests.mgr.SetPeers([]Peer{bare(a, 8, true)}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 30*time.Second, "the members connected to the walled node's home", func() bool {
		return r8.Connected(wgKey(keeps)) && r8.Connected(wgKey(rests))
	})
	// Past the 60 s after the last write magicsock closes an idle
	// connection at, checking every 15 s.
	time.Sleep(90 * time.Second)
	idle := time.Now()
	if !r8.Connected(wgKey(keeps)) || r8.Connected(wgKey(rests)) {
		t.Fatalf("connected to the walled node's home: keeping %v, saving %v; want the keeping member alone",
			r8.Connected(wgKey(keeps)), r8.Connected(wgKey(rests)))
	}
	if _, ok := pingUntil(t, a, keeps.pingAddr(), 20*time.Second); !ok {
		t.Fatal("the walled node did not reach the member keeping its connection first")
	}
	if _, ok := pingUntil(t, keeps, a.pingAddr(), 20*time.Second); !ok {
		t.Fatal("the member did not reach the walled node")
	}

	if _, ok := ping(t, a, rests.pingAddr(), 3*time.Second); ok {
		t.Fatal("the walled node reached a member keeping no connection first")
	}
	waitUntil(t, 10*time.Second, "the home saying the resting member is not there", func() bool {
		_, gone := a.mgr.NotAtHome()[rests.id]
		return gone
	})
	if at, gone := a.mgr.NotAtHome()[keeps.id]; gone && at.After(idle) {
		t.Error("the home said the keeping member is not there")
	}
	if _, ok := pingUntil(t, rests, a.pingAddr(), 20*time.Second); !ok {
		t.Fatal("the resting member did not reach the walled node")
	}
	if _, ok := pingUntil(t, a, rests.pingAddr(), 20*time.Second); !ok {
		t.Fatal("the walled node did not reach the resting member once it sent")
	}
}

// noteNotHere reads magicsock's line for a relay saying a peer is not there,
// at this node's home alone.
func TestNotAtHomeReadsTheRelaysLine(t *testing.T) {
	a := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	b := newNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	m := a.mgr.(*tsManager)
	if err := a.mgr.SetPeers([]Peer{b.peer()}); err != nil {
		t.Fatal(err)
	}
	m.homeRelay.Store(8)
	m.logf(derpNotHere, tailcfg.DERPRegionID(9), b.nodeKey.Public().ShortString())
	if len(a.mgr.NotAtHome()) != 0 {
		t.Error("another relay's answer was taken for the home's")
	}
	m.logf(derpNotHere, tailcfg.DERPRegionID(8), key.NewNode().Public().ShortString())
	m.logf(derpNotHere, tailcfg.DERPRegionID(8), b.nodeKey.Public().ShortString())
	if got := a.mgr.NotAtHome(); len(got) != 1 || got[b.id].IsZero() {
		t.Errorf("not at home: %v, want the peer alone", got)
	}
}

// A report without UDP measures the relays by HTTPS, and by ICMP too where
// it may ping, which says nothing of a relay's own port: then a relay counts
// reached by its name on 443 alone.
func TestARelayPingedIsNotReachedByItsPort(t *testing.T) {
	named := func(region int) Relay { r := namedRelay(); r.Region = region; return r }
	plain := testRelay()
	plain.Region = 9
	relays := []Relay{named(8), plain, named(10)}
	ms := map[tailcfg.DERPRegionID]time.Duration{8: time.Millisecond, 9: time.Millisecond, 10: time.Millisecond}
	for _, c := range []struct {
		name string
		r    *netcheck.Report
		want []int
		ok   bool
	}{
		{"UDP", &netcheck.Report{UDP: true, RegionLatency: ms}, nil, true},
		{"HTTPS reaching all", &netcheck.Report{RegionLatency: ms}, nil, true},
		{"HTTPS reaching the home", &netcheck.Report{RegionLatency: map[tailcfg.DERPRegionID]time.Duration{8: 1}}, []int{9, 10}, true},
		{"ICMP", &netcheck.Report{ICMPv4: true, RegionLatency: ms}, []int{9}, true},
		{"nothing measured", &netcheck.Report{}, nil, false},
	} {
		got, ok := unreachedIn(relays, 8, c.r, false)
		if ok != c.ok || !slices.Equal(slices.Sorted(maps.Keys(got)), c.want) {
			t.Errorf("%s: unreached %v, %v; want %v, %v", c.name, got, ok, c.want, c.ok)
		}
	}
	if got, _ := unreachedIn(relays, 8, &netcheck.Report{UDP: true, RegionLatency: map[tailcfg.DERPRegionID]time.Duration{8: 1}},
		true); len(got) != 2 {
		t.Errorf("HTTPS alone with UDP in the report: unreached %v", got)
	}
}

// With the name first, a relay's name in DNS comes before its addresses,
// which stay among the first three nodes netcheck sends STUN to.
func TestANameFirstComesBeforeTheRelaysPort(t *testing.T) {
	dm, _ := derpMap([]Relay{namedRelay()}, nil, false, true, Networks{})
	nodes := dm.Regions[7].Nodes
	if len(nodes) != 6 || nodes[0].HostName != "relay.example.org" || nodes[0].IPv4 != "" || nodes[0].DERPPort != 443 {
		t.Fatalf("nodes %+v, want the name in DNS first", nodes)
	}
	if nodes[1].DERPPort != 4443 || nodes[1].STUNPort != 4443 || nodes[2].DERPPort != 4443 {
		t.Errorf("the relay's own port is not second and third: %+v", nodes[1:3])
	}
	plain := testRelay()
	if dm, _ := derpMap([]Relay{plain}, nil, false, true, Networks{}); dm.Regions[7].Nodes[0].DERPPort != 4443 {
		t.Error("a relay without a name lost its port first")
	}
}

// Names come first after two reports in a row without UDP that reached no
// relay, as in a network passing 443 alone, whose own ports cost netcheck its
// time, homed or not; one alone, as after a link change, moves nothing; the
// ports again once UDP is back.
func TestNamesComeFirstWhereNoRelayWasReached(t *testing.T) {
	relays := []Relay{namedRelay()}
	none := &netcheck.Report{}
	reached := &netcheck.Report{RegionLatency: map[tailcfg.DERPRegionID]time.Duration{7: time.Millisecond}}
	udp := &netcheck.Report{UDP: true, RegionLatency: reached.RegionLatency}
	blind := 0
	step := func(r *netcheck.Report, was bool) bool {
		blind = blindAfter(r, relays, was, blind)
		return nameFirstAfter(r, false, blind, was)
	}
	if step(none, false) {
		t.Error("one report reaching nothing put names first")
	}
	if !step(none, false) {
		t.Error("two reports reaching nothing did not put names first")
	}
	if !step(reached, true) || blind != 0 {
		t.Errorf("a relay reached by name put the ports first, or left %d blind", blind)
	}
	if step(udp, true) {
		t.Error("UDP back kept names first")
	}
	if nameFirstAfter(none, true, 5, false) {
		t.Error("names first on HTTPS alone, whose map holds names alone")
	}
	if blindAfter(none, []Relay{testRelay()}, false, 3) != 0 {
		t.Error("counted blind without a name to put first")
	}
	pinged := &netcheck.Report{ICMPv4: true, RegionLatency: reached.RegionLatency}
	if blindAfter(pinged, relays, false, 1) != 2 {
		t.Error("a relay pinged, its port first, counted as reached by HTTPS")
	}
	if blindAfter(pinged, relays, true, 1) != 0 {
		t.Error("a named relay measured, its name first and unpinged, did not count as reached")
	}
}

// A relay is out of reach once two reports in a row missed it, as one may
// miss a far relay in the time netcheck leaves HTTPS, and a report reaching
// it, or UDP, ends that; each report counts once, however often it is read,
// and one that measured nothing leaves what was. A relay new to the map has
// missed no report.
func TestWallsNeedTwoReportsInARow(t *testing.T) {
	named, plain := namedRelay(), testRelay()
	plain.Region = 9
	relays := []Relay{named, plain}
	lat := func(regions ...int) *netcheck.Report {
		r := &netcheck.Report{RegionLatency: map[tailcfg.DERPRegionID]time.Duration{}}
		for _, id := range regions {
			r.RegionLatency[tailcfg.DERPRegionID(id)] = time.Millisecond
		}
		return r
	}
	var w walls
	look := func(r *netcheck.Report) map[int]bool {
		w.follow(r, relays, 7, false)
		w.follow(r, relays, 7, false)
		return w.unreachedAt(relays, 7, false)
	}
	if u := look(lat(7)); u != nil || !w.undecided(relays, 7, false) {
		t.Fatalf("one report missing relay 9 walled the node (%v), or left nothing to decide", u)
	}
	if u := look(lat(7)); !u[9] || len(u) != 1 || w.undecided(relays, 7, false) {
		t.Fatalf("two reports missing relay 9 left %v out of reach, undecided %v", u, w.undecided(relays, 7, false))
	}
	if u := look(&netcheck.Report{}); !u[9] {
		t.Errorf("a report that measured nothing changed the walls to %v", u)
	}
	if !w.undecided(relays, 7, false) {
		t.Error("one report reaching no relay leaves nothing to decide, where names may come first")
	}
	if u := look(lat(7, 9)); u != nil {
		t.Errorf("relay 9 reached left %v out of reach", u)
	}
	look(lat(7))
	if u := look(&netcheck.Report{UDP: true, RegionLatency: lat(7).RegionLatency}); u != nil {
		t.Errorf("UDP left %v out of reach", u)
	}
	if u := w.unreachedAt(relays, 0, false); u != nil {
		t.Errorf("a homeless node is walled off %v", u)
	}
	fresh := testRelay()
	fresh.Region = 10
	w = walls{}
	look(lat(7))
	look(lat(7))
	relays = append(relays, fresh)
	if u := w.unreachedAt(relays, 7, false); u[10] {
		t.Error("a relay new to the map is out of reach before a report missed it")
	}
	var homeless walls
	report := lat(7)
	homeless.follow(report, relays, 0, false)
	if !homeless.follow(report, relays, 7, false) || homeless.follow(report, relays, 7, false) {
		t.Error("the report a home came after is not counted again, once, with it")
	}
	if !homeless.undecided(relays, 7, false) || homeless.blind != 0 {
		t.Errorf("the report before the home asks no other, or counted blind %d", homeless.blind)
	}
	var https walls
	https.follow(lat(7), relays, 7, true)
	if u := https.unreachedAt(relays, 7, true); !u[9] || !u[10] {
		t.Errorf("on HTTPS alone, relays without a name, not in the map, are reached: %v", u)
	}
}

// A relay out of reach is reached by no measure, whatever ICMP said of it.
func TestARelayOutOfReachIsNotReached(t *testing.T) {
	var m tsManager
	m.homeRelay.Store(7)
	out := map[int]bool{9: true}
	m.walls.out.Store(&out)
	if m.ReachesRelay(9) {
		t.Error("a relay out of reach reads as reached")
	}
	if !m.ReachesRelay(7) {
		t.Error("the home reads as out of reach")
	}
}

// The meeting loop is kicked where the walled peers or their homes moved,
// not for every peer set, as each kick pings every walled peer.
func TestTheMeetingIsKickedForWalledPeersAlone(t *testing.T) {
	a, b := key.NewNode().Public(), key.NewNode().Public()
	walled := map[key.NodePublic]Peer{a: {Walled: true, HomeRelay: 7}, b: {HomeRelay: 8}}
	same := map[key.NodePublic]Peer{a: {Walled: true, HomeRelay: 7, Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}}, b: {HomeRelay: 9}}
	if walledMoved(walled, same) {
		t.Error("kicked where no walled peer moved")
	}
	moved := map[key.NodePublic]Peer{a: {Walled: true, HomeRelay: 8}, b: {HomeRelay: 8}}
	if !walledMoved(walled, moved) {
		t.Error("not kicked for a walled peer's new home")
	}
	if !walledMoved(walled, map[key.NodePublic]Peer{b: {HomeRelay: 8, Walled: true}}) {
		t.Error("not kicked for a new walled peer")
	}
}

// Another report is asked for once per report that left something
// undecided: none comes while the link is down, and asking every few
// seconds for one would cost a phone its battery.
func TestAReportIsAskedForOncePerReport(t *testing.T) {
	plain := testRelay()
	plain.Region = 9
	relays := []Relay{namedRelay(), plain}
	r := &netcheck.Report{RegionLatency: map[tailcfg.DERPRegionID]time.Duration{7: time.Millisecond}}
	var w walls
	w.follow(r, relays, 7, false)
	if w.askFor(relays, 7, false) {
		t.Error("asked for another report before waiting after this one")
	}
	if !w.waitFor(relays, 7, false) || !w.askFor(relays, 7, false) {
		t.Fatal("a report missing relay 9 once asks for no other")
	}
	if w.askFor(relays, 7, false) {
		t.Error("asked again with no report since, as while the link is down")
	}
	next := &netcheck.Report{RegionLatency: r.RegionLatency}
	w.follow(next, relays, 7, false)
	if w.askFor(relays, 7, false) {
		t.Error("asked again once the second miss decided it")
	}
	var homeless walls
	blind := &netcheck.Report{}
	homeless.follow(blind, relays, 0, false)
	if !homeless.waitFor(relays, 0, false) || !homeless.askFor(relays, 0, false) {
		t.Fatal("a report reaching no relay asks for no other")
	}
	homeless.follow(r, relays, 0, false)
	homeless.follow(r, relays, 7, false)
	if !homeless.waitFor(relays, 7, false) || !homeless.askFor(relays, 7, false) {
		t.Error("the report a home came after, missing relay 9, asks for no other")
	}
}
