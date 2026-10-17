package conn

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/net/stun"
)

// stunCounter is a STUN server on this host's address that answers every
// binding request and counts them.
type stunCounter struct {
	pc   *net.UDPConn
	seen atomic.Int64

	mu     sync.Mutex
	byPort map[uint16]int
}

func newSTUNCounter(t *testing.T) *stunCounter {
	t.Helper()
	pc, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(hostAddr(t), 0)))
	if err != nil {
		t.Fatal(err)
	}
	s := &stunCounter{pc: pc, byPort: map[uint16]int{}}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			tx, err := stun.ParseBindingRequest(buf[:n])
			if err != nil {
				continue
			}
			s.seen.Add(1)
			s.mu.Lock()
			s.byPort[from.Port()]++
			s.mu.Unlock()
			pc.WriteToUDPAddrPort(stun.Response(tx, from), from)
		}
	}()
	return s
}

func (s *stunCounter) addr() string { return s.pc.LocalAddr().String() }

// from is how many requests came from port.
func (s *stunCounter) from(port uint16) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byPort[port]
}

// TestAnIdleNodeWithoutARelayStopsAskingSTUN: with STUN servers and no member
// relay, the engine took a STUN server for its home and asked again every few
// seconds as it failed to connect, which kept a phone's radio awake.
func TestAnIdleNodeWithoutARelayStopsAskingSTUN(t *testing.T) {
	t.Parallel()
	srv := newSTUNCounter(t)
	withSTUN := func(o *Options) { o.STUN = []string{srv.addr()} }
	a := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", withSTUN)
	b := startNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128", withSTUN)
	for _, n := range []*node{a, b} {
		if err := n.mgr.SetPeers([]Peer{a.peer(), b.peer()}); err != nil {
			t.Fatal(err)
		}
	}
	for deadline := time.Now().Add(10 * time.Second); srv.seen.Load() == 0; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no STUN request")
		}
	}
	time.Sleep(3 * time.Second)
	before := srv.seen.Load()
	const window = 20 * time.Second
	time.Sleep(window)
	// Two nodes, each with at most one netcheck of a few requests in the window.
	if asked := srv.seen.Load() - before; asked > 8 {
		t.Errorf("%d STUN requests from two idle nodes in %v", asked, window)
	}
	for _, n := range []*node{a, b} {
		if eps := n.mgr.(*tsManager).LocalEndpoints(); len(eps) == 0 {
			t.Errorf("node %d knows no endpoint of its own", n.id)
		}
	}
}

// TestASavingNodeAsksNoSTUNThoughProbed: a peer's probes keep a node's
// tunnel active, which would have it ask STUN every 25 s while saving.
func TestASavingNodeAsksNoSTUNThoughProbed(t *testing.T) {
	t.Parallel()
	srv := newSTUNCounter(t)
	withSTUN := func(o *Options) { o.STUN = []string{srv.addr()} }
	a := startNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", withSTUN)
	b := startNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128", withSTUN)
	for _, n := range []*node{a, b} {
		if err := n.mgr.SetPeers([]Peer{a.peer(), b.peer()}); err != nil {
			t.Fatal(err)
		}
	}
	a.mgr.(*tsManager).SetSaving(true)
	if _, ok := pingUntil(t, b, a.pingAddr(), 10*time.Second); !ok {
		t.Fatal("no answer from the saving node")
	}
	before := srv.from(a.mgr.LocalPort())
	for end := time.Now().Add(2*stunEvery + 5*time.Second); time.Now().Before(end); time.Sleep(2 * time.Second) {
		ping(t, b, a.pingAddr(), time.Second)
	}
	if asked := srv.from(a.mgr.LocalPort()) - before; asked > 0 {
		t.Errorf("the saving node asked STUN %d times while probed", asked)
	}
}
