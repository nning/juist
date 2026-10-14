package gossip

import (
	"net"
	"net/netip"
	"testing"

	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// A peer that takes the connection and says nothing failed otherwise than
// one whose address takes none, though the catch-up asked of it then finds
// none: only the latter is a firewall's doing.
func TestAConnectionThatSaysNothingIsNoFirewall(t *testing.T) {
	network := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	a := newTestNode(t, network, 3, s)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		// One connection, closed unanswered; the catch-up that follows
		// then finds no listener.
		c, err := ln.Accept()
		ln.Close()
		if err == nil {
			c.Close()
		}
	}()
	peer := newTestNode(t, network, 3, s)
	e, _ := peer.announce()
	e.Addrs, e.GossipPort = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.78:1")}, 1
	if err := e.Sign(peer.priv); err != nil {
		t.Fatal(err)
	}
	testAddrsMu.Lock()
	testAddrs[e.Addrs[0]] = netip.MustParseAddrPort(ln.Addr().String())
	testAddrsMu.Unlock()
	a.cache.Add(e)
	a.node.Sync(t.Context(), []types.Identity{peer.id})
	if got := a.node.Failed(peer.id); got != FailOther {
		t.Fatalf("a connection that says nothing reads as failure %d", got)
	}
	a.node.Sync(t.Context(), []types.Identity{peer.id})
	if got := a.node.Failed(peer.id); got != FailUnconnected {
		t.Fatalf("an address that takes no connection reads as failure %d", got)
	}
}

// A frame naming a field this build does not know reads as a newer build's,
// not as a connection that never came up.
func TestAFrameFromANewerBuildReadsAsNewer(t *testing.T) {
	type newer struct {
		frame
		Later uint64 `cbor:"30,keyasint"`
	}
	network := types.Hash{1}
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	a := newTestNode(t, network, 3, s)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if _, err := readBlob(c); err != nil {
			return
		}
		pt, err := encMode.Marshal(newer{frame: frame{Kind: kindHello, Network: network, Epoch: 3}, Later: 1})
		if err != nil {
			panic(err)
		}
		blob, err := seal(s, 3, pt)
		if err != nil {
			panic(err)
		}
		_ = writeBlob(c, blob, "hello")
		_, _ = readBlob(c)
	}()
	peer := newTestNode(t, network, 3, s)
	e, _ := peer.announce()
	e.Addrs, e.GossipPort = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.77:1")}, 1
	if err := e.Sign(peer.priv); err != nil {
		t.Fatal(err)
	}
	testAddrsMu.Lock()
	testAddrs[e.Addrs[0]] = netip.MustParseAddrPort(ln.Addr().String())
	testAddrsMu.Unlock()
	a.cache.Add(e)
	a.node.Sync(t.Context(), []types.Identity{peer.id})
	if got := a.node.Failed(peer.id); got != FailNewer {
		t.Fatalf("a newer build's frame reads as failure %d", got)
	}
}
