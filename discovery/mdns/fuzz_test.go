package mdns

import (
	"net"
	"net/netip"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/keyring"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// sinkConn counts what a beacon sends and delivers nothing.
type sinkConn struct {
	mu   sync.Mutex
	sent int
}

func (c *sinkConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *sinkConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent++
	return len(b), nil
}
func (c *sinkConn) Close() error { return nil }

func (c *sinkConn) take() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.sent
	c.sent = 0
	return n
}

// FuzzBeaconHandle feeds a beacon datagrams as the multicast group would,
// from anyone on the LAN. Whatever arrives, it answers at most once per name
// it holds, and hands on only announcements that verify.
func FuzzBeaconHandle(f *testing.F) {
	s, err := secrets.NewSecret()
	if err != nil {
		f.Fatal(err)
	}
	kr := keyring.New()
	kr.Adopt(6, s)
	kr.Adopt(7, s)
	priv, err := types.GenerateIdentity()
	if err != nil {
		f.Fatal(err)
	}
	ep := gossip.Endpoint{Identity: priv.Public(), Disco: gossip.DiscoKey{4, 2}, GossipPort: 4001, Seq: 1, Schema: types.CurrentSchema,
		Addrs: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}}
	if err := ep.Sign(priv); err != nil {
		f.Fatal(err)
	}
	conn := &sinkConn{}
	var peers []gossip.Endpoint
	b, err := New(Options{
		Keyring:  kr,
		Announce: func() (gossip.Endpoint, bool) { return ep, true },
		OnPeer:   func(e gossip.Endpoint) { peers = append(peers, e) },
		Conn:     conn,
		Dst:      netip.MustParseAddrPort("224.0.0.251:5353"),
	})
	if err != nil {
		f.Fatal(err)
	}

	for _, epoch := range []uint64{6, 7} {
		query, err := (&dnsmessage.Message{Questions: []dnsmessage.Question{{
			Name: name(s, epoch).dns, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET,
		}}}).Pack()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(query)
		answer, err := b.answerFor(name(s, epoch))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(answer)
	}
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, raw []byte) {
		peers = peers[:0]
		// Clear the rate gate, so every input may be answered: the bound
		// asserted is per datagram.
		b.mu.Lock()
		clear(b.lastSent)
		b.mu.Unlock()
		b.handle(raw)
		if n := conn.take(); n > len(kr.Epochs()) {
			t.Fatalf("one datagram drew %d answers from a beacon holding %d names", n, len(kr.Epochs()))
		}
		for _, e := range peers {
			if err := e.Verify(); err != nil {
				t.Fatalf("handed on an announcement that does not verify: %v", err)
			}
		}
	})
}

// FuzzInviteMessages feeds a guest's answer parser and a host's question
// matcher what any device on the LAN may send. An answer that is taken names
// a 16-character id and a non-zero port.
func FuzzInviteMessages(f *testing.F) {
	n, err := inviteName(42)
	if err != nil {
		f.Fatal(err)
	}
	answer, err := txtAnswer(n, []string{"port=41642", "id=0123456789abcdef"})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(answer)
	query, err := (&dnsmessage.Message{Questions: []dnsmessage.Question{{
		Name: n, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET,
	}}}).Pack()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(query)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, raw []byte) {
		asksFor(raw, n)
		id, port, ok := parseInviteAnswer(raw, n)
		if ok && (len(id) != 16 || port == 0) {
			t.Fatalf("took an answer naming id %q and port %d", id, port)
		}
	})
}
