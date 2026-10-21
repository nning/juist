package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/types/key"

	"github.com/nning/juist/internal/nettest"
	"github.com/nning/juist/relay/forward"
)

// held waits for the relay to hold exactly n connections.
func held(t *testing.T, s *Server, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for s.pending.Len() != n {
		if time.Now().After(deadline) {
			t.Fatalf("the relay holds %d connections, want %d", s.pending.Len(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func dialRelay(t *testing.T, s *Server) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", s.localAddrs()[0].String())
	if err != nil {
		t.Fatalf("dialing the relay: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// closedByRelay reports whether the relay closed c rather than leaving it
// waiting for a request.
func closedByRelay(t *testing.T, c net.Conn, within time.Duration) bool {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(within))
	_, err := c.Read(make([]byte, 1))
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	if err == nil {
		t.Fatal("the relay said something to a connection that asked nothing")
	}
	return true
}

func withBounds(t *testing.T, total, perSite int) {
	oldTotal, oldPer := maxPending, maxPendingPerSite
	maxPending, maxPendingPerSite = total, perSite
	t.Cleanup(func() { maxPending, maxPendingPerSite = oldTotal, oldPer })
}

// TestRelayCapsConnectionsFromOneSite: a site that opens connections and
// says nothing holds no more than its bound, a newcomer closing its oldest,
// and one it closes is given back.
func TestRelayCapsConnectionsFromOneSite(t *testing.T) {
	withBounds(t, 100, 4)
	s := testRelay(t, nil)
	var first []net.Conn
	for range 4 {
		first = append(first, dialRelay(t, s))
		held(t, s, len(first))
	}
	fifth := dialRelay(t, s)
	if !closedByRelay(t, first[0], 5*time.Second) {
		t.Fatal("a site's oldest connection was kept past its bound")
	}
	held(t, s, 4)
	for _, c := range append(first[1:], fifth) {
		if closedByRelay(t, c, 50*time.Millisecond) {
			t.Fatal("a connection within the bound was closed")
		}
	}
	first[1].Close()
	held(t, s, 3)
}

// TestASitesConnectionsKeepNoMemberOfItOut: strangers holding a site's
// every slot do not keep a member from that site from its session.
func TestASitesConnectionsKeepNoMemberOfItOut(t *testing.T) {
	onLoopback(t, "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5")
	withBounds(t, 100, 4)
	member := key.NewNode()
	s := testRelay(t, map[key.NodePublic]bool{member.Public(): true})
	for i := range 4 {
		dialFrom(t, s, fmt.Sprintf("127.0.0.%d", 2+i))
	}
	held(t, s, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admitted(ctx, t, testClient(t, s, member))
}

// TestRelayCapsConnectionsInAll: past the bound in all, where one source's
// does not reach, a newcomer closes the oldest connection held.
func TestRelayCapsConnectionsInAll(t *testing.T) {
	withBounds(t, 3, 100)
	s := testRelay(t, nil)
	oldest := dialRelay(t, s)
	held(t, s, 1)
	for range 2 {
		dialRelay(t, s)
	}
	held(t, s, 3)
	newest := dialRelay(t, s)
	if !closedByRelay(t, oldest, 5*time.Second) {
		t.Fatal("the oldest connection was kept past the bound in all")
	}
	held(t, s, 3)
	if closedByRelay(t, newest, 200*time.Millisecond) {
		t.Fatal("the newcomer was closed rather than the oldest")
	}
}

// TestConnectionsHeldOpenKeepNoMemberOut: strangers holding every slot by
// keeping their connections alive do not keep a member from its session.
func TestConnectionsHeldOpenKeepNoMemberOut(t *testing.T) {
	withBounds(t, 3, 100)
	member := key.NewNode()
	s := testRelay(t, map[key.NodePublic]bool{member.Public(): true})
	for range 3 {
		dialRelay(t, s)
	}
	held(t, s, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admitted(ctx, t, testClient(t, s, member))
}

// admitted connects c and waits for the server info a relay sends once it
// has admitted the session.
func admitted(ctx context.Context, t *testing.T, c *derphttp.Client) {
	t.Helper()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connecting: %v", err)
	}
	m, err := c.Recv()
	if err != nil {
		t.Fatalf("waiting for admission: %v", err)
	}
	if _, ok := m.(derp.ServerInfoMessage); !ok {
		t.Fatalf("first message %T, want the server info", m)
	}
}

// TestRelayClosesTheOldestSessionOfAKey: a member that opens DERP sessions
// under one key keeps maxSessionsPerKey of them, the newest; another member
// is not affected.
func TestRelayClosesTheOldestSessionOfAKey(t *testing.T) {
	flooder, other := key.NewNode(), key.NewNode()
	s := testRelay(t, map[key.NodePublic]bool{flooder.Public(): true, other.Public(): true})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	o := testClient(t, s, other)
	admitted(ctx, t, o)
	oldest := testClient(t, s, flooder)
	admitted(ctx, t, oldest)
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		for {
			if _, err := oldest.Recv(); err != nil {
				return
			}
		}
	}()
	for range maxSessionsPerKey {
		admitted(ctx, t, testClient(t, s, flooder))
	}
	select {
	case <-ended:
	case <-time.After(20 * time.Second):
		t.Fatal("the oldest session of a key past the bound was kept")
	}
	waitClients(t, s, 1+maxSessionsPerKey)
	if n := s.sessions.Count(flooder.Public()); n != maxSessionsPerKey {
		t.Fatalf("%d sessions counted under one key, want %d", n, maxSessionsPerKey)
	}
	if err := o.Send(flooder.Public(), []byte("still here")); err != nil {
		t.Fatalf("the other member lost its session: %v", err)
	}
}

// TestAdmittedSessionsLeaveTheSourceBound: members behind one address, as
// behind one proxy, are not bounded as a stranger's connections are.
func TestAdmittedSessionsLeaveTheSourceBound(t *testing.T) {
	withBounds(t, 100, 2)
	members := map[key.NodePublic]bool{}
	var keys []key.NodePrivate
	for range 5 {
		k := key.NewNode()
		keys, members[k.Public()] = append(keys, k), true
	}
	s := testRelay(t, members)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, k := range keys {
		admitted(ctx, t, testClient(t, s, k))
	}
	held(t, s, 0)
	waitClients(t, s, len(keys))
	for range 2 {
		dialRelay(t, s)
	}
	held(t, s, 2)
}

// TestAWaitingHostLeavesTheBoundInAll: a member's connection waiting for an
// invite's guest is the forwarder's to bound once it registered, so a flood
// of strangers' connections does not close it.
func TestAWaitingHostLeavesTheBoundInAll(t *testing.T) {
	withBounds(t, 2, 100)
	host := newMember(t)
	s, r := forwardRelay(t, func(id [32]byte) bool { return id == host.pub })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	id := [16]byte{9}
	waited := make(chan error, 1)
	go func() {
		c, _, err := forward.Wait(ctx, r, id, host.pub, host.sign)
		if c != nil {
			defer c.Close()
		}
		waited <- err
	}()
	deadline := time.Now().Add(10 * time.Second)
	for s.fwd.waitingIDs() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the host's registration did not land")
		}
		time.Sleep(5 * time.Millisecond)
	}
	held(t, s, 0)
	for range 3 {
		dialRelay(t, s)
	}
	held(t, s, 2)
	g, err := guestFrom(r, id, "127.0.0.1")
	if err != nil {
		t.Fatalf("the guest did not reach the host past a flood: %v", err)
	}
	defer g.Close()
	if err := <-waited; err != nil {
		t.Fatalf("the host's wait: %v", err)
	}
}

// waitingIDs counts the invites waiting here.
func (f *forwarder) waitingIDs() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ids)
}

// TestHoldingRacesNoEviction: listeners taking connections at once, past
// the bound in all, evict one another's newest safely.
func TestHoldingRacesNoEviction(t *testing.T) {
	withBounds(t, 1, 1<<20)
	s := testRelay(t, nil)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 2000 {
				a, b := net.Pipe()
				s.hold(a)
				b.Close()
			}
		})
	}
	wg.Wait()
}

// onLoopback skips where the loopback device lacks one of addrs, as
// FreeBSD's does unless given them with ifconfig lo0 alias.
func onLoopback(t *testing.T, addrs ...string) {
	t.Helper()
	for _, a := range addrs {
		if !nettest.HasLoopbackAddr(netip.MustParseAddr(a)) {
			nettest.SkipUnlessRequired(t, "this host carries no %v on loopback", a)
		}
	}
}

func dialFrom(t *testing.T, s *Server, src string) net.Conn {
	t.Helper()
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
	c, err := d.Dial("tcp", s.localAddrs()[0].String())
	if err != nil {
		t.Fatalf("dialing the relay from %s: %v", src, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// TestTheBoundInAllClosesTheLargestSitesOldest: past the bound in all, the
// connection closed is the oldest of the site holding the most, so a flood
// from a few places displaces its own and not a member's lone connection.
func TestTheBoundInAllClosesTheLargestSitesOldest(t *testing.T) {
	manyLoopbacks(t)
	withBounds(t, 4, 100)
	s := testRelay(t, nil)
	lone := dialFrom(t, s, "127.0.4.1")
	held(t, s, 1)
	first := dialFrom(t, s, "127.0.0.1")
	held(t, s, 2)
	for range 2 {
		dialFrom(t, s, "127.0.0.1")
	}
	held(t, s, 4)
	dialFrom(t, s, "127.0.0.1")
	if !closedByRelay(t, first, 5*time.Second) {
		t.Fatal("the largest site's oldest connection was kept past the bound in all")
	}
	if closedByRelay(t, lone, 200*time.Millisecond) {
		t.Fatal("a lone connection from another site was closed for a flood")
	}
}

// TestAGuestTurnedAwayIsClosed: a guest the forwarder answers without
// taking its connection over, out of the relay's bounds once admitted to
// wait, is not kept open.
func TestAGuestTurnedAwayIsClosed(t *testing.T) {
	host := newMember(t)
	s, r := forwardRelay(t, func(id [32]byte) bool { return id == host.pub })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id := [16]byte{3}
	waited := make(chan net.Conn, 1)
	go func() {
		c, _, _ := forward.Wait(ctx, r, id, host.pub, host.sign)
		waited <- c
	}()
	var g net.Conn
	var err error
	for range 50 {
		if g, err = guestFrom(r, id, "127.0.0.1"); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("the first guest did not reach the host: %v", err)
	}
	defer g.Close()
	if h := <-waited; h != nil {
		defer h.Close()
	}
	held(t, s, 0)
	raw, err := net.Dial("tcp", r.Addrs[0].String())
	if err != nil {
		t.Fatal(err)
	}
	c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(25 * time.Second))
	req := "GET " + forward.GuestPath + hex.EncodeToString(id[:]) + " HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\n" +
		"Upgrade: " + forward.Upgrade + "\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatal("a second guest was joined to a host that waits no more")
	}
	if !resp.Close {
		t.Error("a guest turned away was not told the connection ends")
	}
	if !closedByRelay(t, c, 5*time.Second) {
		t.Fatal("a guest turned away was kept open")
	}
	held(t, s, 0)
}

// TestAGuestWithABodyStaysBounded: a guest's request declaring a body, which
// net/http reads to its end after the answer without a deadline, is refused
// while it still counts against the relay's bounds.
func TestAGuestWithABodyStaysBounded(t *testing.T) {
	host := newMember(t)
	s, r := forwardRelay(t, func(id [32]byte) bool { return id == host.pub })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id := [16]byte{4}
	go func() {
		if c, _, err := forward.Wait(ctx, r, id, host.pub, host.sign); err == nil {
			<-ctx.Done()
			c.Close()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for s.fwd.waitingIDs() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the host's registration did not land")
		}
		time.Sleep(5 * time.Millisecond)
	}
	held(t, s, 0)
	raw, err := net.Dial("tcp", r.Addrs[0].String())
	if err != nil {
		t.Fatal(err)
	}
	c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(25 * time.Second))
	req := "POST " + forward.GuestPath + hex.EncodeToString(id[:]) + " HTTP/1.1\r\nHost: x\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a guest with a body was answered %d", resp.StatusCode)
	}
	if n := s.pending.Len(); n != 1 {
		t.Fatalf("a guest with a body left open counts %d against the bounds, want 1", n)
	}
	if s.fwd.waitingIDs() != 1 {
		t.Fatal("a guest with a body spent the host's waiting connection")
	}
}

// TestAStrangerInAMembersSiteDisplacesItsOwn: past a site's bound, another
// host there holding the most gives way, not a member's older connection.
func TestAStrangerInAMembersSiteDisplacesItsOwn(t *testing.T) {
	onLoopback(t, "127.0.0.2")
	withBounds(t, 100, 4)
	s := testRelay(t, nil)
	member := dialFrom(t, s, "127.0.0.1")
	held(t, s, 1)
	stranger := []net.Conn{dialFrom(t, s, "127.0.0.2")}
	held(t, s, 2)
	for range 3 {
		stranger = append(stranger, dialFrom(t, s, "127.0.0.2"))
	}
	if !closedByRelay(t, stranger[0], 5*time.Second) {
		t.Fatal("the stranger's oldest was kept past the site's bound")
	}
	if closedByRelay(t, member, 200*time.Millisecond) {
		t.Fatal("a member's connection was closed for a stranger in its site")
	}
}

// TestTheRelaySpeaksHTTP1Alone: a client offering HTTP/2 is not given it,
// since a stream there is out of reach of every bound a connection is held to.
func TestTheRelaySpeaksHTTP1Alone(t *testing.T) {
	s := testRelay(t, nil)
	c, err := tls.Dial("tcp", s.localAddrs()[0].String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if p := c.ConnectionState().NegotiatedProtocol; p == "h2" {
		t.Fatal("the relay negotiated HTTP/2")
	}
}
