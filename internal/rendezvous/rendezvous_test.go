package rendezvous

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/net/stun"

	"github.com/nning/juist/trust/enroll"
)

func init() { loopbackMeetings = true }

// memStore is a DHT that forgets nothing and loses nothing.
type memStore struct {
	mu    sync.Mutex
	items map[[32]byte][]byte
}

func newMemStore() *memStore { return &memStore{items: map[[32]byte][]byte{}} }

func (m *memStore) Put(_ context.Context, seed [32]byte, v []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[seed] = bytes.Clone(v)
	return nil
}

func (m *memStore) Get(_ context.Context, seed [32]byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.items[seed]
	if !ok {
		return nil, errors.New("not found")
	}
	return bytes.Clone(v), nil
}

// stunServer answers binding requests on loopback, as a public server
// answers from the internet.
func stunServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
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
			_, _ = pc.WriteToUDPAddrPort(stun.Response(tx, from), from)
		}
	}()
	return pc.LocalAddr().String()
}

func testKeys(t *testing.T) Keys {
	t.Helper()
	var k Keys
	for _, b := range [][]byte{k.Host[:], k.Guest[:], k.Seal[:]} {
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
	}
	return k
}

func TestHostAndGuestMeet(t *testing.T) {
	store := newMemStore()
	o := Options{Keys: testKeys(t), STUN: []string{stunServer(t)}, Store: store, Logf: t.Logf}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ln, err := Listen(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
		}
		accepted <- c
	}()

	guest, err := Dial(ctx, o)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer guest.Close()
	host := <-accepted
	if host == nil {
		t.FailNow()
	}
	defer host.Close()

	// Both directions, more than one window's worth.
	payload := make([]byte, 300<<10)
	_, _ = rand.Read(payload)
	go func() { _, _ = guest.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(host, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("host read %v, equal=%v", err, bytes.Equal(got, payload))
	}
	go func() { _, _ = host.Write(payload[:5000]) }()
	if _, err := io.ReadFull(guest, got[:5000]); err != nil || !bytes.Equal(got[:5000], payload[:5000]) {
		t.Fatalf("guest read %v", err)
	}
}

func TestGuestWithTheWrongLinkMeetsNobody(t *testing.T) {
	store := newMemStore()
	stunAddr := stunServer(t)
	host := Options{Keys: testKeys(t), STUN: []string{stunAddr}, Store: store}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ln, err := Listen(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			t.Error("the host accepted a guest that does not have its link")
			c.Close()
		}
	}()

	// Same places, different seal: the guest finds an item it cannot open.
	other := host
	other.Keys.Seal = testKeys(t).Seal
	dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
	defer dcancel()
	_, err = Dial(dctx, other)
	if err == nil || !strings.Contains(err.Error(), "left no addresses") {
		t.Fatalf("dial = %v, want the host not found", err)
	}
}

func TestItemsAreBoundToTheirRole(t *testing.T) {
	k := testKeys(t)
	it := item{ID: 7, Addrs: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:4000")}}
	blob, err := seal(k.Seal, roleHost, it)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := open(k.Seal, roleHost, blob); err != nil || got.ID != 7 || got.Addrs[0] != it.Addrs[0] {
		t.Fatalf("open = %+v, %v", got, err)
	}
	if _, err := open(k.Seal, roleGuest, blob); err == nil {
		t.Fatal("a host's item opened as a guest's")
	}
	blob[len(blob)-1] ^= 1
	if _, err := open(k.Seal, roleHost, blob); err == nil {
		t.Fatal("a tampered item opened")
	}
	if _, err := seal(k.Seal, roleHost, item{ID: 0, Addrs: it.Addrs}); err != nil {
		t.Fatal(err)
	}
	empty, _ := seal(k.Seal, roleHost, item{ID: 0, Addrs: it.Addrs})
	if _, err := open(k.Seal, roleHost, empty); err == nil {
		t.Fatal("an item without a session opened")
	}
}

// lossy drops and duplicates datagrams it sends, as a bad path would.
type lossy struct {
	net.PacketConn
	drop, dup int // percent
}

func chance(pct int) bool {
	n, _ := rand.Int(rand.Reader, big.NewInt(100))
	return int(n.Int64()) < pct
}

func (l *lossy) WriteTo(b []byte, addr net.Addr) (int, error) {
	if chance(l.drop) {
		return len(b), nil
	}
	if chance(l.dup) {
		_, _ = l.PacketConn.WriteTo(b, addr)
	}
	return l.PacketConn.WriteTo(b, addr)
}

func streamPair(t *testing.T, drop, dup int) (a, b *stream) {
	t.Helper()
	pa, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pb, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a = newStream(&lossy{pa, drop, dup}, pb.LocalAddr().(*net.UDPAddr).AddrPort(), 42)
	b = newStream(&lossy{pb, drop, dup}, pa.LocalAddr().(*net.UDPAddr).AddrPort(), 42)
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func TestStreamSurvivesLossAndDuplication(t *testing.T) {
	a, b := streamPair(t, 10, 5)
	payload := make([]byte, 200<<10)
	_, _ = rand.Read(payload)
	errc := make(chan error, 1)
	go func() {
		_, err := a.Write(payload)
		errc <- err
	}()
	_ = b.SetReadDeadline(time.Now().Add(30 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the stream reordered or corrupted data")
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestStreamEndsAtCloseAndDeadlines(t *testing.T) {
	a, b := streamPair(t, 0, 0)
	_ = b.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := b.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read past the deadline = %v", err)
	}
	_ = b.SetReadDeadline(time.Time{})
	if _, err := a.Write([]byte("bye")); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(b)
	if err != nil || string(got) != "bye" {
		t.Fatalf("read %q, %v; want what was written, then EOF", got, err)
	}
}

func TestStreamIgnoresOtherSessions(t *testing.T) {
	a, b := streamPair(t, 0, 0)
	stranger, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stranger.Close()
	to := b.pc.LocalAddr()
	_, _ = stranger.WriteTo(packet(pktData, 41, 0, []byte("stranger")), to)
	_, _ = a.pc.WriteTo(packet(pktData, 43, 0, []byte("other session")), to)
	_, _ = stranger.WriteTo([]byte{pktData, 0, 0}, to)
	_, _ = a.Write([]byte("real"))
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := b.Read(buf)
	if err != nil || string(buf[:n]) != "real" {
		t.Fatalf("read %q, %v", buf[:n], err)
	}
}

// TestStreamFollowsItsPeer is two sides that took different paths: b first
// heard a at an address a's replies do not come from, as when one side hears
// the other's LAN address first and the other side its public one.
func TestStreamFollowsItsPeer(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs all of 127.0.0.0/8 on loopback")
	}
	pa, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	pb, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	portA, portB := pa.LocalAddr().(*net.UDPAddr).Port, pb.LocalAddr().(*net.UDPAddr).Port
	// a's packets reach b from 127.0.0.1, not the 127.0.0.2 b expects.
	a := newStream(pa, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(portB)), 9)
	b := newStream(pb, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), uint16(portA)), 9)
	defer a.Close()
	defer b.Close()
	if _, err := a.Write([]byte("across")); err != nil {
		t.Fatal(err)
	}
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	n, err := b.Read(buf)
	if err != nil || string(buf[:n]) != "across" {
		t.Fatalf("b read %q, %v", buf[:n], err)
	}
	if _, err := b.Write([]byte("back")); err != nil {
		t.Fatal(err)
	}
	_ = a.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err = a.Read(buf); err != nil || string(buf[:n]) != "back" {
		t.Fatalf("a read %q, %v", buf[:n], err)
	}
}

// dataTo reports whether pc receives a data packet of session id within d.
func dataTo(pc net.PacketConn, id uint32, d time.Duration) bool {
	buf := make([]byte, 2048)
	_ = pc.SetReadDeadline(time.Now().Add(d))
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return false
		}
		if kind, got, _, _, ok := parsePacket(buf[:n]); ok && got == id && kind == pktData {
			return true
		}
	}
}

// TestAStrangerCannotPointTheStreamElsewhere: the session id travels in the
// clear, and a punch carrying it from another address leaves a stream whose
// peer is heard where it was.
func TestAStrangerCannotPointTheStreamElsewhere(t *testing.T) {
	a, b := streamPair(t, 0, 0)
	stranger, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stranger.Close()
	if _, err := b.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = a.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := a.Read(make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	_, _ = stranger.WriteTo(packet(pktPunch, 42, 0, nil), a.pc.LocalAddr())
	time.Sleep(50 * time.Millisecond)
	if _, err := a.Write([]byte("for b alone")); err != nil {
		t.Fatal(err)
	}
	if dataTo(stranger, 42, time.Second) {
		t.Fatal("a stranger's punch pointed the stream at the stranger")
	}
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	if n, err := b.Read(buf); err != nil || string(buf[:n]) != "for b alone" {
		t.Fatalf("b read %q, %v", buf[:n], err)
	}
}

// TestStreamFollowsAPeerThatMoved: once the peer's address is quiet, the
// session going on from another address is followed, as when a NAT moves the
// peer's mapping.
func TestStreamFollowsAPeerThatMoved(t *testing.T) {
	old := followAfter
	followAfter = 300 * time.Millisecond
	defer func() { followAfter = old }()
	pa, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	was, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer was.Close()
	moved, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer moved.Close()
	a := newStream(pa, was.LocalAddr().(*net.UDPAddr).AddrPort(), 7)
	defer a.Close()
	_, _ = moved.WriteTo(packet(pktPunch, 7, 0, nil), pa.LocalAddr())
	time.Sleep(50 * time.Millisecond)
	if _, err := a.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if dataTo(moved, 7, 200*time.Millisecond) {
		t.Fatal("the stream left its peer while its address was still in time")
	}
	time.Sleep(followAfter)
	_, _ = moved.WriteTo(packet(pktPunch, 7, 0, nil), pa.LocalAddr())
	if !dataTo(moved, 7, time.Second) {
		t.Fatal("the stream did not follow its peer, at once, once the old address went quiet")
	}
	_, _ = moved.WriteTo(packet(pktAck, 7, 1, nil), pa.LocalAddr())
}

// TestAStreamResendsPastAnOutage: a window unacknowledged for longer than
// the keepalive interval is still sent again, though the keepalives go on
// both ways and the peer is heard throughout.
func TestAStreamResendsPastAnOutage(t *testing.T) {
	pa, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pb, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pb.Close()
	a := newStream(pa, pb.LocalAddr().(*net.UDPAddr).AddrPort(), 5)
	defer a.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(500 * time.Millisecond):
				_, _ = pb.WriteTo(packet(pktPunch, 5, 1, nil), pa.LocalAddr())
			}
		}
	}()
	if _, err := a.Write([]byte("lost")); err != nil {
		t.Fatal(err)
	}
	outage := time.Now().Add(4 * time.Second)
	for time.Now().Before(outage) {
		dataTo(pb, 5, time.Until(outage))
	}
	if !dataTo(pb, 5, maxRTO+2*time.Second) {
		t.Fatal("a window unacknowledged past an outage was not sent again")
	}
}

// TestAnEnrollmentRunsOverTheMeeting is the point of the package: the
// invite's key exchange, over a punched path instead of TCP.
func TestAnEnrollmentRunsOverTheMeeting(t *testing.T) {
	inv, err := enroll.NewInvite(nil)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{Keys: KeysOf(inv.Link()), STUN: []string{stunServer(t)}, Store: newMemStore()}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ln, err := Listen(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	hostErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			hostErr <- err
			return
		}
		defer c.Close()
		hello, err := enroll.ReadHello(c)
		if err != nil {
			hostErr <- err
			return
		}
		ch, err := inv.AcceptHello(hello, c)
		if err != nil {
			hostErr <- err
			return
		}
		hostErr <- ch.Send(&enroll.Message{Kind: enroll.KindJoined})
	}()
	c, err := Dial(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ch, err := enroll.Join(c, inv.Link())
	if err != nil {
		t.Fatalf("guest: %v", err)
	}
	msg, err := ch.Receive()
	if err != nil || msg.Kind != enroll.KindJoined {
		t.Fatalf("guest received %v, %v", msg, err)
	}
	if err := <-hostErr; err != nil {
		t.Fatalf("host: %v", err)
	}
}

// Two Closes at once — a session's own and its context's — must not tear the
// stream down twice: close of a closed channel would take the daemon with it.
func TestConcurrentClosesAreSafe(t *testing.T) {
	a, _ := streamPair(t, 100, 0) // nothing is ever acknowledged
	if _, err := a.Write([]byte("unacked")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() { defer wg.Done(); a.Close() }()
	}
	wg.Wait()
}

// A Dial that gives up before it took the DHT store still closes it: a node
// left running is a socket and a presence on the public DHT.
func TestAFailedDialClosesTheStore(t *testing.T) {
	closed := make(chan struct{}, 1)
	o := Options{Keys: testKeys(t), STUN: []string{"127.0.0.1:9"}, // nothing answers
		open: func() (Store, func(), error) {
			return newMemStore(), func() { closed <- struct{}{} }, nil
		}}
	if _, err := Dial(context.Background(), o); !errors.Is(err, ErrNoPublicAddress) {
		t.Fatalf("dial = %v, want no public address", err)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the store was left open")
	}
}

// Only an answer to a request this device made adds an address, once, first,
// unmapped, and only one worth punching toward.
func TestOnlyAskedForReflexiveAddressesAreOffered(t *testing.T) {
	have := []netip.AddrPort{netip.MustParseAddrPort("192.168.1.2:4000")}
	asked, other := stun.NewTxID(), stun.NewTxID()
	pending := map[stun.TxID]bool{asked: true}
	public := netip.MustParseAddrPort("[::ffff:198.51.100.7]:5000")

	if _, ok := withReflexive(have, stun.Response(other, public), pending); ok {
		t.Fatal("an unsolicited response added an address")
	}
	if _, ok := withReflexive(have, stun.Response(asked, netip.MustParseAddrPort("224.0.0.1:5000")), pending); ok {
		t.Fatal("a multicast address was offered")
	}
	if pending[asked] {
		t.Fatal("an answered request is still pending")
	}
	pending[asked] = true
	got, ok := withReflexive(have, stun.Response(asked, public), pending)
	if !ok || len(got) != 2 || got[0] != netip.MustParseAddrPort("198.51.100.7:5000") {
		t.Fatalf("offered %v, %v", got, ok)
	}
	if _, ok := withReflexive(got, stun.Response(asked, public), pending); ok {
		t.Fatal("a response was taken twice")
	}
	full := make([]netip.AddrPort, maxCandidates)
	for i := range full {
		full[i] = netip.AddrPortFrom(netip.MustParseAddr("192.168.1.2"), uint16(4000+i))
	}
	pending[asked] = true
	if got, _ := withReflexive(full, stun.Response(asked, public), pending); len(got) != maxCandidates || got[0].Port() != 5000 {
		t.Fatalf("a full set became %v", got)
	}
}
