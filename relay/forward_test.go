package relay

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/relay/forward"
)

// forwardRelay is a relay that holds invites for the members in admitted.
func forwardRelay(t *testing.T, admitted func([32]byte) bool) (*Server, forward.Relay) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Admit:       func([32]byte) bool { return false },
		AdmitHost:   admitted,
		Listener:    ln,
		DisableSTUN: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, forward.Relay{
		Addrs:      []netip.AddrPort{ln.Addr().(*net.TCPAddr).AddrPort()},
		CertHash:   s.CertHash(),
		ServerName: s.HostName(),
	}
}

type member struct {
	pub  [32]byte
	priv ed25519.PrivateKey
}

func newMember(t *testing.T) member {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return member{pub: [32]byte(pub), priv: priv}
}

func (m member) sign(msg []byte) ([]byte, error) { return ed25519.Sign(m.priv, msg), nil }

// A host waits at the relay, and a guest who knows the id reaches it there,
// with bytes flowing both ways as they were sent.
func TestAGuestReachesAHostWaitingAtTheRelay(t *testing.T) {
	host := newMember(t)
	_, r := forwardRelay(t, func(id [32]byte) bool { return id == host.pub })
	id := [16]byte{7}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	type waited struct {
		c   net.Conn
		who string
		err error
	}
	got := make(chan waited, 1)
	go func() {
		c, who, err := forward.Wait(ctx, r, id, host.pub, host.sign)
		got <- waited{c, who, err}
	}()
	var g net.Conn
	var err error
	for range 50 { // until the host's registration has landed
		if g, err = forward.Dial(ctx, r.Addrs[0], id); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("the guest did not reach the host: %v", err)
	}
	defer g.Close()
	w := <-got
	if w.err != nil {
		t.Fatalf("the host's wait: %v", w.err)
	}
	defer w.c.Close()
	if w.who == "" {
		t.Error("the host was not told who the guest is")
	}
	// The guest may speak first, as an enrollment guest does.
	if _, err := g.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(w.c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("the host read %q, %v", buf, err)
	}
	if _, err := w.c.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(g, buf); err != nil || string(buf) != "world" {
		t.Fatalf("the guest read %q, %v", buf, err)
	}
}

// Only members may wait at a relay, and only at the relay they proved
// themselves to; a guest asking for an id nobody waits under hears so at once.
func TestTheRelayHoldsInvitesOnlyForMembers(t *testing.T) {
	host, stranger := newMember(t), newMember(t)
	_, r := forwardRelay(t, func(id [32]byte) bool { return id == host.pub })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, _, err := forward.Wait(ctx, r, [16]byte{1}, stranger.pub, stranger.sign); err == nil {
		t.Fatal("a non-member waited at the relay")
	}
	// A member's signature made for another relay does not register here.
	wrong := func(msg []byte) ([]byte, error) {
		return host.sign(forward.Message([32]byte{9}, [16]byte{1}, [32]byte(msg[len(msg)-32:])))
	}
	if _, _, err := forward.Wait(ctx, r, [16]byte{1}, host.pub, wrong); err == nil {
		t.Fatal("a signature bound to another relay registered")
	}
	// Nor does the host accept a relay whose certificate is not the one
	// announced.
	other := r
	other.CertHash = [32]byte{1}
	if _, _, err := forward.Wait(ctx, other, [16]byte{1}, host.pub, host.sign); err == nil {
		t.Fatal("the host waited at a relay with another certificate")
	}
	start := time.Now()
	if _, err := forward.Dial(ctx, r.Addrs[0], [16]byte{2}); err == nil {
		t.Fatal("a guest reached an invite nobody waits for")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("a guest asking for an unknown invite was kept waiting")
	}
}

// One member cannot take over an id another member waits under, and a
// removed member's waiting connection is dropped.
func TestAWaitingInviteBelongsToItsMember(t *testing.T) {
	a, b := newMember(t), newMember(t)
	var mu sync.Mutex
	admitted := map[[32]byte]bool{a.pub: true, b.pub: true}
	s, r := forwardRelay(t, func(id [32]byte) bool {
		mu.Lock()
		defer mu.Unlock()
		return admitted[id]
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	id := [16]byte{3}
	done := make(chan error, 1)
	go func() {
		_, _, err := forward.Wait(ctx, r, id, a.pub, a.sign)
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	if _, _, err := forward.Wait(ctx, r, id, b.pub, b.sign); err == nil {
		t.Fatal("a second member took over a waiting invite")
	}
	mu.Lock()
	admitted[a.pub] = false
	mu.Unlock()
	s.Reauthorize()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the removed member's wait ended with a guest")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the removed member still waits at the relay")
	}
}

// manyLoopbacks skips where the loopback device holds 127.0.0.1 alone, as
// FreeBSD's does unless given more with ifconfig lo0 alias.
func manyLoopbacks(t *testing.T) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.4.1:0")
	if err != nil {
		t.Skipf("guests from many places need 127.0.4.0/24 on loopback: %v", err)
	}
	l.Close()
}

// guestFrom asks the relay for id from the loopback address src, so that
// tests can stand in for guests from many places, and returns the
// connection once joined.
func guestFrom(r forward.Relay, id [16]byte, src string) (net.Conn, error) {
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 5 * time.Second}
	raw, err := d.Dial("tcp", r.Addrs[0].String())
	if err != nil {
		return nil, err
	}
	c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	req := "GET " + forward.GuestPath + hex.EncodeToString(id[:]) + " HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\n" +
		"Upgrade: " + forward.Upgrade + "\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		c.Close()
		return nil, errors.New("no upgrade")
	}
	if b, err := br.ReadByte(); err != nil || b != forward.Joined {
		c.Close()
		return nil, errors.New("not joined")
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// A member's forwarded sessions are bounded, however many guests arrive
// from however many places, and end when the member leaves the log.
func TestAMembersSessionsAreBoundedAndEndWithIt(t *testing.T) {
	m := newMember(t)
	var mu sync.Mutex
	member := true
	s, r := forwardRelay(t, func(id [32]byte) bool { mu.Lock(); defer mu.Unlock(); return member && id == m.pub })
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	id := [16]byte{0x77}
	type session struct{ host, guest net.Conn }
	var sessions []session
	for i := range maxSessionsPerHost + 4 {
		waited := make(chan net.Conn, 1)
		go func() {
			c, _, err := forward.Wait(ctx, r, id, m.pub, m.sign)
			if err != nil {
				c = nil
			}
			waited <- c
		}()
		var g net.Conn
		var err error
		for range 50 {
			if g, err = guestFrom(r, id, fmt.Sprintf("127.0.3.%d", i+1)); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			break
		}
		sessions = append(sessions, session{<-waited, g})
	}
	if len(sessions) > maxSessionsPerHost {
		t.Fatalf("one member holds %d forwarded sessions, over %d", len(sessions), maxSessionsPerHost)
	}
	mu.Lock()
	member = false
	mu.Unlock()
	s.Reauthorize()
	for i, p := range sessions {
		_ = p.guest.SetDeadline(time.Now().Add(2 * time.Second))
		_ = p.host.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := p.guest.Write([]byte("x")); err != nil {
			continue
		}
		if _, err := io.ReadFull(p.host, make([]byte, 1)); err == nil {
			t.Fatalf("session %d still carries bytes after its member left the log", i)
		}
	}
}

// A host that goes away right after proving itself leaves nothing held:
// no guest waits for good, and the guest bounds come back.
func TestAHostGoneAtOnceHoldsNothing(t *testing.T) {
	manyLoopbacks(t)
	m := newMember(t)
	s, r := forwardRelay(t, func([32]byte) bool { return true })
	id := [16]byte{0x88}
	for range 20 {
		raw, err := net.Dial("tcp", r.Addrs[0].String())
		if err != nil {
			t.Fatal(err)
		}
		c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
		req := "GET " + forward.HostPath + hex.EncodeToString(id[:]) + " HTTP/1.1\r\nHost: x\r\n" +
			"Connection: Upgrade\r\nUpgrade: " + forward.Upgrade + "\r\n\r\n"
		if _, err := io.WriteString(c, req); err != nil {
			t.Fatal(err)
		}
		br := bufio.NewReader(c)
		if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatal("no upgrade")
		}
		var nonce [32]byte
		if _, err := io.ReadFull(br, nonce[:]); err != nil {
			t.Fatal(err)
		}
		// A guest is already asking when the host proves itself and resets.
		go func() { _, _ = guestFrom(r, id, "127.0.4.1") }()
		sig, _ := m.sign(forward.Message(r.CertHash, id, nonce))
		_, _ = c.Write(append(m.pub[:], sig...))
		_ = raw.(*net.TCPConn).SetLinger(0)
		raw.Close()
	}
	deadline := time.Now().Add(guestWait + 5*time.Second)
	for {
		total := s.fwd.waiting.Len()
		if total == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d guests still held after their hosts went away", total)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// A guest is told it joined only within its member's bound: one admitted
// while the last slot was free, and joined after another took it, is turned
// away rather than told it joined and then cut off.
func TestAGuestIsToldItJoinedOnlyWithinTheBound(t *testing.T) {
	manyLoopbacks(t)
	m := newMember(t)
	_, r := forwardRelay(t, func(id [32]byte) bool { return id == m.pub })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id := [16]byte{0x99}
	host := func() {
		go func() {
			if c, _, err := forward.Wait(ctx, r, id, m.pub, m.sign); err == nil {
				t.Cleanup(func() { c.Close() })
			}
		}()
	}
	guest := func(i int) (net.Conn, error) {
		var g net.Conn
		var err error
		for range 50 {
			if g, err = guestFrom(r, id, fmt.Sprintf("127.0.4.%d", i+1)); err == nil {
				t.Cleanup(func() { g.Close() })
				return g, nil
			}
			time.Sleep(20 * time.Millisecond)
		}
		return nil, err
	}
	joined := 0
	for i := range maxSessionsPerHost - 1 {
		host()
		if _, err := guest(i); err != nil {
			t.Fatalf("guest %d: %v", i, err)
		}
		joined++
	}

	held, release := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	guestAdmitted = func() {
		if first.CompareAndSwap(false, true) {
			close(held)
			<-release
		}
	}
	t.Cleanup(func() { guestAdmitted = func() {} })
	host()
	late := make(chan error, 1)
	go func() {
		_, err := guest(100)
		late <- err
	}()
	<-held
	host()
	if _, err := guest(101); err == nil {
		joined++
	}
	close(release)
	if err := <-late; err == nil {
		joined++
	}
	if joined > maxSessionsPerHost {
		t.Fatalf("%d guests were told they joined, over the %d bound", joined, maxSessionsPerHost)
	}
}

// TestGuestsAreBoundedByTheirGroup: guests from many addresses of one IPv6
// /56 are held to the bound on one source, which one /64 would otherwise
// escape by its addresses alone.
func TestGuestsAreBoundedByTheirGroup(t *testing.T) {
	for _, tc := range []struct{ name, format string }{
		{"one /64", "[2001:db8:1:200::%x]:1"},
		{"one /56", "[2001:db8:1:2%02x::1]:1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newForwarder(func([32]byte) bool { return true }, [32]byte{}, t.Logf)
			id := [16]byte{0x56}
			f.ids[id] = &waitingInvite{owner: [32]byte{1}, idle: time.Now()}
			held, release := make(chan struct{}), make(chan struct{})
			guestAdmitted = func() {
				held <- struct{}{}
				<-release
			}
			t.Cleanup(func() { guestAdmitted = func() {} })
			var wg sync.WaitGroup
			defer wg.Wait()
			defer func() {
				f.mu.Lock()
				delete(f.ids, id)
				f.cond.Broadcast()
				f.mu.Unlock()
				close(release)
			}()
			admitted := 0
			for i := range maxGuestsPerSource + 1 {
				r := httptest.NewRequest(http.MethodGet, forward.GuestPath+hex.EncodeToString(id[:]), nil)
				r.RemoteAddr = fmt.Sprintf(tc.format, i+1)
				refused := make(chan int, 1)
				wg.Go(func() {
					w := httptest.NewRecorder()
					f.serveGuest(w, r)
					refused <- w.Code
				})
				select {
				case <-held:
					admitted++
				case code := <-refused:
					if code != http.StatusServiceUnavailable {
						t.Fatalf("guest %d answered %d", i, code)
					}
				}
			}
			if admitted != maxGuestsPerSource {
				t.Fatalf("%d guests from %s were admitted to wait, want %d", admitted, tc.name, maxGuestsPerSource)
			}
		})
	}
}
