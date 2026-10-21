package guest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/relay/forward"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/types"
)

// unreachable is an address nothing listens on: a port taken and closed.
func unreachable(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ap := ln.Addr().(*net.TCPAddr).AddrPort()
	ln.Close()
	return ap
}

func TestAReachableLinkNeverAsksTheDHT(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	link, err := enroll.NewLink([]netip.AddrPort{unreachable(t), ln.Addr().(*net.TCPAddr).AddrPort()})
	if err != nil {
		t.Fatal(err)
	}
	var met atomic.Bool
	meet := func(context.Context, enroll.Link) (net.Conn, error) {
		met.Store(true)
		return nil, errors.New("not in this test")
	}
	var events []EventKind
	conn, err := dialOrMeet(context.Background(), link, meet, func(e Event) { events = append(events, e.Kind) })
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if met.Load() || len(events) != 0 {
		t.Fatalf("met=%v events=%v: a reachable host was looked for in the DHT", met.Load(), events)
	}
}

func TestAnUnreachableLinkMeetsThroughTheDHT(t *testing.T) {
	link, err := enroll.NewLink([]netip.AddrPort{unreachable(t)})
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer b.Close()
	meet := func(_ context.Context, got enroll.Link) (net.Conn, error) {
		if got.String() != link.String() {
			t.Error("the meeting is for another link")
		}
		return a, nil
	}
	var events []EventKind
	start := time.Now()
	conn, err := dialOrMeet(context.Background(), link, meet, func(e Event) { events = append(events, e.Kind) })
	if err != nil || conn != a {
		t.Fatalf("dialOrMeet = %v, %v; want the met connection", conn, err)
	}
	if len(events) != 1 || events[0] != Meeting {
		t.Fatalf("events = %v, want one Meeting", events)
	}
	// A refused dial is a clear answer: no need to sit out the head start.
	if time.Since(start) >= meetAfter {
		t.Fatalf("the meeting waited %v for addresses that had already failed", time.Since(start))
	}
}

func TestFailingBothWaysSaysSo(t *testing.T) {
	link, err := enroll.NewLink([]netip.AddrPort{unreachable(t)})
	if err != nil {
		t.Fatal(err)
	}
	meet := func(context.Context, enroll.Link) (net.Conn, error) {
		return nil, errors.New("no packet got through")
	}
	_, err = dialOrMeet(context.Background(), link, meet, func(Event) {})
	if err == nil || !strings.Contains(err.Error(), "no packet got through") || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("err = %v, want both reasons", err)
	}
}

// A host that asks to compare words twice is refused: with a second salt it
// could try until the words matched another device's.
func TestASecondSaltIsRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	inv, err := enroll.NewInvite([]netip.AddrPort{ln.Addr().(*net.TCPAddr).AddrPort()})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		hello, err := enroll.ReadHello(c)
		if err != nil {
			return
		}
		ch, err := inv.AcceptHello(hello, c)
		if err != nil {
			return
		}
		if _, err := ch.Receive(); err != nil { // the join request
			return
		}
		for i := range 2 {
			salt := enroll.Salt{byte(i)}
			if ch.Send(&enroll.Message{Kind: enroll.KindCompare, Compare: &salt}) != nil {
				return
			}
			if _, err := ch.Receive(); err != nil { // the reveal
				return
			}
		}
		time.Sleep(time.Second)
	}()
	g, err := keys.GenerateNode()
	if err != nil {
		t.Fatal(err)
	}
	compares := 0
	_, err = Join(context.Background(), Options{Invite: inv.Link().String(), Name: "phone", Keys: g,
		Adopt:    func([]types.AUM, bool) error { return nil },
		Progress: func(e Event) { compares += map[bool]int{true: 1}[e.Kind == Compare] }})
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("a second salt: %v", err)
	}
	if compares != 1 {
		t.Fatalf("the guest showed words %d times", compares)
	}
}

// A link that names relays only, none of them up, fails with a message: the
// guest runs in juistd, where a panic would take the daemon down.
func TestARelayOnlyLinkFailsCleanly(t *testing.T) {
	l, err := enroll.NewLink(nil)
	if err != nil {
		t.Fatal(err)
	}
	l = l.WithRelays([]netip.AddrPort{unreachable(t)}, nil)
	g, err := keys.GenerateNode()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := Join(ctx, Options{Invite: l.String(), Keys: g, Adopt: func([]types.AUM, bool) error { return nil }}); err == nil ||
		!strings.Contains(err.Error(), "cannot reach the inviting device") {
		t.Fatalf("a relay-only link: %v", err)
	}
}

// A link or code pasted with the quotes it was printed in is read without
// them, where no shell took them off.
func TestAQuotedInviteParses(t *testing.T) {
	link, err := enroll.NewLink([]netip.AddrPort{netip.MustParseAddrPort("[fd00::1]:41642")})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{link.String(), "'" + link.String() + "'", `"` + link.String() + `"`, " '" + link.String() + "' "} {
		got, err := ParseInvite(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if l, ok := got.(enroll.Link); !ok || l.String() != link.String() {
			t.Fatalf("%q read as %v", s, got)
		}
	}
	if _, err := ParseInvite("'" + link.String()); err == nil {
		t.Fatal("a link with one quote parsed")
	}
}

// A guest asks a relay again while it says no host waits there yet, as the
// host that just printed its link may not have registered, and gives up on
// any other answer at once.
func TestAGuestWaitsForTheHostAtTheRelay(t *testing.T) {
	calls := 0
	c, err := untilWaiting(t.Context(), func(context.Context) (net.Conn, error) {
		if calls++; calls < 3 {
			return nil, fmt.Errorf("the relay at relay.example.org: %w", forward.ErrNotWaiting)
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("after %d dials: %v", calls, err)
	}
	c.Close()
	calls = 0
	if _, err := untilWaiting(t.Context(), func(context.Context) (net.Conn, error) {
		calls++
		return nil, errors.New("refused")
	}); err == nil || calls != 1 {
		t.Errorf("another failure was dialled %d times: %v", calls, err)
	}
}
