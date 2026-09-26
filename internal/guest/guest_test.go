package guest

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/internal/keys"
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
		ch, err := inv.Accept(c)
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
		Adopt:    func([]types.AUM) error { return nil },
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
	l = l.WithRelays([]netip.AddrPort{unreachable(t)})
	g, err := keys.GenerateNode()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := Join(ctx, Options{Invite: l.String(), Keys: g, Adopt: func([]types.AUM) error { return nil }}); err == nil ||
		!strings.Contains(err.Error(), "cannot reach the inviting device") {
		t.Fatalf("a relay-only link: %v", err)
	}
}
