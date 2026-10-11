package gossip

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/nning/juist/types"
)

// sendsNothingFor asserts the peer writes nothing on c for d.
func sendsNothingFor(t *testing.T, c net.Conn, d time.Duration, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	var scratch [1]byte
	_, err := c.Read(scratch[:])
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("%s: the peer spoke out of turn (%v)", what, err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
}

func dialRaw(t *testing.T, to *testNode) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", to.real.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

// In an ordinary session the initiator's records come first: a responder
// answers them and does not speak before.
func TestAnOrdinaryResponderSpeaksLast(t *testing.T) {
	network := types.Hash{1}
	s := mustSecret(t)
	responder := newTestNode(t, network, 1, s)
	us := newTestNode(t, network, 1, s)
	c := dialRaw(t, responder)

	ss := &sessionSeal{epoch: 1}
	view, _ := us.log.View()
	hello := us.node.hello(&view, true)
	if err := us.node.writeSealed(c, ss, &hello); err != nil {
		t.Fatal(err)
	}
	if f, err := us.node.readSealed(c, ss); err != nil || f.Kind != kindHello {
		t.Fatalf("read %v, %v; want a hello", f.Kind, err)
	}
	sendsNothingFor(t, c, 300*time.Millisecond, "after the hellos")
	ours, err := us.node.records(&view, &frame{Anchor: view.Anchor})
	if err != nil {
		t.Fatal(err)
	}
	if err := us.node.writeSealed(c, ss, &ours); err != nil {
		t.Fatal(err)
	}
	if f, err := us.node.readSealed(c, ss); err != nil || f.Kind != kindRecords {
		t.Fatalf("read %v, %v; want records", f.Kind, err)
	}
}

// And the initiator sends its records straight after the hellos, without
// waiting for the responder's.
func TestAnOrdinaryInitiatorSpeaksFirst(t *testing.T) {
	network := types.Hash{1}
	s := mustSecret(t)
	initiator := newTestNode(t, network, 1, s)
	them := newTestNode(t, network, 1, s)
	got := make(chan frameKind, 1)
	addr := fakeResponder(t, func(c net.Conn) {
		ss := &sessionSeal{}
		if _, err := them.node.readSealed(c, ss); err != nil {
			got <- kindInvalid
			return
		}
		view, _ := them.log.View()
		hello := them.node.hello(&view, true)
		if err := them.node.writeSealed(c, ss, &hello); err != nil {
			got <- kindInvalid
			return
		}
		f, err := them.node.readSealed(c, ss)
		if err != nil {
			got <- kindInvalid
			return
		}
		got <- f.Kind
	})
	ctx := t.Context()
	go func() { _ = initiator.node.SyncWith(ctx, addr, them.id) }()
	select {
	case k := <-got:
		if k != kindRecords {
			t.Fatalf("after the hellos the initiator sent %v, want its records", k)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the initiator waited for the responder's records")
	}
}

// In a catch-up the responder's records come first, before the initiator has
// sent anything past its hello.
func TestACatchUpResponderSpeaksFirst(t *testing.T) {
	p := newCatchUpPair(t)
	c := dialRaw(t, p.peer)
	view, _ := p.sleeper.log.View()
	key, from, err := p.sleeper.node.askCatchUp(c, view.Network, view.Epoch)
	if err != nil {
		t.Fatalf("asking: %v", err)
	}
	if from != p.peer.id {
		t.Fatal("granted by someone else")
	}
	ss := &sessionSeal{catchUp: key, with: from}
	hello := p.sleeper.node.hello(&view, true)
	hello.Self, hello.Endpoints = nil, nil
	if err := p.sleeper.node.writeSealed(c, ss, &hello); err != nil {
		t.Fatal(err)
	}
	if f, err := p.sleeper.node.readSealed(c, ss); err != nil || f.Kind != kindHello {
		t.Fatalf("read %v, %v; want a hello", f.Kind, err)
	}
	if f, err := p.sleeper.node.readSealed(c, ss); err != nil || f.Kind != kindRecords {
		t.Fatalf("read %v, %v; want the responder's records unasked", f.Kind, err)
	}
}
