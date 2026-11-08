package mobile

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nning/juist/types"
)

// fakeExits is a network as chooseExit sees it, recording what it was told.
type fakeExits struct {
	mu      sync.Mutex
	node    types.Identity
	failOff bool
	log     *[]string
	name    string
	// meet, where set, holds each useExit, once chosen, until another's
	// is, or a while has passed.
	meet *barrier
}

// A barrier lets those who wait at it go once two have come, or after a
// while.
type barrier struct {
	mu   sync.Mutex
	n    int
	both chan struct{}
}

func (b *barrier) wait() {
	b.mu.Lock()
	b.n++
	if b.n == 2 {
		close(b.both)
	}
	b.mu.Unlock()
	select {
	case <-b.both:
	case <-time.After(200 * time.Millisecond):
	}
}

func (f *fakeExits) exitNode() (types.Identity, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.node, !f.node.IsZero()
}

func (f *fakeExits) useExit(id types.Identity) error {
	f.mu.Lock()
	f.node = id
	*f.log = append(*f.log, f.name+" use")
	f.mu.Unlock()
	if f.meet != nil {
		f.meet.wait()
	}
	return nil
}

func (f *fakeExits) exitOff() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOff {
		return errors.New("busy")
	}
	f.node = types.Identity{}
	*f.log = append(*f.log, f.name+" off")
	return nil
}

func node(b byte) types.Identity { return identity(b) }

// The new exit node is chosen before the other network's goes, and where
// that cannot go, the new network's choice goes back to what it was.
func TestAnExitNodeIsChosenBeforeTheOtherGoes(t *testing.T) {
	var log []string
	a := &fakeExits{node: node(1), log: &log, name: "a"}
	b := &fakeExits{node: node(2), log: &log, name: "b"}
	c := &Core{}
	if err := c.chooseExit(b, node(3), []exitChooser{a}); err != nil {
		t.Fatal(err)
	}
	if len(log) != 2 || log[0] != "b use" || log[1] != "a off" {
		t.Errorf("%v, want b's chosen before a's let go", log)
	}
	a.node, a.failOff = node(1), true
	if err := c.chooseExit(b, node(4), []exitChooser{a}); err == nil {
		t.Error("an exit node the other network kept was taken as chosen")
	}
	if got, _ := b.exitNode(); got != node(3) {
		t.Errorf("b's exit node is %v after the other's could not go, want its own before, %v", got, node(3))
	}
}

// Two networks' exit nodes chosen at once leave one carrying the internet.
func TestExitNodesAreChosenOneAtATime(t *testing.T) {
	var log []string
	meet := &barrier{both: make(chan struct{})}
	a := &fakeExits{log: &log, name: "a", meet: meet}
	b := &fakeExits{log: &log, name: "b", meet: meet}
	c := &Core{}
	var wg sync.WaitGroup
	wg.Go(func() { c.chooseExit(a, node(1), []exitChooser{b}) })
	wg.Go(func() { c.chooseExit(b, node(2), []exitChooser{a}) })
	wg.Wait()
	_, onA := a.exitNode()
	_, onB := b.exitNode()
	if onA == onB {
		t.Errorf("a's exit node chosen %v, b's %v: want exactly one (%v)", onA, onB, log)
	}
}
