package gossip

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// fakeWaiting holds changes and hands them to the members in to.
type fakeWaiting struct {
	mu     sync.Mutex
	held   [][]byte
	to     map[types.Identity]bool
	taken  [][]byte
	asked  [][]types.Hash // the held sets For was asked with
	handed map[types.Identity][][]byte
}

func (w *fakeWaiting) Handed(id types.Identity, changes [][]byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.handed == nil {
		w.handed = map[types.Identity][][]byte{}
	}
	w.handed[id] = append(w.handed[id], changes...)
}

func (w *fakeWaiting) handedTo(id types.Identity) [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.handed[id])
}

func (w *fakeWaiting) Held(types.Identity) []types.Hash {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []types.Hash
	for _, c := range w.held {
		out = append(out, types.Hash(sha(c)))
	}
	return out
}

func (w *fakeWaiting) For(id types.Identity, held []types.Hash) [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.asked = append(w.asked, held)
	if !w.to[id] {
		return nil
	}
	var out [][]byte
	for _, c := range w.held {
		if !slices.Contains(held, types.Hash(sha(c))) {
			out = append(out, c)
		}
	}
	return out
}

func (w *fakeWaiting) Take(changes [][]byte) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.taken = append(w.taken, changes...)
	w.held = append(w.held, changes...)
	return true
}

func (w *fakeWaiting) takenCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.taken)
}

func (w *fakeWaiting) takenCopy() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.taken)
}

// settle waits out the responder's side of a session, which may still be
// taking what it was handed after the initiator's side returned.
func settle(t *testing.T, stores []*fakeWaiting, want ...int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		done := true
		for i, w := range stores {
			done = done && w.takenCount() >= want[i]
		}
		if done {
			return
		}
	}
}

func sha(b []byte) [32]byte { return sha256.Sum256(b) }

// A recordingConn keeps what passes through it.
type recordingConn struct {
	net.Conn
	mu      sync.Mutex
	read    bytes.Buffer
	written bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.read.Write(p[:n])
	c.mu.Unlock()
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.written.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

// framesIn opens the frames of a recorded stream with the group secret, as
// anyone holding it could.
func framesIn(t *testing.T, tn *testNode, stream []byte) []frame {
	t.Helper()
	var out []frame
	for len(stream) >= 4 {
		size := binary.BigEndian.Uint32(stream)
		blob := stream[4 : 4+size]
		stream = stream[4+size:]
		_, pt, err := open(tn.keyring, blob)
		if err != nil {
			t.Fatalf("opening a recorded frame: %v", err)
		}
		f, err := decodeFrame(pt)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, f)
	}
	return out
}

// waitingNodes is a network of nodes that list each other, each with a store
// of waiting changes, and each dialer recording what it exchanged.
func waitingNodes(t *testing.T, n int) ([]*testNode, []*fakeWaiting, *[]*recordingConn) {
	t.Helper()
	s, err := secrets.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	var nodes []*testNode
	var stores []*fakeWaiting
	var mu sync.Mutex
	var conns []*recordingConn
	for range n {
		w := &fakeWaiting{to: map[types.Identity]bool{}}
		tn := newTestNodeTimeout(t, types.Hash{1}, 3, s, DefaultTimeout, func(o *Options) {
			o.Waiting = w
			dial := o.Dial
			o.Dial = func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
				c, err := dial(ctx, addr)
				if err != nil {
					return nil, err
				}
				rc := &recordingConn{Conn: c}
				mu.Lock()
				conns = append(conns, rc)
				mu.Unlock()
				return rc, nil
			}
		})
		nodes, stores = append(nodes, tn), append(stores, w)
	}
	for _, tn := range nodes {
		tn.log.member = func(id types.Identity) (types.NodeRecord, bool, error) {
			for _, other := range nodes {
				if other.id == id {
					return other.record, true, nil
				}
			}
			return types.NodeRecord{}, false, nil
		}
	}
	return nodes, stores, &conns
}

// A change waiting for votes reaches the peer its holder may hand it to, in
// both directions of a session, and is not sent again once held.
func TestWaitingChangesReachTheAdminDevices(t *testing.T) {
	nodes, stores, _ := waitingNodes(t, 2)
	a, b := nodes[0], nodes[1]
	stores[0].held = [][]byte{[]byte("change from a")}
	stores[1].held = [][]byte{[]byte("change from b")}
	stores[0].to[b.id], stores[1].to[a.id] = true, true
	if err := a.node.SyncWith(t.Context(), b.addr(), b.id); err != nil {
		t.Fatal(err)
	}
	settle(t, stores, 1, 1)
	if got := stores[1].takenCopy(); len(got) != 1 || string(got[0]) != "change from a" {
		t.Fatalf("the responder took %q", got)
	}
	if got := stores[0].takenCopy(); len(got) != 1 || string(got[0]) != "change from b" {
		t.Fatalf("the initiator took %q", got)
	}
	if err := a.node.SyncWith(t.Context(), b.addr(), b.id); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // the responder's side, as above
	if stores[0].takenCount() != 1 || stores[1].takenCount() != 1 {
		t.Fatal("a change the peer held was sent again")
	}
}

// A device its holder may not hand a change to is sent none, whichever side
// opens the session: on the wire there is nothing for it, even to someone
// holding the group secret. One claiming another's identity gets it sealed
// to that other device, which is all it can do with it.
func TestWaitingChangesReachNoOtherDevice(t *testing.T) {
	nodes, stores, conns := waitingNodes(t, 4)
	a, c, m, b := nodes[0], nodes[1], nodes[2], nodes[3]
	stores[0].held = [][]byte{[]byte("change from a")}
	stores[0].to[b.id] = true // an admin device, which neither c nor m is
	if err := c.node.SyncWith(t.Context(), a.addr(), a.id); err != nil {
		t.Fatal(err)
	}
	if err := a.node.SyncWith(t.Context(), c.addr(), c.id); err != nil {
		t.Fatal(err)
	}
	if stores[1].takenCount() != 0 {
		t.Fatal("a device its holder may not hand the change to took it")
	}
	for _, rc := range *conns {
		rc.mu.Lock()
		for _, stream := range [][]byte{rc.read.Bytes(), rc.written.Bytes()} {
			for _, f := range framesIn(t, a, stream) {
				if f.Kind == kindRecords && len(f.Waiting) > 0 {
					t.Errorf("a records frame to or from %v carries waiting changes", c.id.ShortString())
				}
			}
		}
		rc.mu.Unlock()
	}

	// m announces itself as b, and is handed the change sealed to b.
	claim, _ := b.announce()
	m.node.opts.Announce = func() (Endpoint, bool) { return claim, true }
	*conns = nil
	if err := m.node.SyncWith(t.Context(), a.addr(), a.id); err != nil {
		t.Fatal(err)
	}
	sealed := false
	for _, rc := range *conns {
		rc.mu.Lock()
		for _, f := range framesIn(t, a, rc.read.Bytes()) {
			sealed = sealed || f.Kind == kindRecords && len(f.Waiting) > 0
		}
		rc.mu.Unlock()
	}
	if !sealed {
		t.Fatal("the holder handed nothing to the device claiming to be b; the test shows nothing")
	}
	if stores[2].takenCount() != 0 {
		t.Fatal("a device claiming an admin device's identity opened what was sealed to it")
	}
}

// What a records frame hands over, sealed, stays within the budget it was
// given, however close the changes come to it.
func TestHandedChangesFitTheirBudget(t *testing.T) {
	nodes, stores, _ := waitingNodes(t, 2)
	a, b := nodes[0], nodes[1]
	stores[0].to[b.id] = true
	const budget = 64 << 10
	stores[0].held = [][]byte{bytes.Repeat([]byte{1}, budget/2), bytes.Repeat([]byte{2}, budget/2-8)}
	hello, _ := b.announce()
	sealed, _ := a.node.waitingFor(types.Hash{1}, &frame{Self: &hello}, budget)
	if len(sealed) == 0 || len(sealed) > budget {
		t.Fatalf("handed over %d bytes against a budget of %d", len(sealed), budget)
	}
}

// Only what a records frame did hand over counts as handed.
func TestOnlyWhatWasSentCountsAsHanded(t *testing.T) {
	nodes, stores, _ := waitingNodes(t, 2)
	a, b := nodes[0], nodes[1]
	stores[0].to[b.id] = true
	stores[0].held = [][]byte{[]byte("small"), bytes.Repeat([]byte{1}, 1<<20)}
	hello, _ := b.announce()
	_, sent := a.node.waitingFor(types.Hash{1}, &frame{Self: &hello}, 64<<10)
	if len(sent) != 1 || string(sent[0]) != "small" {
		t.Fatalf("counted %d changes as sent", len(sent))
	}
	if err := a.node.SyncWith(t.Context(), b.addr(), b.id); err != nil {
		t.Fatal(err)
	}
	if got := stores[0].handedTo(b.id); len(got) != 2 {
		t.Fatalf("a session that handed both over counted %d", len(got))
	}
}
