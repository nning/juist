package gossip

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/nning/juist/types"
)

// SyncWith runs one anti-entropy session against a peer. peerID may be zero
// when the peer is not known yet, in which case the frame is sealed under this
// node's own epoch.
//
// A peer that hangs up on the hello without answering is one that cannot
// open it: behind by an epoch this node has not sealed to it before, as after
// this node rotated its own keys and restarted, when nothing remembers the
// peer's epoch. The session is then tried again under each older epoch this
// node still holds, newest first, and the one that works is remembered. Both
// sides behind a change would otherwise wait for each other forever. When no
// epoch is answered, it asks for a catch-up.
func (n *Node) SyncWith(ctx context.Context, addr netip.AddrPort, peerID types.Identity) error {
	ctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()
	var force uint64
	for {
		used, err := n.syncOnce(ctx, addr, sessionOpts{initiator: true, peerID: peerID, force: force})
		if err == nil {
			return nil
		}
		if errors.Is(err, errNoEpochHeld) {
			return n.catchUpWith(ctx, addr, peerID, err)
		}
		if !errors.Is(err, errNoHelloBack) {
			return err
		}
		lower, ok := n.olderEpoch(used)
		if !ok {
			return n.catchUpWith(ctx, addr, peerID, err)
		}
		force = lower
	}
}

// PushTo runs one session with a member that hands it, after what it lacks of
// this node's log, records this node holds but has not applied: the change
// ending its membership, while it still has a tunnel to hear it through.
func (n *Node) PushTo(ctx context.Context, id types.Identity, records [][]byte) error {
	e, held := n.opts.Endpoints.Get(id)
	if !held {
		return fmt.Errorf("gossip: no announcement of %v to reach it at", id.ShortString())
	}
	ctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()
	addrs := n.gossipAddrs(e)
	if n.opts.OverlayOnly {
		addrs = nil
	}
	if n.opts.OverlayAddrs != nil {
		addrs = append(addrs, n.opts.OverlayAddrs(id)...)
	}
	err := fmt.Errorf("gossip: no address to reach %v at", id.ShortString())
	for _, addr := range addrs {
		if ctx.Err() != nil {
			break
		}
		if _, err = n.syncOnce(ctx, addr, sessionOpts{initiator: true, peerID: id, extra: records}); err == nil {
			return nil
		}
	}
	return err
}

// withExtra appends records to a records frame, after those already in it,
// within the frame's byte budget: all of them, or an error.
func withExtra(f *frame, extra [][]byte) error {
	used := recordBytes(f)
	for _, b := range extra {
		used += len(b)
	}
	if len(f.Records)+len(extra) > MaxRecordsPerFrame || used > maxRecordBytesPerFrame {
		return fmt.Errorf("gossip: %d records to hand over do not fit one frame", len(extra))
	}
	f.Records = append(f.Records, extra...)
	return nil
}

// CatchUpWith runs one catch-up session against a peer, whatever epochs this
// node holds.
func (n *Node) CatchUpWith(ctx context.Context, addr netip.AddrPort) error {
	ctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()
	return n.catchUpWith(ctx, addr, types.Identity{}, nil)
}

func (n *Node) catchUpWith(ctx context.Context, addr netip.AddrPort, peerID types.Identity, unanswered error) error {
	if n.opts.CatchUp == nil {
		if unanswered == nil {
			return errors.New("gossip: this node holds no keys to ask for a catch-up with")
		}
		return unanswered
	}
	_, err := n.syncOnce(ctx, addr, sessionOpts{initiator: true, peerID: peerID, catchUp: true})
	switch {
	case err != nil && unanswered != nil && errors.Is(err, errNoCatchUp):
		return fmt.Errorf("%w, nor a catch-up", unanswered)
	case unanswered != nil && errors.As(err, new(dialError)):
		// The session before it connected.
		return fmt.Errorf("%w; the catch-up: %v", unanswered, err)
	}
	return err
}

// errNoEpochHeld is a node whose keyring is empty, which only a catch-up
// helps.
var errNoEpochHeld = errors.New("this node holds no epoch secret, so it cannot gossip; " +
	"it is not a member of the epoch its log resolves to")

// errNoHelloBack is a peer that closed after this node's hello, unanswered.
var errNoHelloBack = errors.New("the peer did not answer the hello")

// A dialError is a session that never connected.
type dialError struct{ err error }

func (e dialError) Error() string { return e.err.Error() }

func (e dialError) Unwrap() error { return e.err }

func (n *Node) syncOnce(ctx context.Context, addr netip.AddrPort, so sessionOpts) (uint64, error) {
	dctx, cancel := context.WithTimeout(ctx, n.dialTimeout)
	c, err := n.opts.Dial(dctx, addr)
	cancel()
	if err != nil {
		return 0, fmt.Errorf("gossip: dialing %v: %w", addr, dialError{err})
	}
	defer c.Close()
	// Unblock the session's blocking reads and writes when the context ends;
	// a peer that accepts a connection and then says nothing must not hold
	// this goroutine past the timeout.
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	used, err := n.session(c, so)
	if err != nil {
		return used, fmt.Errorf("gossip: session with %v: %w", addr, err)
	}
	return used, nil
}

// olderEpoch returns the newest epoch this node holds below e.
func (n *Node) olderEpoch(e uint64) (uint64, bool) {
	held := n.opts.Keyring.Epochs()
	for i := len(held) - 1; i >= 0; i-- {
		if held[i] < e {
			return held[i], true
		}
	}
	return 0, false
}

// Sync runs one round against every peer it can reach, concurrently, and
// returns how many sessions succeeded. Failures are logged, not returned: a
// peer being asleep is the common case.
func (n *Node) Sync(ctx context.Context, peers []types.Identity) int {
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		ok    int
		slots = make(chan struct{}, maxOutboundSessions)
	)
	for _, id := range peers {
		if id == n.opts.Self {
			continue
		}
		e, held := n.opts.Endpoints.Get(id)
		if !held {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				return
			}
			// One session's worth of time across all a peer's addresses.
			// Without the budget, an announcement of unreachable addresses
			// costs every member a full timeout each — a connection flood
			// aimed wherever the announcer likes.
			pctx, cancel := context.WithTimeout(ctx, n.timeout)
			defer cancel()
			// Announced addresses are tried in order and the round stops at
			// the first that completes: they are alternative paths to one
			// peer, not several peers.
			addrs := n.gossipAddrs(e)
			if n.opts.OverlayOnly {
				addrs = nil
			}
			if n.opts.OverlayAddrs != nil {
				// Last, not first: a peer's overlay address is only routable
				// once the tunnel is up, and a TCP connect into a tunnel that
				// is not would spend the whole per-peer budget waiting rather
				// than failing.
				addrs = append(addrs, n.opts.OverlayAddrs(id)...)
			}
			why := FailUnconnected
			defer func() { n.noteRound(id, why) }()
			for _, addr := range addrs {
				if pctx.Err() != nil {
					return
				}
				if err := n.SyncWith(pctx, addr, id); err != nil {
					n.logf("%v", err)
					// The last address, the overlay's where there is one,
					// says how the round failed, unless a peer said it is
					// newer.
					switch {
					case errors.Is(err, ErrCatchUpRefused):
						// Its log's answer, whichever address it came by.
						why = FailRefused
						return
					case errors.Is(err, errNewerFrame):
						why = FailNewer
					case why == FailNewer:
					case errors.As(err, new(dialError)):
						why = FailUnconnected
					default:
						why = FailOther
					}
					continue
				}
				why = 0
				mu.Lock()
				ok++
				mu.Unlock()
				return
			}
		}()
	}
	wg.Wait()
	return ok
}

// A Failure is why a round completed no session with a peer; zero for one
// that did.
type Failure uint8

func (n *Node) noteRound(id types.Identity, why Failure) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if why == 0 {
		delete(n.failing, id)
		return
	}
	n.failing[id] = why
}

// Failed is why the last round Sync ran against the peer completed no
// session; zero where it completed one.
func (n *Node) Failed(id types.Identity) Failure {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.failing[id]
}

// Failing reports whether the last round Sync ran against the peer completed
// no session.
func (n *Node) Failing(id types.Identity) bool { return n.Failed(id) != 0 }

// Refused reports whether the last round Sync ran against the peer ended in
// its log refusing this node a catch-up.
func (n *Node) Refused(id types.Identity) bool { return n.Failed(id) == FailRefused }

const (
	FailOther Failure = iota + 1
	// FailUnconnected: the last address tried took no connection.
	FailUnconnected
	// FailNewer: the peer sent a frame this build cannot read.
	FailNewer
	// FailRefused: its log refused this node a catch-up.
	FailRefused
)
