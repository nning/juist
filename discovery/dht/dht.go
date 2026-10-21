// Package dht is the cold-start rendezvous: how two members that are not on
// one another's LAN, and have no cached address for each other, meet at all.
//
// It publishes each member's signed endpoint announcement as a BEP 44 mutable
// item in the public BitTorrent DHT, at an address only a holder of the epoch
// group secret can compute, with a payload only a holder of it can read. The
// DHT is a transport and not a party: it cannot recognize the network, read an
// announcement, or say who is a member — the log alone does that, and every
// announcement carries its author's signature.
//
// Nothing here is trust-critical. The worst a hostile DHT can do is deny
// rendezvous, which costs connectivity to peers this node cannot reach any
// other way.
package dht

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anacrolix/dht/v2/krpc"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/aead"
	"github.com/nning/juist/internal/keyring"
	"github.com/nning/juist/internal/malformed"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

const (
	// WindowPeriod is how long one rendezvous address lasts. Rotating it
	// bounds how long an address that leaked — from a device seized with its
	// secrets, say — keeps naming a place members will be.
	WindowPeriod = time.Hour

	// DefaultInterval is how often this node republishes and looks. BEP 44
	// items expire in about two hours on a well-behaved node, so republishing
	// well inside that is what keeps a member findable.
	DefaultInterval = 10 * time.Minute

	// OperationTimeout bounds one publish or one lookup. A traversal ends
	// when it stalls, which is normally seconds, but a round must not be able
	// to outlive its own interval — a stuck one would stop this node
	// republishing, and an item that is not republished expires.
	OperationTimeout = 30 * time.Second

	// KickGap is the least time between the start of one round and a round a
	// [Node.Kick] brings forward, so that members going down together, or a
	// flapping link, cost one round rather than one each.
	KickGap = 15 * time.Second

	// MaxLookupsPerRound bounds how many members one round looks for. A
	// storage node sees this node's queries, so asking for everything at once
	// would tell it how many members are missing; asking for a few, in
	// random order, tells it much less and still converges.
	MaxLookupsPerRound = 4

	// MaxValueSize is BEP 44's limit on an item's value: 1000 bytes
	// bencoded, the "996:" before it included.
	MaxValueSize = 996

	// sendRate and sendBurst bound what this node puts on the wire, matching
	// the library's own defaults. Rendezvous is a handful of queries every
	// few minutes, so the budget is here to stop a bug becoming abuse rather
	// than to shape normal traffic.
	sendRate  = 250
	sendBurst = 25
)

// Options configures a [Node].
type Options struct {
	// Self is this device's identity, whose announcement is published.
	Self types.Identity

	// Keyring holds the epoch secrets. Publication uses the newest; lookups
	// try each, so a member an epoch behind can still be found.
	Keyring *keyring.Keyring

	// Announce returns this node's current signed announcement, or false if
	// it has none to make.
	Announce func() (gossip.Endpoint, bool)

	// Wanted returns the members to look up: those this node has no
	// announcement for or cannot reach. Only these are looked up: a query is
	// visible to whichever storage node answers it, so asking for a member
	// already reachable would spend privacy on nothing.
	Wanted func() []types.Identity

	// OnPeer receives each announcement found, already verified.
	OnPeer func(gossip.Endpoint)

	// Ask, where set, is asked for each wanted member before the DHT, and
	// reports whether it found news of it: a member relay, which learns
	// from the question nothing it does not hold.
	Ask func(ctx context.Context, id types.Identity) bool

	// Seeks, where set, reports whether this node asks the DHT after
	// members this round; nil is always. It still publishes.
	Seeks func() bool

	// Joins, where set, reports whether this node takes part in the DHT
	// this round, publishing and looking; nil is always. Ask is asked
	// either way, and a node that never takes part never bootstraps.
	Joins func() bool

	// Bootstrap overrides the public DHT routers a fresh node starts from.
	// Tests pass a private swarm's addresses.
	Bootstrap []string

	// Conn is the UDP socket to run on. Nil binds one.
	Conn net.PacketConn

	// Items, where set, holds the announcements instead of the public DHT,
	// which is then not joined at all.
	Items Items

	// NoSecurity disables the DHT's node-ID-from-IP rule, which a swarm on
	// loopback cannot satisfy. Tests only.
	NoSecurity bool

	// Interval overrides [DefaultInterval].
	Interval time.Duration

	// Clock overrides time.Now, for tests.
	Clock func() time.Time

	// Logf receives diagnostics. Nil discards them.
	Logf func(format string, args ...any)
}

// Items keeps one sealed announcement at each seed's address, as [Store]
// does in the public DHT.
type Items interface {
	Put(ctx context.Context, seed [32]byte, value []byte) error
	Get(ctx context.Context, seed [32]byte) ([]byte, error)
	Close() error
}

// A Node publishes this member's announcement and looks for others'.
type Node struct {
	opts     Options
	store    *Store // the public DHT's, nil where Items replaces it
	items    Items
	interval time.Duration

	closeOnce sync.Once
	closed    chan struct{}
	kick      chan struct{}
	joined    atomic.Bool // in the last round

	// published is what was last put, under which epoch and when; a round
	// brought forward does not put the same announcement again.
	publishMu      sync.Mutex
	published      *gossip.Endpoint
	publishedEpoch uint64
	publishedWhen  time.Time
}

// New starts a DHT node. Bootstrapping happens in the background: a network
// with no internet finds nobody here and loses nothing, since the LAN and
// gossip paths are unaffected.
func New(opts Options) (*Node, error) {
	switch {
	case opts.Self.IsZero():
		return nil, errors.New("dht: Self is required")
	case opts.Keyring == nil:
		return nil, errors.New("dht: Keyring is required")
	case opts.Announce == nil:
		return nil, errors.New("dht: Announce is required")
	case opts.Wanted == nil:
		return nil, errors.New("dht: Wanted is required")
	case opts.OnPeer == nil:
		return nil, errors.New("dht: OnPeer is required")
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}

	items := opts.Items
	var store *Store
	if items == nil {
		var err error
		if store, err = newStore(opts.Conn, opts.Bootstrap, opts.NoSecurity); err != nil {
			return nil, err
		}
		items = store
	}
	n := &Node{
		opts:     opts,
		store:    store,
		items:    items,
		interval: cmp.Or(opts.Interval, DefaultInterval),
		closed:   make(chan struct{}),
		kick:     make(chan struct{}, 1),
	}
	return n, nil
}

// Run publishes and looks until ctx is cancelled or [Node.Close] is called.
func (n *Node) Run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-n.closed:
			cancel()
		case <-ctx.Done():
		}
	}()

	t := time.NewTicker(n.interval)
	defer t.Stop()
	early := false
	for {
		started := time.Now()
		n.round(ctx, early)
		early = false
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-n.kick:
			early = true
			if wait := KickGap - time.Since(started); wait > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
			}
		}
	}
}

// Kick runs a round soon rather than at the next interval, as for a member
// just admitted, whose announcement nobody holds yet, or one whose tunnel just
// went down. Kicks while one is pending are one kick, and none comes sooner
// than [KickGap] after the last round started.
func (n *Node) Kick() {
	select {
	case n.kick <- struct{}{}:
	default:
	}
}

// Round is one publish-and-look cycle, exported so a test can drive it without
// waiting out an interval.
func (n *Node) Round(ctx context.Context) { n.round(ctx, false) }

// round is [Node.Round]; early says a [Node.Kick] brought it forward, which
// puts this node's announcement only if it says something new. A round on
// the interval always puts, so the item stays alive and freshly signed.
func (n *Node) round(ctx context.Context, early bool) {
	joins := n.opts.Joins == nil || n.opts.Joins()
	if n.joined.Swap(joins) != joins && joins {
		n.bootstrap()
	}
	if joins {
		if err := n.publish(ctx, early); err != nil {
			n.opts.Logf("dht: publishing this node's announcement: %v", err)
		}
	}
	wanted := n.opts.Wanted()
	if len(wanted) == 0 {
		return
	}
	// Random order and a small bound: what a storage node learns from a
	// query is that someone asked for one opaque address, and a node that
	// asked for all of its missing peers at once would turn that into a
	// count.
	rand.Shuffle(len(wanted), func(i, j int) { wanted[i], wanted[j] = wanted[j], wanted[i] })
	if len(wanted) > MaxLookupsPerRound {
		wanted = wanted[:MaxLookupsPerRound]
	}
	seeks := joins && (n.opts.Seeks == nil || n.opts.Seeks())
	for _, id := range wanted {
		if ctx.Err() != nil {
			return
		}
		if n.opts.Ask != nil && n.opts.Ask(ctx, id) || !seeks {
			continue
		}
		e, err := n.Lookup(ctx, id)
		if err != nil {
			n.opts.Logf("dht: looking up %v: %v", id.ShortString(), err)
			continue
		}
		n.opts.OnPeer(e)
	}
}

// bootstrap joins the public DHT, as this node takes part after a round it
// did not: the routing table of one that stayed away is stale.
func (n *Node) bootstrap() {
	if n.store == nil {
		return
	}
	if _, err := n.store.srv.Bootstrap(); err != nil {
		n.opts.Logf("dht: bootstrap: %v", err)
	}
}

// window is the coarse clock bucket a rendezvous address is derived for.
func (n *Node) window() uint64 {
	now := time.Now()
	if n.opts.Clock != nil {
		now = n.opts.Clock()
	}
	return Window(now)
}

// Publish puts this node's announcement at its own rendezvous address, under
// the newest epoch it holds. It publishes under one epoch and looks under
// every one, so that a member and a peer an epoch apart still meet: whichever
// of them is behind is the one that finds the other.
func (n *Node) Publish(ctx context.Context) error { return n.publish(ctx, false) }

func (n *Node) publish(ctx context.Context, early bool) error {
	e, ok := n.opts.Announce()
	if !ok {
		return nil
	}
	epoch, secret, ok := n.opts.Keyring.Latest()
	if !ok {
		return errors.New("dht: no epoch secret to publish under")
	}
	n.publishMu.Lock()
	same := early && n.published != nil && n.published.SameAs(&e) && epoch == n.publishedEpoch &&
		time.Since(n.publishedWhen) < n.interval
	n.publishMu.Unlock()
	if same {
		return nil
	}
	value, err := sealAnnouncement(secret, epoch, e)
	if err != nil {
		return err
	}
	if err := n.items.Put(ctx, secret.TopicSeed(epoch, n.window(), n.opts.Self), value); err != nil {
		return fmt.Errorf("dht: putting this node's announcement: %w", err)
	}
	n.publishMu.Lock()
	n.published, n.publishedEpoch, n.publishedWhen = e.Clone(), epoch, time.Now()
	n.publishMu.Unlock()
	return nil
}

// Lookup finds one member's announcement. It tries every epoch this node
// holds, newest first, and the previous window as well as the current one: a
// publisher republishes on its own interval, so for a few minutes after a
// rollover the item that exists is the old one.
func (n *Node) Lookup(ctx context.Context, id types.Identity) (gossip.Endpoint, error) {
	cur := n.window()
	var lastErr error
	// Newest epoch first: the common case is that both sides are current, and
	// the older ones are the fallback for a peer that has not caught up.
	epochs := n.opts.Keyring.Epochs()
	slices.Reverse(epochs)
	for _, epoch := range epochs {
		secret, ok := n.opts.Keyring.Secret(epoch)
		if !ok {
			continue
		}
		windows := []uint64{cur, cur - 1}
		if n.store == nil {
			// A relay answers for a member under each window around its own.
			windows = windows[:1]
		}
		for _, w := range windows {
			raw, err := n.items.Get(ctx, secret.TopicSeed(epoch, w, id))
			if err != nil {
				lastErr = err
				continue
			}
			e, err := openAnnouncement(n.opts.Keyring, epoch, raw)
			if err != nil {
				lastErr = err
				continue
			}
			// The item's address proves a holder of the group secret put it
			// there; the signature proves who it is about. Neither implies the
			// other, so both are required.
			if e.Identity != id {
				lastErr = fmt.Errorf("dht: item for %v is about %v", id.ShortString(), e.Identity.ShortString())
				continue
			}
			return e, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("dht: no epoch secret to look under")
	}
	return gossip.Endpoint{}, lastErr
}

// sealAnnouncement encodes and seals an announcement for publication, padded
// to [MaxValueSize], as a hint: without its ML-DSA signature, which does not
// fit. The size check is not a formality: a member whose announcement grew
// past BEP 44's limit would be silently unpublishable.
func sealAnnouncement(s secrets.Secret, epoch uint64, e gossip.Endpoint) ([]byte, error) {
	hint := e.Hint()
	body, err := hint.Encode()
	if err != nil {
		return nil, err
	}
	value, err := aead.SealPadded(s.DiscoveryKey(epoch), epoch, body, MaxValueSize)
	if err != nil {
		return nil, fmt.Errorf("dht: sealing an announcement: %w", err)
	}
	if len(value) > MaxValueSize {
		return nil, fmt.Errorf("dht: sealed announcement is %d bytes, over BEP 44's %d-byte limit",
			len(value), MaxValueSize)
	}
	return value, nil
}

// openAnnouncement opens and verifies an announcement published under epoch.
func openAnnouncement(kr *keyring.Keyring, epoch uint64, blob []byte) (_ gossip.Endpoint, err error) {
	defer malformed.Recover(&err)
	s, ok := kr.Secret(epoch)
	if !ok {
		return gossip.Endpoint{}, fmt.Errorf("dht: no secret for epoch %d", epoch)
	}
	body, err := aead.OpenPadded(s.DiscoveryKey(epoch), epoch, blob)
	if err != nil {
		return gossip.Endpoint{}, fmt.Errorf("dht: opening a published announcement: %w", err)
	}
	return gossip.DecodeEndpoint(body)
}

// Addr reports the UDP address this node's DHT socket is bound to.
func (n *Node) Addr() net.Addr { return n.store.srv.Addr() }

// ID reports this node's DHT identifier, for tests.
func (n *Node) ID() krpc.ID { return n.store.srv.ID() }

// Public reports whether n runs on the public DHT, not on [Options.Items].
func (n *Node) Public() bool { return n.store != nil }

// Window is the rendezvous window t falls in, which with an epoch and a
// member derives where the member is published.
func Window(t time.Time) uint64 { return uint64(t.Unix()) / uint64(WindowPeriod.Seconds()) }

// Close shuts the node down. It is idempotent.
func (n *Node) Close() error {
	n.closeOnce.Do(func() {
		close(n.closed)
		n.items.Close()
	})
	return nil
}
