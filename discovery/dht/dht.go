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
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"time"

	anacrolix "github.com/anacrolix/dht/v2"
	"github.com/anacrolix/dht/v2/bep44"
	"github.com/anacrolix/dht/v2/exts/getput"
	"github.com/anacrolix/dht/v2/krpc"
	alog "github.com/anacrolix/log"
	"github.com/anacrolix/torrent/bencode"
	"golang.org/x/time/rate"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/aead"
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

	// MaxLookupsPerRound bounds how many members one round looks for. A
	// storage node sees this node's queries, so asking for everything at once
	// would tell it how many members are missing; asking for a few, in
	// random order, tells it much less and still converges.
	MaxLookupsPerRound = 4

	// MaxValueSize is BEP 44's limit on an item's value.
	MaxValueSize = 1000

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
	Keyring *secrets.Keyring

	// Announce returns this node's current signed announcement, or false if
	// it has none to make.
	Announce func() (gossip.Endpoint, bool)

	// Wanted returns the members this node has no announcement for. Only
	// these are looked up: a query is visible to whichever storage node
	// answers it, so asking for a member already known would spend privacy
	// on nothing.
	Wanted func() []types.Identity

	// OnPeer receives each announcement found, already verified.
	OnPeer func(gossip.Endpoint)

	// Bootstrap overrides the public DHT routers a fresh node starts from.
	// Tests pass a private swarm's addresses.
	Bootstrap []string

	// Conn is the UDP socket to run on. Nil binds one.
	Conn net.PacketConn

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

// A Node publishes this member's announcement and looks for others'.
type Node struct {
	opts     Options
	srv      *anacrolix.Server
	interval time.Duration

	closeOnce sync.Once
	closed    chan struct{}
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

	conn := opts.Conn
	if conn == nil {
		var err error
		conn, err = net.ListenPacket("udp", ":0")
		if err != nil {
			return nil, fmt.Errorf("dht: binding a UDP socket: %w", err)
		}
	}
	cfg := anacrolix.NewDefaultServerConfig()
	cfg.Conn = conn
	cfg.NoSecurity = opts.NoSecurity
	// Its own send budget rather than the library's process-global one. That
	// one is shared by every DHT server in the process and sized for a
	// torrent client; sharing it means another node's burst silently costs
	// this one its replies, which look exactly like an unreachable peer.
	cfg.SendLimiter = rate.NewLimiter(sendRate, sendBurst)
	// The library logs to the standard logger by default, which in a daemon
	// means DHT chatter on stderr no operator asked for.
	cfg.Logger = alog.Default.FilterLevel(alog.Critical)
	if len(opts.Bootstrap) > 0 {
		addrs := opts.Bootstrap
		cfg.StartingNodes = func() ([]anacrolix.Addr, error) { return resolveAll(addrs) }
	}
	srv, err := anacrolix.NewServer(cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("dht: starting the DHT node: %w", err)
	}
	n := &Node{
		opts:     opts,
		srv:      srv,
		interval: cmpOr(opts.Interval, DefaultInterval),
		closed:   make(chan struct{}),
	}
	return n, nil
}

func resolveAll(hostPorts []string) ([]anacrolix.Addr, error) {
	out := make([]anacrolix.Addr, 0, len(hostPorts))
	for _, hp := range hostPorts {
		ua, err := net.ResolveUDPAddr("udp", hp)
		if err != nil {
			continue
		}
		out = append(out, anacrolix.NewAddr(ua))
	}
	if len(out) == 0 {
		return nil, errors.New("dht: no bootstrap address resolved")
	}
	return out, nil
}

func cmpOr[T comparable](v, fallback T) T {
	var zero T
	if v == zero {
		return fallback
	}
	return v
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

	if _, err := n.srv.Bootstrap(); err != nil {
		n.opts.Logf("dht: bootstrap: %v", err)
	}
	t := time.NewTicker(n.interval)
	defer t.Stop()
	for {
		n.Round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Round is one publish-and-look cycle, exported so a test can drive it without
// waiting out an interval.
func (n *Node) Round(ctx context.Context) {
	if err := n.Publish(ctx); err != nil {
		n.opts.Logf("dht: publishing this node's announcement: %v", err)
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
	for _, id := range wanted {
		if ctx.Err() != nil {
			return
		}
		e, err := n.Lookup(ctx, id)
		if err != nil {
			continue
		}
		n.opts.OnPeer(e)
	}
}

// window is the coarse clock bucket a rendezvous address is derived for.
func (n *Node) window() uint64 {
	now := time.Now()
	if n.opts.Clock != nil {
		now = n.opts.Clock()
	}
	return uint64(now.Unix()) / uint64(WindowPeriod.Seconds())
}

// Publish puts this node's announcement at its own rendezvous address, under
// the newest epoch it holds. It publishes under one epoch and looks under
// every one, so that a member and a peer an epoch apart still meet: whichever
// of them is behind is the one that finds the other.
func (n *Node) Publish(ctx context.Context) error {
	e, ok := n.opts.Announce()
	if !ok {
		return nil
	}
	epoch, secret, ok := n.opts.Keyring.Latest()
	if !ok {
		return errors.New("dht: no epoch secret to publish under")
	}
	value, err := sealAnnouncement(secret, epoch, e)
	if err != nil {
		return err
	}
	priv := ed25519.NewKeyFromSeed(seedFor(secret, epoch, n.window(), n.opts.Self))
	target := bep44.MakeMutableTarget([32]byte(priv.Public().(ed25519.PublicKey)), nil)
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	_, err = getput.Put(ctx, target, n.srv, nil, func(seq int64) bep44.Put {
		put := bep44.Put{
			V:   value,
			K:   (*[32]byte)([]byte(priv.Public().(ed25519.PublicKey))),
			Seq: seq + 1,
		}
		put.Sign(priv)
		return put
	})
	if err != nil {
		return fmt.Errorf("dht: putting this node's announcement: %w", err)
	}
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
		for _, w := range [2]uint64{cur, cur - 1} {
			priv := ed25519.NewKeyFromSeed(seedFor(secret, epoch, w, id))
			target := bep44.MakeMutableTarget([32]byte(priv.Public().(ed25519.PublicKey)), nil)
			res, err := n.get(ctx, target)
			if err != nil {
				lastErr = err
				continue
			}
			var raw []byte
			if err := bencode.Unmarshal(res.V, &raw); err != nil {
				lastErr = fmt.Errorf("dht: item for %v is not a byte string: %w", id.ShortString(), err)
				continue
			}
			e, err := openAnnouncement(n.opts.Keyring, raw)
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

// get is one bounded traversal.
func (n *Node) get(ctx context.Context, target bep44.Target) (getput.GetResult, error) {
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	res, _, err := getput.Get(ctx, target, n.srv, nil, nil)
	return res, err
}

// seedFor is the rendezvous key one member's announcement lives under.
func seedFor(s secrets.Secret, epoch, window uint64, subject types.Identity) []byte {
	seed := s.TopicSeed(epoch, window, subject)
	return seed[:]
}

// sealAnnouncement encodes and seals an announcement for publication. The
// size check is not a formality: a member whose announcement grew past BEP
// 44's limit would be silently unpublishable.
func sealAnnouncement(s secrets.Secret, epoch uint64, e gossip.Endpoint) ([]byte, error) {
	body, err := e.Encode()
	if err != nil {
		return nil, err
	}
	value, err := aead.Seal(s.DiscoveryKey(epoch), epoch, body)
	if err != nil {
		return nil, fmt.Errorf("dht: sealing an announcement: %w", err)
	}
	if len(value) > MaxValueSize {
		return nil, fmt.Errorf("dht: sealed announcement is %d bytes, over BEP 44's %d-byte limit",
			len(value), MaxValueSize)
	}
	return value, nil
}

// openAnnouncement opens and verifies a published announcement.
func openAnnouncement(kr *secrets.Keyring, blob []byte) (gossip.Endpoint, error) {
	epoch, err := aead.Epoch(blob)
	if err != nil {
		return gossip.Endpoint{}, fmt.Errorf("dht: %w", err)
	}
	s, ok := kr.Secret(epoch)
	if !ok {
		return gossip.Endpoint{}, fmt.Errorf("dht: item is sealed under epoch %d, which this node does not hold", epoch)
	}
	body, err := aead.Open(s.DiscoveryKey(epoch), blob)
	if err != nil {
		return gossip.Endpoint{}, fmt.Errorf("dht: opening a published announcement: %w", err)
	}
	return gossip.DecodeEndpoint(body)
}

// Addr reports the UDP address this node's DHT socket is bound to.
func (n *Node) Addr() net.Addr { return n.srv.Addr() }

// ID reports this node's DHT identifier, for tests.
func (n *Node) ID() krpc.ID { return n.srv.ID() }

// Close shuts the node down. It is idempotent.
func (n *Node) Close() error {
	n.closeOnce.Do(func() {
		close(n.closed)
		n.srv.Close()
	})
	return nil
}
