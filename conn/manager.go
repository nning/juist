// Package conn is the connectivity layer: it turns membership state — a set of
// authorized peers with keys and overlay addresses — into live WireGuard
// tunnels.
//
// Nothing in this package is trust-critical. Per docs/04-architecture.md, the
// connectivity layer may delay or deny connectivity, but it can never change
// who is a member, and it cannot read or alter traffic: WireGuard's cryptokey
// routing enforces that below it. The [Manager] interface is deliberately
// narrow so the Tailscale-backed implementation can be swapped for a minimal
// from-scratch disco manager if the fork burden ever outweighs the benefit.
package conn

import (
	"net/netip"
	"time"

	"tailscale.com/types/key"
)

// Peer is the subset of a member's log state that the connectivity layer needs.
// It is derived from membership records by the reconciler; this package never
// decides who belongs in the set.
type Peer struct {
	// ID is a stable non-zero identifier for the peer, unique within the
	// network. The Tailscale-backed manager maps it to a tailcfg.NodeID.
	ID uint64

	// NodeKey is the peer's WireGuard static public key.
	NodeKey key.NodePublic

	// DiscoKey is the peer's NAT-traversal (disco) public key.
	DiscoKey key.DiscoPublic

	// Addrs are the peer's overlay addresses, as recorded in the log. They
	// become the peer's WireGuard AllowedIPs, so this field — and only this
	// field — is what binds an overlay address to a key.
	//
	// Every prefix must be a single host address (/32 or /128): AllowedIPs
	// also authorizes the *source* addresses a peer may originate, so a
	// wider prefix would let this peer impersonate other members. Routed
	// prefixes are a post-v1 feature with their own quorum-granted path
	// (docs/04-architecture.md, SetNodeRoutes).
	Addrs []netip.Prefix

	// Endpoints are last-known reachable UDP endpoints for the peer, from
	// gossiped endpoint records or the persistent cache. Hints only: disco
	// discovers and verifies the working path itself.
	Endpoints []netip.AddrPort
}

// Self is the local node's identity and overlay addressing. Addrs follows the
// same contract as [Peer.Addrs]: single host addresses only.
type Self struct {
	ID       uint64
	NodeKey  key.NodePrivate
	DiscoKey key.DiscoPrivate
	Addrs    []netip.Prefix
}

// Manager owns the data plane and the NAT-traversal machinery.
//
// SetPeers is the only way membership enters this layer: the reconciler calls
// it with the full authorized set, and the manager makes the data plane match.
// A peer absent from the set cannot complete a WireGuard handshake.
type Manager interface {
	// SetPeers makes the data plane reflect exactly the given peer set. The
	// set may include the local node itself (the reconciler passes the full
	// membership); that entry must match Self and is otherwise ignored.
	// After Close, SetPeers returns an error.
	SetPeers(peers []Peer) error

	// LocalPort reports the UDP port the manager is bound to.
	LocalPort() uint16

	// Ping sends an overlay ICMP echo to ip and reports the result to cb,
	// possibly from another goroutine. cb may never be invoked — the engine
	// drops the callback if no reply arrives within its own expiry, and a
	// manager shutting down drops the echo silently — so callers apply
	// their own timeout. Used by diagnostics and tests.
	Ping(ip netip.Addr, cb func(PingResult))

	// Close shuts the manager down and releases the data plane. It is
	// idempotent.
	Close() error
}

// PingResult reports the outcome of a [Manager.Ping]. It is this package's
// own type so that the Manager seam stays free of the backing
// implementation's diagnostic types.
//
// It deliberately carries no path information (endpoint, relay): the ICMP
// ping path in the embedded engine never reports any, so a field for it
// would always be empty — a promise the seam cannot keep. The direct-only
// property is asserted where it actually lives, in the egress test's
// relay-connection and socket checks.
type PingResult struct {
	// Err is a human-readable failure, empty on success.
	Err string

	// Latency is the round-trip time, zero if unknown.
	Latency time.Duration
}
