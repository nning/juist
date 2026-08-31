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
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"time"

	"go4.org/mem"
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

// Key conversions from the raw 32-byte form the membership log and the gossip
// layer carry.
//
// They exist so that this package stays the only one that names Tailscale's
// types, which is what docs/04-architecture.md promises about the adapter: the
// reconciler holds a WireGuard key as the log records it and a disco key as an
// endpoint announcement carries it, and hands both here without importing
// anything from the connectivity stack.
//
// None of these can fail. A 32-byte string is a valid Curve25519 scalar or
// point by construction; whether it is a key anyone holds the other half of is
// a question only a handshake answers.
//
// The private one goes the long way round, through hex, because the direct
// raw-bytes constructor is deprecated upstream and the untyped-hex one is not.
// It runs once per daemon start.
func NodeKeyFromRaw32(b [32]byte) key.NodePrivate {
	k, err := key.ParseNodePrivateUntyped(mem.B([]byte(hex.EncodeToString(b[:]))))
	if err != nil {
		// Unreachable: 32 bytes always encode to 64 valid hex characters,
		// which is exactly what the parser wants.
		panic(fmt.Sprintf("conn: converting a 32-byte WireGuard key failed: %v", err))
	}
	return k
}

// DiscoKeyFromRaw32 converts a raw disco private key.
func DiscoKeyFromRaw32(b [32]byte) key.DiscoPrivate { return key.DiscoPrivateFromRaw32(mem.B(b[:])) }

// NodePublicFromRaw32 converts a peer's WireGuard public key, as the log
// records it.
func NodePublicFromRaw32(b [32]byte) key.NodePublic { return key.NodePublicFromRaw32(mem.B(b[:])) }

// DiscoPublicFromRaw32 converts a peer's disco public key, as its endpoint
// announcement carries it.
func DiscoPublicFromRaw32(b [32]byte) key.DiscoPublic { return key.DiscoPublicFromRaw32(mem.B(b[:])) }

// NewDiscoKey draws a fresh NAT-traversal keypair in the raw form the gossip
// layer announces.
//
// Clamping matches what the connectivity stack's own generator does: a disco
// key is used for NaCl box, so the scalar has to be clamped, and
// [DiscoKeyFromRaw32] does not clamp what it is handed. Generating the key
// here rather than in the daemon is what keeps the two halves guaranteed to
// agree — a private key clamped after its public half was derived would
// announce a key no peer could reach.
func NewDiscoKey() (priv, pub [32]byte, err error) {
	if _, err := rand.Read(priv[:]); err != nil {
		return priv, pub, fmt.Errorf("conn: generating a disco key: %w", err)
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	// crypto/ecdh's X25519 public value is the scalar times the base point,
	// which is exactly what the disco key type derives. TestDiscoKeyAgrees
	// pins that equality.
	k, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return priv, pub, fmt.Errorf("conn: deriving a disco public key: %w", err)
	}
	copy(pub[:], k.PublicKey().Bytes())
	return priv, pub, nil
}
