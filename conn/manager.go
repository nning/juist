// Package conn turns membership state — authorized peers with keys and overlay
// addresses — into live WireGuard tunnels. Nothing here is trust-critical: it
// may delay or deny connectivity, but it cannot change who is a member, and
// cryptokey routing below it stops it reading or altering traffic.
package conn

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"go4.org/mem"
	"tailscale.com/types/key"
)

// ErrPortTaken reports a requested UDP port another socket already holds.
var ErrPortTaken = errors.New("the port is taken")

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

	// Addrs are the peer's overlay addresses as recorded in the log, and
	// become its WireGuard AllowedIPs. Every prefix must be a single host
	// address: AllowedIPs also authorize the source addresses a peer may
	// originate, so a wider one would let it impersonate other members.
	Addrs []netip.Prefix

	// Routes are prefixes outside the overlay the peer carries for this node:
	// sent to it, and accepted from it as sources. They overlap no peer's
	// address or routes and no address of this node's; the caller leaves the
	// overlay out. Subnets are carried the same way, and routed into the
	// tunnel by the host's own routes too; Routes, the internet an exit
	// node carries, only as [Egress] says.
	Routes  []netip.Prefix
	Subnets []netip.Prefix

	// Endpoints are last-known reachable UDP endpoints for the peer, from
	// gossiped endpoint records or the persistent cache. Hints only: disco
	// discovers and verifies the working path itself.
	Endpoints []netip.AddrPort

	// HomeRelay is the relay region the peer says it can be reached through,
	// or zero for none. It is the peer's own choice — a packet sent to any
	// other region is dropped, since member relays are not meshed — so it
	// travels in the peer's announcement rather than being decided here.
	// Where this node is walled and does not reach it, what goes to the peer
	// goes to this node's own home instead.
	HomeRelay int

	// Walled says the peer reaches named relays alone, as [Manager.Walled]
	// says of this node: unless saving battery, this node keeps its
	// connection to the peer's home open, where the peer sends to it.
	Walled bool

	// Access is what the peer may open on this node and this node on it;
	// nil leaves it to the filter, which takes anything from a member.
	Access *Access

	// PSK is the preshared key every handshake with the peer mixes in, zero
	// for none. A change keeps the session and takes effect at the next
	// handshake, which fails unless the peer holds the same key.
	PSK [32]byte
}

// Self is the local node's identity and overlay addressing. Addrs follows the
// same contract as [Peer.Addrs]: single host addresses only.
type Self struct {
	ID       uint64
	NodeKey  key.NodePrivate
	DiscoKey key.DiscoPrivate
	Addrs    []netip.Prefix
}

// Manager owns the data plane and the NAT-traversal machinery. SetPeers is the
// only way membership enters this layer, and a peer absent from the set cannot
// complete a WireGuard handshake.
type Manager interface {
	// SetPeers makes the data plane reflect exactly the given peer set, which
	// may include the local node itself; that entry must match Self and is
	// otherwise ignored. After Close it returns an error.
	SetPeers(peers []Peer) error

	// SetSelf gives the running data plane this node's new key or
	// addresses; its ID and disco key stay. Under a new key every peer
	// handshakes again; what comes under its old sessions is taken until
	// they expire.
	SetSelf(s Self) error

	// SetEgress says where traffic bound outside the overlay goes, and with
	// isolate, answers to connections that came in by another device too.
	// Only a node with a device of its own routes it; EgressTunnel and
	// EgressRefused return an error where the platform cannot.
	SetEgress(e Egress, isolate bool) error

	// AnswersThrough says why answers to connections that came in by another
	// device would go through the exit node though not isolated, as where
	// the host's own firewall decides; "" where they leave the way they came.
	AnswersThrough() string

	// SetServe says what this node forwards for its peers out of the overlay,
	// masquerading their sources, where the platform can.
	SetServe(s Serve) error

	// HostRoutes is what the host reaches but by its default routes: the
	// networks of its interfaces, and its routes in the main table,
	// tailscaled's and lower juist instances', but for those DHCP or router
	// advertisements pushed.
	HostRoutes() []netip.Prefix

	// SetRelays makes the data plane reflect exactly the given relay set: the
	// fallback path for a pair that cannot be punched, and the channel over
	// which the NAT-traversal layer asks a peer to punch back. An empty set
	// is direct-only. Regions must be unique.
	SetRelays(relays []Relay) error

	// HomeRelay reports the relay region this node has chosen to be reached
	// through, or zero if it has none yet. Peers must be told, so it belongs
	// in this node's announcement.
	HomeRelay() int

	// ReachesRelay reports whether region is this node's home relay, or one
	// its last measurement of the relays reached.
	ReachesRelay(region int) bool

	// Walled reports whether this node reaches member relays by TCP alone,
	// and not all of them, as on a network passing 443 alone: peers homed
	// where it does not reach are sent to at its own home, so it must
	// announce that, by announcing no address.
	Walled() bool

	// NotAtHome reports the peers this node's home relay said were not
	// connected to it when sent to, by [Peer.ID], with when it last said so.
	NotAtHome() map[uint64]time.Time

	// LocalEndpoints reports the underlay addresses the NAT-traversal layer
	// believes this node can be reached at, including reflexive ones learned
	// from a relay's STUN responder. It is empty until there is a relay to
	// learn them from.
	LocalEndpoints() []netip.AddrPort

	// LocalPort reports the UDP port the manager is bound to.
	LocalPort() uint16

	// Ping sends an overlay ICMP echo to ip and reports to cb, possibly from
	// another goroutine. cb may never be invoked, so callers need their own
	// timeout. Diagnostics and tests only.
	Ping(ip netip.Addr, cb func(PingResult))

	// Echo sends ip a TSMP ping, which the peer's data plane answers past
	// its host's firewall and stack, and reports the round trip to cb,
	// possibly from another goroutine. cb may never be invoked.
	Echo(ip netip.Addr, cb func(PingResult))

	// Tunnels reports what each installed peer's WireGuard session has done,
	// keyed by [Peer.ID].
	Tunnels() map[uint64]Tunnel

	// Probe sends the peer at overlay address ip a message its data plane
	// answers itself, past any host firewall, and reports to cb whether the
	// answer came within timeout. cb is called once, possibly from another
	// goroutine.
	Probe(ip netip.Addr, timeout time.Duration, cb func(answered bool))

	// ProbeQuietly is Probe by a ping that starts no heartbeat, for a peer
	// that rests or while this node saves battery.
	ProbeQuietly(ip netip.Addr, timeout time.Duration, cb func(answered bool))

	// SetSaving has the data plane save battery, measuring and keeping its
	// paths less often.
	SetSaving(saving bool)

	// NetworkChanged tells the data plane that the host's networks changed,
	// where its monitor would not notice, so that it finds its paths again.
	NetworkChanged()

	// Close shuts the manager down and releases the data plane. It is
	// idempotent.
	Close() error
}

// PingResult reports the outcome of a [Manager.Ping], as this package's own
// type so the seam stays free of the backing implementation's. It carries no
// path information, because the engine's ICMP path reports none.
type PingResult struct {
	// Err is a human-readable failure, empty on success.
	Err string

	// Latency is the round-trip time, zero if unknown.
	Latency time.Duration
}

// A Tunnel is what the data plane knows of one peer's WireGuard session.
type Tunnel struct {
	// LastHandshake is when a handshake last completed, zero if none has.
	LastHandshake time.Time

	// Direct is the UDP path the tunnel uses, invalid where it has none and
	// runs through a relay if at all.
	Direct netip.AddrPort
}

// Key conversions from the raw 32-byte form the log and gossip carry, so this
// package stays the only one naming Tailscale's types. None can fail: 32 bytes
// are a valid Curve25519 scalar or point by construction.
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

// NewDiscoKey draws a fresh NAT-traversal keypair in the raw form gossip
// announces. The scalar must be clamped for NaCl box and [DiscoKeyFromRaw32]
// does not clamp, so clamping after deriving the public half would announce an
// unreachable key.
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
