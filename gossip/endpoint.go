package gossip

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/nning/juist/types"
)

// DiscoKeySize is the length of a NAT-traversal (disco) public key.
const DiscoKeySize = 32

// A DiscoKey is a node's NAT-traversal public key.
//
// It is this package's own type rather than the connectivity stack's, so that
// the adapter in conn stays the only place that touches Tailscale's types
// (docs/04-architecture.md). Converting is a 32-byte copy.
type DiscoKey [DiscoKeySize]byte

// IsZero reports whether the key is unset.
func (k DiscoKey) IsZero() bool { return k == DiscoKey{} }

// MarshalBinary implements [encoding.BinaryMarshaler], so the CBOR codec
// encodes the key as a fixed-length byte string.
func (k DiscoKey) MarshalBinary() ([]byte, error) {
	out := make([]byte, DiscoKeySize)
	copy(out, k[:])
	return out, nil
}

// UnmarshalBinary implements [encoding.BinaryUnmarshaler]. A short or long
// input is an error rather than silent truncation.
func (k *DiscoKey) UnmarshalBinary(b []byte) error {
	if len(b) != DiscoKeySize {
		return fmt.Errorf("gossip: disco key is %d bytes, want %d", len(b), DiscoKeySize)
	}
	copy(k[:], b)
	return nil
}

// MaxEndpointAddrs caps the underlay addresses one announcement may carry.
// A multi-homed laptop has a handful; the limit is only here so that a
// hostile announcement cannot make every member allocate.
const MaxEndpointAddrs = 16

// An Endpoint is a node's connectivity announcement: where to reach it on the
// underlay, and the disco key it will answer NAT-traversal probes with.
//
// # Why this is not a log record
//
// docs/04-architecture.md puts the disco key in the connectivity layer and
// endpoint records in gossip, and the reason is lifetime. A node's underlay
// addresses change when it moves between networks, and its disco key changes
// every time its daemon restarts — the connectivity layer treats a changed
// disco key as exactly that signal (see conn's peerDelta). Membership records
// need a k-of-n admin quorum, so putting either in the log would mean an
// admin ceremony per reboot.
//
// So an Endpoint is signed by the node's own identity key and by nothing else.
// That is the right amount of authority for what it claims: a node may say
// where it is, and no node may say anything about another. Everything an
// Endpoint could lie about costs connectivity and nothing more — a wrong
// address fails to connect, and a wrong disco key fails to complete a disco
// handshake. What it can never do is make its subject a member: the reconciler
// reads the member set from the log and joins the announcements onto it,
// dropping any for a node the log does not carry.
//
// # Ordering
//
// Seq is what makes a replayed announcement lose to the current one. It is the
// author's own counter, so only the author can be harmed by rolling it back,
// and rolling it back only costs the author reachability.
type Endpoint struct {
	// Identity is the announcing node, and the key that signs the record.
	Identity types.Identity `cbor:"1,keyasint"`

	// Disco is the node's current NAT-traversal public key.
	Disco DiscoKey `cbor:"2,keyasint"`

	// Addrs are the underlay UDP endpoints the node's data plane is
	// reachable at. Hints only: disco discovers and verifies the working
	// path itself.
	//
	// The order is canonical (see [Endpoint.StaticValidate]), not a
	// preference: one announcement must have one encoding, and a signature
	// covers the encoding. So a reader must not read the first address as
	// the best one — it is the numerically lowest, which on a host with a
	// bridge or VPN interface is often the least useful.
	Addrs []netip.AddrPort `cbor:"3,keyasint,omitempty"`

	// GossipPort is the TCP port this node accepts anti-entropy sessions
	// on, at each of Addrs' addresses.
	GossipPort uint16 `cbor:"4,keyasint"`

	// Seq orders a node's own announcements. Strictly increasing per node;
	// a record with a lower Seq than one already held is ignored.
	Seq uint64 `cbor:"5,keyasint"`

	// Sig is the author's signature over the rest of the record. CBOR key 23
	// for the same reason [types.AUM] uses it: the highest key that still
	// encodes in one byte, leaving room for payload fields below it.
	Sig types.Sig `cbor:"23,keyasint"`
}

// labelEndpoint is the domain-separation label for an endpoint record's
// signature. It is distinct from every label in types, so a signature over an
// announcement can never be replayed as a signature over a log record.
const labelEndpoint = "juist/endpoint/v1"

// signingBytes returns what an endpoint record's signature covers: a labelled
// digest of the record with the signature field cleared.
func (e *Endpoint) signingBytes() ([]byte, error) {
	unsigned := *e
	unsigned.Sig = types.Sig{}
	body, err := encode(&unsigned)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(labelEndpoint))
	h.Write([]byte{0})
	h.Write(body)
	return h.Sum(nil), nil
}

// Sign fills in the record's signature. The identity must be the one the
// record names, which is checked rather than assumed: a record signed by the
// wrong key is one every recipient silently drops, and the failure would
// otherwise only show up as a node nobody can reach.
func (e *Endpoint) Sign(priv types.PrivateIdentity) error {
	if priv.Public() != e.Identity {
		return fmt.Errorf("gossip: endpoint record names %v but would be signed by %v",
			e.Identity.ShortString(), priv.Public().ShortString())
	}
	if err := e.StaticValidate(); err != nil {
		return err
	}
	msg, err := e.signingBytes()
	if err != nil {
		return err
	}
	sig, err := priv.Sign(msg)
	if err != nil {
		return fmt.Errorf("gossip: signing endpoint record: %w", err)
	}
	e.Sig = sig
	return nil
}

// Verify checks the record's shape and its signature.
func (e *Endpoint) Verify() error {
	if err := e.StaticValidate(); err != nil {
		return err
	}
	msg, err := e.signingBytes()
	if err != nil {
		return err
	}
	if !e.Identity.Verify(msg, e.Sig) {
		return fmt.Errorf("gossip: endpoint record for %v is not signed by that key",
			e.Identity.ShortString())
	}
	return nil
}

// StaticValidate checks everything about the record that does not depend on
// the network's state.
//
// The address rules matter more than they look. An announcement is what a
// member's daemon will hand to the connectivity layer as a place to send UDP
// to, and what its sync layer will open TCP sessions to, so an address the
// announcer does not control is a member directing every other member's
// traffic somewhere of its choosing. They are rejected here rather than
// filtered later, because "later" would be several packages away from the
// record that caused it.
//
// The accepted set is exactly what a correct node announces about itself
// (daemon.underlayEndpoints): a routable unicast address. Loopback and
// link-local are refused for the same reason the unspecified and multicast
// ones are — a peer is by construction not on this host, so "connect to your
// own 127.0.0.1" is never a path to it, and the only thing such an
// announcement can achieve is to point the member set at services it did not
// choose to reach.
func (e *Endpoint) StaticValidate() error {
	if err := e.Identity.Validate(); err != nil {
		return fmt.Errorf("gossip: endpoint record: %w", err)
	}
	if e.Disco.IsZero() {
		return fmt.Errorf("gossip: endpoint record for %v has no disco key", e.Identity.ShortString())
	}
	if e.GossipPort == 0 {
		return fmt.Errorf("gossip: endpoint record for %v has no gossip port", e.Identity.ShortString())
	}
	if len(e.Addrs) > MaxEndpointAddrs {
		return fmt.Errorf("gossip: endpoint record for %v carries %d addresses, over the %d limit",
			e.Identity.ShortString(), len(e.Addrs), MaxEndpointAddrs)
	}
	for i, ap := range e.Addrs {
		if err := validateEndpointAddr(ap); err != nil {
			return fmt.Errorf("gossip: endpoint record for %v: %w", e.Identity.ShortString(), err)
		}
		// Sorted and duplicate-free, like every other set in this project's
		// wire formats, so that one announcement has one encoding.
		if i > 0 && compareAddrPort(e.Addrs[i-1], ap) >= 0 {
			return fmt.Errorf("gossip: endpoint record for %v has unsorted or duplicate addresses at %v",
				e.Identity.ShortString(), ap)
		}
	}
	return nil
}

func validateEndpointAddr(ap netip.AddrPort) error {
	a := ap.Addr()
	switch {
	case !a.IsValid():
		return errors.New("address is invalid")
	case a.Is4In6():
		return fmt.Errorf("address %v is IPv4-mapped IPv6; use the 4-byte form", ap)
	case a.Zone() != "":
		return fmt.Errorf("address %v carries a zone", ap)
	case a.IsUnspecified():
		return fmt.Errorf("address %v is unspecified", ap)
	case a.IsMulticast():
		return fmt.Errorf("address %v is multicast", ap)
	case a.IsLoopback():
		return fmt.Errorf("address %v is loopback; a peer is never reached on this host's own loopback", ap)
	case a.IsLinkLocalUnicast():
		return fmt.Errorf("address %v is link-local", ap)
	case ap.Port() == 0:
		return fmt.Errorf("address %v has no port", ap)
	case !a.IsGlobalUnicast():
		// The cases above are a denylist, and a denylist of an open set leaks:
		// the limited broadcast address 255.255.255.255 passes every one of
		// them, yet the comment on [Endpoint.StaticValidate] promises "a
		// routable unicast address" — which a broadcast address is not, and
		// which an announcement pointing the whole member set at it could turn
		// into an amplifier. IsGlobalUnicast is the positive form of the rule
		// (it is true for public, RFC 1918 and ULA addresses alike, and false
		// for broadcast), so requiring it closes the broadcast case the
		// denylist missed. A directed broadcast such as 192.168.1.255 is
		// indistinguishable from a unicast host without the subnet mask and so
		// is not caught here; disco verifying the working path before any real
		// traffic flows is the backstop for that.
		return fmt.Errorf("address %v is not a global unicast address", ap)
	}
	return nil
}

// compareAddrPort orders endpoints deterministically: by address, then port.
func compareAddrPort(a, b netip.AddrPort) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return int(a.Port()) - int(b.Port())
}

// SortAddrs puts an address set into the canonical order [Endpoint.StaticValidate]
// requires, dropping duplicates. Callers building a record use it so they do
// not have to know the rule.
func SortAddrs(addrs []netip.AddrPort) []netip.AddrPort {
	out := slices.Clone(addrs)
	slices.SortFunc(out, compareAddrPort)
	return slices.Compact(out)
}

// GossipAddrs returns the addresses an anti-entropy session can be opened to:
// each announced address, with the gossip port substituted for the data
// plane's.
func (e *Endpoint) GossipAddrs() []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(e.Addrs))
	for _, ap := range e.Addrs {
		out = append(out, netip.AddrPortFrom(ap.Addr(), e.GossipPort))
	}
	return slices.Compact(out)
}

// Clone returns a deep copy.
func (e *Endpoint) Clone() *Endpoint {
	out := *e
	out.Addrs = slices.Clone(e.Addrs)
	return &out
}

// DecodeEndpoint decodes and verifies one endpoint record.
func DecodeEndpoint(b []byte) (Endpoint, error) {
	e, err := decodeCanonical[Endpoint](b)
	if err != nil {
		return Endpoint{}, err
	}
	if err := e.Verify(); err != nil {
		return Endpoint{}, err
	}
	return e, nil
}

// Encode returns the record's canonical encoding.
func (e *Endpoint) Encode() ([]byte, error) { return encode(e) }
