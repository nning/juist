package gossip

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/nning/juist/internal/addrkey"
	"github.com/nning/juist/internal/aead"
	"github.com/nning/juist/types"
)

// DiscoKeySize is the length of a NAT-traversal (disco) public key.
const DiscoKeySize = 32

// A DiscoKey is a node's NAT-traversal public key. This package's own type, so
// the adapter in conn stays the only place that touches Tailscale's types.
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

// RelayCertSize is the length of the certificate hash a relay announcement
// pins: a SHA-256 digest.
const RelayCertSize = 32

// A RelayInfo is a relay-capable member's statement of where its embedded
// relay listens. Whether the member *may* relay comes from the log — the
// `relay-capable` role — and never from here; this only says where.
//
// The certificate hash is what authenticates the relay in place of a
// certificate authority. It is drawn fresh each time the relay starts, like
// the disco key, so it belongs in the announcement rather than in the log.
type RelayInfo struct {
	// Port is the TCP port the relay serves DERP on, at each of the
	// announcement's addresses.
	Port uint16 `cbor:"1,keyasint"`

	// STUNPort is the UDP port it answers binding requests on, or zero if it
	// does not reflect.
	STUNPort uint16 `cbor:"2,keyasint,omitempty"`

	// Cert is the SHA-256 of the relay's TLS certificate.
	Cert []byte `cbor:"3,keyasint"`

	// HostName is the name the certificate is issued for, and the TLS server
	// name a member must use. It is never resolved: the addresses come from
	// the announcement.
	HostName string `cbor:"4,keyasint"`

	// Name, where set, is a public DNS name the relay serves DERP on at
	// 443/tcp too, under a certificate a public CA issued for it, which
	// members verify by WebPKI instead of Cert. Sent only in a network at
	// [types.SchemaRelayName] or above: older builds refuse the field.
	Name string `cbor:"5,keyasint,omitempty"`
}

// MaxRelayHostNameLen caps the announced TLS server name. It is a derivation
// of the relay's own certificate key, so the limit only has to stop a hostile
// announcement being unbounded.
const MaxRelayHostNameLen = 64

// Clone returns a deep copy.
func (r *RelayInfo) Clone() *RelayInfo {
	out := *r
	out.Cert = slices.Clone(r.Cert)
	return &out
}

func (r *RelayInfo) validate() error {
	switch {
	case r.Port == 0:
		return errors.New("relay announcement has no port")
	case len(r.Cert) != RelayCertSize:
		return fmt.Errorf("relay certificate hash is %d bytes, want %d", len(r.Cert), RelayCertSize)
	case r.HostName == "":
		return errors.New("relay announcement has no host name")
	case len(r.HostName) > MaxRelayHostNameLen:
		return fmt.Errorf("relay host name is %d bytes, over the %d limit",
			len(r.HostName), MaxRelayHostNameLen)
	}
	for _, c := range r.HostName {
		// A name that is only ever a TLS server name, so the accepted set is
		// the one a certificate can be issued for and nothing wider.
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '.' && c != '-' {
			return fmt.Errorf("relay host name %q holds a character a certificate name may not", r.HostName)
		}
	}
	if r.Name != "" {
		if err := types.ValidateHostName(r.Name); err != nil {
			return fmt.Errorf("relay name: %w", err)
		}
	}
	return nil
}

// MaxEndpointAddrs caps the underlay addresses one announcement may carry.
// A multi-homed laptop has a handful; the limit is only here so that a
// hostile announcement cannot make every member allocate.
const MaxEndpointAddrs = 16

// An Endpoint is a node's connectivity announcement: where to reach it on the
// underlay, and the disco key it answers NAT-traversal probes with. Not a log
// record, because of lifetime — addresses and disco keys change per restart,
// while membership records need a quorum ceremony.
//
// Signed by the node's own identity key alone, which is the right authority
// for what it claims: a node may say where it is and nothing about another, so
// every lie costs only its own connectivity. Seq makes a replayed announcement
// lose to the current one, and is the author's own counter.
type Endpoint struct {
	// Identity is the announcing node, and the key that signs the record.
	Identity types.Identity `cbor:"1,keyasint"`

	// Disco is the node's current NAT-traversal public key.
	Disco DiscoKey `cbor:"2,keyasint"`

	// Addrs are the underlay UDP endpoints the node's data plane is reachable
	// at. Hints only: disco verifies the working path itself. The order is
	// canonical, not a preference — the first address is the numerically
	// lowest, which is often the least useful.
	Addrs []netip.AddrPort `cbor:"3,keyasint,omitempty"`

	// GossipPort is the TCP port this node accepts anti-entropy sessions
	// on, at each of Addrs' addresses.
	GossipPort uint16 `cbor:"4,keyasint"`

	// Seq orders a node's own announcements. Strictly increasing per node;
	// a record with a lower Seq than one already held is ignored.
	Seq uint64 `cbor:"5,keyasint"`

	// Relay is where this node's embedded relay listens, or nil if it runs
	// none. A member that announces one without the log granting it
	// `relay-capable` is ignored by the reconciler.
	Relay *RelayInfo `cbor:"6,keyasint,omitempty"`

	// HomeRelay is the relay region this node can be reached through, or zero
	// for none. Member relays are not meshed, so a peer that sends to any
	// other region reaches nothing — which is why this is the node's own
	// statement rather than each peer's guess.
	HomeRelay uint16 `cbor:"7,keyasint,omitempty"`

	// Exit says the node forwards members' internet traffic, as its operator
	// agreed. Whether it may comes from the log, the `exit` role, and
	// never from here.
	Exit bool `cbor:"8,keyasint,omitempty"`

	// Subnets says the node routes the subnets the log grants it, as its
	// operator agreed; which ones comes from the log alone.
	Subnets bool `cbor:"9,keyasint,omitempty"`

	// DNS is the port, on the node's overlay addresses, of the resolver it
	// answers for members through as an exit node; zero for none.
	DNS uint16 `cbor:"10,keyasint,omitempty"`

	// NoV4 says the node runs without overlay IPv4, as where another network
	// on its host holds the range: it carries no member's IPv4.
	NoV4 bool `cbor:"11,keyasint,omitempty"`

	// Published says the node serves the names the log publishes on it, as
	// its operator agreed; which ones comes from the log alone.
	Published bool `cbor:"12,keyasint,omitempty"`

	// Share is what the node publishes under its own name, as the publish
	// role lets it; an ingress takes it from a member holding the role alone.
	Share *Share `cbor:"13,keyasint,omitempty"`

	// Sealed holds Addrs in their stead, sealed for the node's peers under
	// the key its [AddrKey] wraps for them, where an access policy keeps
	// it apart from some member.
	Sealed []byte `cbor:"14,keyasint,omitempty"`

	// Sig is the author's signature over the rest of the record. CBOR key 23
	// for the same reason [types.AUM] uses it: the highest key that still
	// encodes in one byte, leaving room for payload fields below it.
	Sig types.Sig `cbor:"23,keyasint"`
}

// SameAs reports whether two announcements say the same, whatever their
// sequence numbers and signatures: one renews the other.
func (e *Endpoint) SameAs(o *Endpoint) bool {
	return e.Identity == o.Identity && e.Disco == o.Disco && slices.Equal(e.Addrs, o.Addrs) &&
		e.GossipPort == o.GossipPort && e.HomeRelay == o.HomeRelay && sameRelay(e.Relay, o.Relay) && e.Exit == o.Exit &&
		e.Subnets == o.Subnets && e.DNS == o.DNS && e.NoV4 == o.NoV4 && e.Published == o.Published &&
		(e.Share == nil) == (o.Share == nil) && (e.Share == nil || *e.Share == *o.Share) &&
		bytes.Equal(e.Sealed, o.Sealed)
}

// A Share is the port of a node's overlay addresses its own name is reached
// on, until Until, in Unix seconds.
type Share struct {
	Port  uint16 `cbor:"1,keyasint"`
	Until int64  `cbor:"2,keyasint"`
}

// Live reports whether s is announced and not past at now.
func (s *Share) Live(now time.Time) bool { return s != nil && now.Unix() < s.Until }

func sameRelay(a, b *RelayInfo) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Port == b.Port && a.STUNPort == b.STUNPort && a.HostName == b.HostName && slices.Equal(a.Cert, b.Cert) &&
		a.Name == b.Name
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
// record names, which is checked rather than assumed: every recipient silently
// drops a record signed by the wrong key.
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
// The address rules carry weight: every member sends UDP and opens TCP
// sessions to what an announcement names, so an address the announcer does not
// control is a member directing everyone else's traffic where it likes. The
// accepted set is what a correct node announces about itself — a routable
// unicast address. Loopback and link-local are refused because a peer is by
// construction not on this host.
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
	if e.Sealed != nil && (len(e.Addrs) > 0 || len(e.Sealed) < aead.Overhead || len(e.Sealed) > addrkey.MaxSealedSize) {
		return fmt.Errorf("gossip: endpoint record for %v carries %d bytes of sealed addresses beside %d open ones",
			e.Identity.ShortString(), len(e.Sealed), len(e.Addrs))
	}
	if e.Share != nil && (e.Share.Port == 0 || e.Share.Until <= 0) {
		return fmt.Errorf("gossip: endpoint record for %v shares with no port or end", e.Identity.ShortString())
	}
	if e.Relay != nil {
		if err := e.Relay.validate(); err != nil {
			return fmt.Errorf("gossip: endpoint record for %v: %w", e.Identity.ShortString(), err)
		}
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

// CheckAddrs applies the rules [Endpoint.StaticValidate] applies to its
// addresses to a set opened from [Endpoint.Sealed].
func CheckAddrs(addrs []netip.AddrPort) error {
	if len(addrs) > MaxEndpointAddrs {
		return fmt.Errorf("gossip: %d addresses, over the %d limit", len(addrs), MaxEndpointAddrs)
	}
	for i, ap := range addrs {
		if err := validateEndpointAddr(ap); err != nil {
			return fmt.Errorf("gossip: %w", err)
		}
		if i > 0 && compareAddrPort(addrs[i-1], ap) >= 0 {
			return fmt.Errorf("gossip: unsorted or duplicate addresses at %v", ap)
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
		// The cases above are a denylist, which leaks: 255.255.255.255 passes
		// all of them and would point the member set at an amplifier.
		// IsGlobalUnicast is the positive form of the rule and closes it. A
		// directed broadcast is indistinguishable from a host without the
		// subnet mask; disco verifying the path is the backstop.
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
func (e *Endpoint) GossipAddrs() []netip.AddrPort { return e.gossipAddrsAt(e.Addrs) }

// gossipAddrsAt is addrs with e's gossip port for each one's.
func (e *Endpoint) gossipAddrsAt(addrs []netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(addrs))
	for _, ap := range addrs {
		out = append(out, netip.AddrPortFrom(ap.Addr(), e.GossipPort))
	}
	return slices.Compact(out)
}

// Clone returns a deep copy.
func (e *Endpoint) Clone() *Endpoint {
	out := *e
	out.Addrs = slices.Clone(e.Addrs)
	out.Sealed = slices.Clone(e.Sealed)
	if e.Relay != nil {
		out.Relay = e.Relay.Clone()
	}
	return &out
}

// RelayAddrs returns the addresses this node's relay can be reached at: each
// announced address with the relay's TCP port substituted for the data
// plane's.
func (e *Endpoint) RelayAddrs() []netip.AddrPort {
	if e.Relay == nil {
		return nil
	}
	out := make([]netip.AddrPort, 0, len(e.Addrs))
	for _, ap := range e.Addrs {
		out = append(out, netip.AddrPortFrom(ap.Addr(), e.Relay.Port))
	}
	return slices.Compact(out)
}

// cachedEndpoints is the wire form of a persisted announcement set: an array
// under one key, so that a truncated file fails to decode rather than
// producing half a cache.
type cachedEndpoints struct {
	Endpoints []Endpoint `cbor:"1,keyasint,omitempty"`
	Keys      []AddrKey  `cbor:"2,keyasint,omitempty"`
}

// EncodeCachedEndpoints encodes announcements, and the address keys their
// sealed addresses open under, for persistence.
func EncodeCachedEndpoints(eps []Endpoint, keys []AddrKey) ([]byte, error) {
	return encode(&cachedEndpoints{Endpoints: eps, Keys: keys})
}

// DecodeCachedEndpoints decodes a persisted announcement set. It does not
// verify them: the caller drops the ones that do not, since a file this node
// wrote is no more trusted than a frame a peer sent.
func DecodeCachedEndpoints(b []byte, out *[]Endpoint, keys *[]AddrKey) error {
	held, err := decodeCanonical[cachedEndpoints](b)
	if err != nil {
		return err
	}
	if len(held.Endpoints) > types.MaxNodes || len(held.Keys) > types.MaxNodes {
		return fmt.Errorf("gossip: cached announcement set holds %d records and %d keys, over the %d limit",
			len(held.Endpoints), len(held.Keys), types.MaxNodes)
	}
	*out = held.Endpoints
	if keys != nil {
		*keys = held.Keys
	}
	return nil
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
