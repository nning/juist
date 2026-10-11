// Package secrets implements the epoch group secret: a symmetric secret held
// by exactly the current member set, sealed to each member inside a signed log
// record and replaced whenever membership changes.
//
// It gates discovery and gossip confidentiality — blinded DHT topics, AEAD
// announcement payloads, blinded mDNS beacons — and never the data plane,
// which WireGuard secures end to end. A leak costs discovery privacy and
// nothing else. Against a revoked member it buys what removing a WireGuard
// peer does not: the device can no longer recognize the network's topics or
// read its announcements, so it cannot find members whose stale state might
// still trust it. MLS was evaluated and rejected in
// docs/research/building-blocks.md §3.
//
// The ciphersuite is HPKE (RFC 9180) in base mode with
// DHKEM(X25519)+ML-KEM-768, HKDF-SHA256 and ChaCha20-Poly1305. The hybrid KEM
// is the post-quantum hedge, at about 1.2 KiB per member per epoch — which is
// where the schema's size limits come from.
package secrets

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/nning/juist/types"
)

// The HPKE ciphersuite. Fixed, not negotiated: there is no peer to negotiate
// with, and negotiation is where downgrade attacks live. The KEM follows from
// the key halves passed to hpke.NewHybridPublicKey, and
// TestCiphersuiteIsTheIntendedOne pins it.
func kdf() hpke.KDF   { return hpke.HKDFSHA256() }
func aead() hpke.AEAD { return hpke.ChaCha20Poly1305() }

// A Secret is an epoch group secret. All derived values come from it through
// [Secret.derive], never from the secret directly, so that no two uses share
// key material.
type Secret [types.GroupSecretSize]byte

// NewSecret draws a fresh group secret from the system CSPRNG. Each epoch's
// secret is independent of the last, which is what lets an admin rekey holding
// only a signing key — no bump ever requires reading the previous secret.
func NewSecret() (Secret, error) {
	var s Secret
	if _, err := rand.Read(s[:]); err != nil {
		return Secret{}, fmt.Errorf("secrets: drawing group secret: %w", err)
	}
	return s, nil
}

// Commit returns the commitment recorded in [types.EpochRecord.Commit].
func (s Secret) Commit() types.Hash { return types.EpochCommit(s[:]) }

// Equal reports whether two secrets match, in constant time.
func (s Secret) Equal(other Secret) bool {
	return subtle.ConstantTimeCompare(s[:], other[:]) == 1
}

// PrivateKeys is a node's HPKE recipient key material: the two halves of the
// hybrid KEM, whose public halves [types.NodeRecord] carries. Unlike admin
// signing keys, the daemon needs these, so they live on the member device.
type PrivateKeys struct {
	x25519 *ecdh.PrivateKey
	mlkem  *mlkem.DecapsulationKey768
}

// GenerateKeys creates a node's HPKE recipient keys.
func GenerateKeys() (*PrivateKeys, error) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("secrets: generating X25519 key: %w", err)
	}
	m, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("secrets: generating ML-KEM key: %w", err)
	}
	return &PrivateKeys{x25519: x, mlkem: m}, nil
}

// NewPrivateKeys reconstructs recipient keys from the persisted form: a
// 32-byte X25519 scalar and the 64-byte ML-KEM seed.
func NewPrivateKeys(x25519Scalar, mlkemSeed []byte) (*PrivateKeys, error) {
	x, err := ecdh.X25519().NewPrivateKey(x25519Scalar)
	if err != nil {
		return nil, fmt.Errorf("secrets: loading X25519 key: %w", err)
	}
	m, err := mlkem.NewDecapsulationKey768(mlkemSeed)
	if err != nil {
		return nil, fmt.Errorf("secrets: loading ML-KEM key: %w", err)
	}
	return &PrivateKeys{x25519: x, mlkem: m}, nil
}

// Bytes returns the persistable secret key material: the X25519 scalar and the
// ML-KEM seed, in the form [NewPrivateKeys] accepts.
func (p *PrivateKeys) Bytes() (x25519Scalar, mlkemSeed []byte) {
	return p.x25519.Bytes(), p.mlkem.Bytes()
}

// Decapsulate recovers what a peer encapsulated to this node's ML-KEM key.
func (p *PrivateKeys) Decapsulate(ciphertext []byte) ([]byte, error) {
	return p.mlkem.Decapsulate(ciphertext)
}

// Public returns the public halves, as they appear in a node record.
func (p *PrivateKeys) Public() (types.X25519Key, types.MLKEMKey, error) {
	var xk types.X25519Key
	var mk types.MLKEMKey
	if err := xk.UnmarshalBinary(p.x25519.PublicKey().Bytes()); err != nil {
		return xk, mk, err
	}
	if err := mk.UnmarshalBinary(p.mlkem.EncapsulationKey().Bytes()); err != nil {
		return xk, mk, err
	}
	return xk, mk, nil
}

// recipientKey assembles a node's HPKE public key from the two halves in its
// record, rejecting either half if it is not a valid key. Neither check is
// complete — an all-zero ML-KEM key is a structurally valid encoding — so
// degenerate keys are caught by the schema's shape rules and by quorum.
func recipientKey(x types.X25519Key, m types.MLKEMKey) (hpke.PublicKey, error) {
	xpub, err := ecdh.X25519().NewPublicKey(x[:])
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 key: %w", err)
	}
	mpub, err := mlkem.NewEncapsulationKey768(m[:])
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM key: %w", err)
	}
	pub, err := hpke.NewHybridPublicKey(mpub, xpub)
	if err != nil {
		return nil, fmt.Errorf("assembling hybrid recipient key: %w", err)
	}
	return pub, nil
}

// sealInfo is the HPKE info string, binding a wrap to one epoch and one
// recipient, so it cannot be lifted into another epoch's record or
// re-addressed — both of which would decrypt fine, since recipient keys are
// reused across epochs. Binding to the network too would be circular for the
// genesis record; the signatures over the record supply that.
func sealInfo(epoch uint64, recipient types.Identity) []byte {
	info := make([]byte, 0, len(labelSealInfo)+1+8+types.IdentitySize)
	info = append(info, labelSealInfo...)
	info = append(info, 0)
	info = binary.BigEndian.AppendUint64(info, epoch)
	info = append(info, recipient[:]...)
	return info
}

// NewEpoch draws a fresh secret and builds the epoch record that distributes
// it. nodes must be the member set as it will be after the carrying record is
// applied, which is the set the log requires the wraps to cover exactly.
func NewEpoch(epoch uint64, nodes []types.NodeRecord) (Secret, *types.EpochRecord, error) {
	secret, err := NewSecret()
	if err != nil {
		return Secret{}, nil, err
	}
	rec, err := SealTo(secret, epoch, nodes)
	if err != nil {
		return Secret{}, nil, err
	}
	return secret, rec, nil
}

// SealTo builds the epoch record distributing an existing secret. Separate
// from [NewEpoch] so tests can pin the secret; production paths should draw a
// fresh one.
func SealTo(secret Secret, epoch uint64, nodes []types.NodeRecord) (*types.EpochRecord, error) {
	if epoch == 0 {
		return nil, errors.New("secrets: epoch 0; epochs start at 1")
	}
	if len(nodes) > types.MaxNodes {
		return nil, fmt.Errorf("secrets: %d recipients, over the %d limit", len(nodes), types.MaxNodes)
	}
	rec := &types.EpochRecord{
		Epoch:  epoch,
		Commit: secret.Commit(),
		Wraps:  make([]types.EpochWrap, 0, len(nodes)),
	}
	for i := range nodes {
		n := &nodes[i]
		pub, err := recipientKey(n.X25519, n.MLKEM)
		if err != nil {
			return nil, fmt.Errorf("secrets: node %v: %w", n.Identity.ShortString(), err)
		}
		sealed, err := hpke.Seal(pub, kdf(), aead(), sealInfo(epoch, n.Identity), secret[:])
		if err != nil {
			return nil, fmt.Errorf("secrets: sealing to %v: %w", n.Identity.ShortString(), err)
		}
		if len(sealed) != types.SealedSecretSize {
			// The schema pins this length so that malformed wraps are
			// rejected by shape. If the ciphersuite ever changes, that
			// constant has to change with it, deliberately.
			return nil, fmt.Errorf("secrets: sealed secret is %d bytes, schema expects %d",
				len(sealed), types.SealedSecretSize)
		}
		rec.Wraps = append(rec.Wraps, types.EpochWrap{Recipient: n.Identity, Sealed: sealed})
	}
	// The schema requires the wrap set sorted by recipient, so that one set
	// has one encoding.
	slices.SortFunc(rec.Wraps, func(a, b types.EpochWrap) int {
		return a.Recipient.Compare(b.Recipient)
	})
	if err := rec.StaticValidate(); err != nil {
		return nil, fmt.Errorf("secrets: built an invalid epoch record: %w", err)
	}
	return rec, nil
}

// Open recovers the group secret for the local node from an epoch record. self
// identifies which wrap to open, and the result is checked against the
// record's commitment — one value the whole network sees, so a malicious
// quorum cannot hand different members different secrets.
func Open(rec *types.EpochRecord, self types.Identity, priv *PrivateKeys) (Secret, error) {
	if err := rec.StaticValidate(); err != nil {
		return Secret{}, fmt.Errorf("secrets: %w", err)
	}
	i := slices.IndexFunc(rec.Wraps, func(w types.EpochWrap) bool { return w.Recipient == self })
	if i < 0 {
		return Secret{}, fmt.Errorf("secrets: epoch %d has no wrap for %v", rec.Epoch, self.ShortString())
	}
	hpkePriv, err := hpke.NewHybridPrivateKey(priv.mlkem, priv.x25519)
	if err != nil {
		return Secret{}, fmt.Errorf("secrets: assembling recipient key: %w", err)
	}
	pt, err := hpke.Open(hpkePriv, kdf(), aead(), sealInfo(rec.Epoch, self), rec.Wraps[i].Sealed)
	if err != nil {
		return Secret{}, fmt.Errorf("secrets: opening epoch %d wrap: %w", rec.Epoch, err)
	}
	if len(pt) != types.GroupSecretSize {
		return Secret{}, fmt.Errorf("secrets: epoch %d secret is %d bytes, want %d",
			rec.Epoch, len(pt), types.GroupSecretSize)
	}
	var s Secret
	copy(s[:], pt)
	if s.Commit() != rec.Commit {
		return Secret{}, fmt.Errorf(
			"secrets: epoch %d secret does not match the record's commitment; "+
				"members may have been given different secrets", rec.Epoch)
	}
	return s, nil
}

// CatchUpKeySize is the length of a catch-up session key.
const CatchUpKeySize = 32

// catchUpInfo binds a catch-up grant to one network, one recipient and the
// nonce of one session, so it can be neither replayed nor re-addressed.
func catchUpInfo(network types.Hash, recipient types.Identity, nonce []byte) []byte {
	info := make([]byte, 0, len(labelCatchUp)+1+len(network)+types.IdentitySize+len(nonce))
	info = append(info, labelCatchUp...)
	info = append(info, 0)
	info = append(info, network[:]...)
	info = append(info, recipient[:]...)
	return append(info, nonce...)
}

// SealCatchUp draws a fresh session key for a member catching up and seals it
// to the recipient keys its record names: only that device can open it.
func SealCatchUp(network types.Hash, n *types.NodeRecord, nonce []byte) (key [CatchUpKeySize]byte, sealed []byte, err error) {
	pub, err := recipientKey(n.X25519, n.MLKEM)
	if err != nil {
		return key, nil, fmt.Errorf("secrets: node %v: %w", n.Identity.ShortString(), err)
	}
	if _, err := rand.Read(key[:]); err != nil {
		return key, nil, fmt.Errorf("secrets: drawing a catch-up key: %w", err)
	}
	sealed, err = hpke.Seal(pub, kdf(), aead(), catchUpInfo(network, n.Identity, nonce), key[:])
	if err != nil {
		return key, nil, fmt.Errorf("secrets: sealing a catch-up key to %v: %w", n.Identity.ShortString(), err)
	}
	return key, sealed, nil
}

// OpenCatchUp recovers the session key a peer sealed to this node.
func OpenCatchUp(network types.Hash, self types.Identity, priv *PrivateKeys, nonce, sealed []byte) (key [CatchUpKeySize]byte, err error) {
	hpkePriv, err := hpke.NewHybridPrivateKey(priv.mlkem, priv.x25519)
	if err != nil {
		return key, fmt.Errorf("secrets: assembling recipient key: %w", err)
	}
	pt, err := hpke.Open(hpkePriv, kdf(), aead(), catchUpInfo(network, self, nonce), sealed)
	if err != nil {
		return key, fmt.Errorf("secrets: opening a catch-up key: %w", err)
	}
	if len(pt) != CatchUpKeySize {
		return key, fmt.Errorf("secrets: catch-up key is %d bytes, want %d", len(pt), CatchUpKeySize)
	}
	copy(key[:], pt)
	return key, nil
}

// AdminRecipient derives an admin key's encryption keys from its signing
// seed, so that the admin key file holds both and a copy of it covers both.
func AdminRecipient(seed []byte) (*PrivateKeys, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("secrets: an admin key seed is %d bytes, want 32", len(seed))
	}
	x, err := hkdf.Key(sha256.New, seed, nil, labelAdminX25519, 32)
	if err != nil {
		return nil, err
	}
	m, err := hkdf.Key(sha256.New, seed, nil, labelAdminMLKEM, mlkem.SeedSize)
	if err != nil {
		return nil, err
	}
	return NewPrivateKeys(x, m)
}

// Recipient returns the public halves as an admin key carries them.
func (p *PrivateKeys) Recipient() (types.RecipientKey, error) {
	x, m, err := p.Public()
	return types.RecipientKey{X25519: x, MLKEM: m}, err
}

// SealedKeySize is the length of what [SealKeyTo] returns.
const SealedKeySize = types.SealedSecretSize

// KeySize is the length of a key [SealKeyTo] seals.
const KeySize = 32

func keyInfo(context []byte, reader types.Identity) []byte {
	info := append([]byte(labelWaitingKey), 0)
	info = append(info, context...)
	return append(info, reader[:]...)
}

// SealKeyTo seals key to the encryption key r of the admin key reader, bound
// to context: only that admin opens it, and only as sealed for context.
func SealKeyTo(context []byte, reader types.Identity, r types.RecipientKey, key [KeySize]byte) ([]byte, error) {
	pub, err := recipientKey(r.X25519, r.MLKEM)
	if err != nil {
		return nil, fmt.Errorf("secrets: %v's encryption key: %w", reader.ShortString(), err)
	}
	sealed, err := hpke.Seal(pub, kdf(), aead(), keyInfo(context, reader), key[:])
	if err != nil {
		return nil, fmt.Errorf("secrets: sealing to %v: %w", reader.ShortString(), err)
	}
	return sealed, nil
}

// OpenKey opens what [SealKeyTo] sealed to reader, whose encryption keys
// priv are.
func OpenKey(context []byte, reader types.Identity, priv *PrivateKeys, sealed []byte) ([KeySize]byte, error) {
	var key [KeySize]byte
	hpkePriv, err := hpke.NewHybridPrivateKey(priv.mlkem, priv.x25519)
	if err != nil {
		return key, fmt.Errorf("secrets: assembling recipient key: %w", err)
	}
	pt, err := hpke.Open(hpkePriv, kdf(), aead(), keyInfo(context, reader), sealed)
	if err != nil {
		return key, fmt.Errorf("secrets: opening a key: %w", err)
	}
	if len(pt) != KeySize {
		return key, fmt.Errorf("secrets: a key of %d bytes", len(pt))
	}
	copy(key[:], pt)
	return key, nil
}

func peerInfo(network types.Hash, recipient types.Identity) []byte {
	info := append([]byte(labelPeer), 0)
	info = append(info, network[:]...)
	return append(info, recipient[:]...)
}

// SealToPeer seals plaintext to the member n, in network: only that device
// can open it, whoever holds the connection it is sent on.
func SealToPeer(network types.Hash, n *types.NodeRecord, plaintext []byte) ([]byte, error) {
	pub, err := recipientKey(n.X25519, n.MLKEM)
	if err != nil {
		return nil, fmt.Errorf("secrets: node %v: %w", n.Identity.ShortString(), err)
	}
	return hpke.Seal(pub, kdf(), aead(), peerInfo(network, n.Identity), plaintext)
}

// OpenFromPeer opens what [SealToPeer] sealed to this device, self.
func OpenFromPeer(network types.Hash, self types.Identity, priv *PrivateKeys, sealed []byte) ([]byte, error) {
	hpkePriv, err := hpke.NewHybridPrivateKey(priv.mlkem, priv.x25519)
	if err != nil {
		return nil, fmt.Errorf("secrets: assembling recipient key: %w", err)
	}
	pt, err := hpke.Open(hpkePriv, kdf(), aead(), peerInfo(network, self), sealed)
	if err != nil {
		return nil, fmt.Errorf("secrets: opening what a peer sealed: %w", err)
	}
	return pt, nil
}

// Domain-separation labels. Every derived value is bound to one of these, so
// the discovery AEAD key and a topic ID can never come out equal, and neither
// can ever equal the secret itself.
const (
	labelSealInfo     = "juist/epoch-seal/v1"
	labelCatchUp      = "juist/catch-up/v1"
	labelTopic        = "juist/dht-topic/v1"
	labelDiscoveryKey = "juist/discovery-aead/v1"
	labelMDNS         = "juist/mdns-beacon/v1"
	labelGossipKey    = "juist/gossip-aead/v1"
	labelAdminX25519  = "juist/admin-recipient-x25519/v1"
	labelAdminMLKEM   = "juist/admin-recipient-mlkem/v1"
	labelWaitingKey   = "juist/waiting-key/v1"
	labelPeer         = "juist/peer-seal/v1"
	labelPSK          = "juist/wg-psk/v1"
)

// derive expands the secret into keying material for one labelled use:
// HKDF-SHA256 with the epoch as salt and label plus context as info. Mixing
// the epoch in guards against a secret ever being reused by mistake.
func (s Secret) derive(label string, epoch uint64, context []byte, length int) []byte {
	salt := binary.BigEndian.AppendUint64(nil, epoch)
	info := make([]byte, 0, len(label)+1+len(context))
	info = append(info, label...)
	info = append(info, 0)
	info = append(info, context...)
	out, err := hkdf.Key(sha256.New, s[:], salt, string(info), length)
	if err != nil {
		// HKDF-SHA256 fails only on a length above 255 hash blocks, which no
		// caller in this package comes near.
		panic(fmt.Sprintf("secrets: deriving %s: %v", label, err))
	}
	return out
}

// TopicIDSize is the length of a blinded rendezvous label. Twenty bytes
// matches a BitTorrent DHT infohash.
const TopicIDSize = 20

// TopicSeed returns the Ed25519 seed one member's announcement is published
// under for one epoch and time window. It is a keyed derivation rather than a
// name, so an outsider watching the public DHT cannot recognize the network,
// enumerate its members or count them, and a revoked member stops being able
// to compute it at the next epoch.
//
// A *key* rather than a location, because BEP 44 does not let a publisher
// choose where an item lands: a mutable item's address is the hash of the
// public key and the salt, so what a network gets to blind is the key. A
// per-member key rather than one key with per-member salts, because the key
// travels in the clear with every item — one shared key would let a storage
// node holding two of a network's items link them and count the members.
//
// window is the caller's coarse clock bucket, floor(unix / period), so nothing
// here reads the clock.
func (s Secret) TopicSeed(epoch, window uint64, subject types.Identity) [32]byte {
	ctx := binary.BigEndian.AppendUint64(nil, window)
	ctx = append(ctx, subject[:]...)
	var out [32]byte
	copy(out[:], s.derive(labelTopic, epoch, ctx, len(out)))
	return out
}

// DiscoveryKey returns the AEAD key protecting announcement payloads, so that
// a DHT storage node sees opaque bytes at an opaque key.
func (s Secret) DiscoveryKey(epoch uint64) [32]byte {
	var out [32]byte
	copy(out[:], s.derive(labelDiscoveryKey, epoch, nil, len(out)))
	return out
}

// MDNSName returns the blinded LAN beacon label. Announcing a recognizable
// service name would tell every coffee-shop LAN that this network exists and
// who is on it.
func (s Secret) MDNSName(epoch uint64) []byte {
	return s.derive(labelMDNS, epoch, nil, TopicIDSize)
}

// PSKSeed returns what an epoch's WireGuard preshared keys are derived from:
// a member keeps it longer than the secret, which answers gossip and
// discovery, so as to reach a peer still behind.
func (s Secret) PSKSeed(epoch uint64) [32]byte {
	var out [32]byte
	copy(out[:], s.derive(labelPSK, epoch, nil, len(out)))
	return out
}

// GossipKey returns the AEAD key protecting gossip frames on the underlay.
// Separate from [Secret.DiscoveryKey] by label, so a frame and an announcement
// cannot be decrypted with one another's key. It buys confidentiality only:
// every record inside a frame carries its own signatures.
func (s Secret) GossipKey(epoch uint64) [32]byte {
	var out [32]byte
	copy(out[:], s.derive(labelGossipKey, epoch, nil, len(out)))
	return out
}
