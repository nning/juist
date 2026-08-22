// Package secrets implements the epoch group secret: a symmetric secret held
// by exactly the current member set, distributed by sealing it to each member
// individually inside a signed log record, and replaced whenever membership
// changes.
//
// # What it is for, and what it is not for
//
// The group secret gates discovery and gossip confidentiality: blinded DHT
// topic IDs, AEAD-encrypted announcement payloads, blinded mDNS beacons. It
// never gates the data plane, which WireGuard secures end to end from keys in
// the log. That separation is a design rule
// (docs/02-threat-model.md): "the data plane never depends on the group
// secret; discovery privacy never gates data-plane security". A leaked group
// secret costs discovery privacy and nothing else.
//
// What it buys against a revoked member is the thing a WireGuard peer removal
// alone does not: the removed device can no longer recognize the network's
// topics or read its announcements, so it cannot even find the members whose
// stale state might still trust it
// (docs/research/building-blocks.md §5, step 4).
//
// # Why not MLS
//
// Continuous group key agreement (RFC 9420) is the obvious-looking fit and was
// evaluated and rejected in docs/research/building-blocks.md §3: MLS needs an
// ordered broadcast channel, which here means the signed log — so MLS would be
// a second, far larger state machine layered on the one that already provides
// ordering — and its forward secrecy and post-compromise security protect
// message content, which is WireGuard's job in this design. An epoch-numbered
// secret fanned out by HPKE is O(n) per rekey, which at 25–100 members is
// nothing.
//
// # Ciphersuite
//
// HPKE (RFC 9180) in base mode with DHKEM(X25519)+ML-KEM-768, HKDF-SHA256 and
// ChaCha20-Poly1305. The hybrid KEM is the post-quantum hedge: an adversary
// recording epoch records today and breaking X25519 later still needs to break
// ML-KEM-768 to read them. It costs about 1.2 KiB per member per epoch, which
// is the reason for the size limits in the schema and an acceptable price at
// this scale.
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

	"github.com/nning/wg-p2p/types"
)

// The HPKE ciphersuite. Fixed, not negotiated: there is no peer to negotiate
// with — a sealed secret is written into a record every member reads — and
// negotiation is where downgrade attacks live.
//
// The KEM is not named here because it follows from the key halves passed to
// hpke.NewHybridPublicKey. TestCiphersuiteIsTheIntendedOne pins it, so a
// change in what the standard library assembles cannot quietly cost the
// post-quantum property.
func kdf() hpke.KDF   { return hpke.HKDFSHA256() }
func aead() hpke.AEAD { return hpke.ChaCha20Poly1305() }

// A Secret is an epoch group secret. All derived values come from it through
// [Secret.derive], never from the secret directly, so that no two uses share
// key material.
type Secret [types.GroupSecretSize]byte

// NewSecret draws a fresh group secret from the system CSPRNG.
//
// Each epoch's secret is independent of the last rather than derived from it.
// That is what lets an admin rekey the network holding only an admin signing
// key: producing a bump never requires reading the previous secret, so admin
// keys stay out of the daemon and off the member devices, as
// docs/04-architecture.md requires.
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
// hybrid KEM. The public halves are what [types.NodeRecord] records.
//
// On a member device these are the keys the daemon needs to read the group
// secret, so unlike admin signing keys they have to be available to it. They
// are the sealed-at-rest material docs/04-architecture.md describes under key
// custody.
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
// record, rejecting either half if it is not a valid key.
//
// This is the only place a node record's encryption keys are interpreted. Both
// checks are real but neither is complete: ML-KEM's modulus check rejects most
// random byte strings, yet an all-zero key is a structurally valid encoding of
// the all-zero polynomial and passes. Degenerate encryption keys are therefore
// caught by shape in the record schema, which rejects zero-valued keys, and by
// the fact that admitting one takes a quorum.
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
// recipient.
//
// It stops a wrap being lifted out of one epoch's record and dropped into
// another's, or re-addressed to a different member — both of which would
// otherwise decrypt fine, since the same recipient key is used across epochs.
// Binding to the network as well would be circular for the genesis record,
// whose own hash names the network; that binding comes instead from the
// signatures over the record, which are by that network's admin keys.
func sealInfo(epoch uint64, recipient types.Identity) []byte {
	info := make([]byte, 0, len(labelSealInfo)+1+8+types.IdentitySize)
	info = append(info, labelSealInfo...)
	info = append(info, 0)
	info = binary.BigEndian.AppendUint64(info, epoch)
	info = append(info, recipient[:]...)
	return info
}

// NewEpoch draws a fresh secret and builds the epoch record that distributes
// it to nodes.
//
// nodes must be the member set as it will be *after* the record that carries
// this epoch is applied — the set the log then requires the wraps to cover
// exactly. Callers get that from the log's own projection of the change rather
// than assembling it by hand; see trust/log's builders.
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

// Open recovers the group secret for the local node from an epoch record.
//
// self identifies which wrap to open. The recovered secret is checked against
// the record's commitment: that check is what makes it impossible for a
// malicious quorum to hand different members different secrets and split
// discovery invisibly, since the commitment is one value the whole network
// sees.
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

// Domain-separation labels. Every derived value is bound to one of these, so
// the discovery AEAD key and a topic ID can never come out equal, and neither
// can ever equal the secret itself.
const (
	labelSealInfo     = "wg-p2p/epoch-seal/v1"
	labelTopic        = "wg-p2p/dht-topic/v1"
	labelDiscoveryKey = "wg-p2p/discovery-aead/v1"
	labelMDNS         = "wg-p2p/mdns-beacon/v1"
)

// derive expands the secret into keying material for one labelled use.
//
// HKDF-SHA256 with the epoch as salt and the label plus context as info. The
// epoch is mixed in as well as being part of which secret is used, so that a
// derivation cannot be replayed across epochs even if a secret were ever
// reused by mistake.
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

// TopicIDSize is the length of a blinded rendezvous topic. Twenty bytes
// matches a BitTorrent DHT infohash, which is what a BEP 44 lookup key is.
const TopicIDSize = 20

// TopicID returns the blinded DHT rendezvous topic for a time window.
//
// Blinded and rotating, per docs/research/building-blocks.md §6: an outsider
// watching the public DHT cannot recognize the network, enumerate its members,
// or count them, because the topic is a keyed derivation rather than a name.
// A revoked member loses the ability to compute it at the next epoch, which is
// the discovery half of revocation.
//
// window is the caller's coarse clock bucket — floor(unix / period) — so that
// the topic rotates on a schedule all members agree on without any of them
// needing an accurate clock. Nothing here reads the clock: the caller supplies
// the window, and discovery/dht owns the period.
func (s Secret) TopicID(epoch uint64, window uint64) []byte {
	ctx := binary.BigEndian.AppendUint64(nil, window)
	return s.derive(labelTopic, epoch, ctx, TopicIDSize)
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
