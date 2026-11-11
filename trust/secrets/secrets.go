// Package secrets implements the epoch group secret: a symmetric secret held
// by exactly the current member set, sealed to each member inside a signed log
// record and replaced whenever membership changes.
//
// It keys discovery and gossip confidentiality and seeds the WireGuard PSKs of
// pairs without a pair key. A leak costs discovery privacy and those pairs'
// post-quantum hedge, not their X25519 handshakes. A revoked member can no
// longer recognize the network's topics or read its announcements.
//
// Ciphersuite: HPKE (RFC 9180) base mode, X-Wing (MLKEM768-X25519, KEM ID
// 0x647a), HKDF-SHA256, ChaCha20-Poly1305; about 1.2 KiB per member per epoch,
// which sets the schema's size limits.
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

	"github.com/nning/juist/internal/malformed"
	"github.com/nning/juist/types"
)

// The HPKE ciphersuite, fixed so it cannot be downgraded. The KEM follows from
// hpke.NewHybridPublicKey; TestCiphersuiteIsTheIntendedOne pins it.
func kdf() hpke.KDF   { return hpke.HKDFSHA256() }
func aead() hpke.AEAD { return hpke.ChaCha20Poly1305() }

// A Secret is an epoch group secret. Use it only through [Secret.derive], so
// that no two uses share key material.
type Secret [types.GroupSecretSize]byte

// NewSecret draws a fresh group secret, independent of the last epoch's, so
// an admin can rekey without reading the previous secret.
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

// PrivateKeys is a node's HPKE recipient key material: both halves of the
// hybrid KEM, whose public halves [types.NodeRecord] carries.
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

// Bytes returns the persistable form [NewPrivateKeys] accepts.
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

// recipientKey assembles a node's HPKE public key, rejecting invalid halves.
// The check is incomplete (an all-zero ML-KEM key is a valid encoding); the
// schema's shape rules and quorum catch degenerate keys.
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

// sealInfo binds a wrap to one epoch and one recipient: recipient keys are
// reused across epochs, so an unbound wrap would still decrypt if lifted into
// another record or re-addressed. The record's signatures bind the network;
// binding it here would be circular for genesis.
func sealInfo(epoch uint64, recipient types.Identity) []byte {
	info := make([]byte, 0, len(types.LabelEpochSeal)+1+8+types.IdentitySize)
	info = append(info, types.LabelEpochSeal...)
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

// SealTo builds the epoch record distributing secret, for tests that pin it;
// production paths draw a fresh one with [NewEpoch].
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
			// The schema pins this length to reject malformed wraps by
			// shape; a ciphersuite change must change it deliberately.
			return nil, fmt.Errorf("secrets: sealed secret is %d bytes, schema expects %d",
				len(sealed), types.SealedSecretSize)
		}
		rec.Wraps = append(rec.Wraps, types.EpochWrap{Recipient: n.Identity, Sealed: sealed})
	}
	// The schema requires wraps sorted by recipient: one set, one encoding.
	slices.SortFunc(rec.Wraps, func(a, b types.EpochWrap) int {
		return a.Recipient.Compare(b.Recipient)
	})
	if err := rec.StaticValidate(); err != nil {
		return nil, fmt.Errorf("secrets: built an invalid epoch record: %w", err)
	}
	return rec, nil
}

// Open recovers self's group secret from rec and checks it against the
// record's commitment, which the whole network sees, so a malicious quorum
// cannot hand different members different secrets.
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
	info := make([]byte, 0, len(types.LabelCatchUp)+1+len(network)+types.IdentitySize+len(nonce))
	info = append(info, types.LabelCatchUp...)
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
	defer malformed.Recover(&err)
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
	x, err := hkdf.Key(sha256.New, seed, nil, types.LabelAdminX25519, 32)
	if err != nil {
		return nil, err
	}
	m, err := hkdf.Key(sha256.New, seed, nil, types.LabelAdminMLKEM, mlkem.SeedSize)
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
	info := append([]byte(types.LabelWaitingKey), 0)
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

// OpenKey opens what [SealKeyTo] sealed to reader, whose keys priv are.
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
	info := append([]byte(types.LabelPeerSeal), 0)
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
func OpenFromPeer(network types.Hash, self types.Identity, priv *PrivateKeys, sealed []byte) (_ []byte, err error) {
	defer malformed.Recover(&err)
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
		// Fails only above 255 hash blocks; no caller comes near.
		panic(fmt.Sprintf("secrets: deriving %s: %v", label, err))
	}
	return out
}

// TopicIDSize is the length of a blinded rendezvous label, a DHT infohash's.
const TopicIDSize = 20

// TopicSeed returns the Ed25519 seed subject's announcement is published under
// for epoch and window (the caller's floor(unix / period)). Keyed, so DHT
// observers cannot recognize the network or count its members, and a revoked
// member loses it at the next epoch. A key, because a BEP 44 address is the
// hash of the key; one per member, because the key travels in the clear and a
// shared one would link a network's items.
func (s Secret) TopicSeed(epoch, window uint64, subject types.Identity) [32]byte {
	ctx := binary.BigEndian.AppendUint64(nil, window)
	ctx = append(ctx, subject[:]...)
	var out [32]byte
	copy(out[:], s.derive(types.LabelDHTTopic, epoch, ctx, len(out)))
	return out
}

// DiscoveryKey returns the AEAD key protecting announcement payloads, so that
// a DHT storage node sees opaque bytes at an opaque key.
func (s Secret) DiscoveryKey(epoch uint64) [32]byte {
	var out [32]byte
	copy(out[:], s.derive(types.LabelDiscoveryKey, epoch, nil, len(out)))
	return out
}

// MDNSName returns the blinded LAN beacon label, so a LAN does not learn that
// the network exists or who is on it.
func (s Secret) MDNSName(epoch uint64) []byte {
	return s.derive(types.LabelMDNS, epoch, nil, TopicIDSize)
}

// PSKSeed returns the seed of an epoch's WireGuard preshared keys. Members keep
// it longer than the secret, to reach a peer still behind.
func (s Secret) PSKSeed(epoch uint64) [32]byte {
	var out [32]byte
	copy(out[:], s.derive(types.LabelPSK, epoch, nil, len(out)))
	return out
}

// GossipKey returns the AEAD key for gossip frames, label-separated from
// [Secret.DiscoveryKey]. Confidentiality only: records carry their own
// signatures.
func (s Secret) GossipKey(epoch uint64) [32]byte {
	var out [32]byte
	copy(out[:], s.derive(types.LabelGossipKey, epoch, nil, len(out)))
	return out
}
