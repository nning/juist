// Package waiting is how a change to a network's log that waits for more
// votes travels between admin devices: sealed to the admins, and signed by
// the admin key that hands it on, so that a daemon can check and bound it
// without reading it. Nothing here authorizes anything: a change counts once
// its own signatures reach the quorum where it is applied.
package waiting

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// Limits on a change as it travels.
const (
	// MaxLifetime is how long a change may wait, from when it is handed on.
	MaxLifetime = 7 * 24 * time.Hour

	// MaxSize caps an encoded change: the largest record, sealed, and a key
	// for every admin.
	MaxSize = types.MaxRecordSize + types.MaxAdmins*(secrets.SealedKeySize+64) + types.SigSize + types.PQSigSize + 4096

	// MaxAbout caps the devices a change is about.
	MaxAbout = 16

	maxNestedLevels = 4
	maxMapPairs     = 16
)

// A Change is one admin key's copy of a change waiting for votes.
type Change struct {
	// Network is the genesis hash, and Prev the record the change builds on:
	// once the log has moved past it, the change can no longer apply.
	Network types.Hash `cbor:"1,keyasint"`
	Prev    types.Hash `cbor:"2,keyasint"`

	// ID is the change's [types.AUM.SigHash], which every copy of it shares
	// however many signatures each carries.
	ID types.Hash `cbor:"3,keyasint"`

	// About are the devices the change is about, which are never sent it.
	About []types.Identity `cbor:"4,keyasint,omitempty"`

	// Issued and Expires are Unix seconds.
	Issued  int64 `cbor:"5,keyasint"`
	Expires int64 `cbor:"6,keyasint"`

	// Body is the record, sealed under a key each of Readers holds sealed to
	// that admin key's encryption key.
	Body    []byte   `cbor:"7,keyasint"`
	Readers []Reader `cbor:"8,keyasint"`

	// Signer is the admin key that hands the change on, and Sig its
	// signature over everything else; PQ its ML-DSA one, past the cut-over.
	Signer types.Identity `cbor:"9,keyasint"`
	Sig    types.Sig      `cbor:"10,keyasint"`

	// Proposer is the admin key that handed the change on first, which the
	// record is signed by too.
	Proposer types.Identity `cbor:"11,keyasint"`

	PQ *types.PQSig `cbor:"12,keyasint,omitempty"`
}

// A Reader is an admin key the change is sealed to, and its key to the body.
type Reader struct {
	Admin types.Identity `cbor:"1,keyasint"`
	Key   []byte         `cbor:"2,keyasint"`
}

// ErrNoReaders is a change no admin key could be sent: none has an
// encryption key yet.
var ErrNoReaders = errors.New("no admin key has an encryption key to seal the change to")

// Seal hands on aum, a change to network, as signer, for proposer, or the
// signer where that is zero: sealed to every admin key of admins with an
// encryption key it can be sealed to, and expiring after ttl, at most
// [MaxLifetime]. keyOf names the signing keys records are verified against,
// nil below the cut-over; where it names the signer's, the copy is signed by
// ML-DSA too.
func Seal(network types.Hash, aum *types.AUM, admins []types.AdminKey, keyOf func(types.Identity) *types.SigningKey,
	signer types.PrivateIdentity, proposer types.Identity, now time.Time, ttl time.Duration) (*Change, error) {
	if aum.Prev == nil {
		return nil, errors.New("waiting: a genesis does not wait in a network")
	}
	if !proposer.IsZero() && !aum.VerifySignature(proposer, keyOf(proposer)) {
		return nil, errors.New("waiting: the proposer has not signed the record")
	}
	c := &Change{
		Network:  network,
		Prev:     *aum.Prev,
		ID:       aum.SigHash(),
		About:    AboutOf(aum),
		Issued:   now.Unix(),
		Expires:  now.Add(min(ttl, MaxLifetime)).Unix(),
		Signer:   signer.Public(),
		Proposer: cmp.Or(proposer, signer.Public()),
	}
	body, err := aum.Encode()
	if err != nil {
		return nil, err
	}
	var key [secrets.KeySize]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, fmt.Errorf("waiting: drawing a key: %w", err)
	}
	if c.Body, err = sealBody(key, c.context(), body); err != nil {
		return nil, err
	}
	for _, k := range admins {
		if k.Recipient == nil {
			continue
		}
		// One admin's unusable key must not stop the change reaching the rest.
		if wrap, err := secrets.SealKeyTo(c.context(), k.Public, *k.Recipient, key); err == nil {
			c.Readers = append(c.Readers, Reader{Admin: k.Public, Key: wrap})
		}
	}
	if len(c.Readers) == 0 {
		return nil, ErrNoReaders
	}
	slices.SortFunc(c.Readers, func(a, b Reader) int { return a.Admin.Compare(b.Admin) })
	if c.Sig, c.PQ, err = signer.SignBoth(c.signed(), keyOf(signer.Public()) != nil); err != nil {
		return nil, err
	}
	return c, c.validate()
}

// AboutOf lists the devices a change is about: whose record it changes or
// removes.
func AboutOf(aum *types.AUM) []types.Identity {
	if aboutSubject[aum.Kind] {
		return []types.Identity{*aum.Subject}
	}
	return nil
}

// aboutSubject is, for every kind, whether its subject is the device whose
// record it changes.
var aboutSubject = map[types.Kind]bool{
	types.KindGenesis:           false,
	types.KindAddNode:           false,
	types.KindRemoveNode:        true,
	types.KindSetNodeRoutes:     true,
	types.KindRotateNodeKey:     true,
	types.KindRotateIdentity:    true,
	types.KindAddAdminKey:       false,
	types.KindRemoveAdminKey:    false,
	types.KindSetQuorum:         false,
	types.KindCheckpoint:        false,
	types.KindEpochBump:         false,
	types.KindSchemaUpgrade:     false,
	types.KindSetVouchers:       false,
	types.KindSetHolder:         false,
	types.KindRenumberNetwork:   false,
	types.KindRenumberNode:      true,
	types.KindRetireAddresses:   false,
	types.KindRenameNetwork:     false,
	types.KindSetAdminRecipient: false,
	types.KindSetNodeNames:      true,
	types.KindSetDomain:         false,
	types.KindSetPublished:      true,
	types.KindRenameNode:        true,
	types.KindDisable:           false,
	types.KindSetPolicy:         false,
	types.KindSetSigningKeys:    false,
	types.KindSetAdminSigning:   false,
}

// Open reads the change as the admin key admin, and checks that it is what
// its signer said: the record it names, carrying the signer's signature,
// checked against the signing key keyOf names, nil below the cut-over.
func (c *Change) Open(admin types.PrivateIdentity, keyOf func(types.Identity) *types.SigningKey) (types.AUM, error) {
	id := admin.Public()
	i := slices.IndexFunc(c.Readers, func(r Reader) bool { return r.Admin == id })
	if i < 0 {
		return types.AUM{}, fmt.Errorf("waiting: not sealed to %v", id.ShortString())
	}
	priv, err := secrets.AdminRecipient(admin.Seed())
	if err != nil {
		return types.AUM{}, err
	}
	key, err := secrets.OpenKey(c.context(), id, priv, c.Readers[i].Key)
	if err != nil {
		return types.AUM{}, fmt.Errorf("waiting: %w", err)
	}
	body, err := openBody(key, c.context(), c.Body)
	if err != nil {
		return types.AUM{}, err
	}
	aum, err := types.DecodeUnsignedAUM(body)
	switch {
	case err != nil:
		return types.AUM{}, fmt.Errorf("waiting: %w", err)
	case aum.Prev == nil || *aum.Prev != c.Prev || aum.SigHash() != c.ID:
		return types.AUM{}, errors.New("waiting: the record is not the change its copy names")
	case !aum.VerifySignature(c.Signer, keyOf(c.Signer)) || !aum.VerifySignature(c.Proposer, keyOf(c.Proposer)):
		return types.AUM{}, errors.New("waiting: the record does not carry its signer's and proposer's signatures")
	case !slices.Equal(AboutOf(&aum), c.About):
		return types.AUM{}, errors.New("waiting: the change is about other devices than its copy says")
	}
	return aum, nil
}

// SealedTo reports whether the change is sealed to the admin key id.
func (c *Change) SealedTo(id types.Identity) bool {
	return slices.ContainsFunc(c.Readers, func(r Reader) bool { return r.Admin == id })
}

// IsAbout reports whether the change is about the device id.
func (c *Change) IsAbout(id types.Identity) bool { return slices.Contains(c.About, id) }

// Encode returns the change's canonical encoding.
func (c *Change) Encode() ([]byte, error) {
	b, err := encMode.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("waiting: encoding: %w", err)
	}
	return b, nil
}

// Hash names one copy of a change, by its encoding.
func Hash(encoded []byte) types.Hash { return sha256.Sum256(encoded) }

// Decode decodes a change and checks its shape and its signer's Ed25519
// signature, which every copy carries. Whether the signer is an admin, its
// ML-DSA signature past the cut-over ([Change.VerifyPQ]), and whether the
// change still fits the log, the caller decides against the log.
func Decode(b []byte) (*Change, error) {
	if len(b) == 0 || len(b) > MaxSize {
		return nil, fmt.Errorf("waiting: a change of %d bytes", len(b))
	}
	var c Change
	if err := decMode.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("waiting: decoding: %w", err)
	}
	if re, err := c.Encode(); err != nil || !bytes.Equal(re, b) {
		return nil, errors.New("waiting: not the canonical encoding")
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if !c.Signer.Verify(c.signed(), c.Sig) {
		return nil, errors.New("waiting: the signer's signature does not verify")
	}
	return &c, nil
}

// VerifyPQ checks the signer's ML-DSA signature against key, the signing key
// the log names for it.
func (c *Change) VerifyPQ(key *types.SigningKey) error {
	if key == nil || !key.Verify(c.signed(), c.PQ) {
		return errors.New("waiting: the signer's ML-DSA signature does not verify")
	}
	return nil
}

func (c *Change) validate() error {
	switch {
	case c.Network.IsZero() || c.Prev.IsZero() || c.ID.IsZero():
		return errors.New("waiting: a change names no network, parent or record")
	case len(c.About) > MaxAbout:
		return fmt.Errorf("waiting: a change about %d devices", len(c.About))
	case c.Issued <= 0 || c.Expires <= c.Issued || c.Expires-c.Issued > int64(MaxLifetime/time.Second):
		return errors.New("waiting: a change that expires before it is issued, or waits too long")
	case len(c.Readers) == 0 || len(c.Readers) > types.MaxAdmins:
		return fmt.Errorf("waiting: a change sealed to %d admin keys", len(c.Readers))
	}
	if err := c.Signer.Validate(); err != nil {
		return fmt.Errorf("waiting: signer: %w", err)
	}
	if err := c.Proposer.Validate(); err != nil {
		return fmt.Errorf("waiting: proposer: %w", err)
	}
	for i, r := range c.Readers {
		if i > 0 && c.Readers[i-1].Admin.Compare(r.Admin) >= 0 {
			return errors.New("waiting: readers are not sorted and unique")
		}
		if len(r.Key) != secrets.SealedKeySize {
			return fmt.Errorf("waiting: a reader's key is %d bytes", len(r.Key))
		}
	}
	return nil
}

// signed is what the signer signs: the change without its signature, under
// a label of its own.
func (c *Change) signed() []byte {
	unsigned := *c
	unsigned.Sig, unsigned.PQ = types.Sig{}, nil
	b, err := encMode.Marshal(&unsigned)
	if err != nil {
		panic(fmt.Sprintf("waiting: encoding a change: %v", err))
	}
	h := sha256.Sum256(append([]byte("juist/waiting-change/v1\x00"), b...))
	return h[:]
}

// context binds the sealed body and its keys to one network and one change.
func (c *Change) context() []byte {
	return append(append([]byte("juist/waiting-body/v1\x00"), c.Network[:]...), c.ID[:]...)
}

// sealBody encrypts the record under key, a fresh one per change:
// XChaCha20-Poly1305 with a random nonce, the context as additional data.
func sealBody(key [secrets.KeySize]byte, context, plaintext []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, a.NonceSize(), a.NonceSize()+len(plaintext)+a.Overhead())
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("waiting: drawing a nonce: %w", err)
	}
	return a.Seal(out, out, plaintext, context), nil
}

func openBody(key [secrets.KeySize]byte, context, body []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	if len(body) < a.NonceSize()+a.Overhead() {
		return nil, errors.New("waiting: a sealed record shorter than its nonce")
	}
	pt, err := a.Open(nil, body[:a.NonceSize()], body[a.NonceSize():], context)
	if err != nil {
		return nil, fmt.Errorf("waiting: opening the record: %w", err)
	}
	return pt, nil
}

var encMode = func() cbor.EncMode {
	m, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("waiting: building CBOR encoder: %v", err))
	}
	return m
}()

var decMode = func() cbor.DecMode {
	m, err := types.StrictDecOptions(maxNestedLevels, types.MaxAdmins, maxMapPairs).DecMode()
	if err != nil {
		panic(fmt.Sprintf("waiting: building CBOR decoder: %v", err))
	}
	return m
}()
