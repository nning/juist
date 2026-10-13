package pairkey

import (
	"crypto/mlkem"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/nning/juist/types"
)

// A Msg is one member's state of the exchange with one peer, sent in every
// log sync between the two. It says the whole state, so a lost one costs
// nothing the next does not carry, and a stale one moves nothing back.
type Msg struct {
	From types.Identity `cbor:"1,keyasint"`
	To   types.Identity `cbor:"2,keyasint"`

	// Store is the sender's store of pair keys, as its announcement names
	// it, and ToStore the receiver's as the sender holds it; FromWG and
	// ToWG the two's WireGuard keys as the sender's log names them. A
	// message for another store, or other keys, is one for a pair that has
	// since started over.
	Store   uint64      `cbor:"3,keyasint"`
	ToStore uint64      `cbor:"9,keyasint"`
	FromWG  types.WGKey `cbor:"10,keyasint"`
	ToWG    types.WGKey `cbor:"11,keyasint"`

	// Gen is the newest generation the sender holds, Epoch the epoch whose
	// group key it mixes in, CT the sender's ciphertext for it and Check
	// the follower's confirmation of the key; set only while the generation
	// is not yet in use.
	Gen   uint64 `cbor:"4,keyasint,omitempty"`
	Epoch uint64 `cbor:"5,keyasint,omitempty"`
	CT    []byte `cbor:"6,keyasint,omitempty"`
	Check []byte `cbor:"7,keyasint,omitempty"`

	// Use is the generation the sender's handshakes with the peer use, zero
	// for the group key; from the leader, a generation it commits to.
	Use uint64 `cbor:"8,keyasint,omitempty"`

	// MLDSA is the sender's ML-DSA signature, past the cut-over.
	MLDSA *types.PQSig `cbor:"22,keyasint,omitempty"`
	Sig   types.Sig    `cbor:"23,keyasint"`
}

// MaxMsgSize bounds an encoded message.
const MaxMsgSize = 2*types.IdentitySize + 2*types.WGKeySize + 5*9 + mlkem.CiphertextSize768 + checkSize + types.SigSize +
	types.PQSigSize + 40

const labelMsg = "juist/pair-msg/v1"

var encMode = func() cbor.EncMode {
	m, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("pairkey: building CBOR encoder: %v", err))
	}
	return m
}()

func (m *Msg) signingBytes(network types.Hash) ([]byte, error) {
	unsigned := *m
	unsigned.Sig, unsigned.MLDSA = types.Sig{}, nil
	body, err := encMode.Marshal(&unsigned)
	if err != nil {
		return nil, fmt.Errorf("pairkey: encoding: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(labelMsg))
	h.Write([]byte{0})
	h.Write(network[:])
	h.Write(body)
	return h.Sum(nil), nil
}

// Sign fills in the signature, by the sender's identity key, for network;
// by ML-DSA too where pq, as past the cut-over.
func (m *Msg) Sign(priv types.PrivateIdentity, network types.Hash, pq bool) error {
	if priv.Public() != m.From {
		return fmt.Errorf("pairkey: a message from %v would be signed by %v", m.From.ShortString(), priv.Public().ShortString())
	}
	if err := m.StaticValidate(); err != nil {
		return err
	}
	msg, err := m.signingBytes(network)
	if err != nil {
		return err
	}
	m.Sig, m.MLDSA, err = priv.SignBoth(msg, pq)
	return err
}

// Verify checks the message's shape and that its sender signed it for
// network: by ML-DSA against key where it is set, as past the cut-over, and
// by Ed25519 always.
func (m *Msg) Verify(network types.Hash, key *types.SigningKey) error {
	if err := m.StaticValidate(); err != nil {
		return err
	}
	msg, err := m.signingBytes(network)
	if err != nil {
		return err
	}
	if !m.From.Verify(msg, m.Sig) || key != nil && !key.Verify(msg, m.MLDSA) {
		return fmt.Errorf("pairkey: a message from %v is not signed by it", m.From.ShortString())
	}
	return nil
}

// StaticValidate checks the message's shape.
func (m *Msg) StaticValidate() error {
	if err := m.From.Validate(); err != nil {
		return fmt.Errorf("pairkey: sender: %w", err)
	}
	if err := m.To.Validate(); err != nil {
		return fmt.Errorf("pairkey: receiver: %w", err)
	}
	switch {
	case m.From == m.To:
		return errors.New("pairkey: a message to its sender")
	case m.Store == 0 || m.ToStore == 0:
		return errors.New("pairkey: a message names no store")
	case m.FromWG == m.ToWG:
		return errors.New("pairkey: a message between one WireGuard key")
	case m.CT != nil && len(m.CT) != mlkem.CiphertextSize768:
		return fmt.Errorf("pairkey: a ciphertext of %d bytes", len(m.CT))
	case m.Check != nil && len(m.Check) != checkSize:
		return fmt.Errorf("pairkey: a confirmation of %d bytes", len(m.Check))
	case (m.CT != nil || m.Check != nil) && m.Gen == 0:
		return errors.New("pairkey: a ciphertext for no generation")
	case m.Use > m.Gen:
		return fmt.Errorf("pairkey: generation %d in use, past the newest, %d", m.Use, m.Gen)
	}
	return nil
}
