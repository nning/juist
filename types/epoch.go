package types

import (
	"errors"
	"fmt"
)

// Sizes of the secrets the log carries and commits to.
const (
	GroupSecretSize = 32

	// DisablementSecretSize is the length of a break-glass secret.
	DisablementSecretSize = 32

	// SealedSecretSize is the exact length of [EpochWrap.Sealed] (X-Wing HPKE,
	// ChaCha20-Poly1305), so a malformed wrap fails before any crypto.
	SealedSecretSize = 1088 + // ML-KEM-768 ciphertext
		32 + // X25519 encapsulated key
		GroupSecretSize +
		16 // Poly1305 tag
)

// An EpochSuite names the HPKE ciphersuite epoch wraps are sealed under, so a
// new suite is a value, not a schema break. A node meeting an unknown suite
// rejects the record rather than open a wrap with the wrong algorithm.
type EpochSuite uint64

// SuiteHybridX25519MLKEM768 is HPKE base mode with X-Wing (KEM ID 0x647a),
// HKDF-SHA256 and ChaCha20-Poly1305. Zero, so absent from the encoding.
const SuiteHybridX25519MLKEM768 EpochSuite = 0

func (s EpochSuite) String() string {
	if s == SuiteHybridX25519MLKEM768 {
		return "MLKEM768-X25519/HKDF-SHA256/ChaCha20-Poly1305"
	}
	return fmt.Sprintf("suite?<%d>", uint64(s))
}

// validateSuite rejects every suite this build does not implement, since the
// sealed length is pinned per suite.
func validateSuite(s EpochSuite) error {
	if s != SuiteHybridX25519MLKEM768 {
		return fmt.Errorf("epoch secret is sealed under %v, which this version does not implement", s)
	}
	return nil
}

// An EpochWrap is one recipient's copy of an epoch group secret.
type EpochWrap struct {
	Recipient Identity `cbor:"1,keyasint"`

	// Sealed is the HPKE single-shot ciphertext.
	Sealed []byte `cbor:"2,keyasint"`
}

// An EpochRecord distributes a fresh random group secret to the member set.
// The secret gates discovery and gossip, never the data plane.
type EpochRecord struct {
	// Epoch is exactly one more than the current epoch, never a jump.
	Epoch uint64 `cbor:"1,keyasint"`

	// Commit is [EpochCommit] of the secret, so a quorum cannot seal each
	// member a different one unnoticed.
	Commit Hash `cbor:"2,keyasint"`

	// Wraps seal the secret to each member, sorted by recipient and covering
	// the member set exactly, so a bump cannot quietly drop or add anyone.
	Wraps []EpochWrap `cbor:"3,keyasint,omitempty"`

	// Suite seals Wraps; absent means [SuiteHybridX25519MLKEM768].
	Suite EpochSuite `cbor:"4,keyasint,omitempty"`
}

// EpochCommit returns the commitment to a group secret that recipients check
// what they decrypt against.
func EpochCommit(secret []byte) Hash {
	return hashLabeled(LabelEpochCommit, secret)
}

// A DisablementSecret is a break-glass secret, as [KindDisable] reveals it.
type DisablementSecret [DisablementSecretSize]byte

func (s DisablementSecret) MarshalBinary() ([]byte, error) { return cloneArray(s[:]) }

func (s *DisablementSecret) UnmarshalBinary(b []byte) error {
	return unmarshalKeyBinary("break-glass secret", b, s[:])
}

// DisablementCommit returns a break-glass secret's [Snapshot.Disablement]
// commitment. No KDF needed: the secrets are full-length random.
func DisablementCommit(secret []byte) Hash {
	return hashLabeled(LabelDisablement, secret)
}

// StaticValidate checks an epoch record's shape; trust/log matches its wraps
// to the member set.
func (e *EpochRecord) StaticValidate() error {
	if e.Epoch == 0 {
		return errors.New("epoch record has epoch 0; epochs start at 1")
	}
	if e.Commit.IsZero() {
		return errors.New("epoch record has no secret commitment")
	}
	if err := validateSuite(e.Suite); err != nil {
		return err
	}
	if len(e.Wraps) > MaxNodes {
		return fmt.Errorf("epoch record has %d wraps, over the %d limit", len(e.Wraps), MaxNodes)
	}
	for i := range e.Wraps {
		w := &e.Wraps[i]
		// No point check: recipients must equal validated member identities.
		if w.Recipient.IsZero() {
			return fmt.Errorf("epoch wrap %d has a zero recipient", i)
		}
		if len(w.Sealed) != SealedSecretSize {
			return fmt.Errorf("epoch wrap for %v is %d bytes, want %d",
				w.Recipient.ShortString(), len(w.Sealed), SealedSecretSize)
		}
		if i > 0 && e.Wraps[i-1].Recipient.Compare(w.Recipient) >= 0 {
			return fmt.Errorf("epoch wraps are not sorted and unique at %v", w.Recipient.ShortString())
		}
	}
	return nil
}
