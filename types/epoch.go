package types

import (
	"errors"
	"fmt"
)

// Sizes of the secrets the log carries and commits to.
const (
	// GroupSecretSize is the length of an epoch group secret.
	GroupSecretSize = 32

	// DisablementSecretSize is the length of a break-glass secret.
	DisablementSecretSize = 32

	// SealedSecretSize is the exact length of [EpochWrap.Sealed]: an HPKE
	// single-shot ciphertext under MLKEM768-X25519 (X-Wing) with
	// ChaCha20-Poly1305 over a GroupSecretSize plaintext. Pinning it lets a
	// malformed wrap be rejected by shape, before any cryptographic work.
	SealedSecretSize = 1088 + // ML-KEM-768 ciphertext
		32 + // X25519 encapsulated key
		GroupSecretSize +
		16 // Poly1305 tag
)

// An EpochSuite names the HPKE ciphersuite an epoch record's wraps are sealed
// under. It exists so that replacing the ciphersuite is a value a decoder
// already understands rather than a schema break, which the M3 freeze would
// otherwise put out of reach: a node meeting a suite it does not implement
// rejects the record and stops, instead of opening a wrap with the wrong
// algorithm or splitting the network by ignoring a field.
type EpochSuite uint64

// SuiteHybridX25519MLKEM768 is the only suite v1 implements: HPKE base mode
// with the MLKEM768-X25519 hybrid KEM (X-Wing, KEM ID 0x647a), HKDF-SHA256
// and ChaCha20-Poly1305. It is zero, and therefore absent from the encoding,
// so naming the suite costs nothing until there is a second one.
const SuiteHybridX25519MLKEM768 EpochSuite = 0

// String names the suite, so an error about an unimplemented one is readable.
func (s EpochSuite) String() string {
	if s == SuiteHybridX25519MLKEM768 {
		return "MLKEM768-X25519/HKDF-SHA256/ChaCha20-Poly1305"
	}
	return fmt.Sprintf("suite?<%d>", uint64(s))
}

// validateSuite rejects every suite this build does not implement. The sealed
// length is pinned per suite, so accepting an unknown one would mean accepting
// a length rule that does not exist yet.
func validateSuite(s EpochSuite) error {
	if s != SuiteHybridX25519MLKEM768 {
		return fmt.Errorf("epoch secret is sealed under %v, which this version does not implement", s)
	}
	return nil
}

// An EpochWrap is one recipient's copy of an epoch group secret.
type EpochWrap struct {
	// Recipient is the node the secret is sealed to, named by identity key.
	Recipient Identity `cbor:"1,keyasint"`

	// Sealed is the HPKE single-shot ciphertext. Its exact length is fixed
	// by the ciphersuite; see trust/secrets.
	Sealed []byte `cbor:"2,keyasint"`
}

// An EpochRecord distributes a new epoch group secret to the member set. The
// secret gates discovery and gossip confidentiality, never the data plane, and
// losing it is what stops a revoked member from finding the network at all.
// Each epoch's secret is fresh randomness rather than a derivation, so an admin
// can rekey from an admin key alone.
type EpochRecord struct {
	// Epoch is the new epoch number, always exactly one more than the current
	// one: strictly sequential, so no record can jump the counter and a node's
	// persisted epoch floor has an exact meaning.
	Epoch uint64 `cbor:"1,keyasint"`

	// Commit is a commitment to the secret: see [EpochCommit]. Without it a
	// malicious quorum could seal a different secret to each member and
	// partition discovery invisibly.
	Commit Hash `cbor:"2,keyasint"`

	// Wraps holds the secret sealed to each member, sorted by recipient and
	// covering the member set exactly. Exactness is what stops a bump from
	// quietly excluding a member or including a removed one.
	Wraps []EpochWrap `cbor:"3,keyasint,omitempty"`

	// Suite names the ciphersuite Wraps are sealed under. Absent means
	// [SuiteHybridX25519MLKEM768].
	Suite EpochSuite `cbor:"4,keyasint,omitempty"`
}

// EpochCommit returns the commitment stored in [EpochRecord.Commit] for a
// group secret. Recipients compare it against what they decrypt.
func EpochCommit(secret []byte) Hash {
	return hashLabeled(LabelEpochCommit, secret)
}

// A DisablementSecret is a break-glass secret, as [KindDisable] reveals it.
type DisablementSecret [DisablementSecretSize]byte

func (s DisablementSecret) MarshalBinary() ([]byte, error) { return cloneArray(s[:]) }

func (s *DisablementSecret) UnmarshalBinary(b []byte) error {
	return unmarshalKeyBinary("break-glass secret", b, s[:])
}

// DisablementCommit returns the value committed in [Snapshot.Disablement] for
// a break-glass secret. A plain labelled hash, not a password KDF: these are
// full-length CSPRNG output, so there is no guessing to slow down.
func DisablementCommit(secret []byte) Hash {
	return hashLabeled(LabelDisablement, secret)
}

// StaticValidate checks an epoch record's shape. Whether its wrap set matches
// the member set is a question about state, answered in trust/log.
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
		// Shape only, not a curve point: every recipient must equal a member's
		// identity key for the record to be accepted, and those are validated
		// where they are admitted.
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
