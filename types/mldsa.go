package types

import (
	"cmp"
	"crypto/hkdf"
	"crypto/mldsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

// ML-DSA-44 sizes, in bytes.
const (
	SigningKeySize = mldsa.MLDSA44PublicKeySize
	PQSigSize      = mldsa.MLDSA44SignatureSize
)

// A SigningKey is an ML-DSA-44 public key: what verifies an identity's
// signatures.
type SigningKey [SigningKeySize]byte

// A PQSig is an ML-DSA-44 signature.
type PQSig [PQSigSize]byte

const (
	labelSigningSeed = "juist/mldsa44-seed/v1"
	labelEndorsement = "juist/signing-key/v1"
)

// IsZero reports whether k is the zero value.
func (k *SigningKey) IsZero() bool { return *k == SigningKey{} }

// Validate reports whether k decodes as an ML-DSA-44 public key.
func (k *SigningKey) Validate() error {
	if k.IsZero() {
		return fmt.Errorf("signing key is zero")
	}
	if _, err := mldsa.NewPublicKey(mldsa.MLDSA44(), k[:]); err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	return nil
}

// Verify reports whether sig is a valid signature by k over msg.
func (k *SigningKey) Verify(msg []byte, sig *PQSig) bool {
	if sig == nil {
		return false
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA44(), k[:])
	if err != nil {
		return false
	}
	return mldsa.Verify(pk, msg, sig[:], nil) == nil
}

func (k SigningKey) MarshalBinary() ([]byte, error) { return cloneArray(k[:]) }

func (k *SigningKey) UnmarshalBinary(b []byte) error {
	return unmarshalKeyBinary("signing key", b, k[:])
}

func (s *PQSig) IsZero() bool                  { return *s == PQSig{} }
func (s PQSig) MarshalBinary() ([]byte, error) { return cloneArray(s[:]) }

func (s *PQSig) UnmarshalBinary(b []byte) error {
	return unmarshalKeyBinary("ML-DSA signature", b, s[:])
}

// signingKeyFromSeed derives an identity's ML-DSA key from its Ed25519 seed,
// so that whatever holds the one holds the other.
func signingKeyFromSeed(seed []byte) (*mldsa.PrivateKey, error) {
	s, err := hkdf.Key(sha256.New, seed, nil, labelSigningSeed, mldsa.PrivateKeySize)
	if err != nil {
		return nil, err
	}
	return mldsa.NewPrivateKey(mldsa.MLDSA44(), s)
}

// SigningKey returns the identity's ML-DSA public key.
func (p PrivateIdentity) SigningKey() SigningKey {
	var out SigningKey
	if p.pq != nil {
		copy(out[:], p.pq.PublicKey().Bytes())
	}
	return out
}

// SignPQ signs msg with the identity's ML-DSA key, deterministically.
func (p PrivateIdentity) SignPQ(msg []byte) (PQSig, error) {
	var out PQSig
	if p.pq == nil {
		return out, fmt.Errorf("types: signing with an empty identity")
	}
	sig, err := p.pq.SignDeterministic(msg, nil)
	if err != nil {
		return out, err
	}
	copy(out[:], sig)
	return out, nil
}

// Endorse signs, by Ed25519, that the identity's signing key is its own.
func (p PrivateIdentity) Endorse() (Sig, error) {
	k := p.SigningKey()
	h := endorsement(p.Public(), &k)
	return p.Sign(h[:])
}

// Endorsement returns [PrivateIdentity.Endorse]'s signature, nil for an
// empty identity.
func (p PrivateIdentity) Endorsement() *Sig {
	e, err := p.Endorse()
	if err != nil {
		return nil
	}
	return &e
}

// VerifyEndorsement reports whether sig is i's endorsement of key.
func (i Identity) VerifyEndorsement(key *SigningKey, sig Sig) bool {
	h := endorsement(i, key)
	return i.Verify(h[:], sig)
}

func endorsement(id Identity, key *SigningKey) Hash {
	return hashLabeled(labelEndorsement, id[:], key[:])
}

// SignBoth signs msg by Ed25519 and by ML-DSA.
func (p PrivateIdentity) SignBoth(msg []byte) (Sig, *PQSig, error) {
	sig, err := p.Sign(msg)
	if err != nil {
		return sig, nil, err
	}
	s, err := p.SignPQ(msg)
	if err != nil {
		return Sig{}, nil, err
	}
	return sig, &s, nil
}

// AdminKeyText is how an admin key is handed to the admins who add it: its
// identity and, after dots, its signing key and the endorsement that binds
// them.
func AdminKeyText(priv PrivateIdentity) (string, error) {
	e, err := priv.Endorse()
	if err != nil {
		return "", err
	}
	k := priv.SigningKey()
	return priv.Public().String() + "." + b64.EncodeToString(k[:]) + "." + b64.EncodeToString(e[:]), nil
}

// ParseAdminKey parses [AdminKeyText], or an identity alone, which names no
// signing key; one whose endorsement does not verify is refused.
func ParseAdminKey(s string) (Identity, *SigningKey, *Sig, error) {
	idText, rest, hasKey := strings.Cut(s, ".")
	id, err := ParseIdentity(idText)
	if err != nil || !hasKey {
		return id, nil, nil, err
	}
	keyText, sigText, _ := strings.Cut(rest, ".")
	var key SigningKey
	var e Sig
	if err := cmp.Or(unmarshalKeyText("signing key", "", []byte(keyText), key[:]),
		unmarshalKeyText("endorsement", "", []byte(sigText), e[:]), key.Validate()); err != nil {
		return Identity{}, nil, nil, err
	}
	if !id.VerifyEndorsement(&key, e) {
		return Identity{}, nil, nil, errors.New("types: the key's signing key is not the one it endorsed")
	}
	return id, &key, &e, nil
}
