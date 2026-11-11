package types

import (
	"errors"
	"fmt"

	"github.com/nning/juist/internal/malformed"
)

// A Lease is an admin device's signed statement that its log's head was Head
// at Issued. A node without a recent one may be missing a removal and fails
// closed. Leases are not log records, which would grow without bound.
type Lease struct {
	// Network is the genesis hash.
	Network Hash `cbor:"1,keyasint"`

	Head Hash `cbor:"2,keyasint"`

	// Issued is in Unix seconds by the signer's clock.
	Issued uint64 `cbor:"3,keyasint"`

	Signer Identity `cbor:"4,keyasint"`

	// Sig is Signer's Ed25519 signature over the fields above, MLDSA its
	// ML-DSA one.
	Sig   Sig    `cbor:"5,keyasint"`
	MLDSA *PQSig `cbor:"6,keyasint,omitempty"`
}

const MaxLeaseSize = 4096

// sigHash covers the lease without signatures, under its own label so it can
// be no other signature by the same key.
func (l *Lease) sigHash() Hash {
	unsigned := *l
	unsigned.Sig, unsigned.MLDSA = Sig{}, nil
	return hashLabeled(LabelLease, mustEncode(&unsigned))
}

// Sign sets Signer and signs by Ed25519 and ML-DSA.
func (l *Lease) Sign(priv PrivateIdentity) error {
	l.Signer = priv.Public()
	h := l.sigHash()
	sig, mldsa, err := priv.SignBoth(h[:])
	if err != nil {
		return err
	}
	l.Sig, l.MLDSA = sig, mldsa
	return nil
}

// VerifyPQ checks the ML-DSA signature against key, the one the log names for
// Signer.
func (l *Lease) VerifyPQ(key *SigningKey) error {
	h := l.sigHash()
	if key == nil || !key.Verify(h[:], l.MLDSA) {
		return errors.New("the lease carries no valid ML-DSA signature")
	}
	return nil
}

// Verify checks the Ed25519 signature, not whether Signer may issue leases.
func (l *Lease) Verify() error {
	if err := l.Signer.Validate(); err != nil {
		return fmt.Errorf("lease signer: %w", err)
	}
	h := l.sigHash()
	if !l.Signer.Verify(h[:], l.Sig) {
		return errors.New("the lease's signature does not verify")
	}
	return nil
}

// Encode returns the lease's canonical encoding.
func (l *Lease) Encode() ([]byte, error) { return encode(l) }

// DecodeLease decodes a lease and checks its shape and signature.
func DecodeLease(b []byte) (_ Lease, err error) {
	defer malformed.Recover(&err)
	if len(b) > MaxLeaseSize {
		return Lease{}, fmt.Errorf("types: a lease is %d bytes, over the %d limit", len(b), MaxLeaseSize)
	}
	l, err := DecodeCanonical[Lease](decMode, b, MaxRecordSize)
	if err != nil {
		return Lease{}, err
	}
	if l.Network.IsZero() || l.Head.IsZero() || l.Issued == 0 {
		return Lease{}, errors.New("types: a lease must name a network, a head and a time")
	}
	if l.MLDSA != nil && l.MLDSA.IsZero() {
		return Lease{}, errors.New("types: a lease carries a zero ML-DSA signature")
	}
	if err := l.Verify(); err != nil {
		return Lease{}, err
	}
	return l, nil
}
