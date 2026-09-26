package types

import (
	"errors"
	"fmt"
)

// A Lease is an admin device's signed statement that, at Issued, its log's
// head was Head. A node holding one recent enough knows its view of the
// network is not older than that; one holding none knows it may be missing a
// removal, and fails closed. Leases are not log records: they are issued
// hourly, and chaining them would grow every log without bound.
type Lease struct {
	// Network is the genesis hash of the network the lease speaks for.
	Network Hash `cbor:"1,keyasint"`

	// Head is the signer's log head when it signed.
	Head Hash `cbor:"2,keyasint"`

	// Issued is when the lease was signed, in Unix seconds by the signer's
	// clock.
	Issued uint64 `cbor:"3,keyasint"`

	// Signer is the identity key of the admin device that signed it.
	Signer Identity `cbor:"4,keyasint"`

	// Sig is Signer's signature over everything above.
	Sig Sig `cbor:"5,keyasint"`
}

// MaxLeaseSize bounds an encoded lease.
const MaxLeaseSize = 256

// sigHash is what a lease's signature covers: its encoding without the
// signature, under its own label, so a lease signature can be no other
// signature by the same device key.
func (l *Lease) sigHash() Hash {
	unsigned := *l
	unsigned.Sig = Sig{}
	return hashLabeled(labelLease, mustEncode(&unsigned))
}

// Sign signs the lease with the signer's identity key, setting Signer.
func (l *Lease) Sign(priv PrivateIdentity) error {
	l.Signer = priv.Public()
	h := l.sigHash()
	sig, err := priv.Sign(h[:])
	if err != nil {
		return err
	}
	l.Sig = sig
	return nil
}

// Verify checks the signature against Signer. It says nothing about whether
// Signer may issue leases, which is the log's to decide.
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
func DecodeLease(b []byte) (Lease, error) {
	if len(b) > MaxLeaseSize {
		return Lease{}, fmt.Errorf("types: a lease is %d bytes, over the %d limit", len(b), MaxLeaseSize)
	}
	l, err := decodeCanonical[Lease](b)
	if err != nil {
		return Lease{}, err
	}
	if l.Network.IsZero() || l.Head.IsZero() || l.Issued == 0 {
		return Lease{}, errors.New("types: a lease must name a network, a head and a time")
	}
	if err := l.Verify(); err != nil {
		return Lease{}, err
	}
	return l, nil
}
