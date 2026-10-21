package gossip

import (
	"fmt"

	"github.com/nning/juist/internal/addrkey"
	"github.com/nning/juist/types"
)

// An AddrKey is the key a member's sealed addresses ([Endpoint.Sealed]) open
// under, wrapped for each of its peers. Every member carries it; only a
// peer unwraps its own wrap, which it finds by trying them. Signed, so that
// no other member can displace it.
type AddrKey struct {
	Owner types.Identity `cbor:"1,keyasint"`
	ID    addrkey.ID     `cbor:"2,keyasint"`

	// Seq orders an owner's keys, as [Endpoint.Seq] its announcements.
	Seq   uint64   `cbor:"3,keyasint"`
	Wraps [][]byte `cbor:"4,keyasint,omitempty"`

	// MLDSA is the owner's ML-DSA signature, which members require.
	MLDSA *types.PQSig `cbor:"22,keyasint,omitempty"`
	Sig   types.Sig    `cbor:"23,keyasint"`
}

func (k *AddrKey) author() types.Identity { return k.Owner }
func (k *AddrKey) label() string          { return types.LabelAddrKey }
func (k *AddrKey) describe() string       { return "address key of " + k.Owner.ShortString() }
func (k *AddrKey) unsigned() any {
	u := *k
	u.Sig, u.MLDSA = types.Sig{}, nil
	return &u
}
func (k *AddrKey) sigs() (*types.Sig, **types.PQSig) { return &k.Sig, &k.MLDSA }

// Sign fills in the signature, by the owner's identity key.
func (k *AddrKey) Sign(priv types.PrivateIdentity) error { return sign(k, priv) }

// SignPQ is [AddrKey.Sign], adding the ML-DSA signature members require.
func (k *AddrKey) SignPQ(priv types.PrivateIdentity) error { return signPQ(k, priv) }

// VerifyPQ checks the record's ML-DSA signature against key, the signing
// key the log names for its owner.
func (k *AddrKey) VerifyPQ(key *types.SigningKey) error { return verifyPQ(k, key) }

// Verify checks the record's shape and its signature.
func (k *AddrKey) Verify() error { return verify(k) }

// StaticValidate checks the record's shape.
func (k *AddrKey) StaticValidate() error {
	if err := k.Owner.Validate(); err != nil {
		return fmt.Errorf("gossip: address key: %w", err)
	}
	if len(k.Wraps) > types.MaxNodes {
		return fmt.Errorf("gossip: address key of %v has %d wraps, over the %d limit",
			k.Owner.ShortString(), len(k.Wraps), types.MaxNodes)
	}
	for _, w := range k.Wraps {
		if len(w) != addrkey.WrapSize {
			return fmt.Errorf("gossip: address key of %v has a wrap of %d bytes", k.Owner.ShortString(), len(w))
		}
	}
	if k.MLDSA != nil && k.MLDSA.IsZero() {
		return fmt.Errorf("gossip: address key of %v carries a zero ML-DSA signature", k.Owner.ShortString())
	}
	return nil
}
