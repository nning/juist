package gossip

import (
	"crypto/sha256"
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
	Seq   uint64    `cbor:"3,keyasint"`
	Wraps [][]byte  `cbor:"4,keyasint,omitempty"`
	Sig   types.Sig `cbor:"23,keyasint"`
}

const labelAddrKey = "juist/addr-key/v1"

func (k *AddrKey) signingBytes() ([]byte, error) {
	unsigned := *k
	unsigned.Sig = types.Sig{}
	body, err := encode(&unsigned)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(labelAddrKey))
	h.Write([]byte{0})
	h.Write(body)
	return h.Sum(nil), nil
}

// Sign fills in the signature, by the owner's identity key.
func (k *AddrKey) Sign(priv types.PrivateIdentity) error {
	if priv.Public() != k.Owner {
		return fmt.Errorf("gossip: address key of %v would be signed by %v", k.Owner.ShortString(), priv.Public().ShortString())
	}
	if err := k.StaticValidate(); err != nil {
		return err
	}
	msg, err := k.signingBytes()
	if err != nil {
		return err
	}
	k.Sig, err = priv.Sign(msg)
	return err
}

// Verify checks the record's shape and its signature.
func (k *AddrKey) Verify() error {
	if err := k.StaticValidate(); err != nil {
		return err
	}
	msg, err := k.signingBytes()
	if err != nil {
		return err
	}
	if !k.Owner.Verify(msg, k.Sig) {
		return fmt.Errorf("gossip: address key of %v is not signed by it", k.Owner.ShortString())
	}
	return nil
}

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
	return nil
}
