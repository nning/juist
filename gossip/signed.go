package gossip

import (
	"crypto/sha256"
	"fmt"

	"github.com/nning/juist/types"
)

// A signedRecord is one its author signs by Ed25519 and ML-DSA under a label
// of its own: an endpoint record or an address key.
type signedRecord interface {
	StaticValidate() error
	author() types.Identity
	label() string
	// unsigned is a copy with both signatures cleared, sigs where they are.
	unsigned() any
	sigs() (*types.Sig, **types.PQSig)
	describe() string
}

// signingBytes is what r's signatures cover: a labelled digest of its
// unsigned encoding.
func signingBytes(r signedRecord) ([]byte, error) {
	body, err := encode(r.unsigned())
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(r.label()))
	h.Write([]byte{0})
	h.Write(body)
	return h.Sum(nil), nil
}

// sign fills in r's Ed25519 signature, by priv, which must be its author's:
// every recipient silently drops a record signed by another key.
func sign(r signedRecord, priv types.PrivateIdentity) error {
	if priv.Public() != r.author() {
		return fmt.Errorf("gossip: %v would be signed by %v", r.describe(), priv.Public().ShortString())
	}
	if err := r.StaticValidate(); err != nil {
		return err
	}
	msg, err := signingBytes(r)
	if err != nil {
		return err
	}
	sig, pq := r.sigs()
	if *sig, err = priv.Sign(msg); err != nil {
		return fmt.Errorf("gossip: signing %v: %w", r.describe(), err)
	}
	*pq = nil
	return nil
}

// signPQ is sign, adding the ML-DSA signature members require.
func signPQ(r signedRecord, priv types.PrivateIdentity) error {
	if err := sign(r, priv); err != nil {
		return err
	}
	msg, err := signingBytes(r)
	if err != nil {
		return err
	}
	sig, err := priv.SignPQ(msg)
	if err != nil {
		return fmt.Errorf("gossip: signing %v: %w", r.describe(), err)
	}
	_, pq := r.sigs()
	*pq = &sig
	return nil
}

// verify checks r's shape and its Ed25519 signature.
func verify(r signedRecord) error {
	if err := r.StaticValidate(); err != nil {
		return err
	}
	msg, err := signingBytes(r)
	if err != nil {
		return err
	}
	if sig, _ := r.sigs(); !r.author().Verify(msg, *sig) {
		return fmt.Errorf("gossip: %v is not signed by its author", r.describe())
	}
	return nil
}

// verifyPQ checks r's ML-DSA signature against key, the signing key the log
// names for its author.
func verifyPQ(r signedRecord, key *types.SigningKey) error {
	msg, err := signingBytes(r)
	if err != nil {
		return err
	}
	if _, pq := r.sigs(); key == nil || !key.Verify(msg, *pq) {
		return fmt.Errorf("gossip: %v carries no valid ML-DSA signature", r.describe())
	}
	return nil
}
