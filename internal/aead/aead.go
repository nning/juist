// Package aead is the sealed-blob format the sync and discovery layers share.
// It buys metadata confidentiality and nothing else: every record inside is
// separately signed, so losing an epoch secret costs discovery privacy alone.
// One implementation rather than one per caller, since the two differ only in
// which key they derive and nonce handling is worth writing once.
//
//	[8 bytes]  epoch, big-endian, in the clear
//	[24 bytes] nonce
//	[n bytes]  XChaCha20-Poly1305 ciphertext
//
// The epoch is in the clear because the recipient must know which key to try,
// and is the additional data so a blob cannot be relabelled as another
// epoch's.
package aead

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Sizes of the framing.
const (
	EpochLen = 8
	NonceLen = chacha20poly1305.NonceSizeX

	// Overhead is what sealing adds to a plaintext.
	Overhead = EpochLen + NonceLen + chacha20poly1305.Overhead
)

// Seal encrypts plaintext under an epoch's key. XChaCha20-Poly1305 with a
// random nonce: at 192 bits there is no practical collision bound, which
// matters because neither caller has session state to count from.
func Seal(key [32]byte, epoch uint64, plaintext []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("aead: building the cipher: %w", err)
	}
	out := make([]byte, EpochLen+NonceLen, EpochLen+NonceLen+len(plaintext)+chacha20poly1305.Overhead)
	binary.BigEndian.PutUint64(out[:EpochLen], epoch)
	if _, err := rand.Read(out[EpochLen:]); err != nil {
		return nil, fmt.Errorf("aead: drawing a nonce: %w", err)
	}
	return a.Seal(out, out[EpochLen:], plaintext, out[:EpochLen]), nil
}

// Epoch reports which epoch a blob is sealed under, so the caller can look up
// the key before any cryptography is attempted.
func Epoch(blob []byte) (uint64, error) {
	if len(blob) < Overhead {
		return 0, fmt.Errorf("aead: sealed blob is %d bytes, below the %d-byte minimum",
			len(blob), Overhead)
	}
	return binary.BigEndian.Uint64(blob[:EpochLen]), nil
}

// Open decrypts a blob. The key must be the one for the epoch [Epoch] reports;
// a blob whose epoch label was edited fails here rather than decrypting under
// the wrong key.
func Open(key [32]byte, blob []byte) ([]byte, error) {
	if len(blob) < Overhead {
		return nil, fmt.Errorf("aead: sealed blob is %d bytes, below the %d-byte minimum",
			len(blob), Overhead)
	}
	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("aead: building the cipher: %w", err)
	}
	pt, err := a.Open(nil, blob[EpochLen:EpochLen+NonceLen], blob[EpochLen+NonceLen:], blob[:EpochLen])
	if err != nil {
		return nil, fmt.Errorf("aead: sealed blob does not authenticate: %w", err)
	}
	return pt, nil
}
