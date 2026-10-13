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
// epoch's. A padded blob ([SealPadded]) is for a recipient that knows the
// epoch already, and shows neither it nor the plaintext's length:
//
//	[24 bytes] nonce
//	[n bytes]  ciphertext of a 2-byte length, the plaintext and zeros
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

	// PaddedOverhead is the least a padded blob adds to a plaintext.
	PaddedOverhead = NonceLen + lengthLen + chacha20poly1305.Overhead

	lengthLen = 2
)

// labelPadded is in a padded blob's additional data, beside the epoch.
const labelPadded = "juist/padded/v1"

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

// SealPadded encrypts plaintext under an epoch's key into a blob of exactly
// size bytes, which [OpenPadded] opens given the same epoch.
func SealPadded(key [32]byte, epoch uint64, plaintext []byte, size int) ([]byte, error) {
	if len(plaintext) > size-PaddedOverhead || len(plaintext) > 1<<16-1 {
		return nil, fmt.Errorf("aead: a %d-byte plaintext does not fit a %d-byte padded blob", len(plaintext), size)
	}
	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("aead: building the cipher: %w", err)
	}
	out := make([]byte, NonceLen, size)
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("aead: drawing a nonce: %w", err)
	}
	padded := make([]byte, size-NonceLen-chacha20poly1305.Overhead)
	binary.BigEndian.PutUint16(padded, uint16(len(plaintext)))
	copy(padded[lengthLen:], plaintext)
	return a.Seal(out, out, padded, paddedAD(epoch)), nil
}

// OpenPadded decrypts a blob [SealPadded] made under epoch.
func OpenPadded(key [32]byte, epoch uint64, blob []byte) ([]byte, error) {
	if len(blob) < PaddedOverhead {
		return nil, fmt.Errorf("aead: padded blob is %d bytes, below the %d-byte minimum", len(blob), PaddedOverhead)
	}
	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("aead: building the cipher: %w", err)
	}
	pt, err := a.Open(nil, blob[:NonceLen], blob[NonceLen:], paddedAD(epoch))
	if err != nil {
		return nil, fmt.Errorf("aead: padded blob does not authenticate: %w", err)
	}
	n := int(binary.BigEndian.Uint16(pt))
	if n > len(pt)-lengthLen {
		return nil, fmt.Errorf("aead: padded blob says %d bytes and holds %d", n, len(pt)-lengthLen)
	}
	return pt[lengthLen : lengthLen+n], nil
}

func paddedAD(epoch uint64) []byte {
	return binary.BigEndian.AppendUint64([]byte(labelPadded), epoch)
}
