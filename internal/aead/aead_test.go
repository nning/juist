package aead

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestPaddedShowsNeitherEpochNorLength(t *testing.T) {
	key := [32]byte{7}
	short, err := SealPadded(key, 3, []byte("a"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	long, err := SealPadded(key, 3, bytes.Repeat([]byte("b"), 1000-PaddedOverhead), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(short) != 1000 || len(long) != 1000 {
		t.Fatalf("padded blobs are %d and %d bytes, want 1000", len(short), len(long))
	}
	if binary.BigEndian.Uint64(short) == 3 {
		t.Error("a padded blob starts with its epoch")
	}
	for _, c := range []struct {
		blob []byte
		want int
	}{{short, 1}, {long, 1000 - PaddedOverhead}} {
		pt, err := OpenPadded(key, 3, c.blob)
		if err != nil || len(pt) != c.want {
			t.Errorf("opened %d bytes, %v; want %d", len(pt), err, c.want)
		}
	}
	if _, err := SealPadded(key, 3, make([]byte, 1001-PaddedOverhead), 1000); err == nil {
		t.Error("a plaintext past the size was sealed")
	}
}

func TestPaddedBindsTheEpoch(t *testing.T) {
	key := [32]byte{7}
	blob, err := SealPadded(key, 3, []byte("x"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPadded(key, 4, blob); err == nil {
		t.Error("a blob sealed under epoch 3 opened as epoch 4's")
	}
	old, err := Seal(key, 3, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPadded(key, 3, old); err == nil {
		t.Error("an unpadded blob opened as a padded one")
	}
	if _, err := Open(key, blob); err == nil {
		t.Error("a padded blob opened as an unpadded one")
	}
}

// The layouts are wire formats: a blob sealed by an older build must open.
func TestLayoutsAreTheWireFormats(t *testing.T) {
	key, nonce := [32]byte{7}, [NonceLen]byte{9}
	x, _ := chacha20poly1305.NewX(key[:])
	epoch := binary.BigEndian.AppendUint64(nil, 5)
	want := x.Seal(append(slices.Clone(epoch), nonce[:]...), nonce[:], []byte("hi"), epoch)
	if got := SealNonce(key, 5, nonce, []byte("hi")); !bytes.Equal(got, want) {
		t.Fatalf("SealNonce gave %x, want %x", got, want)
	}
	if pt, err := Open(key, want); err != nil || string(pt) != "hi" {
		t.Fatalf("Open: %q, %v", pt, err)
	}
	blob := x.Seal(slices.Clone(nonce[:]), nonce[:], []byte("hi"), []byte("ad"))
	if pt, err := OpenAD(key, []byte("ad"), blob); err != nil || string(pt) != "hi" {
		t.Fatalf("OpenAD: %q, %v", pt, err)
	}
	if _, err := OpenAD(key, []byte("other"), blob); err == nil {
		t.Fatal("OpenAD opened a blob under other additional data")
	}
	sealed, err := SealAD(key, []byte("ad"), []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := x.Open(nil, sealed[:NonceLen], sealed[NonceLen:], []byte("ad")); err != nil || string(pt) != "hi" {
		t.Fatalf("SealAD's blob is not nonce and ciphertext: %q, %v", pt, err)
	}
}
