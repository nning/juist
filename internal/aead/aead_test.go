package aead

import (
	"bytes"
	"encoding/binary"
	"testing"
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
