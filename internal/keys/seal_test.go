package keys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type gcmSealer struct{ aead cipher.AEAD }

func newGCMSealer(t *testing.T) gcmSealer {
	key := make([]byte, 32)
	rand.Read(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return gcmSealer{aead}
}

func (s gcmSealer) Seal(plain []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	rand.Read(nonce)
	return s.aead.Seal(nonce, nonce, plain, nil), nil
}

func (s gcmSealer) Open(sealed []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	return s.aead.Open(nil, sealed[:n], sealed[n:], nil)
}

func TestSealedNodeKeysOpenOnlyWithTheirSealer(t *testing.T) {
	t.Cleanup(func() { SealWith(nil) })
	k, err := GenerateNode()
	if err != nil {
		t.Fatal(err)
	}
	k.Name = "phone"
	path := filepath.Join(t.TempDir(), NodeKeysFile)
	SealWith(newGCMSealer(t))
	if err := WriteSecret(path, k.Lines("test")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(IdentityTag)) || !bytes.Contains(raw, []byte(SealedTag)) {
		t.Fatalf("a sealed key file reads:\n%s", raw)
	}
	got, err := LoadNode(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Identity.Public() != k.Identity.Public() || got.WireGuardPrivate() != k.WireGuardPrivate() || got.Name != "phone" {
		t.Error("the keys opened are not the keys sealed")
	}

	SealWith(newGCMSealer(t))
	if _, err := LoadNode(path); err == nil || !strings.Contains(err.Error(), "opening the sealed key material") {
		t.Errorf("opened by another keystore key: %v", err)
	}
	SealWith(nil)
	if _, err := LoadNode(path); err == nil || !strings.Contains(err.Error(), "sealed by a device keystore") {
		t.Errorf("opened with no keystore: %v", err)
	}
	if err := WriteSecret(filepath.Join(filepath.Dir(path), "plain.keys"), k.Lines("test")); err != nil {
		t.Errorf("writing with no sealer after one: %v", err)
	}
}
