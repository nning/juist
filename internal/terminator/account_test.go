package terminator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/acme/autocert"
)

// The account key is autocert's, read where autocert keeps it, so the
// account named in a CAA record is the one certificates were issued to; one
// made is kept there.
func TestTheAccountKeyIsAutocertsOwn(t *testing.T) {
	ctx := context.Background()
	cache := autocert.DirCache(t.TempDir())
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(key)
	if err := cache.Put(ctx, "acme_account+key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
		t.Fatal(err)
	}
	got, err := accountKey(ctx, cache)
	if err != nil {
		t.Fatal(err)
	}
	if !key.PublicKey.Equal(got.Public()) {
		t.Error("autocert's account key was not the one read")
	}

	empty := autocert.DirCache(t.TempDir())
	made, err := accountKey(ctx, empty)
	if err != nil {
		t.Fatal(err)
	}
	again, err := accountKey(ctx, empty)
	if err != nil {
		t.Fatal(err)
	}
	if !made.Public().(*ecdsa.PublicKey).Equal(again.Public()) {
		t.Error("a key made was not kept")
	}
}
