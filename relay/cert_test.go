package relay

import (
	"bytes"
	"testing"
	"time"
)

func TestStoredCertificateKeepsItsHash(t *testing.T) {
	c, err := NewCertificate()
	if err != nil {
		t.Fatal(err)
	}
	owner := [32]byte{1}
	b, err := c.Encode(owner)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeCertificate(b, owner, time.Now())
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if got.Hash() != c.Hash() {
		t.Fatal("a stored certificate came back with another hash")
	}
	if got.s.hostName != c.s.hostName {
		t.Fatalf("host name %q, want %q", got.s.hostName, c.s.hostName)
	}
}

func TestStoredCertificateIsRefusedForOtherKeys(t *testing.T) {
	c, err := NewCertificate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Encode([32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCertificate(b, [32]byte{2}, time.Now()); err == nil {
		t.Fatal("a certificate stored for other device keys was loaded")
	}
	if _, err := DecodeCertificate(b, [32]byte{1}, time.Now().Add(certLifetime)); err == nil {
		t.Fatal("an expired certificate was loaded")
	}
}

func TestStoredCertificateWithAnotherKeyIsRefused(t *testing.T) {
	a, err := NewCertificate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCertificate()
	if err != nil {
		t.Fatal(err)
	}
	owner := [32]byte{1}
	ea, _ := a.Encode(owner)
	eb, _ := b.Encode(owner)
	// a's certificate block followed by b's key block.
	i := bytes.Index(ea, []byte("-----BEGIN EC PRIVATE KEY"))
	j := bytes.Index(eb, []byte("-----BEGIN EC PRIVATE KEY"))
	mixed := append(append([]byte{}, ea[:i]...), eb[j:]...)
	if _, err := DecodeCertificate(mixed, owner, time.Now()); err == nil {
		t.Fatal("a certificate with another certificate's key was loaded")
	}
}
