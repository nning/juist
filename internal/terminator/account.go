package terminator

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/nning/juist/ipc"
)

// orderUnder has client order certificates for the names served admits alone,
// under the account whose key cache keeps, from a CA as Pebble is too.
func orderUnder(ctx context.Context, client *acme.Client, cache autocert.Cache, served func(string) bool) error {
	hc := http.Client{}
	if client.HTTPClient != nil {
		hc = *client.HTTPClient
	}
	hc.Transport = withOrderLocations(servedOrders{rt: hc.Transport, served: served})
	client.HTTPClient = &hc
	if client.Key == nil {
		key, err := accountKey(ctx, cache)
		if err != nil {
			return err
		}
		client.Key = key
	}
	return nil
}

// NewManager is a certificate manager for the one name, by TLS-ALPN-01, from
// client's CA, kept in cache with the account's key, as the terminator's.
func NewManager(ctx context.Context, client *acme.Client, cache autocert.Cache, name string) (*autocert.Manager, error) {
	served := func(host string) bool { return strings.EqualFold(strings.TrimSuffix(host, "."), name) }
	if err := orderUnder(ctx, client, cache, served); err != nil {
		return nil, err
	}
	return &autocert.Manager{Prompt: autocert.AcceptTOS, Cache: cache, Client: client,
		HostPolicy: func(_ context.Context, host string) error {
			if !served(host) {
				return fmt.Errorf("terminator: %s is not served here", host)
			}
			return nil
		}}, nil
}

// accountKeyName is where autocert keeps its account key in the cache, so
// that the account named is the one certificates are issued to.
const accountKeyName = "acme_account+key"

// accountKey is the ACME account's key from cache, made and kept there where
// there is none yet.
func accountKey(ctx context.Context, cache autocert.Cache) (crypto.Signer, error) {
	if cache == nil {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	data, err := cache.Get(ctx, accountKeyName)
	if errors.Is(err, autocert.ErrCacheMiss) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		_ = pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		if err := cache.Put(ctx, accountKeyName, buf.Bytes()); err != nil {
			return nil, err
		}
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, errors.New("terminator: the cached ACME account key is no PEM")
	}
	if key, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
		if s, ok := key.(crypto.Signer); ok {
			return s, nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("terminator: the cached ACME account key is unreadable")
}

// accountRetry bounds the wait between attempts to learn the account.
const accountRetry = 10 * time.Minute

// learnAccount registers with the CA, or finds the account its key has
// there, until it knows it or ctx ends.
func (t *terminator) learnAccount(ctx context.Context) {
	wait := time.Second
	for {
		a, err := account(ctx, t.o.ACME, t.o.Email)
		if err == nil {
			t.account.Store(a)
			return
		}
		if ctx.Err() != nil {
			return
		}
		t.o.Logf("terminator: no ACME account yet: %v", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(2*wait, accountRetry)
	}
}

// account is c's account at its CA, registered where it is not yet.
func account(ctx context.Context, c *acme.Client, email string) (*ipc.ACMEAccount, error) {
	dir, err := c.Discover(ctx)
	if err != nil {
		return nil, err
	}
	var contact []string
	if email != "" {
		contact = []string{"mailto:" + email}
	}
	a, err := c.Register(ctx, &acme.Account{Contact: contact}, acme.AcceptTOS)
	var ae *acme.Error
	if errors.Is(err, acme.ErrAccountAlreadyExists) || errors.As(err, &ae) && ae.StatusCode == http.StatusConflict {
		a, err = c.GetReg(ctx, "")
	}
	if err != nil {
		return nil, err
	}
	out := &ipc.ACMEAccount{URI: a.URI, Issuers: dir.CAA}
	if !out.Valid() {
		return nil, fmt.Errorf("the CA's account %q does not fit a CAA record", a.URI)
	}
	return out, nil
}
