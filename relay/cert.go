package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// selfSigned is the relay's TLS identity: a certificate no authority signed,
// authenticated instead by the hash a member's signed announcement carries.
// The client pins that hash (tailcfg.DERPNode.CertName, "sha256-raw:" form),
// so a certificate authority would add a trusted third party without adding a
// property.
type selfSigned struct {
	tls      tls.Certificate
	sha256   [32]byte
	hostName string
}

// certLifetime is deliberately long. The certificate is pinned by hash in a
// signed announcement and kept across restarts, so expiry protects nothing
// here — while an expired one would take the relay down with an error about
// clocks.
const certLifetime = 20 * 365 * 24 * time.Hour

// A Certificate is a relay's TLS identity. A caller that restarts its relay
// may pass the same one again, so the hash members pinned stays good.
type Certificate struct{ s *selfSigned }

// NewCertificate draws a fresh key and certificate.
func NewCertificate() (*Certificate, error) {
	s, err := newSelfSigned()
	if err != nil {
		return nil, err
	}
	return &Certificate{s: s}, nil
}

const (
	pemCert  = "CERTIFICATE"
	pemKey   = "EC PRIVATE KEY"
	pemOwner = "Juist-Owner"
)

// Encode returns the certificate and its key as PEM, bound to owner: the
// device keys it may be loaded for again.
func (c *Certificate) Encode(owner [32]byte) ([]byte, error) {
	priv, ok := c.s.tls.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("relay: certificate key is not ECDSA")
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("relay: encoding the certificate key: %w", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: pemCert, Bytes: c.s.tls.Certificate[0]})
	return append(out, pem.EncodeToMemory(&pem.Block{Type: pemKey, Bytes: der,
		Headers: map[string]string{pemOwner: hex.EncodeToString(owner[:])}})...), nil
}

// DecodeCertificate reads what [Certificate.Encode] wrote, and fails for any
// owner but the one it was bound to, or a certificate that has expired.
func DecodeCertificate(b []byte, owner [32]byte, now time.Time) (*Certificate, error) {
	certBlock, rest := pem.Decode(b)
	keyBlock, _ := pem.Decode(rest)
	if certBlock == nil || certBlock.Type != pemCert || keyBlock == nil || keyBlock.Type != pemKey {
		return nil, errors.New("relay: not a stored relay certificate")
	}
	if keyBlock.Headers[pemOwner] != hex.EncodeToString(owner[:]) {
		return nil, errors.New("relay: stored certificate belongs to other device keys")
	}
	leaf, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("relay: parsing the stored certificate: %w", err)
	}
	priv, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("relay: parsing the stored certificate key: %w", err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&priv.PublicKey) {
		return nil, errors.New("relay: stored certificate and key do not match")
	}
	host := hostNameFor(priv)
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != host {
		return nil, errors.New("relay: stored certificate names another key")
	}
	if !now.Before(leaf.NotAfter) {
		return nil, errors.New("relay: stored certificate has expired")
	}
	return &Certificate{s: &selfSigned{
		tls:      tls.Certificate{Certificate: [][]byte{certBlock.Bytes}, PrivateKey: priv, Leaf: leaf},
		sha256:   sha256.Sum256(certBlock.Bytes),
		hostName: host,
	}}, nil
}

// Hash returns the SHA-256 of the certificate members pin.
func (c *Certificate) Hash() [32]byte { return c.s.sha256 }

// newSelfSigned draws a fresh key and certificate.
func newSelfSigned() (*selfSigned, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("relay: generating a TLS key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("relay: drawing a certificate serial: %w", err)
	}
	host := hostNameFor(priv)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		// Backdated by a day so that a member whose clock is behind can still
		// verify it; the pin, not the validity window, is the check that
		// matters.
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(certLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("relay: creating a certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("relay: parsing the certificate just created: %w", err)
	}
	return &selfSigned{
		tls:      tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf},
		sha256:   sha256.Sum256(der),
		hostName: host,
	}, nil
}

// hostNameFor derives the certificate's name from its own public key, under
// the reserved .invalid TLD: the name is a TLS server name and nothing else,
// and must never resolve. A member dials the addresses in the announcement.
func hostNameFor(priv *ecdsa.PrivateKey) string {
	pub, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		// Unreachable: the key was just generated by this package.
		panic(fmt.Sprintf("relay: marshalling a public key: %v", err))
	}
	sum := sha256.Sum256(pub)
	label := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:10]))
	return label + ".relay.juist.invalid"
}

// CertPin returns the value a DERP map's CertName field takes to pin a
// certificate by hash.
func CertPin(sum [32]byte) string {
	return fmt.Sprintf("sha256-raw:%x", sum)
}
