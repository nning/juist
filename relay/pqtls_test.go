package relay

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"slices"
	"testing"

	"github.com/nning/juist/internal/pqtls"
	"github.com/nning/juist/relay/forward"
)

// A relay speaks TLS 1.3 with X25519MLKEM768 alone, at its own addresses and
// at its public name: a client offering TLS 1.2 alone, or no ML-KEM, is
// refused, so no session can be made to fall back to what a quantum
// computer reads. Exit criterion (4).
func TestARelayRefusesTLSWithoutMLKEM(t *testing.T) {
	cert, err := newSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	named := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert.tls, nil }
	server := tlsConfig(cert, "relay.example.org", named)
	for _, sni := range []string{"203.0.113.7", "relay.example.org"} {
		for _, tc := range []struct {
			what string
			cfg  *tls.Config
			ok   bool
		}{
			{"a juist client", forward.PinnedConfig(sni, cert.sha256), true},
			{"TLS 1.2 alone", &tls.Config{ServerName: sni, InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}, false},
			{"no ML-KEM", &tls.Config{ServerName: sni, InsecureSkipVerify: true,
				CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}}, false},
		} {
			c, s := net.Pipe()
			errs := make(chan error, 1)
			go func() {
				srv := tls.Server(s, server)
				err := srv.Handshake()
				errs <- err
				if err == nil {
					_, _ = io.Copy(io.Discard, srv) // until the client's close_notify
				}
				srv.Close()
			}()
			cl := tls.Client(c, tc.cfg)
			cerr := cl.Handshake()
			cl.Close()
			serr := <-errs
			if got := cerr == nil && serr == nil; got != tc.ok {
				t.Errorf("%s, by %s: client %v, server %v", tc.what, sni, cerr, serr)
			}
			if tc.ok && cl.ConnectionState().CurveID != tls.X25519MLKEM768 {
				t.Errorf("%s, by %s, agreed %v", tc.what, sni, cl.ConnectionState().CurveID)
			}
		}
	}
}

// A relay's public name holds the certificate autocert gives, which is ECDSA
// only for a client offering P-256 and an ECDSA suite of TLS 1.2; a juist
// client offers neither and still gets it.
func TestARelaysPublicNameAnswersAJuistClient(t *testing.T) {
	cert, err := newSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	named := func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if !slices.Contains(h.SupportedCurves, tls.CurveP256) ||
			!slices.Contains(h.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) {
			return nil, errors.New("acme/autocert: no RSA certificate held") // as autocert falls back
		}
		return &cert.tls, nil
	}
	c, s := net.Pipe()
	errs := make(chan error, 1)
	go func() {
		srv := tls.Server(s, tlsConfig(cert, "relay.example.org", named))
		errs <- srv.Handshake()
		srv.Close()
	}()
	cl := tls.Client(c, pqtls.Config(&tls.Config{ServerName: "relay.example.org", InsecureSkipVerify: true}))
	cerr := cl.Handshake()
	cl.Close()
	if serr := <-errs; cerr != nil || serr != nil {
		t.Fatalf("a juist client at the relay's public name: client %v, server %v", cerr, serr)
	}
}
