package terminator

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/nning/juist/internal/ingress"
	"github.com/nning/juist/ipc"
)

// With Pebble as the CA, the terminator takes a certificate for a name by
// TLS-ALPN-01, answering the challenge itself, and a client that trusts the
// CA's root alone ends TLS with it. Pebble runs where JUIST_PEBBLE names its
// binary.
func TestACertificateFromPebble(t *testing.T) {
	for _, through := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "through an ingress"}[through], func(t *testing.T) {
			certificateFromPebble(t, through)
		})
	}
}

func certificateFromPebble(t *testing.T, throughIngress bool) {
	bin := os.Getenv("JUIST_PEBBLE")
	if bin == "" {
		t.Skip("JUIST_PEBBLE names no Pebble binary")
	}
	dir := t.TempDir()
	ca, caPEM := newCA(t)
	writeLeaf(t, ca, dir)
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	dns := answerEveryName(t, netip.MustParseAddr("127.0.0.1"))
	acmePort, mgmtPort, tlsPort := freePort(t), freePort(t), freePort(t)
	cfg := fmt.Sprintf(`{"pebble": {"listenAddress": "127.0.0.1:%d", "managementListenAddress": "127.0.0.1:%d",
		"certificate": %q, "privateKey": %q, "httpPort": %d, "tlsPort": %d}}`,
		acmePort, mgmtPort, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), freePort(t), tlsPort)
	if err := os.WriteFile(filepath.Join(dir, "pebble.json"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-config", filepath.Join(dir, "pebble.json"), "-dnsserver", dns)
	cmd.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	dirURL := fmt.Sprintf("https://127.0.0.1:%d/dir", acmePort)
	for deadline := time.Now().Add(10 * time.Second); ; {
		if resp, err := hc.Get(dirURL); err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pebble does not answer")
		}
		time.Sleep(100 * time.Millisecond)
	}

	b := newBackend(t)
	termPort := tlsPort
	if throughIngress {
		// Pebble asks the ingress, which splices to the terminator.
		termPort = freePort(t)
		startIngress(t, tlsPort, termPort)
	}
	src := &source{asked: make(chan struct{}, 1), p: &ipc.Published{Names: []ipc.PublishedTarget{{
		Name: "immich.pub.example.org", Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		Port: uint16(termPort), To: b.ln.Addr().String()}}}}
	if throughIngress {
		src.p.Ingresses = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Serve(ctx, Options{Serving: src.serving, Poll: 50 * time.Millisecond,
			ACME: &acme.Client{DirectoryURL: dirURL, HTTPClient: hc}, Cache: autocert.DirCache(filepath.Join(dir, "cache")),
			Logf: t.Logf})
	}()
	t.Cleanup(func() { cancel(); <-done })

	resp, err := hc.Get(fmt.Sprintf("https://127.0.0.1:%d/roots/0", mgmtPort))
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	issued := x509.NewCertPool()
	if !issued.AppendCertsFromPEM(issuer) {
		t.Fatalf("pebble's root is %q", issuer)
	}
	var line string
	for deadline := time.Now().Add(30 * time.Second); ; {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", tlsPort),
			&tls.Config{ServerName: "immich.pub.example.org", RootCAs: issued})
		if err == nil {
			_, _ = c.Write([]byte("GET /\n"))
			line, err = bufio.NewReader(c).ReadString('\n')
			c.Close()
			if err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no certificate pebble issued: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if line != "ok\n" {
		t.Errorf("the client got %q", line)
	}
	var a *ipc.ACMEAccount
	for deadline := time.Now().Add(5 * time.Second); a == nil && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		src.mu.Lock()
		a = src.account
		src.mu.Unlock()
	}
	if a == nil || !strings.HasPrefix(a.URI, dirURL[:strings.LastIndex(dirURL, "/")]) ||
		!slices.Equal(a.Issuers, []string{"pebble.letsencrypt.org"}) {
		t.Errorf("juistd is told the account %+v", a)
	}
}

// startIngress runs an ingress on port, splicing immich to target.
func startIngress(t *testing.T, port, target int) {
	t.Helper()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	p := &ipc.Published{Names: []ipc.PublishedTarget{{Name: "immich.pub.example.org",
		Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Port: uint16(target)}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ingress.Serve(ctx, ln, nil, ingress.Options{
			Published: func(context.Context) (*ipc.Published, error) { return p, nil }, Poll: 50 * time.Millisecond})
	}()
	t.Cleanup(func() { cancel(); <-done })
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type certAuthority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T) (certAuthority, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return certAuthority{cert, key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// writeLeaf writes cert.pem and key.pem into dir for 127.0.0.1, signed by ca.
func writeLeaf(t *testing.T, ca certAuthority, dir string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{"cert.pem": {Type: "CERTIFICATE", Bytes: der},
		"key.pem": {Type: "EC PRIVATE KEY", Bytes: kder}} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// answerEveryName serves DNS on loopback, over TCP as Pebble asks,
// answering every A query with a, and returns where.
func answerEveryName(t *testing.T, a netip.Addr) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					var n [2]byte
					if _, err := io.ReadFull(c, n[:]); err != nil {
						return
					}
					q := make([]byte, int(n[0])<<8|int(n[1]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					out := answer(q, a)
					if out == nil {
						return
					}
					if _, err := c.Write(append([]byte{byte(len(out) >> 8), byte(len(out))}, out...)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// answer is the reply to query, an A record of a for an A question.
func answer(query []byte, a netip.Addr) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true})
	b.StartQuestions()
	b.Question(q)
	b.StartAnswers()
	if q.Type == dnsmessage.TypeA {
		b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 5},
			dnsmessage.AResource{A: a.As4()})
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}
