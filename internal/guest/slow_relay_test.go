package guest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/nning/juist/relay/forward"
	"github.com/nning/juist/trust/enroll"
)

func TestASlowRelayDoesNotHoldADirectWinner(t *testing.T) {
	direct, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	accepted := make(chan time.Time, 1)
	go func() {
		c, err := direct.Accept()
		if err == nil {
			accepted <- time.Now()
			defer c.Close()
			time.Sleep(30 * time.Second)
		}
	}()
	// A "relay" that finishes TLS and then never answers the upgrade.
	cert := selfSignedForTest(t)
	rl, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()
	go func() {
		for {
			c, err := rl.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				time.Sleep(30 * time.Second)
				c.Close()
			}()
		}
	}()
	inv, _ := enroll.NewInvite([]netip.AddrPort{direct.Addr().(*net.TCPAddr).AddrPort()})
	link := inv.Link().WithRelays([]netip.AddrPort{rl.Addr().(*net.TCPAddr).AddrPort()})
	start := time.Now()
	dials := []func(context.Context) (net.Conn, error){
		func(ctx context.Context) (net.Conn, error) {
			time.Sleep(300 * time.Millisecond) // a direct path farther away than the relay
			return direct0(ctx, link)
		},
		func(ctx context.Context) (net.Conn, error) {
			return forward.Dial(ctx, link.Relays[0], link.ForwardID())
		},
	}
	c, err := dialFirst(context.Background(), dials)
	took := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	at := <-accepted
	t.Logf("direct accepted after %v; dialLink returned after %v", at.Sub(start), took)
	if took > 5*time.Second {
		t.Errorf("the direct winner was held %v, past the host's 5s hello timeout", took)
	}
}

func direct0(ctx context.Context, link enroll.Link) (net.Conn, error) {
	return direct(link.Addrs)[0](ctx)
}

func selfSignedForTest(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"x"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}
