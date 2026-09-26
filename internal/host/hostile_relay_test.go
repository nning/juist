package host

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/internal/guest"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/relay/forward"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/types"
)

// fakeRelay is a hostile member relay: it accepts every registration, joins
// it at once to a "guest" at a new address, and then says nothing.
func fakeRelay(t *testing.T, joins *atomic.Int64) forward.Relay {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"fake"}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		n := 0
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n++
			go func(n int) {
				br := bufio.NewReader(c)
				if _, err := http.ReadRequest(br); err != nil {
					c.Close()
					return
				}
				io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: "+forward.Upgrade+"\r\nConnection: Upgrade\r\n\r\n")
				c.Write(make([]byte, 32))
				proof := make([]byte, 96)
				io.ReadFull(br, proof)
				who := fmt.Sprintf("203.0.113.%d:%d", n%250, 1000+n)
				c.Write(append([]byte{forward.Waiting, forward.Joined, byte(len(who))}, who...))
				joins.Add(1)
				time.Sleep(20 * time.Second) // silent
				c.Close()
			}(n)
		}
	}()
	sum := sha256.Sum256(der)
	return forward.Relay{Addrs: []netip.AddrPort{ln.Addr().(*net.TCPAddr).AddrPort()}, CertHash: sum, ServerName: "fake"}
}

// A hostile relay fills the host's greeting slots, so a guest reaching the
// host directly is turned away.
func TestAHostileRelayCannotStarveTheInvite(t *testing.T) {
	admin, _ := types.GenerateIdentity()
	hostID, _ := types.GenerateIdentity()
	g, _ := keys.GenerateNode()
	records := network(t, admin, g)
	var joins atomic.Int64
	fake := fakeRelay(t, &joins)
	h, err := Listen(Options{
		Addrs: func(port uint16) []netip.AddrPort {
			return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
		},
		Relays:   []forward.Relay{fake},
		Identity: hostID,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	served := make(chan error, 1)
	go func() {
		served <- h.Serve(ctx, admitting{func(req *enroll.JoinRequest) *enroll.Admission {
			a, _ := enroll.SignAdmission(admin, records[0].Hash(), records[1].Hash(), req.Identity)
			return a
		}}, func() ([]types.AUM, [][]byte, [][]byte, error) { return records, nil, nil, nil }, nil)
	}()
	time.Sleep(2 * time.Second)
	if n := joins.Load(); n > 20 {
		t.Errorf("a relay joined %d fake guests to the host in 2s; its connections are not held to one at a time", n)
	}
	link := h.Invite().Link().WithRelays(nil).WithAdmin(admin.Public())
	_, joinErr := guest.Join(ctx, guest.Options{Invite: link.String(), Name: "phone", Keys: g,
		Adopt: func([]types.AUM) error { return nil }})
	t.Logf("a direct guest's join: %v", joinErr)
	if joinErr != nil {
		t.Errorf("a hostile relay kept a direct guest from joining")
	}
	cancel()
	<-served
}
