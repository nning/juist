package terminator

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/acme"

	"github.com/nning/juist/internal/proxyproto"
	"github.com/nning/juist/ipc"
)

// A name for members alone is taken from the members it is for, by the
// address the connection comes from; from the ingress, whose header could
// say anything, for the CA's validation alone; from anyone else, not at
// all. A member it is no longer for loses the connection it holds.
func TestANameForMembersIsTheirsAlone(t *testing.T) {
	b := newBackend(t)
	src, addr := start(t, b, false, nil)
	member, ingress, stranger := "127.0.0.2", "127.0.0.3", "127.0.0.4"
	for _, a := range []string{member, ingress, stranger} {
		if ln, err := net.Listen("tcp", a+":0"); err != nil {
			t.Skipf("no %s here: %v", a, err)
		} else {
			ln.Close()
		}
	}
	p := *src.p
	photos := p.Names[0]
	photos.Name, photos.From = "photos.pub.example.org", []netip.Addr{netip.MustParseAddr(member)}
	p.Names, p.Members = nil, []ipc.PublishedTarget{photos}
	p.Ingresses = []netip.Addr{netip.MustParseAddr(ingress)}
	src.set(&p, false)

	if got, err := ask(t, addr, "photos.pub.example.org", member, nil); err != nil || got != "ok\n" {
		t.Fatalf("the member got %q, %v", got, err)
	}
	<-b.got
	header := proxyproto.Header(netip.MustParseAddrPort(member+":1"), netip.MustParseAddrPort(addr))
	for _, c := range []struct {
		what, from string
		header     []byte
		protos     []string
	}{
		{"a stranger", stranger, nil, nil},
		{"the ingress", ingress, header, []string{"h2", "http/1.1"}},
		{"the ingress, asking acme-tls/1 among others", ingress, header, []string{"h2", acme.ALPNProto}},
		{"a stranger asking acme-tls/1", stranger, nil, []string{acme.ALPNProto}},
	} {
		if got, err := ask(t, addr, "photos.pub.example.org", c.from, c.header, c.protos...); err == nil {
			t.Errorf("%s got %q", c.what, got)
		}
	}
	d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(ingress)}}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Write(header); err != nil {
		t.Fatal(err)
	}
	ca := tls.Client(raw, &tls.Config{ServerName: "photos.pub.example.org", InsecureSkipVerify: true,
		NextProtos: []string{acme.ALPNProto}})
	if err := ca.Handshake(); err != nil || ca.ConnectionState().NegotiatedProtocol != acme.ALPNProto {
		t.Fatalf("the CA through the ingress: %v, %q", err, ca.ConnectionState().NegotiatedProtocol)
	}
	select {
	case got := <-b.got:
		t.Fatalf("the service got %q from someone it is not for", got)
	case <-time.After(100 * time.Millisecond):
	}

	held, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(member)}}).Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	tc := tls.Client(held, &tls.Config{ServerName: "photos.pub.example.org", InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	gone := p
	gone.Members = []ipc.PublishedTarget{photos}
	gone.Members[0].From = nil
	src.set(&gone, false)
	_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := tc.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Errorf("a member the name is no longer for keeps its connection: %v", err)
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// A name made for members alone ends the connections of whoever it is not
// for, though they were opened while it was public.
func TestANameMadeForMembersEndsWhatOthersOpened(t *testing.T) {
	b := newBackend(t)
	src, addr := start(t, b, false, nil)
	stranger := "127.0.0.4"
	if ln, err := net.Listen("tcp", stranger+":0"); err != nil {
		t.Skipf("no %s here: %v", stranger, err)
	} else {
		ln.Close()
	}
	c, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(stranger)}}).Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tc := tls.Client(c, &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	p := *src.p
	p.Members, p.Names = slices.Clone(p.Names), nil
	p.Members[0].From = []netip.Addr{netip.MustParseAddr("127.0.0.2")}
	src.set(&p, false)
	_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := tc.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Errorf("a connection opened while the name was public outlives it being for members alone: %v", err)
	}
}

// HTTP/3 takes a name for members alone from its members alone.
func TestHTTP3ForMembersAlone(t *testing.T) {
	b := newHTTPBackend(t, false)
	src, addr := startOpts(t, ipc.HTTP3To(b.addr), false, func(*Options) {})
	member, stranger := "127.0.0.2", "127.0.0.4"
	p := *src.p
	p.Members, p.Names = slices.Clone(p.Names), nil
	p.Members[0].From = []netip.Addr{netip.MustParseAddr(member)}
	src.set(&p, false)
	from := func(a string) error {
		t.Helper()
		pc, err := net.ListenPacket("udp", a+":0")
		if err != nil {
			t.Skipf("no %s here: %v", a, err)
		}
		defer pc.Close()
		_, _, err = h3Get(addr, pc)
		return err
	}
	if err := from(member); err != nil {
		t.Errorf("the member: %v", err)
	}
	if err := from(stranger); err == nil {
		t.Error("a stranger got the name over HTTP/3")
	}
}

// A hello refused a name for members asks for no certificate, over TCP or
// QUIC, so that nobody it is not for has one ordered.
func TestARefusedHelloOrdersNoCertificate(t *testing.T) {
	b := newHTTPBackend(t, false)
	var asked atomic.Int32
	cert := selfSigned(t)
	src, addr := startOpts(t, ipc.HTTP3To(b.addr), false, func(o *Options) {
		o.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			asked.Add(1)
			return cert(h)
		}
	})
	member, ingress, stranger := "127.0.0.2", "127.0.0.3", "127.0.0.4"
	p := *src.p
	p.Members, p.Names = slices.Clone(p.Names), nil
	p.Members[0].From = []netip.Addr{netip.MustParseAddr(member)}
	p.Ingresses = []netip.Addr{netip.MustParseAddr(ingress)}
	src.set(&p, false)
	name := p.Members[0].Name
	for _, from := range []string{stranger, ingress} {
		if _, err := ask(t, addr, name, from, nil, "h2"); err == nil {
			t.Errorf("%s was taken", from)
		}
		pc, err := net.ListenPacket("udp", from+":0")
		if err != nil {
			t.Skipf("no %s here: %v", from, err)
		}
		if _, _, err := h3Get(addr, pc); err == nil {
			t.Errorf("%s was taken over QUIC", from)
		}
		pc.Close()
	}
	if n := asked.Load(); n != 0 {
		t.Fatalf("refused hellos asked for a certificate %d times", n)
	}
	pc, err := net.ListenPacket("udp", member+":0")
	if err != nil {
		t.Skipf("no %s here: %v", member, err)
	}
	defer pc.Close()
	if _, _, err := h3Get(addr, pc); err != nil || asked.Load() == 0 {
		t.Fatalf("the member: %v, %d certificates asked for", err, asked.Load())
	}
}

// A request whose Host is another name than its connection's is refused,
// which a service picking its site by Host would otherwise answer.
func TestARequestForAnotherNameIsMisdirected(t *testing.T) {
	b := newHTTPBackend(t, false)
	_, addr := startOpts(t, ipc.HTTP3To(b.addr), false, func(*Options) {})
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true}}}
	for host, want := range map[string]int{"immich.pub.example.org": 200, "Immich.Pub.Example.org:443": 200,
		"photos.pub.example.org": http.StatusMisdirectedRequest} {
		req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
		req.Host = host
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("Host %s: %d, want %d", host, resp.StatusCode, want)
		}
	}
}

// A client resumes its TLS session.
func TestATLSSessionIsResumed(t *testing.T) {
	b := newBackend(t)
	_, addr := start(t, b, false, nil)
	cfg := &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(4)}
	resumed := false
	for range 2 {
		c, err := tls.Dial("tcp", addr, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write([]byte("GET /\n")); err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(c)
		resumed = c.ConnectionState().DidResume
		c.Close()
	}
	if !resumed {
		t.Error("a second connection did not resume the first's session")
	}
}

// A member a name for members alone is no longer for loses its QUIC
// connection, as over TCP.
func TestAMemberNoLongerForANameLosesItsQUIC(t *testing.T) {
	b := newHTTPBackend(t, false)
	src, addr := startOpts(t, ipc.HTTP3To(b.addr), false, func(*Options) {})
	member := "127.0.0.2"
	p := *src.p
	p.Members, p.Names = slices.Clone(p.Names), nil
	p.Members[0].From = []netip.Addr{netip.MustParseAddr(member)}
	src.set(&p, false)
	pc, err := net.ListenPacket("udp", member+":0")
	if err != nil {
		t.Skipf("no %s here: %v", member, err)
	}
	defer pc.Close()
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := quic.Dial(ctx, pc, ua, &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true,
		NextProtos: []string{"h3"}}, &quic.Config{})
	if err != nil {
		t.Fatalf("the member: %v", err)
	}
	defer c.CloseWithError(0, "")
	gone := p
	gone.Members = slices.Clone(p.Members)
	gone.Members[0].From = nil
	src.set(&gone, false)
	select {
	case <-c.Context().Done():
	case <-time.After(3 * time.Second):
		t.Error("a member the name is no longer for keeps its QUIC connection")
	}
}
