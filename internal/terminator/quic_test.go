package terminator

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/nning/juist/internal/nettest"
	"github.com/nning/juist/internal/proxyproto"
	"github.com/nning/juist/ipc"
)

// httpBackend is a service speaking HTTP/1.1, which answers with the host
// and headers it was asked with, and where a PROXY header came first, the
// client it named.
type httpBackend struct {
	addr string
	mu   sync.Mutex
	from []netip.AddrPort
}

func newHTTPBackend(t *testing.T, proxied bool) *httpBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &httpBackend{addr: ln.Addr().String()}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s xff=%q proto=%s", r.Host, r.Header.Get("X-Forwarded-For"), r.Proto)
	})}
	go func() { _ = srv.Serve(&proxiedListener{Listener: ln, b: b, proxied: proxied}) }()
	t.Cleanup(func() { srv.Close() })
	return b
}

// proxiedListener reads a PROXY header off each connection where proxied.
type proxiedListener struct {
	net.Listener
	b       *httpBackend
	proxied bool
}

func (l *proxiedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil || !l.proxied {
		return c, err
	}
	r := bufio.NewReader(c)
	src, ok, err := proxyproto.Read(r)
	if err == nil && ok {
		l.b.mu.Lock()
		l.b.from = append(l.b.from, src)
		l.b.mu.Unlock()
	}
	return bufferedConn{Conn: c, r: r}, nil
}

func (b *httpBackend) told() []netip.AddrPort {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]netip.AddrPort(nil), b.from...)
}

// h3Get fetches https://immich.pub.example.org/ over HTTP/3 at addr,
// through pc where given.
func h3Get(addr string, pc net.PacketConn) (*http.Response, string, error) {
	tr := &http3.Transport{TLSClientConfig: &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true}}
	if pc != nil {
		tr.Dial = func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			ua, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			return quic.Dial(ctx, pc, ua, tlsCfg, cfg)
		}
	}
	defer tr.Close()
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
	req.Host = "immich.pub.example.org"
	resp, err := c.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp, string(b), err
}

// A name offered HTTP/3 is answered over QUIC by its service, proxied as
// HTTP/1.1 with its own Host and no header of the proxy's; over TCP too,
// with HTTP/2 offered and Alt-Svc saying where HTTP/3 is.
func TestHTTP3IsProxiedToTheService(t *testing.T) {
	b := newHTTPBackend(t, false)
	_, addr := startOpts(t, ipc.HTTP3To(b.addr), false, func(*Options) {})
	resp, body, err := h3Get(addr, nil)
	if err != nil {
		t.Fatalf("over HTTP/3: %v", err)
	}
	if resp.Proto != "HTTP/3.0" || body != `host=immich.pub.example.org xff="" proto=HTTP/1.1` {
		t.Errorf("over HTTP/3, %s: %q", resp.Proto, body)
	}

	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true}}}
	req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
	req.Host = "immich.pub.example.org"
	req.Header.Set("X-Forwarded-For", "6.6.6.6")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatalf("over TCP: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Proto != "HTTP/2.0" || resp.Header.Get("Alt-Svc") != `h3=":443"; ma=86400` ||
		string(got) != `host=immich.pub.example.org xff="" proto=HTTP/1.1` {
		t.Errorf("over TCP, %s, Alt-Svc %q: %q", resp.Proto, resp.Header.Get("Alt-Svc"), got)
	}
}

// A service taking h2c is proxied so.
func TestHTTP3ToAServiceTakingH2C(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := new(http.Protocols)
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Protocols: p, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.Proto)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	_, addr := startOpts(t, ipc.HTTP3To(ipc.HTTP2To(ln.Addr().String())), false, func(*Options) {})
	if _, body, err := h3Get(addr, nil); err != nil || body != "HTTP/2.0" {
		t.Errorf("the service was asked by %q, %v", body, err)
	}
}

// A name not offered HTTP/3 gets no QUIC handshake: the client keeps to TCP.
func TestNoQUICForANameWithoutHTTP3(t *testing.T) {
	b := newHTTPBackend(t, false)
	_, addr := startOpts(t, b.addr, false, func(*Options) {})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if c, err := quic.DialAddr(ctx, addr, &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true,
		NextProtos: []string{"h3"}}, nil); err == nil {
		c.CloseWithError(0, "")
		t.Error("a QUIC handshake for a name without HTTP/3")
	}
}

// Behind --proxy, each connection to the service is told the client an
// ingress named in a datagram of its own ahead of the flow, over QUIC as
// over TCP; a header from one that is no ingress is no client.
func TestHTTP3TellsTheServiceTheClient(t *testing.T) {
	b := newHTTPBackend(t, true)
	_, addr := startOpts(t, ipc.HTTP3To(b.addr), true, func(*Options) {})
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	client := netip.MustParseAddrPort("203.0.113.7:51000")
	to := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(addr))
	if _, err := pc.WriteToUDP(proxyproto.HeaderUDP(client, netip.MustParseAddrPort(addr)), to); err != nil {
		t.Fatal(err)
	}
	if _, body, err := h3Get(addr, pc); err != nil || !strings.HasPrefix(body, "host=immich.pub.example.org") {
		t.Fatalf("over HTTP/3 behind --proxy: %q, %v", body, err)
	}
	if told := b.told(); len(told) != 1 || told[0] != client {
		t.Errorf("the service was told %v, want %v", told, client)
	}
}

// A header from a member, which is no ingress, names no client: the service
// is told the member.
func TestHTTP3BelievesNoMembersHeader(t *testing.T) {
	if !nettest.HasLoopbackAddr(netip.MustParseAddr("127.0.0.2")) {
		nettest.SkipUnlessRequired(t, "this host carries no 127.0.0.2 for a member")
	}
	b := newHTTPBackend(t, true)
	_, addr := startOpts(t, ipc.HTTP3To(b.addr), true, func(*Options) {})
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	to := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(addr))
	lie := proxyproto.HeaderUDP(netip.MustParseAddrPort("203.0.113.7:51000"), netip.MustParseAddrPort(addr))
	if _, err := pc.WriteToUDP(lie, to); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h3Get(addr, pc); err != nil {
		t.Fatal(err)
	}
	if told := b.told(); len(told) != 1 || told[0] != pc.LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Errorf("the service was told %v, want the member", told)
	}
}

// Members' requests over HTTP/3 name another host than the connection's
// alone where the name is the connection's.
func TestHTTP3AnswersTheConnectionsNameAlone(t *testing.T) {
	b := newHTTPBackend(t, false)
	_, addr := startOpts(t, ipc.HTTP3To(b.addr), false, func(*Options) {})
	tr := &http3.Transport{TLSClientConfig: &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true}}
	defer tr.Close()
	req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
	req.Host = "other.pub.example.org"
	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("another host over the connection: %d", resp.StatusCode)
	}
}

// An ingress passing a client is told by a LOCAL header naming it once
// the client completed its handshake, which proves its address, and by one
// with a NOOP TLV once the connection ended.
func TestHTTP3TellsTheIngressTheClientIsProven(t *testing.T) {
	b := newHTTPBackend(t, false)
	_, addr := startOpts(t, ipc.HTTP3To(b.addr), false, func(*Options) {})
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	to := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(addr))
	client := netip.MustParseAddrPort("203.0.113.7:51000")
	if _, err := pc.WriteToUDP(proxyproto.HeaderUDP(client, netip.MustParseAddrPort("0.0.0.0:443")), to); err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := tr.Dial(ctx, to, &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true,
		NextProtos: []string{"h3"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, _, err := tr.ReadNonQUICPacket(ctx, buf)
	if got, done, ok := proxyproto.ReadLocalUDP(buf[:n]); err != nil || !ok || done || got != client {
		t.Errorf("the ingress was told %x, %v", buf[:n], err)
	}
	c.CloseWithError(0, "")
	for {
		n, _, err := tr.ReadNonQUICPacket(ctx, buf)
		if err != nil {
			t.Fatalf("the ingress was not told the connection ended: %v", err)
		}
		if got, done, ok := proxyproto.ReadLocalUDP(buf[:n]); ok && done && got == client {
			break
		}
	}
}

// QUIC's connections count against the terminator's bound as TCP's do.
func TestHTTP3CountsAgainstTheBound(t *testing.T) {
	b := newHTTPBackend(t, false)
	_, addr := startOpts(t, ipc.HTTP3To(b.addr), false, func(o *Options) { o.MaxConns = 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg := &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	first, err := quic.DialAddr(ctx, addr, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.CloseWithError(0, "")
	short, cancel2 := context.WithTimeout(ctx, 2*time.Second)
	defer cancel2()
	if second, err := quic.DialAddr(short, addr, cfg, nil); err == nil {
		second.CloseWithError(0, "")
		t.Error("a connection past the bound")
	}
}

// A header an ingress sends as soon as the socket is open names the client:
// quic-go drops what is not QUIC until it is first asked for it.
func TestAHeaderAtOnceNamesTheClient(t *testing.T) {
	ingress := netip.MustParseAddr("127.0.0.1")
	tt := &terminator{o: Options{ListenPacket: net.ListenPacket}}
	tt.now.Store(&what{ingresses: []netip.Addr{ingress}})
	q := &quicServer{t: tt}
	client := netip.MustParseAddrPort("203.0.113.7:51000")
	for range 200 {
		s, err := q.open(netip.AddrPortFrom(ingress, 0), &tls.Config{GetCertificate: selfSigned(t)})
		if err != nil {
			t.Fatal(err)
		}
		to := addrPortUDP(s.conn.LocalAddr())
		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: ingress.AsSlice()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pc.WriteToUDP(proxyproto.HeaderUDP(client, to), net.UDPAddrFromAddrPort(to)); err != nil {
			t.Fatal(err)
		}
		flow := addrPortUDP(pc.LocalAddr())
		var got netip.AddrPort
		var named bool
		for deadline := time.Now().Add(time.Second); !named && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
			got, named = s.pc.client(flow)
		}
		pc.Close()
		s.close()
		if !named || got != client {
			t.Fatalf("a header sent at once named %v (%v), want %v", got, named, client)
		}
	}
}
