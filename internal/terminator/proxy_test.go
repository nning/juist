package terminator

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/nning/juist/ipc"
)

// serveBackend serves h on 127.0.0.1, by HTTP/1.1 and h2c where asked,
// and counts the connections open to it.
func serveBackend(t *testing.T, h2c bool, h http.Handler) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var open atomic.Int32
	srv := &http.Server{Handler: h, ConnState: func(_ net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			open.Add(1)
		case http.StateClosed, http.StateHijacked:
			open.Add(-1)
		}
	}}
	if h2c {
		srv.Protocols = new(http.Protocols)
		srv.Protocols.SetHTTP1(true)
		srv.Protocols.SetUnencryptedHTTP2(true)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), &open
}

// echoUpgrade switches a request to upgrade to echo, and echoes.
var echoUpgrade = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") != "echo" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	c, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer c.Close()
	fmt.Fprint(brw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	_ = brw.Flush()
	_, _ = io.Copy(c, brw)
})

// A request upgrading its connection, as to a WebSocket, is proxied, the
// connection kept as long as it is used; to a service taking h2c by
// HTTP/1.1.
func TestAnUpgradeIsProxied(t *testing.T) {
	for _, h2c := range []bool{false, true} {
		addr, _ := serveBackend(t, h2c, echoUpgrade)
		to := ipc.HTTP3To(addr)
		if h2c {
			to = ipc.HTTP3To(ipc.HTTP2To(addr))
		}
		_, at := startOpts(t, to, false, func(*Options) {})
		c, err := tls.Dial("tcp", at, &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true,
			NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: immich.pub.example.org\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		r := bufio.NewReader(c)
		resp, err := http.ReadResponse(r, nil)
		if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("h2c %v: %v, %v", h2c, resp, err)
		}
		time.Sleep(100 * time.Millisecond)
		fmt.Fprint(c, "ping\n")
		if line, err := r.ReadString('\n'); line != "ping\n" {
			t.Errorf("h2c %v, the upgraded connection: %q, %v", h2c, line, err)
		}
	}
}

// A request to upgrade to h2c reaches no service, which would take any Host
// in the HTTP/2 that follows.
func TestNoUpgradeToH2C(t *testing.T) {
	var got atomic.Int32
	addr, _ := serveBackend(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", r.Header.Get("Upgrade"))
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	_, at := startOpts(t, ipc.HTTP3To(addr), false, func(*Options) {})
	for _, up := range []string{"h2c", "H2C", "websocket, h2c"} {
		c, err := tls.Dial("tcp", at, &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true,
			NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: immich.pub.example.org\r\nConnection: Upgrade, HTTP2-Settings\r\n"+
			"Upgrade: %s\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n", up)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		c.Close()
		if err != nil || resp.StatusCode == http.StatusSwitchingProtocols {
			t.Errorf("Upgrade: %s: %v, %v", up, resp, err)
		}
	}
	if n := got.Load(); n != 0 {
		t.Errorf("the service got %d requests to upgrade to h2c", n)
	}
}

// What a client connection held of the service goes once it ends.
func TestTheServicesConnectionsGoWithTheClients(t *testing.T) {
	addr, open := serveBackend(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	_, at := startOpts(t, ipc.HTTP3To(addr), false, func(*Options) {})
	tr := &http.Transport{ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true}}
	for range 3 {
		req, _ := http.NewRequest("GET", "https://"+at+"/", nil)
		req.Host = "immich.pub.example.org"
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if open.Load() == 0 {
		t.Fatal("no connection to the service")
	}
	tr.CloseIdleConnections()
	waitFor(t, "the service's connections closed", func() bool { return open.Load() == 0 })
}

// A client's headers naming a client reach the service no more than the
// proxy's would; a header as large as an application's cookies does.
func TestTheProxyPassesNoClientsNaming(t *testing.T) {
	addr, _ := serveBackend(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%q %q %d", r.Header.Get("X-Real-Ip"), r.Header.Get("True-Client-Ip"), len(r.Header.Get("Cookie")))
	}))
	_, at := startOpts(t, ipc.HTTP3To(addr), false, func(*Options) {})
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true}}}
	req, _ := http.NewRequest("GET", "https://"+at+"/", nil)
	req.Host = "immich.pub.example.org"
	req.Header.Set("X-Real-Ip", "6.6.6.6")
	req.Header.Set("True-Client-Ip", "6.6.6.6")
	req.Header.Set("Cookie", strings.Repeat("a", 32<<10))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if want := fmt.Sprintf(`"" "" %d`, 32<<10); string(got) != want {
		t.Errorf("the service got %q, want %q", got, want)
	}
}

// A name withdrawn ends its clients' QUIC connections.
func TestAWithdrawnNameEndsItsHTTP3(t *testing.T) {
	addr, _ := serveBackend(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	src, at := startOpts(t, ipc.HTTP3To(addr), false, func(*Options) {})
	var conn *quic.Conn
	tr := &http3.Transport{TLSClientConfig: &tls.Config{ServerName: "immich.pub.example.org", InsecureSkipVerify: true},
		Dial: func(ctx context.Context, a string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			c, err := quic.DialAddr(ctx, a, tlsCfg, cfg)
			conn = c
			return c, err
		}}
	defer tr.Close()
	req, _ := http.NewRequest("GET", "https://"+at+"/", nil)
	req.Host = "immich.pub.example.org"
	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	src.set(&ipc.Published{}, false)
	select {
	case <-conn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Error("the connection outlived its name")
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("not after 5s: %s", what)
		}
	}
}

// Past a service's bound, the connections other clients' proxies keep idle
// give way to a new client's request.
func TestIdleConnectionsGiveWayToAnotherClient(t *testing.T) {
	addr, open := serveBackend(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	var d net.Dialer
	s := newServiceConns(1)
	n := ipc.PublishedTarget{Name: "immich.pub.example.org", To: ipc.HTTP3To(addr)}
	ask := func(px *connProxy) int {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		rec := httptest.NewRecorder()
		px.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, "GET", "http://immich.pub.example.org/", nil))
		return rec.Code
	}
	a := &connProxy{dial: d.DialContext, service: s, n: n}
	defer a.close()
	if code := ask(a); code != http.StatusOK || open.Load() != 1 {
		t.Fatalf("the first client: %d, %d connections", code, open.Load())
	}
	b := &connProxy{dial: d.DialContext, service: s, n: n}
	defer b.close()
	if code := ask(b); code != http.StatusOK {
		t.Errorf("another client, past the bound: %d", code)
	}
}
