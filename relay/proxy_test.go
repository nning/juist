package relay

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nning/juist/internal/proxyproto"
	"github.com/nning/juist/relay/forward"
)

// connectProxy is an HTTP proxy taking CONNECT alone, from a client who says
// auth, to the relay's name on 443 alone, which it sends to to.
type connectProxy struct {
	addr string
	mu   sync.Mutex
	asks []string
}

func startProxy(t *testing.T, to netip.AddrPort, auth string) *connectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &connectProxy{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c, to, auth)
		}
	}()
	return p
}

func (p *connectProxy) serve(c net.Conn, to netip.AddrPort, auth string) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.asks = append(p.asks, req.Method+" "+req.Host)
	p.mu.Unlock()
	switch {
	case req.Method != http.MethodConnect:
		io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return
	case req.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)):
		io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
		return
	case req.Host != testName+":443":
		io.WriteString(c, "HTTP/1.1 403 Forbidden\r\n\r\n")
		return
	}
	up, err := net.Dial("tcp", to.String())
	if err != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer up.Close()
	io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	go io.Copy(up, br)
	io.Copy(c, up)
}

func (p *connectProxy) asked() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.asks)
}

// A host and a guest that reach nothing but a proxy meet at the relay by its
// public name, the proxy told no more than the name and 443, and the relay
// verified by WebPKI; a proxy that wants credentials gets them from the URL.
func TestAHostAndAGuestMeetByTheRelaysNameThroughAProxy(t *testing.T) {
	host := newMember(t)
	n := startNamed(t, nil, nil, host.pub)
	p := startProxy(t, n.https, "user:secret")
	via, _ := url.Parse("http://user:secret@" + p.addr)
	proxy := func(name string) (*url.URL, error) {
		if name != testName {
			t.Errorf("asked for a proxy to %q", name)
		}
		return via, nil
	}
	r := forward.Relay{CertHash: n.CertHash(), ServerName: n.HostName(), Name: testName}
	id := [16]byte{9}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	got := make(chan net.Conn, 1)
	go func() {
		c, _, err := forward.WaitNamed(ctx, r, id, host.pub, host.sign, proxy)
		if err != nil {
			t.Errorf("the host's wait: %v", err)
		}
		got <- c
	}()
	var g net.Conn
	var err error
	for range 50 {
		if g, err = forward.DialNamed(ctx, testName, id, proxy); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		cancel()
		<-got // the host's wait reports before the test ends
		t.Fatalf("the guest did not reach the host: %v", err)
	}
	defer g.Close()
	h := <-got
	if h == nil {
		t.FailNow()
	}
	defer h.Close()
	g.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(h, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("the host read %q, %v", buf, err)
	}
	for _, a := range p.asked() {
		if a != "CONNECT "+testName+":443" {
			t.Errorf("the proxy was asked %q", a)
		}
	}

	wrong, _ := url.Parse("http://user:guess@" + p.addr)
	if _, err := forward.DialNamed(ctx, testName, id, func(string) (*url.URL, error) { return wrong, nil }); err == nil {
		t.Error("a proxy refusing the credentials let the guest through")
	}
}

// The rendezvous is reached by a relay's name through the proxy as well, by
// the client a device on HTTPS alone keeps announcements with.
func TestTheRendezvousIsReachedThroughAProxy(t *testing.T) {
	rv := &fakeRendezvous{held: map[[32]byte][]byte{}}
	n := startNamed(t, nil, rv)
	p := startProxy(t, n.https, "user:secret")
	via, _ := url.Parse("http://user:secret@" + p.addr)
	hc := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return via, nil }}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key := [32]byte{1, 5}
	if _, err := GetAnnouncement(ctx, hc, testName, key); err != ErrNotHeld {
		t.Errorf("an empty key: %v", err)
	}
	if err := PutAnnouncement(ctx, hc, testName, key, []byte("sealed")); err != nil {
		t.Fatal(err)
	}
	if v, err := GetAnnouncement(ctx, hc, testName, key); err != nil || string(v) != "sealed" {
		t.Errorf("got %q, %v", v, err)
	}
	if err := PutAnnouncement(ctx, hc, testName, [32]byte{2}, []byte("sealed")); err == nil {
		t.Error("a refused put said nothing")
	}
	if asks := p.asked(); len(asks) == 0 || asks[0] != "CONNECT "+testName+":443" {
		t.Errorf("the proxy was asked %q", asks)
	}
}

// flakyListener fails its first Accept as a host out of descriptors does.
type flakyListener struct {
	net.Listener
	failed bool
}

func (f *flakyListener) Accept() (net.Conn, error) {
	if !f.failed {
		f.failed = true
		return nil, &net.OpError{Op: "accept", Err: os.NewSyscallError("accept", syscall.EMFILE)}
	}
	return f.Listener.Accept()
}

// A relay out of descriptors for a moment takes connections again after,
// rather than refusing every one for good.
func TestARelayOutlivesATemporaryAcceptError(t *testing.T) {
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "relay.sock"))
	if err != nil {
		t.Fatal(err)
	}
	h := HandedOn(&flakyListener{Listener: ln}, func(net.Conn) bool { return true })
	defer h.Close()
	go func() {
		if c, err := net.Dial("unix", ln.Addr().String()); err == nil {
			defer c.Close()
			c.Write(proxyproto.Header(netip.MustParseAddrPort("192.0.2.1:5000"), netip.MustParseAddrPort("192.0.2.2:443")))
			time.Sleep(time.Second)
		}
	}()
	c, err := h.Accept()
	if err != nil {
		t.Fatalf("after a temporary error: %v", err)
	}
	if got := c.RemoteAddr().String(); got != "192.0.2.1:5000" {
		t.Errorf("the client is %s", got)
	}
	c.Close()
}

// A connection to the hand-off socket that admit refuses, as one from
// another user's process, is closed before a byte of it is read, and holds
// none of the slots the ingress's connections take.
func TestARefusedHandOffHoldsNoSlot(t *testing.T) {
	rv := &fakeRendezvous{held: map[[32]byte][]byte{}}
	n := startNamed(t, nil, rv)
	n.admitting.Store(false)
	var idle []net.Conn
	for range maxHandingOver + 8 {
		c, err := net.Dial("unix", n.handOff)
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, c)
	}
	for _, c := range idle {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("a refused connection was answered")
		}
		c.Close()
	}
	c := rendezvousClient(n, netip.MustParseAddrPort("192.0.2.1:5000"))
	req, _ := http.NewRequest(http.MethodGet, "https://"+testName+RendezvousPath+"01", nil)
	if res, err := c.Do(req); err == nil {
		res.Body.Close()
		t.Fatal("a connection admit refused was served")
	}
	n.admitting.Store(true)
	if code, _ := call(t, c, http.MethodGet, [32]byte{1}, ""); code == 0 {
		t.Fatal("no answer")
	}
}
