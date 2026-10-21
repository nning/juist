package published

import (
	"net"
	"net/http/httptest"
	"testing"
)

// An IPv4 client on a dual-stack listener is IPv4, by TCP, UDP or an
// address written out; what has none is [::]:0.
func TestAddrPortUnmaps(t *testing.T) {
	for _, a := range []net.Addr{
		&net.TCPAddr{IP: net.ParseIP("::ffff:203.0.113.7"), Port: 51000},
		&net.UDPAddr{IP: net.ParseIP("::ffff:203.0.113.7"), Port: 51000},
		&net.UnixAddr{Name: "[::ffff:203.0.113.7]:51000"},
	} {
		if got := AddrPort(a).String(); got != "203.0.113.7:51000" {
			t.Errorf("%T: %s", a, got)
		}
	}
	for _, a := range []net.Addr{nil, &net.UnixAddr{Name: "/run/x"}} {
		if got := AddrPort(a).String(); got != "[::]:0" {
			t.Errorf("%v: %s", a, got)
		}
	}
}

// A redirect takes the path alone: an opaque target names no other host.
func TestRedirectHTTPSKeepsTheHost(t *testing.T) {
	r := httptest.NewRequest("GET", "http:@evil.com", nil)
	r.Host = "immich.example.org:80"
	w := httptest.NewRecorder()
	RedirectHTTPS(w, r, Host(r))
	if got := w.Header().Get("Location"); got != "https://immich.example.org/" {
		t.Fatalf("redirected to %q", got)
	}
}
