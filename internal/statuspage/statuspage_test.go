package statuspage

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

var testNow = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func id(b byte) types.Identity {
	var i types.Identity
	i[0] = b
	return i
}

// sample is a network of four seen from mailer: vps relays and is reached
// directly, phone through a relay, nas not at all.
func sample() *ipc.StatusPage {
	mailer, vps, phone, nas := id(1), id(2), id(3), id(4)
	st := ipc.Status{Self: mailer, Addrs: []netip.Prefix{netip.MustParsePrefix("100.80.0.1/32"),
		netip.MustParsePrefix("fd7a:1::1/128")}, InNetwork: true}
	st.NetworkName, st.SelfName, st.Members, st.Peers, st.Schema = "home", "mailer", 4, 3, 10
	st.Devices = []ipc.Device{
		{Identity: mailer, Name: "mailer", V4: "100.80.0.1", V6: "fd7a:1::1", Roles: []types.Role{types.RoleAdmin},
			Published: []string{"status.pub.example.org", "immich.pub.example.org"}},
		{Identity: vps, Name: "vps", V4: "100.80.0.2", Roles: []types.Role{types.RoleIngress, types.RoleRelayCapable}},
		{Identity: phone, Name: "phone", V4: "100.80.0.3"},
		{Identity: nas, Name: "nas", V4: "100.80.0.4", Published: []string{"files.pub.example.org"}, Serving: true},
	}
	st.TunnelsChecked, st.TunnelsLive, st.TunnelsDown = true, 2, []string{"nas"}
	st.Reach = []ipc.PeerReach{
		{Identity: vps, Live: true, Direct: true, Heard: testNow.Add(-time.Minute).Unix()},
		{Identity: phone, Live: true, Heard: testNow.Add(-3 * time.Minute).Unix()},
		{Identity: nas, Absent: true, Heard: testNow.Add(-5 * time.Hour).Unix()},
	}
	st.Absent, st.SyncFailing = []string{"nas"}, []string{"phone"}
	st.Terminator = &ipc.Terminator{Running: true, Unbound: []string{"100.80.0.1:80"}}
	st.Publish = &ipc.Publish{Consent: true, Serving: []string{"status.pub.example.org", "immich.pub.example.org"}}
	return &ipc.StatusPage{Status: st, Total: 7,
		Changes: []ipc.Change{{Index: 6, What: "device admission: nas", Signers: []string{"alex"}}},
		Members: []netip.Addr{netip.MustParseAddr("100.80.0.1"), netip.MustParseAddr("100.80.0.3"),
			netip.MustParseAddr("100.80.0.4")},
		Shares: []string{"phone.pub.example.org"}}
}

func serve(t *testing.T, p *ipc.StatusPage, public ipc.Visibility, from, path string) *httptest.ResponseRecorder {
	t.Helper()
	s := New(func(context.Context) (*ipc.StatusPage, error) { return p, nil }, func() time.Time { return testNow })
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = from
	w := httptest.NewRecorder()
	s.Handler("status.pub.example.org", public).ServeHTTP(w, r)
	return w
}

const (
	member = "100.80.0.3:51000"
	public = "203.0.113.9:51000"
	ingres = "100.80.0.2:51000" // the ingress brings the public
)

// A member sees the whole page; the public as much as the operator lets it.
func TestWhatAClientSees(t *testing.T) {
	everything := []string{"immich.pub.example.org", "phone.pub.example.org", "nas", "absent",
		"direct", "relay", "device admission: nas", "approved by alex", "log sync to phone fails",
		"another program holds port 80 on 100.80.0.1"}
	for _, c := range []struct {
		name, from string
		public     ipc.Visibility
		code       int
		has, lacks []string
	}{
		{"a member, the public seeing nothing", member, ipc.ShowNone, 200, everything, nil},
		{"the public, seeing nothing", public, ipc.ShowNone, 404, nil, []string{"immich"}},
		{"the public through an ingress, seeing nothing", ingres, ipc.ShowNone, 404, nil, []string{"immich"}},
		{"the public, seeing services", public, ipc.ShowServices, 200,
			[]string{"immich.pub.example.org", "phone.pub.example.org", "3 of 4 services up"},
			[]string{"mailer", "vps", ">nas<", "100.80.", "device admission", "Devices", "the public sees"}},
		{"the public through an ingress, seeing the network", ingres, ipc.ShowNetwork, 200,
			[]string{"immich.pub.example.org", "vps", "100.80.0.2", "log sync to phone fails"},
			[]string{"device admission", "Changes"}},
		{"the public, seeing all", public, ipc.ShowAll, 200, []string{"device admission: nas", "newest 1 of 7"}, nil},
	} {
		w := serve(t, sample(), c.public, c.from, "/")
		body := w.Body.String()
		if w.Code != c.code {
			t.Errorf("%s: %d", c.name, w.Code)
			continue
		}
		for _, s := range c.has {
			if !strings.Contains(body, s) {
				t.Errorf("%s: the page lacks %q", c.name, s)
			}
		}
		for _, s := range c.lacks {
			if strings.Contains(body, s) {
				t.Errorf("%s: the page shows %q", c.name, s)
			}
		}
	}
}

// A member is told what the public sees, and the page says whose view it
// is.
func TestThePageSaysWhoseViewItIs(t *testing.T) {
	body := serve(t, sample(), ipc.ShowNetwork, member, "/").Body.String()
	for _, want := range []string{"seen from mailer", "the public sees all of this page but the changes"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if body := serve(t, sample(), ipc.ShowAll, public, "/").Body.String(); strings.Contains(body, "the public sees") {
		t.Error("the public is told what the public sees")
	}
}

func TestThePageEscapesWhatItShows(t *testing.T) {
	p := sample()
	p.Status.NetworkName = `<script>alert(1)</script>`
	p.Changes[0].What = `<img src=x onerror=alert(1)>`
	body := serve(t, p, ipc.ShowAll, public, "/").Body.String()
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "<img src=x") {
		t.Error("the page renders markup it was given")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("the network's name is not shown")
	}
}

func TestThePageServesItsAssetsAndNothingElse(t *testing.T) {
	for path, want := range map[string]int{"/": 200, "/.juist/plex-sans-400.woff2": 200, "/.juist/refresh.js": 200,
		"/.juist/page.html": 404, "/index.html": 404, "/.juist/": 404} {
		if w := serve(t, sample(), ipc.ShowServices, public, path); w.Code != want {
			t.Errorf("%s: %d, want %d", path, w.Code, want)
		}
	}
	w := serve(t, sample(), ipc.ShowServices, public, "/")
	if hsts := w.Header().Get("Strict-Transport-Security"); !strings.HasPrefix(hsts, "max-age=") {
		t.Errorf("HSTS %q", hsts)
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") ||
		!strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP %q", csp)
	}
	if w := serve(t, sample(), ipc.ShowNone, public, "/.juist/refresh.js"); w.Code != 404 {
		t.Errorf("a page that answers members alone serves its script to the public: %d", w.Code)
	}
	s := New(func(context.Context) (*ipc.StatusPage, error) { return sample(), nil }, nil)
	r := httptest.NewRequest("POST", "/", nil)
	w = httptest.NewRecorder()
	s.Handler("x", ipc.ShowAll).ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", w.Code)
	}
}

// juistd is asked once for every client within a moment; its last answer
// covers a moment's silence, and the page says a longer one.
func TestJuistdIsAskedOnceAMoment(t *testing.T) {
	var asked atomic.Int32
	now := testNow
	fail := false
	s := New(func(context.Context) (*ipc.StatusPage, error) {
		asked.Add(1)
		if fail {
			return nil, errors.New("no")
		}
		return sample(), nil
	}, func() time.Time { return now })
	get := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = public
		w := httptest.NewRecorder()
		s.Handler("x", ipc.ShowServices).ServeHTTP(w, r)
		return w
	}
	for range 5 {
		get()
	}
	if n := asked.Load(); n != 1 {
		t.Errorf("asked %d times", n)
	}
	now, fail = now.Add(cacheFor), true
	if w := get(); w.Code != 200 {
		t.Errorf("juistd silent a moment: %d", w.Code)
	}
	now = now.Add(keepFor)
	if w := get(); w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "juistd does not answer") {
		t.Errorf("juistd silent: %d", w.Code)
	}
	if n := asked.Load(); n != 3 {
		t.Errorf("asked %d times", n)
	}
}
