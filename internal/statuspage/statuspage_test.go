package statuspage

import (
	"context"
	"errors"
	"fmt"
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
	st.NetworkName, st.SelfName, st.Members, st.Peers, st.Schema = "home", "mailer", 4, 3, types.CurrentSchema
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
		// The lists say device by device what a count of them would.
		{"a member, the public seeing nothing", member, ipc.ShowNone, 200, everything, []string{"3 reached", "2 of 3 live"}},
		{"the public, seeing nothing", public, ipc.ShowNone, 404, nil, []string{"immich"}},
		{"the public through an ingress, seeing nothing", ingres, ipc.ShowNone, 404, nil, []string{"immich"}},
		{"the public, seeing services", public, ipc.ShowServices, 200,
			[]string{"immich.pub.example.org", "phone.pub.example.org"},
			[]string{"mailer", "vps", ">nas<", "100.80.", "device admission", "Devices", "the public sees", "services up"}},
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

// A name for members alone is marked so for members and left out for the
// public, who reach none of it.
func TestANameForMembersAloneIsShownToMembers(t *testing.T) {
	p := sample()
	p.Status.Devices[0].Members = []string{"immich.pub.example.org"}
	body := serve(t, p, ipc.ShowServices, member, "/").Body.String()
	if !strings.Contains(body, `immich.pub.example.org</a><span class="sub">members only</span>`) {
		t.Errorf("a member is not told immich is for members alone:\n%s", body)
	}
	if strings.Count(body, "members only") != 1 {
		t.Errorf("a public name is marked for members alone:\n%s", body)
	}
	for _, from := range []string{public, ingres} {
		body := serve(t, p, ipc.ShowAll, from, "/").Body.String()
		if strings.Contains(body, "immich") {
			t.Errorf("from %s, the public is shown a name for members alone", from)
		}
		if !strings.Contains(body, "files.pub.example.org") {
			t.Errorf("from %s, the public names are gone too", from)
		}
	}
}

// The page calls a device outdated whose tunnel is up and carries nothing
// of the user's, says why, and calls its services unreached.
func TestThePageMarksOutdatedDevices(t *testing.T) {
	p := sample()
	p.Status.Reach[0].Outdated = true
	p.Status.Reach[2].Live, p.Status.Reach[2].Outdated = true, true
	p.Status.Outdated = []string{"nas", "vps"}
	for _, s := range services(p) {
		if s.Name == "files.pub.example.org" && s.State != "unreached" {
			t.Errorf("a service on an outdated device reads %s", s.State)
		}
	}
	body := serve(t, p, ipc.ShowNetwork, member, "/").Body.String()
	for _, want := range []string{`<span class="pill outdated">outdated</span>`,
		"nas, vps run an older juist, unreachable until updated"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not say %q:\n%s", want, body)
		}
	}
	if strings.Contains(strings.ToLower(body), "quantum") {
		t.Errorf("the page speaks of quantum:\n%s", body)
	}
}

// When a peer was last heard from shows once: in its column on a wide
// screen, under the state on a narrow one. The copy under the state is a
// td .sub, so the rule hiding it outside the narrow layout must be as
// specific.
func TestTheLastHeardShowsOnce(t *testing.T) {
	css := pageHTML[:strings.Index(pageHTML, "@media")]
	if !strings.Contains(css, "td .sub.narrow { display: none; }") {
		t.Error("the narrow copy of when a peer was last heard from shows on a wide screen too")
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
		"/.juist/icon.svg": 200, "/.juist/page.html": 404, "/index.html": 404, "/.juist/": 404} {
		if w := serve(t, sample(), ipc.ShowServices, public, path); w.Code != want {
			t.Errorf("%s: %d, want %d", path, w.Code, want)
		}
	}
	w := serve(t, sample(), ipc.ShowServices, public, "/")
	if hsts := w.Header().Get("Strict-Transport-Security"); !strings.HasPrefix(hsts, "max-age=") {
		t.Errorf("HSTS %q", hsts)
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") ||
		!strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "img-src 'self'") {
		t.Errorf("CSP %q", csp)
	}
	if !strings.Contains(w.Body.String(), `<link rel="icon" href="/.juist/icon.svg"`) {
		t.Error("the page has no icon")
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

// A name published by TCP is shown with its port, and links nowhere: it is
// no web page.
func TestANamePublishedByTCPIsNoLink(t *testing.T) {
	p := sample()
	p.Status.Devices[3].Published = append(p.Status.Devices[3].Published, "mc.pub.example.org:25565")
	body := serve(t, p, ipc.ShowServices, public, "/").Body.String()
	if !strings.Contains(body, ">mc.pub.example.org:25565<") || strings.Contains(body, "https://mc.pub.example.org") {
		t.Errorf("the page shows the name published by TCP as:\n%s", body)
	}
	if !strings.Contains(body, `href="https://files.pub.example.org/"`) {
		t.Error("a name published by TLS links nowhere")
	}
}

func TestADisabledNetworkSaysSo(t *testing.T) {
	st := &ipc.Status{InNetwork: true, Disabled: "IY5WHNAM5UBB", NotMember: true}
	if s, class := state(st); s != "disabled" || class != "alarm" {
		t.Fatalf("state %q, class %q", s, class)
	}
	if a := alarms(st); len(a) != 1 || !strings.Contains(a[0], "break-glass") {
		t.Fatalf("alarms %q", a)
	}
}

// A device on HTTPS alone says so, and by which relays; and one with none on
// 443 says it reaches nobody.
func TestThePageSaysHTTPSAlone(t *testing.T) {
	p := sample()
	p.Status.HTTPS = &ipc.HTTPS{Only: true, Relays: []string{"relay.example.org"}}
	if body := serve(t, p, ipc.ShowNone, member, "/").Body.String(); !strings.Contains(body, "only, by relay.example.org") {
		t.Errorf("the page does not say HTTPS alone:\n%s", body)
	}
	p.Status.HTTPS.Relays = nil
	if body := serve(t, p, ipc.ShowNone, member, "/").Body.String(); !strings.Contains(body, "no relay on 443/tcp") {
		t.Errorf("the page does not say no relay is on 443:\n%s", body)
	}
}

// The page says the network's schema as juist status does, and the one this
// juist runs where the network is behind it.
func TestThePageSaysTheSchema(t *testing.T) {
	p := sample()
	body := serve(t, p, ipc.ShowServices, member, "/").Body.String()
	if want := fmt.Sprintf("<dt>Schema</dt><dd>%d</dd>", types.CurrentSchema); !strings.Contains(body, want) {
		t.Errorf("a member is not shown the schema, %s:\n%s", want, body)
	}
	if strings.Contains(serve(t, p, ipc.ShowServices, public, "/").Body.String(), "Schema") {
		t.Error("the public seeing services is shown the schema")
	}
	p.Status.Schema = types.CurrentSchema - 1
	body = serve(t, p, ipc.ShowServices, member, "/").Body.String()
	if want := fmt.Sprintf(`<dt>Schema</dt><dd class="relay">%d (%d)</dd>`, types.CurrentSchema-1,
		types.CurrentSchema); !strings.Contains(body, want) {
		t.Errorf("a network behind this juist's schema is not marked, %s:\n%s", want, body)
	}
}

// Each device's schema shows as juist devices shows it: marked where older
// than this juist's, - where unannounced, and left out where none is.
func TestThePageSaysEachDevicesSchema(t *testing.T) {
	p := sample()
	if body := serve(t, p, ipc.ShowServices, member, "/").Body.String(); strings.Contains(body, "<th>Schema</th>") {
		t.Errorf("a schema column with no schema announced:\n%s", body)
	}
	p.Status.Devices[0].Build, p.Status.Devices[1].Build = types.CurrentSchema, types.CurrentSchema-1
	body := serve(t, p, ipc.ShowServices, member, "/").Body.String()
	for _, want := range []string{"<th>Schema</th>",
		fmt.Sprintf(`<td class="dim schema">%d</td>`, types.CurrentSchema),
		fmt.Sprintf(`<td class="dim schema relay">%d</td>`, types.CurrentSchema-1),
		`<td class="dim schema">-</td>`} {
		if !strings.Contains(body, want) {
			t.Errorf("the devices lack %s:\n%s", want, body)
		}
	}
	if strings.Contains(serve(t, p, ipc.ShowServices, public, "/").Body.String(), "<th>Schema</th>") {
		t.Error("the public seeing services is shown the devices' schemas")
	}
}
