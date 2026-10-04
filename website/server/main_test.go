package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func TestTheServerServesFilesAlone(t *testing.T) {
	site := fstest.MapFS{
		"index.html":    {Data: []byte("root")},
		"de/index.html": {Data: []byte("deutsch")},
		"fonts/a.woff2": {Data: []byte("font")},
		"empty/x.txt":   {Data: []byte("x")},
		"404.html":      {Data: []byte("gone")},
		"de/404.html":   {Data: []byte("weg")},
	}
	h := handler(site)
	for _, tc := range []struct {
		method, path string
		code         int
		body, loc    string
	}{
		{"GET", "/", 200, "root", ""},
		{"GET", "/de/", 200, "deutsch", ""},
		{"GET", "/de", 301, "", "/de/"},
		{"GET", "/empty/", 404, "gone", ""},
		{"GET", "/nothing", 404, "gone", ""},
		{"GET", "/de/nichts", 404, "weg", ""},
		{"GET", "/../etc/passwd", 404, "gone", ""},
		{"POST", "/", 405, "", ""},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.code {
			t.Errorf("%s %s: %d, want %d", tc.method, tc.path, rec.Code, tc.code)
		}
		if tc.body != "" && !strings.Contains(rec.Body.String(), tc.body) {
			t.Errorf("%s %s: body %q, want %q", tc.method, tc.path, rec.Body.String(), tc.body)
		}
		if tc.loc != "" && rec.Header().Get("Location") != tc.loc {
			t.Errorf("%s %s: Location %q, want %q", tc.method, tc.path, rec.Header().Get("Location"), tc.loc)
		}
		if rec.Header().Get("Content-Security-Policy") != csp {
			t.Errorf("%s %s: no CSP", tc.method, tc.path)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/fonts/a.woff2", nil))
	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Errorf("a font is cached as %q", got)
	}
}

// Each request leaves a line: host, method, path, status, bytes, referrer,
// User-Agent and duration, what the client said quoted.
func TestEachRequestIsLogged(t *testing.T) {
	site := fstest.MapFS{"index.html": {Data: []byte("root")}, "404.html": {Data: []byte("gone")}}
	var log strings.Builder
	h := logged(handler(site), &log)
	for _, path := range []string{"/", "/nothing?x=1"} {
		r := httptest.NewRequest("GET", "http://docs.example.org"+path, nil)
		r.Header.Set("User-Agent", `ClaudeBot/1.0 "x"`)
		r.Header.Set("Referer", "https://search.example/")
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	lines := strings.Split(strings.TrimSpace(log.String()), "\n")
	for i, want := range []string{
		`access: "docs.example.org" GET "/" 200 4 "https://search.example/" "ClaudeBot/1.0 \"x\"" `,
		`access: "docs.example.org" GET "/nothing?x=1" 404 4 "https://search.example/" "ClaudeBot/1.0 \"x\"" `,
	} {
		if i >= len(lines) || !strings.HasPrefix(lines[i], want) {
			t.Errorf("line %d: %q, want %q…", i, lines, want)
		}
	}
}

// Text goes in the smallest coding the client takes, Brotli, zstd or gzip,
// and plain to one that takes none; what is compressed already goes as it is.
func TestTextGoesInTheSmallestCoding(t *testing.T) {
	page := strings.Repeat("<p>juist</p>", 200)
	mod := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	site := fstest.MapFS{
		"en/index.html": {Data: []byte(page), ModTime: mod},
		"css/site.css":  {Data: []byte(strings.Repeat("a{}", 300)), ModTime: mod},
		"robots.txt":    {Data: []byte("x"), ModTime: mod},
		"fonts/a.woff2": {Data: []byte(strings.Repeat("f", 900)), ModTime: mod},
		"404.html":      {Data: []byte("gone")},
	}
	h := handler(site)
	get := func(path, accept string, hdr ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		if accept != "" {
			r.Header.Set("Accept-Encoding", accept)
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	decode := func(coding string, b []byte) string {
		t.Helper()
		var r io.Reader
		switch coding {
		case "br":
			r = brotli.NewReader(bytes.NewReader(b))
		case "zstd":
			d, err := zstd.NewReader(bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			r = d
		case "gzip":
			z, err := gzip.NewReader(bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			r = z
		default:
			t.Fatalf("coding %q", coding)
		}
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	for accept, want := range map[string][]string{
		"gzip, deflate, br, zstd": {"br", "zstd"},
		"gzip, zstd":              {"zstd", "gzip"},
		"gzip":                    {"gzip"},
		"zstd":                    {"zstd"},
		"br;q=0, gzip;q=0.5":      {"gzip"},
		"*":                       {"br", "zstd", "gzip"},
		"*, br;q=0, zstd;q=0":     {"gzip"},
	} {
		rec := get("/en/", accept)
		coding := rec.Header().Get("Content-Encoding")
		if rec.Code != 200 || !slices.Contains(want, coding) {
			t.Errorf("%q: %d, coding %q, want one of %q", accept, rec.Code, coding, want)
			continue
		}
		if decode(coding, rec.Body.Bytes()) != page {
			t.Errorf("%q: the page decoded differs", accept)
		}
		if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") || rec.Header().Get("Vary") != "Accept-Encoding" {
			t.Errorf("%q: headers %v", accept, rec.Header())
		}
	}
	if rec := get("/css/site.css", "gzip"); rec.Header().Get("Content-Encoding") != "gzip" ||
		!strings.HasPrefix(rec.Header().Get("Content-Type"), "text/css") {
		t.Errorf("the CSS goes as %v", rec.Header())
	}
	for _, accept := range []string{"", "identity", "deflate", "gzip;q=0", "*;q=0"} {
		if rec := get("/en/", accept); rec.Header().Get("Content-Encoding") != "" || rec.Body.String() != page {
			t.Errorf("%q: not plain: %v", accept, rec.Header())
		}
	}
	if rec := get("/robots.txt", "gzip, br, zstd"); rec.Header().Get("Content-Encoding") != "" {
		t.Error("a file smaller than its encoding is encoded")
	}
	if rec := get("/fonts/a.woff2", "gzip, br, zstd"); rec.Header().Get("Content-Encoding") != "" {
		t.Error("a font is encoded")
	}
	if rec := get("/en/", "br", "If-Modified-Since", mod.Format(http.TimeFormat)); rec.Code != 304 {
		t.Errorf("an encoded page not modified since: %d", rec.Code)
	}
}

// The server takes HTTP/2 without TLS, which the terminator offers browsers
// where the site is published with --http2, and HTTP/1.1 beside it.
func TestTheServerTakesH2C(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(fstest.MapFS{"index.html": {Data: []byte("root")}}, "", time.Second, io.Discard)
	go srv.Serve(ln)
	defer srv.Close()
	for _, h2 := range []bool{true, false} {
		var p http.Protocols
		p.SetUnencryptedHTTP2(h2)
		p.SetHTTP1(!h2)
		c := &http.Client{Transport: &http.Transport{Protocols: &p}}
		resp, err := c.Get("http://" + ln.Addr().String() + "/")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if want := map[bool]int{true: 2, false: 1}[h2]; resp.ProtoMajor != want || string(b) != "root" {
			t.Errorf("HTTP/%d answered %q, want HTTP/%d", resp.ProtoMajor, b, want)
		}
	}
}

// A quiet keep-alive connection holds one of the ingress's slots, so the
// server closes it soon.
func TestAQuietConnectionIsClosedSoon(t *testing.T) {
	if defaultIdle > 15*time.Second {
		t.Errorf("a quiet connection stays %v", defaultIdle)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(fstest.MapFS{"index.html": {Data: []byte("root")}}, "", 200*time.Millisecond, io.Discard)
	go srv.Serve(ln)
	defer srv.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := br.ReadByte(); err != io.EOF {
		t.Errorf("the quiet connection was not closed: %v", err)
	}
}
