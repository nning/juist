// Command server serves the built website from a directory: files only, no
// listings, and the same security headers on every answer.
package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// csp allows the site's own files and nothing else; the pages hold no inline
// script or style.
const csp = "default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// defaultIdle is how long a quiet keep-alive connection stays open. Each one
// holds one of the ingress's slots, which a crowd of visitors would exhaust.
const defaultIdle = 10 * time.Second

func main() {
	root := flag.String("root", "/site", "directory to serve")
	addr := flag.String("addr", ":8080", "address to listen on")
	idle := flag.Duration("idle", defaultIdle, "how long a quiet connection stays open")
	noindex := flag.Bool("noindex", false, "ask search engines not to index the site")
	flag.Parse()
	log.Fatal(newServer(os.DirFS(*root), *addr, *idle, *noindex, os.Stderr).ListenAndServe())
}

func newServer(site fs.FS, addr string, idle time.Duration, noindex bool, logTo io.Writer) *http.Server {
	// HTTP/2 without TLS as well, which the terminator offers clients where
	// the site is published with --http2.
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	h := handler(site)
	if noindex {
		h = noindexed(h)
	}
	return &http.Server{
		Addr:              addr,
		Protocols:         &protocols,
		Handler:           logged(h, logTo),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       idle,
		MaxHeaderBytes:    16 << 10,
	}
}

// handler serves site's files, text in the smallest coding the client takes,
// Brotli, zstd or gzip. A
// directory is served as its index.html, and a name that is no file gets a
// 404 page.
func handler(site fs.FS) http.Handler {
	files := http.FileServerFS(site)
	enc := &encodedCache{site: site}
	go enc.warm()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" {
			name = "."
		}
		st, err := fs.Stat(site, name)
		if err == nil && st.IsDir() {
			if _, err = fs.Stat(site, path.Join(name, "index.html")); err == nil && !strings.HasSuffix(r.URL.Path, "/") {
				http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
				return
			}
		}
		if errors.Is(err, fs.ErrNotExist) {
			notFound(w, site, name)
			return
		}
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Fingerprinted assets never change under their name.
		if strings.HasPrefix(name, "css/") || strings.HasPrefix(name, "js/") || strings.HasPrefix(name, "fonts/") {
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			h.Set("Cache-Control", "no-cache")
		}
		file := name
		if st.IsDir() {
			file = path.Join(name, "index.html")
		}
		if compressible(file) {
			h.Add("Vary", "Accept-Encoding")
			if b, coding, mod, ok := enc.get(file, r); ok {
				h.Set("Content-Encoding", coding)
				http.ServeContent(w, r, file, mod, bytes.NewReader(b))
				return
			}
		}
		files.ServeHTTP(w, r)
	})
}

// noindexed asks search engines to index none of h's answers.
func noindexed(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Robots-Tag", "noindex")
		h.ServeHTTP(w, r)
	})
}

func compressible(name string) bool {
	switch path.Ext(name) {
	case ".html", ".css", ".js", ".svg", ".xml", ".txt", ".json":
		return true
	}
	return false
}

// codings are the encodings served, each with how to make it.
var codings = []struct {
	name   string
	encode func([]byte) []byte
}{
	{"br", func(b []byte) []byte {
		var buf bytes.Buffer
		w := brotli.NewWriterLevel(&buf, brotli.BestCompression)
		w.Write(b)
		w.Close()
		return buf.Bytes()
	}},
	{"zstd", func(b []byte) []byte {
		// A single segment, so no window a browser refuses.
		enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression), zstd.WithSingleSegment(true))
		defer enc.Close()
		return enc.EncodeAll(b, nil)
	}},
	{"gzip", func(b []byte) []byte {
		var buf bytes.Buffer
		w, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		w.Write(b)
		w.Close()
		return buf.Bytes()
	}},
}

// accepted is the codings r's Accept-Encoding takes, by name.
func accepted(r *http.Request) map[string]bool {
	ok := map[string]bool{}
	star := false
	no := map[string]bool{}
	for _, e := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		coding, params, _ := strings.Cut(strings.TrimSpace(e), ";")
		coding = strings.ToLower(strings.TrimSpace(coding))
		zero := false
		for _, p := range strings.Split(params, ";") {
			if k, v, _ := strings.Cut(strings.TrimSpace(p), "="); strings.TrimSpace(k) == "q" {
				q, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
				zero = err != nil || q <= 0
			}
		}
		switch {
		case coding == "*":
			star = !zero
		case zero:
			no[coding] = true
		case coding != "":
			ok[coding] = true
		}
	}
	if star {
		for _, c := range codings {
			if !no[c.name] {
				ok[c.name] = true
			}
		}
	}
	return ok
}

// encodedCache holds each text file in every coding, made once per version
// of the file.
type encodedCache struct {
	site fs.FS
	mu   sync.Mutex
	m    map[string]*encoded
}

type encoded struct {
	mod  time.Time
	once sync.Once
	raw  int
	by   map[string][]byte
}

// get is name's smallest encoding r accepts, its coding and the file's
// time; ok is false where none is smaller than the file.
func (c *encodedCache) get(name string, r *http.Request) (b []byte, coding string, mod time.Time, ok bool) {
	e := c.entry(name)
	if e == nil {
		return nil, "", time.Time{}, false
	}
	took := accepted(r)
	for _, cd := range codings {
		if v, has := e.by[cd.name]; has && took[cd.name] && len(v) < e.raw && (b == nil || len(v) < len(b)) {
			b, coding = v, cd.name
		}
	}
	return b, coding, e.mod, b != nil
}

func (c *encodedCache) entry(name string) *encoded {
	st, err := fs.Stat(c.site, name)
	if err != nil {
		return nil
	}
	c.mu.Lock()
	e := c.m[name]
	if e == nil || !e.mod.Equal(st.ModTime()) {
		e = &encoded{mod: st.ModTime()}
		if c.m == nil {
			c.m = map[string]*encoded{}
		}
		c.m[name] = e
	}
	c.mu.Unlock()
	e.once.Do(func() {
		raw, err := fs.ReadFile(c.site, name)
		if err != nil {
			return
		}
		e.raw, e.by = len(raw), map[string][]byte{}
		for _, cd := range codings {
			e.by[cd.name] = cd.encode(raw)
		}
	})
	if e.by == nil {
		return nil
	}
	return e
}

// warm encodes every text file of the site ahead of its first visitor.
func (c *encodedCache) warm() {
	_ = fs.WalkDir(c.site, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && compressible(p) {
			c.entry(p)
		}
		return nil
	})
}

// logged writes a line to w for each request h answers: host, method, path,
// status, bytes, referrer, User-Agent and duration, what the client said
// quoted. The client's address is the TLS terminator's, which is left out.
func logged(h http.Handler, w io.Writer) http.Handler {
	var mu sync.Mutex
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: rw, status: http.StatusOK}
		h.ServeHTTP(rec, r)
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(w, "access: %q %s %q %d %d %q %q %v\n", r.Host, r.Method, r.URL.RequestURI(), rec.status, rec.bytes,
			r.Referer(), r.UserAgent(), time.Since(start).Round(time.Millisecond))
	})
}

// recorder notes the status and size of an answer.
type recorder struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (r *recorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status, r.wroteHeader = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.wroteHeader = true
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// notFound answers with the 404 page of the name's language, else the root's.
func notFound(w http.ResponseWriter, site fs.FS, name string) {
	lang, _, _ := strings.Cut(name, "/")
	b, err := fs.ReadFile(site, path.Join(lang, "404.html"))
	if err != nil {
		b, err = fs.ReadFile(site, "404.html")
	}
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	w.Write(b)
}
