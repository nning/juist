// Package webstyle is the website's look for the pages juist serves itself:
// its fonts, colours from design/tokens.json and wordmark.
package webstyle

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
	"time"
)

//go:embed base.html
var baseHTML string

//go:embed fonts/*.woff2
var fonts embed.FS

// icon is design/logo/icon.svg, as the website's favicon.
//
//go:embed icon.svg
var icon []byte

// FontFiles are the fonts a page loads, by the name it asks for, under its
// .Assets.
var FontFiles = map[string]string{
	"plex-sans-400.woff2": "fonts/ibm-plex-sans-400-latin1.woff2",
	"plex-sans-600.woff2": "fonts/ibm-plex-sans-600-latin1.woff2",
	"plex-mono-400.woff2": "fonts/ibm-plex-mono-400-latin1.woff2",
}

var base = template.Must(template.New("webstyle").Parse(baseHTML))

// Page parses text as a page that may use funcs, "juist-style", which takes
// the fonts' and icon's path from the data's Assets, and "juist-wordmark".
func Page(name, text string, funcs template.FuncMap) *template.Template {
	return template.Must(template.Must(base.Clone()).New(name).Funcs(funcs).Parse(text))
}

// Font is a font's bytes, by the name a page asks for.
func Font(name string) ([]byte, bool) {
	file, ok := FontFiles[name]
	if !ok {
		return nil, false
	}
	b, err := fonts.ReadFile(file)
	return b, err == nil
}

// ServeAsset serves the font or icon name, 404 for none.
func ServeAsset(w http.ResponseWriter, r *http.Request, name string) {
	b, ok, typ := icon, true, "image/svg+xml"
	if name != "icon.svg" {
		b, ok = Font(name)
		typ = "font/woff2"
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", typ)
	w.Header().Set("Cache-Control", "max-age=86400")
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(b))
}
