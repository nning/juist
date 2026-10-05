package main

import (
	"archive/zip"
	"cmp"
	"compress/flate"
	_ "embed"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/nning/juist/internal/webstyle"
)

//go:embed sharelist.html
var shareListHTML string

// shareAssets is where, under a share's token, the listing's fonts and icon
// are: a dot-entry, so that no shared file is in the way.
const shareAssets = ".juist/"

var shareListTmpl = webstyle.Page("list", shareListHTML, nil)

// shareListCSP lets the listing style itself and load its fonts and icon, and
// nothing else; it is no sandbox, which would keep a browser from downloading
// what it links to.
const shareListCSP = "default-src 'none'; style-src 'unsafe-inline'; font-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

type shareCrumb struct{ Name, Href string }

type shareEntry struct {
	Name, Href, Size, Time string
	Dir                    bool
	size                   int64
	mod                    time.Time
}

type shareList struct {
	Title, Name, Summary, Assets string
	Crumbs                       []shareCrumb
	Parent                       bool
	Entries                      []shareEntry
	sort                         string
	desc                         bool
}

// SortHref is the link that sorts by key, the other way where it does so.
func (l shareList) SortHref(key string) string {
	v := url.Values{"sort": {key}}
	if key == l.sort && !l.desc {
		v.Set("order", "desc")
	}
	return "?" + v.Encode()
}

// Arrow marks the column the listing is sorted by.
func (l shareList) Arrow(key string) string {
	switch {
	case key != l.sort:
		return ""
	case l.desc:
		return " ↓"
	}
	return " ↑"
}

// serveListing lists the directory dir of fsys, top its name where dir is
// ".", folders first, sorted as the query asks; prefix is the share's path.
func serveListing(w http.ResponseWriter, r *http.Request, fsys fs.FS, dir, top, prefix string) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	l := shareList{sort: q.Get("sort"), desc: q.Get("order") == "desc", Assets: prefix + shareAssets}
	if !slices.Contains([]string{"name", "size", "time"}, l.sort) {
		l.sort = "name"
	}
	var files, dirs int
	var total int64
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if e.Type()&fs.ModeSymlink != 0 {
			// Shown as what it points at, where that is in the share.
			if info, err = fs.Stat(fsys, path.Join(dir, e.Name())); err != nil {
				continue
			}
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			continue
		}
		// "./" keeps a name such as "a:b" from reading as a scheme.
		se := shareEntry{Name: e.Name(), Href: "./" + url.PathEscape(e.Name()), Dir: info.IsDir(), mod: info.ModTime(),
			Time: info.ModTime().Format("2006-01-02 15:04")}
		if se.Dir {
			se.Href += "/"
			dirs++
		} else {
			se.size, se.Size = info.Size(), humanSize(info.Size())
			total += info.Size()
			files++
		}
		l.Entries = append(l.Entries, se)
	}
	slices.SortFunc(l.Entries, func(a, b shareEntry) int {
		if a.Dir != b.Dir {
			if a.Dir {
				return -1
			}
			return 1
		}
		var c int
		switch l.sort {
		case "size":
			c = cmp.Compare(a.size, b.size)
		case "time":
			c = a.mod.Compare(b.mod)
		}
		c = cmp.Or(c, cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)), cmp.Compare(a.Name, b.Name))
		if l.desc {
			return -c
		}
		return c
	})
	parts := []string{}
	if dir != "." {
		parts = strings.Split(dir, "/")
	}
	l.Name = cmp.Or(top, "shared")
	if len(parts) > 0 {
		l.Name = parts[len(parts)-1]
		l.Parent = true
		names := append([]string{cmp.Or(top, "shared")}, parts[:len(parts)-1]...)
		for i, n := range names {
			l.Crumbs = append(l.Crumbs, shareCrumb{Name: n, Href: strings.Repeat("../", len(parts)-i)})
		}
	}
	l.Title = l.Name
	l.Summary = summarize(dirs, files, total)
	h := w.Header()
	h.Set("Content-Security-Policy", shareListCSP)
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	_ = shareListTmpl.Execute(w, l)
}

// summarize says how many folders and files a listing holds, and how much.
func summarize(dirs, files int, total int64) string {
	var parts []string
	if dirs > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", dirs, plural(dirs, "folder")))
	}
	if files > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", files, plural(files, "file")), humanSize(total))
	}
	if len(parts) == 0 {
		return "empty"
	}
	return strings.Join(parts, " · ")
}

// humanSize is n bytes as a person reads them.
func humanSize(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}

// serveZip sends the directory dir of fsys as a ZIP named name, its files
// as the listing shows them: what a link reaches outside the share, and
// folders a link points at, are left out.
func serveZip(w http.ResponseWriter, r *http.Request, fsys fs.FS, dir, name string) {
	h := w.Header()
	h.Set("Content-Type", "application/zip")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name + ".zip"}))
	h.Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	zw := zip.NewWriter(w)
	zw.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, flate.BestSpeed)
	})
	err := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		f, err := fsys.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		rel := strings.TrimPrefix(p, dir+"/")
		if dir == "." {
			rel = p
		}
		hdr := &zip.FileHeader{Name: name + "/" + rel, Method: zip.Deflate, Modified: info.ModTime()}
		hdr.SetMode(0o644)
		zf, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		_, err = io.Copy(zf, f)
		return err
	})
	if err == nil {
		_ = zw.Close()
	}
}
