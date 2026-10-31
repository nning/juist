package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func build(t *testing.T, dir, out string) {
	t.Helper()
	if err := run("../manifest.json", "../scripts", "1.2", "FreeBSD:15:amd64", 1700000000, out, []string{
		"/usr/local/sbin/tool=" + filepath.Join(dir, "tool"),
		"/usr/local/share/man/man8/tool.8.gz=" + filepath.Join(dir, "tool.8"),
	}); err != nil {
		t.Fatal(err)
	}
}

// A package is the same bytes each time, its manifests first, with every
// file's sum and mode as pkg checks them, and pages compressed.
func TestPackage(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "tool"), []byte("#!/bin/sh\n"), 0o755)
	os.WriteFile(filepath.Join(dir, "tool.8"), []byte(".TH TOOL 8\n"), 0o644)
	a, b := filepath.Join(dir, "a.pkg"), filepath.Join(dir, "b.pkg")
	build(t, dir, a)
	build(t, dir, b)
	pa, _ := os.ReadFile(a)
	pb, _ := os.ReadFile(b)
	if !bytes.Equal(pa, pb) {
		t.Fatal("two builds differ")
	}
	z, err := gzip.NewReader(bytes.NewReader(pa))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(z)
	var names []string
	contents := map[string][]byte{}
	modes := map[string]int64{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(tr)
		names = append(names, h.Name)
		contents[h.Name] = data
		modes[h.Name] = h.Mode
		if h.Uname != "root" || h.Gname != "wheel" {
			t.Errorf("%s is %s:%s", h.Name, h.Uname, h.Gname)
		}
	}
	if len(names) != 4 || names[0] != "+COMPACT_MANIFEST" || names[1] != "+MANIFEST" {
		t.Fatalf("entries %q", names)
	}
	var m struct {
		ABI         string            `json:"abi"`
		Arch        string            `json:"arch"`
		Annotations map[string]string `json:"annotations"`
		Files       map[string]struct {
			Sum  string `json:"sum"`
			Perm string `json:"perm"`
		} `json:"files"`
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(contents["+MANIFEST"], &m); err != nil {
		t.Fatal(err)
	}
	if m.Arch != "freebsd:15:x86:64" || m.Annotations["FreeBSD_version"] != "1500000" {
		t.Errorf("arch %q, FreeBSD_version %q", m.Arch, m.Annotations["FreeBSD_version"])
	}
	for name, f := range m.Files {
		sum := sha256.Sum256(contents[name])
		if f.Sum != "1$"+hex.EncodeToString(sum[:]) {
			t.Errorf("%s: sum %s", name, f.Sum)
		}
	}
	if m.Files["/usr/local/sbin/tool"].Perm != "0755" || modes["/usr/local/sbin/tool"] != 0o755 {
		t.Errorf("the tool's mode: %s, %o", m.Files["/usr/local/sbin/tool"].Perm, modes["/usr/local/sbin/tool"])
	}
	page, err := gzip.NewReader(bytes.NewReader(contents["/usr/local/share/man/man8/tool.8.gz"]))
	if err != nil {
		t.Fatalf("the page is not compressed: %v", err)
	}
	if got, _ := io.ReadAll(page); string(got) != ".TH TOOL 8\n" {
		t.Errorf("the page reads %q", got)
	}
	if m.Scripts["pre-install"] == "" || m.Scripts["pre-deinstall"] == "" {
		t.Errorf("scripts %v", m.Scripts)
	}
}

// An rc.d script, and a script in libexec, runs though the checkout lost its
// mode; a file given twice,
// a path not clean, or a script pkg does not run is refused.
func TestModesAndMistakes(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "juistd")
	os.WriteFile(src, []byte("#!/bin/sh\n"), 0o644)
	out := filepath.Join(dir, "p.pkg")
	if err := run("../manifest.json", "../scripts", "1", "FreeBSD:15:amd64", 0, out,
		[]string{"/usr/local/etc/rc.d/juistd=" + src, "/usr/local/libexec/juist/serve.sh=" + src}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	z, _ := gzip.NewReader(bytes.NewReader(b))
	tr := tar.NewReader(z)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		if (h.Name == "/usr/local/etc/rc.d/juistd" || h.Name == "/usr/local/libexec/juist/serve.sh") && h.Mode != 0o755 {
			t.Errorf("%s's mode is %o", h.Name, h.Mode)
		}
	}
	for _, specs := range [][]string{
		{"/usr/local/bin/x=" + src, "/usr/local/bin/x=" + src},
		{"/usr/local/bin/../x=" + src},
	} {
		if err := run("../manifest.json", "../scripts", "1", "FreeBSD:15:amd64", 0, out, specs); err == nil {
			t.Errorf("%q taken", specs)
		}
	}
	scripts := t.TempDir()
	os.WriteFile(filepath.Join(scripts, "pre-install~"), []byte("true\n"), 0o644)
	if err := run("../manifest.json", scripts, "1", "FreeBSD:15:amd64", 0, out, []string{"/usr/local/bin/x=" + src}); err == nil {
		t.Error("an editor's backup taken for a script")
	}
}
