package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A package's BLAKE2b sum and its checksum as pkg 2.8.4's pkg repo wrote it.
func TestBase32(t *testing.T) {
	in, _ := hex.DecodeString("0a2e4096ab2975fe29c51a6c824a730c9f99dce937e7810e8db9fb17197569f0" +
		"cb698213f391d0a20b56dd1f7b181496d62ff17738b88f6eb41d1d25a7a923b6")
	const want = "komyrmqijj7h9wwa4y5refpqca8ujq87z33de8wt376xtcwqjdhzhwjouahdjemwmoi47xcxayfcjm9ft97odh6tqdp5tqwr8pk8n5n"
	if got := base32(in); got != want {
		t.Fatalf("base32 = %s, want %s", got, want)
	}
}

func writePkg(t *testing.T, path, name, version string, mtime time.Time) {
	t.Helper()
	m, _ := json.Marshal(map[string]any{"name": name, "version": version, "flatsize": 73616298})
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	tw := tar.NewWriter(z)
	tw.WriteHeader(&tar.Header{Name: "+COMPACT_MANIFEST", Mode: 0o644, Size: int64(len(m)), Typeflag: tar.TypeReg})
	tw.Write(m)
	tw.Close()
	z.Close()
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func entry(t *testing.T, archive, name string) []byte {
	t.Helper()
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(z)
	for {
		h, err := tr.Next()
		if err != nil {
			t.Fatalf("%s: no %s: %v", archive, name, err)
		}
		if h.Name == name {
			b, _ := io.ReadAll(tr)
			return b
		}
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "key")
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	repo := filepath.Join(dir, "FreeBSD:15:amd64")
	os.Mkdir(repo, 0o755)
	now := time.Now()
	writePkg(t, filepath.Join(repo, "juist-2.pkg"), "juist", "2", now)
	writePkg(t, filepath.Join(repo, "juist-1.pkg"), "juist", "1", now.Add(-time.Hour))
	writePkg(t, filepath.Join(repo, "other-1.pkg"), "other", "1", now)
	if err := run(keyPath, repo, now); err != nil {
		t.Fatal(err)
	}

	site := entry(t, filepath.Join(repo, "packagesite.pkg"), "packagesite.yaml")
	lines := strings.Split(strings.TrimSpace(string(site)), "\n")
	if len(lines) != 2 {
		t.Fatalf("packagesite.yaml has %d lines, want one per name:\n%s", len(lines), site)
	}
	var p map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &p); err != nil {
		t.Fatal(err)
	}
	if p["version"] != "2" || p["path"] != "juist-2.pkg" || p["repopath"] != "juist-2.pkg" {
		t.Errorf("juist's entry is not the newest package: %v", p)
	}
	if s, _ := p["sum"].(string); !strings.HasPrefix(s, "2$") || len(s) != 105 {
		t.Errorf("sum %q is no BLAKE2b in pkg's base32", s)
	}
	if !strings.Contains(lines[0], `"flatsize":73616298`) {
		t.Errorf("flatsize lost its form: %s", lines[0])
	}

	for _, a := range [][2]string{{"packagesite.pkg", "packagesite.yaml"}, {"data.pkg", "data"}} {
		body := entry(t, filepath.Join(repo, a[0]), a[1])
		sig := entry(t, filepath.Join(repo, a[0]), "signature")
		sum := sha256.Sum256(body)
		h := sha256.Sum256([]byte(hex.EncodeToString(sum[:])))
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h[:], sig); err != nil {
			t.Errorf("%s: signature does not verify: %v", a[0], err)
		}
	}
	var data struct{ Packages []map[string]any }
	if err := json.Unmarshal(entry(t, filepath.Join(repo, "data.pkg"), "data"), &data); err != nil || len(data.Packages) != 2 {
		t.Errorf("data lists %d packages (%v), want 2", len(data.Packages), err)
	}
	if b, err := os.ReadFile(filepath.Join(repo, "meta.conf")); err != nil || !strings.Contains(string(b), `packing_format = "tgz"`) {
		t.Errorf("meta.conf: %q, %v", b, err)
	}
}
