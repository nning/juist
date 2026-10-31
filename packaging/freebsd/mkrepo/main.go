// Command mkrepo writes the catalog of a FreeBSD pkg repository in DIR: the
// newest .pkg there of each name, by modification time, signed with an RSA
// key for pkg's signature_type "pubkey".
//
//	mkrepo -key KEY DIR
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
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
)

// meta tells pkg how the catalog is packed; tgz needs no compressor beyond Go's.
const meta = `version = 2;
packing_format = "tgz";
manifests = "packagesite.yaml";
data = "data";
filesite = "files";
manifests_archive = "packagesite";
filesite_archive = "files";
`

func main() {
	key := flag.String("key", "", "the RSA private key, PEM, that signs the catalog")
	flag.Parse()
	if *key == "" || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: mkrepo -key KEY DIR")
		os.Exit(2)
	}
	if err := run(*key, flag.Arg(0), time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "mkrepo:", err)
		os.Exit(1)
	}
}

func run(keyPath, dir string, now time.Time) error {
	key, err := readKey(keyPath)
	if err != nil {
		return err
	}
	pkgs, err := catalog(dir)
	if err != nil {
		return err
	}
	var site bytes.Buffer
	for _, p := range pkgs {
		b, err := json.Marshal(p)
		if err != nil {
			return err
		}
		site.Write(b)
		site.WriteByte('\n')
	}
	data, err := json.Marshal(map[string]any{"groups": []any{}, "expired_packages": []any{}, "packages": pkgs})
	if err != nil {
		return err
	}
	for _, name := range []string{"meta.conf", "meta"} {
		if err := writeFile(filepath.Join(dir, name), []byte(meta)); err != nil {
			return err
		}
	}
	for _, a := range []struct {
		archive, name string
		body          []byte
	}{
		{"packagesite.pkg", "packagesite.yaml", site.Bytes()},
		{"data.pkg", "data", data},
	} {
		b, err := pack(a.name, a.body, key, now)
		if err != nil {
			return err
		}
		if err := writeFile(filepath.Join(dir, a.archive), b); err != nil {
			return err
		}
	}
	return nil
}

func readKey(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM", path)
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an RSA key", path)
	}
	return rk, nil
}

// catalog is each name's newest package in dir, as pkg's catalog lists it:
// its compact manifest with the file's checksum, size and path.
func catalog(dir string) ([]map[string]any, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.pkg"))
	if err != nil {
		return nil, err
	}
	type entry struct {
		m     map[string]any
		mtime time.Time
	}
	newest := map[string]entry{}
	for _, path := range paths {
		base := filepath.Base(path)
		if base == "packagesite.pkg" || base == "data.pkg" {
			continue
		}
		f, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		st, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		m, err := manifest(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		name, _ := m["name"].(string)
		if name == "" {
			return nil, fmt.Errorf("%s: manifest without a name", path)
		}
		if e, ok := newest[name]; ok && !st.ModTime().After(e.mtime) {
			continue
		}
		sum := blake2b.Sum512(f)
		m["sum"] = "2$" + base32(sum[:])
		m["path"] = base
		m["repopath"] = base
		m["pkgsize"] = len(f)
		newest[name] = entry{m, st.ModTime()}
	}
	var out []map[string]any
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for n := range newest {
			if !yield(n) {
				return
			}
		}
	}) {
		out = append(out, newest[name].m)
	}
	return out, nil
}

// manifest is the +COMPACT_MANIFEST of a gzip-packed package.
func manifest(pkg []byte) (map[string]any, error) {
	z, err := gzip.NewReader(bytes.NewReader(pkg))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(z)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("no +COMPACT_MANIFEST")
		}
		if err != nil {
			return nil, err
		}
		if h.Name != "+COMPACT_MANIFEST" {
			continue
		}
		d := json.NewDecoder(tr)
		d.UseNumber()
		var m map[string]any
		if err := d.Decode(&m); err != nil {
			return nil, err
		}
		return m, nil
	}
}

// base32 is pkg's own encoding of a checksum: its alphabet, least
// significant bits first.
func base32(in []byte) string {
	const b32 = "ybndrfg8ejkmcpqxot1uwisza345h769"
	var out strings.Builder
	remain := -1
	for i, c := range in {
		x := int(c)
		switch i % 5 {
		case 0:
			out.WriteByte(b32[x&0x1f])
			remain = x >> 5
		case 1:
			x = remain | x<<3
			out.WriteByte(b32[x&0x1f])
			out.WriteByte(b32[x>>5&0x1f])
			remain = x >> 10
		case 2:
			x = remain | x<<1
			out.WriteByte(b32[x&0x1f])
			remain = x >> 5
		case 3:
			x = remain | x<<4
			out.WriteByte(b32[x&0x1f])
			out.WriteByte(b32[x>>5&0x1f])
			remain = x >> 10 & 0x3
		case 4:
			x = remain | x<<2
			out.WriteByte(b32[x&0x1f])
			out.WriteByte(b32[x>>5&0x1f])
			remain = -1
		}
	}
	if remain >= 0 {
		out.WriteByte(b32[remain])
	}
	return out.String()
}

// sign is pkg's RSA signature of body: PKCS #1 v1.5 over the SHA-256 of
// body's SHA-256 in hex.
func sign(body []byte, key *rsa.PrivateKey) ([]byte, error) {
	sum := sha256.Sum256(body)
	h := sha256.Sum256([]byte(hex.EncodeToString(sum[:])))
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
}

// pack is the archive pkg fetches: name, holding body, and its signature.
func pack(name string, body []byte, key *rsa.PrivateKey, now time.Time) ([]byte, error) {
	sig, err := sign(body, key)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	z, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
	tw := tar.NewWriter(z)
	for _, f := range []struct {
		name string
		data []byte
	}{{"signature", sig}, {name, body}} {
		h := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.data)), Uname: "root", Gname: "wheel",
			ModTime: now, Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// writeFile replaces path at once, so a client never reads half of it.
func writeFile(path string, data []byte) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
