package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func untar(t *testing.T, b []byte) (map[string][]byte, map[string]*tar.Header) {
	t.Helper()
	files, headers := map[string][]byte{}, map[string]*tar.Header{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return files, headers
		}
		if err != nil {
			t.Fatal(err)
		}
		files[h.Name], _ = io.ReadAll(tr)
		headers[h.Name] = h
	}
}

// The image is what docker load takes: a manifest naming the config and the
// layer by their sums, the binaries in it to run with their licenses, its
// home the user's and juist's; and built twice, the same bytes.
func TestTheImageLoads(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"juistd", "juist", "certs", "license", "third"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(f), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	build := func(out string) []byte {
		t.Helper()
		if err := run(out, "juist:1.0", "amd64", 1700000000, filepath.Join(dir, "juistd"), filepath.Join(dir, "juist"),
			filepath.Join(dir, "certs"), filepath.Join(dir, "license"), filepath.Join(dir, "third")); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	b := build(filepath.Join(dir, "a.tar"))
	if !bytes.Equal(b, build(filepath.Join(dir, "b.tar"))) {
		t.Error("two builds differ")
	}
	files, _ := untar(t, b)
	var manifest []archiveManifest
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil || len(manifest) != 1 {
		t.Fatalf("manifest %s: %v", files["manifest.json"], err)
	}
	m := manifest[0]
	var config imageConfig
	if err := json.Unmarshal(files[m.Config], &config); err != nil {
		t.Fatalf("config %q: %v", m.Config, err)
	}
	sum := sha256.Sum256(files[m.Config])
	if m.Config != hex.EncodeToString(sum[:])+".json" {
		t.Errorf("the config is named %s, not by its sum", m.Config)
	}
	layer := files[m.Layers[0]]
	diff := sha256.Sum256(layer)
	if len(m.Layers) != 1 || config.RootFS.DiffIDs[0] != "sha256:"+hex.EncodeToString(diff[:]) {
		t.Errorf("the layer %v is not the config's %v", m.Layers, config.RootFS.DiffIDs)
	}
	if m.RepoTags[0] != "juist:1.0" || config.Architecture != "amd64" || config.Config.User != "65532:65532" ||
		config.Config.Entrypoint[0] != "/usr/local/bin/juistd" || !slices.Contains(config.Config.Env, "JUIST_HOME=/var/lib/juist") {
		t.Errorf("the image is %+v, %+v", m, config)
	}
	inside, headers := untar(t, layer)
	for name, mode := range map[string]int64{"usr/local/bin/juistd": 0o755, "usr/local/bin/juist": 0o755,
		"etc/ssl/certs/ca-certificates.crt": 0o644, "usr/local/share/doc/juist/LICENSE": 0o644,
		"usr/local/share/doc/juist/THIRD_PARTY_LICENSES": 0o644} {
		if h := headers[name]; h == nil || h.Mode != mode || h.Uid != 0 {
			t.Errorf("%s: %+v", name, h)
		}
	}
	if string(inside["usr/local/bin/juistd"]) != "juistd" {
		t.Error("juistd is not the one given")
	}
	if h := headers["var/lib/juist/"]; h == nil || h.Uid != 65532 || h.Mode != 0o700 {
		t.Errorf("the home is %+v", h)
	}
}
