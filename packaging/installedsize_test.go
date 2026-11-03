package packaging

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A .deb's Installed-Size must not depend on the file system it was built on,
// or CI's package and the one release-ci builds differ.
func TestInstalledSizeCountsSizesNotBlocks(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "usr", "bin")
	for _, d := range []string{bin, filepath.Join(root, "DEBIAN")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Sparse: its blocks are next to none, its size 10 MiB.
	if err := os.WriteFile(filepath.Join(bin, "big"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filepath.Join(bin, "big"), 10<<20); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"usr/bin/small": "x", "DEBIAN/control": strings.Repeat("x", 5000)} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("big", filepath.Join(bin, "link")); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "deb/installed-size", root).CombinedOutput()
	if err != nil {
		t.Fatalf("installed-size: %v\n%s", err, out)
	}
	// usr, usr/bin and the link 1 each, big 10240, small 1; DEBIAN not at all.
	if got := strings.TrimSpace(string(out)); got != "10244" {
		t.Errorf("installed-size = %s, want 10244", got)
	}
}
