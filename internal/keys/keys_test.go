package keys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteSecretRefusesToOverwrite: silently replacing key material is how a
// network loses an admin below quorum, so a second write to a live path must
// fail and leave the original untouched.
func TestWriteSecretRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.keys")

	if err := WriteSecret(path, []string{"identity AAAA"}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	err := WriteSecret(path, []string{"identity BBBB"})
	if err == nil {
		t.Fatal("overwrote existing key material")
	}
	if !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Errorf("error %q does not say why it refused", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "AAAA") {
		t.Errorf("the refused write changed the file; it now reads %q", got)
	}
}

// TestWriteSecretIsAtomicAndPrivate: the write goes through a temp file and a
// rename, so it is never observed half-written, it lands at mode 0600, and it
// leaves no stray temp behind on success.
func TestWriteSecretIsAtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.keys")

	if err := WriteSecret(path, []string{"identity AAAA", "wireguard BBBB"}); err != nil {
		t.Fatalf("write: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != FileMode {
		t.Errorf("key file is mode %o, want %o", perm, FileMode)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "node.keys" {
			t.Errorf("directory holds a stray file after a successful write: %q", e.Name())
		}
	}
}
