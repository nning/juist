package keys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nning/juist/types"
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

func stage(t *testing.T, home string) *Node {
	t.Helper()
	k, err := GenerateNode()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteSecret(filepath.Join(home, NodeKeysFile+StagedSuffix), k.Lines("staged")); err != nil {
		t.Fatal(err)
	}
	return k
}

// Abandoned key sets are bounded: an operator looping rotate and abandon
// cannot grow what every log change has the daemon re-read.
func TestAbandonedKeysAreBounded(t *testing.T) {
	home := t.TempDir()
	for range MaxAbandoned + 3 {
		stage(t, home)
		if err := Abandon(home); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := filepath.Glob(filepath.Join(home, NodeKeysFile+AbandonedSuffix+"*"))
	if len(got) != MaxAbandoned {
		t.Fatalf("%d abandoned key sets kept, want %d", len(got), MaxAbandoned)
	}
}

// One damaged archive does not stop the device adopting the keys the log
// names.
func TestADamagedArchiveDoesNotBlockPromotion(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, NodeKeysFile+AbandonedSuffix+"-0"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := stage(t, home)
	named := func(id types.Identity) (types.NodeRecord, bool) {
		return types.NodeRecord{Identity: id, WireGuard: k.Public.WireGuard, X25519: k.Public.X25519,
			MLKEM: k.Public.MLKEM}, id == k.Identity.Public()
	}
	if err := Abandon(home); err != nil {
		t.Fatal(err)
	}
	got, err := MaybePromote(home, named)
	if err != nil || got == nil {
		t.Fatalf("promoting past a damaged archive: %v, %v", got, err)
	}
}
