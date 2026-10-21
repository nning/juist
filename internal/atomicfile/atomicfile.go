// Package atomicfile replaces files whole, so that a crash or a power cut
// leaves the old content or the new under a name, never a part of either.
package atomicfile

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Write replaces path with b at mode perm, through a temporary file created
// exclusively beside it, so nothing planted in the directory is written
// through; the file is synced before the rename, the directory after it.
func Write(path string, b []byte, perm fs.FileMode) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	if err := f.Chmod(perm); err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("writing %s: %w", f.Name(), err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("syncing %s: %w", f.Name(), err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", f.Name(), err)
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return SyncDir(dir)
}

// SyncDir makes renames and creations in dir durable: without it a file's
// content survives a power cut but the name pointing at it may not.
func SyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("opening %s to sync: %w", dir, err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("syncing %s: %w", dir, err)
	}
	return nil
}

// RefuseSharedWritable refuses a directory group or other can write to, where
// anyone could replace what Write renames into it; risk says what they could
// do then, chmod the mode to suggest.
func RefuseSharedWritable(path, risk, chmod string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspecting %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s is mode %o, writable by group or other; anyone who can write there can %s. "+
			"Run: chmod %s %s", path, perm, risk, chmod, path)
	}
	return nil
}
