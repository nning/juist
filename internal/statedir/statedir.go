// Package statedir is the layout of a juist state directory, which juistd and
// the CLI share: its files, its lock, and the hints an invite leaves for a new
// member.
package statedir

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/sys/unix"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/types"
)

// Files in the state directory the service owns besides the log and keys.
const (
	// LockName is the single-instance lock file's name.
	LockName = "daemon.lock"

	OperatorFile = "operator"
)

// StateFiles are what a daemon keeps in its state directory beside the log
// and the node keys, for a reset of a home no daemon runs from.
var StateFiles = []string{EndpointCacheFile, KeyringFile, LeaseFile, OperatorFile}

// EndpointCacheFile is the cache's name inside the state directory.
const EndpointCacheFile = "endpoints.cbor"

// EndpointCachePath returns where a home directory keeps the cache.
func EndpointCachePath(home string) string { return filepath.Join(home, EndpointCacheFile) }

// LeaseFile holds the newest lease per signer, so a restarted node knows how
// fresh it is before it hears from anyone: the startup gate.
const LeaseFile = "leases.cbor"

// KeyringPath returns where a home directory keeps its epoch secrets.
func KeyringPath(home string) string { return filepath.Join(home, KeyringFile) }

// KeyringFile holds the epoch secrets a node holds, which a rotation of its
// own keys would otherwise cost it: the chain's older wraps are sealed to the
// keys it had.
const KeyringFile = "epochs.secret"

// LeasePath returns where a home directory keeps its leases.
func LeasePath(home string) string { return filepath.Join(home, LeaseFile) }

// WriteFilePrivate writes owner-only, through a temporary file so a crash
// cannot leave a half-written file under the name a later run will read. The
// temporary name is fresh and created exclusively, so nothing planted in the
// directory — a symlink under a predictable name — is written through.
func WriteFilePrivate(path string, b []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // a no-op once renamed
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	// Synced before the rename, so the name never points at bytes the
	// filesystem has not committed, and the directory after it, so the name
	// survives a power cut too.
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("renaming %s: %w", tmp, err)
	}
	return keys.SyncDir(dir)
}

// EncodeLeaseFile and DecodeLeaseFile are the lease file's format.
func EncodeLeaseFile(raw [][]byte) ([]byte, error) { return cbor.Marshal(raw) }

func DecodeLeaseFile(b []byte) ([][]byte, error) {
	dm, err := cbor.DecOptions{MaxArrayElements: gossip.MaxLeasesPerFrame}.DecMode()
	if err != nil {
		return nil, err
	}
	var raw [][]byte
	if err := dm.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// SeedHints stores what an inviting device sent a new member — its members'
// signed announcements and its leases, which the caller has checked against
// the adopted log — where the daemon looks for them at startup. Everything is
// verified again when read: the hints save a search, they grant nothing.
func SeedHints(home string, endpoints, leases [][]byte) error {
	var eps []gossip.Endpoint
	for _, b := range endpoints {
		e, err := gossip.DecodeEndpoint(b)
		if err != nil || e.Verify() != nil {
			continue
		}
		eps = append(eps, e)
		if len(eps) == types.MaxNodes {
			break
		}
	}
	if len(eps) > 0 {
		b, err := gossip.EncodeCachedEndpoints(eps)
		if err != nil {
			return err
		}
		if err := WriteFilePrivate(EndpointCachePath(home), b); err != nil {
			return fmt.Errorf("writing the endpoint cache: %w", err)
		}
	}
	newest := map[types.Identity]types.Lease{}
	for _, b := range leases {
		if l, err := types.DecodeLease(b); err == nil && l.Issued > newest[l.Signer].Issued {
			newest[l.Signer] = l
		}
	}
	// The newest are kept where there are more signers than a frame holds:
	// they are the ones that still vouch.
	ls := slices.Collect(maps.Values(newest))
	slices.SortFunc(ls, func(a, b types.Lease) int { return cmp.Compare(b.Issued, a.Issued) })
	var keep [][]byte
	for _, l := range ls[:min(len(ls), gossip.MaxLeasesPerFrame)] {
		if b, err := l.Encode(); err == nil {
			keep = append(keep, b)
		}
	}
	if len(keep) > 0 {
		b, err := EncodeLeaseFile(keep)
		if err != nil {
			return err
		}
		if err := WriteFilePrivate(LeasePath(home), b); err != nil {
			return fmt.Errorf("writing leases: %w", err)
		}
	}
	return nil
}

// OpenLock opens the lock file, which must be a regular file: not a link,
// and not a FIFO that would hang whoever opened it.
func OpenLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return f, nil
}

// ErrHomeInUse is [ShareHome]'s answer while a juistd runs from the directory.
var ErrHomeInUse = errors.New("statedir: juistd runs from this directory")

// ShareHome takes home's lock shared, for a CLI that works on the state
// directory itself: juistd cannot start on it for as long as the returned
// file stays open, and a juistd already running refuses it. Checking
// [HomeInUse] instead would leave the window between the check and the
// writes. The kernel drops the lock with the process.
func ShareHome(home string) (*os.File, error) {
	path := filepath.Join(home, LockName)
	f, err := OpenLock(path)
	if err != nil {
		return nil, fmt.Errorf("opening the lock file %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrHomeInUse
		}
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	return f, nil
}

// HomeInUse reports whether a running juistd holds home. Its state is then
// the daemon's to change, through its socket, and nobody else's.
func HomeInUse(home string) bool {
	// Not following a link, nor waiting on a FIFO planted under the name.
	f, err := os.OpenFile(filepath.Join(home, LockName), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		return errors.Is(err, unix.EWOULDBLOCK)
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return false
}
