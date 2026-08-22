// Package store persists the membership log on disk.
//
// Three rules from docs/04-architecture.md shape it:
//
//   - Records are content-addressed. A record's file is named by its hash, and
//     every read checks that the bytes still hash to the name. Nothing else can
//     serve as an integrity check here, because the file is the only copy.
//   - State that a decision depends on is fsynced before the decision is
//     acted on. That covers the anchor and the epoch floor, which are the
//     ratchets protecting against being walked backwards, and the records
//     themselves.
//   - Corruption makes the store refuse to open, with an error naming the file,
//     and never repairs itself. A node that has lost its log must be recovered
//     or re-enrolled; silently starting over would turn a disk fault into a
//     network with two histories.
package store

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/nning/wg-p2p/trust/log"
	"github.com/nning/wg-p2p/types"
)

// Layout inside the store directory.
const (
	versionFile = "version"
	anchorFile  = "anchor"
	floorFile   = "epoch-floor"
	recordsDir  = "records"
	recordExt   = ".cbor"

	// formatVersion is written at creation and checked at open. A future
	// layout change bumps it, so an older binary refuses a newer store
	// instead of misreading it.
	formatVersion = "wg-p2p-log-v1"

	// Owner-only: the log is not secret — every member has it — but the
	// epoch floor and anchor are integrity-critical, and a world-writable
	// state directory is how a local user rolls a daemon back.
	dirMode  fs.FileMode = 0o700
	fileMode fs.FileMode = 0o600
)

// A Dir is a [log.Storage] backed by a directory.
//
// Record bodies are not cached: the index holds hashes and parent links, and
// bodies are read and re-verified on demand. Rereading costs a syscall and
// removes any question of whether memory and disk agree.
type Dir struct {
	path    string
	records string

	parents  map[types.Hash]types.Hash // record -> parent; absent value means genesis
	children map[types.Hash][]types.Hash
	anchor   *types.Hash
	floor    uint64
}

var _ log.Storage = (*Dir)(nil)

// Open opens or creates a store at path.
//
// Every record file is read and verified against its name, so opening is where
// corruption is caught. On a fresh directory the store is empty and the caller
// proceeds to [log.Create] or [log.Bootstrap].
func Open(path string) (*Dir, error) {
	if err := os.MkdirAll(path, dirMode); err != nil {
		return nil, fmt.Errorf("store: creating %s: %w", path, err)
	}
	d := &Dir{
		path:     path,
		records:  filepath.Join(path, recordsDir),
		parents:  map[types.Hash]types.Hash{},
		children: map[types.Hash][]types.Hash{},
	}
	if err := os.MkdirAll(d.records, dirMode); err != nil {
		return nil, fmt.Errorf("store: creating %s: %w", d.records, err)
	}
	if err := checkNotSharedWritable(path); err != nil {
		return nil, err
	}
	if err := d.checkVersion(); err != nil {
		return nil, err
	}
	if err := d.loadIndex(); err != nil {
		return nil, err
	}
	if err := d.loadAnchor(); err != nil {
		return nil, err
	}
	if err := d.loadFloor(); err != nil {
		return nil, err
	}
	return d, nil
}

// Path returns the store's directory.
func (d *Dir) Path() string { return d.path }

func (d *Dir) checkVersion() error {
	name := filepath.Join(d.path, versionFile)
	b, err := os.ReadFile(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// A directory with records but no version marker is not a store this
		// code wrote; refusing beats guessing at its layout.
		entries, err := os.ReadDir(d.records)
		if err != nil {
			return fmt.Errorf("store: reading %s: %w", d.records, err)
		}
		if len(entries) > 0 {
			return fmt.Errorf("store: %s holds records but no %s marker; refusing to guess its format",
				d.path, versionFile)
		}
		return writeFileSync(name, []byte(formatVersion+"\n"))
	case err != nil:
		return fmt.Errorf("store: reading %s: %w", name, err)
	}
	if got := strings.TrimSpace(string(b)); got != formatVersion {
		return fmt.Errorf("store: %s says format %q, this build writes %q; "+
			"recover the log from another member rather than editing it", name, got, formatVersion)
	}
	return nil
}

func (d *Dir) loadIndex() error {
	entries, err := os.ReadDir(d.records)
	if err != nil {
		return fmt.Errorf("store: reading %s: %w", d.records, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), recordExt) {
			// Leftover temporary files from an interrupted write are the
			// expected case here; they are named with a distinct prefix and
			// are safe to remove. Both prefixes are swept: tempPrefix is what
			// Add stages under now, and tmpPrefix is what it staged under
			// before, by way of writeFileSync. A store written by an older
			// build can hold either, and neither must be able to keep this
			// one from opening.
			if strings.HasPrefix(e.Name(), tempPrefix) || strings.HasPrefix(e.Name(), tmpPrefix) {
				_ = os.Remove(filepath.Join(d.records, e.Name()))
				continue
			}
			return fmt.Errorf("store: %s contains an unexpected entry %q",
				d.records, e.Name())
		}
		want, err := types.ParseHash(strings.TrimSuffix(e.Name(), recordExt))
		if err != nil {
			return fmt.Errorf("store: %s is not named by a record hash: %w",
				filepath.Join(d.records, e.Name()), err)
		}
		aum, err := d.readRecord(want)
		if err != nil {
			return err
		}
		d.link(want, &aum)
	}
	return nil
}

func (d *Dir) link(h types.Hash, aum *types.AUM) {
	if aum.Prev != nil {
		d.parents[h] = *aum.Prev
		if !slices.Contains(d.children[*aum.Prev], h) {
			d.children[*aum.Prev] = append(d.children[*aum.Prev], h)
		}
	} else {
		d.parents[h] = types.Hash{}
	}
}

// readRecord reads and verifies one record file.
func (d *Dir) readRecord(h types.Hash) (types.AUM, error) {
	name := d.recordPath(h)
	b, err := os.ReadFile(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return types.AUM{}, fmt.Errorf("%w: %v", log.ErrNotFound, h)
		}
		return types.AUM{}, fmt.Errorf("store: reading %s: %w", name, err)
	}
	aum, err := types.DecodeAUM(b)
	if err != nil {
		return types.AUM{}, fmt.Errorf("store: %s does not hold a valid record: %w", name, err)
	}
	// The file name is the claim; this is the check. Without it a single
	// flipped bit — or an edit — would be indistinguishable from a record the
	// network actually authorized.
	if got := aum.Hash(); got != h {
		return types.AUM{}, fmt.Errorf(
			"store: %s holds a record that hashes to %v; the file is corrupt or was edited. "+
				"Recover the log from another member; do not delete state to start over",
			name, got)
	}
	return aum, nil
}

func (d *Dir) recordPath(h types.Hash) string {
	return filepath.Join(d.records, h.String()+recordExt)
}

func (d *Dir) AUM(h types.Hash) (types.AUM, error) {
	if _, known := d.parents[h]; !known {
		return types.AUM{}, fmt.Errorf("%w: %v", log.ErrNotFound, h)
	}
	return d.readRecord(h)
}

func (d *Dir) Children(h types.Hash) ([]types.Hash, error) {
	return slices.Clone(d.children[h]), nil
}

// Prefixes that name a file which is not a record: an in-progress write,
// recognizable and removable rather than mistaken for a record. tempPrefix is
// what Add stages under; tmpPrefix is what writeFileSync replaces through.
// Both are swept by loadIndex, because a file left under either is the normal
// residue of a crash and must not make the store unopenable.
const (
	tempPrefix = ".incoming-"
	tmpPrefix  = ".tmp-"
)

// Add writes records durably.
//
// Every file is written and fsynced before any of them is renamed into place,
// so a crash cannot leave a half-written record under a name that claims to
// hash to it. A crash between renames can leave part of the batch stored, which
// is safe by construction: a record whose parent is missing does not descend
// from the anchor, so chain resolution never looks at it, and the sender will
// offer it again.
func (d *Dir) Add(aums ...types.AUM) error {
	type staged struct {
		hash types.Hash
		temp string
	}
	var pending []staged
	cleanup := func() {
		for _, s := range pending {
			_ = os.Remove(s.temp)
		}
	}
	for i := range aums {
		if err := aums[i].StaticValidate(); err != nil {
			cleanup()
			return fmt.Errorf("store: refusing to write an invalid record: %w", err)
		}
		h := aums[i].Hash()
		if _, have := d.parents[h]; have {
			continue
		}
		body, err := aums[i].Encode()
		if err != nil {
			cleanup()
			return fmt.Errorf("store: encoding record: %w", err)
		}
		temp := filepath.Join(d.records, tempPrefix+h.String())
		if err := writeSync(temp, body); err != nil {
			cleanup()
			return err
		}
		pending = append(pending, staged{hash: h, temp: temp})
	}
	for _, s := range pending {
		if err := os.Rename(s.temp, d.recordPath(s.hash)); err != nil {
			cleanup()
			return fmt.Errorf("store: publishing record %v: %w", s.hash, err)
		}
	}
	// The renames are only durable once the directory entry is.
	if len(pending) > 0 {
		if err := fsyncDir(d.records); err != nil {
			return err
		}
	}
	for _, s := range pending {
		aum, err := d.readRecord(s.hash)
		if err != nil {
			return err
		}
		d.link(s.hash, &aum)
	}
	return nil
}

func (d *Dir) Delete(hashes ...types.Hash) error {
	var removed bool
	for _, h := range hashes {
		parent, known := d.parents[h]
		if !known {
			continue
		}
		if err := os.Remove(d.recordPath(h)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("store: removing record %v: %w", h, err)
		}
		removed = true
		delete(d.parents, h)
		d.children[parent] = slices.DeleteFunc(d.children[parent],
			func(c types.Hash) bool { return c == h })
		if len(d.children[parent]) == 0 {
			delete(d.children, parent)
		}
	}
	if removed {
		return fsyncDir(d.records)
	}
	return nil
}

// Hashes returns every stored record hash, sorted.
func (d *Dir) Hashes() ([]types.Hash, error) {
	out := make([]types.Hash, 0, len(d.parents))
	for h := range d.parents {
		out = append(out, h)
	}
	slices.SortFunc(out, func(a, b types.Hash) int { return bytes.Compare(a[:], b[:]) })
	return out, nil
}

func (d *Dir) loadAnchor() error {
	name := filepath.Join(d.path, anchorFile)
	b, err := os.ReadFile(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: reading %s: %w", name, err)
	}
	h, err := types.ParseHash(strings.TrimSpace(string(b)))
	if err != nil {
		return fmt.Errorf("store: %s does not hold a record hash: %w", name, err)
	}
	if _, known := d.parents[h]; !known {
		return fmt.Errorf(
			"store: %s names record %v, which is not in %s; the log is incomplete. "+
				"Recover it from another member; do not delete state to start over",
			name, h, d.records)
	}
	d.anchor = &h
	return nil
}

func (d *Dir) Anchor() (types.Hash, bool, error) {
	if d.anchor == nil {
		return types.Hash{}, false, nil
	}
	return *d.anchor, true, nil
}

func (d *Dir) SetAnchor(h types.Hash) error {
	if _, known := d.parents[h]; !known {
		return fmt.Errorf("store: refusing to anchor at %v, which is not stored", h)
	}
	if err := writeFileSync(filepath.Join(d.path, anchorFile), []byte(h.String()+"\n")); err != nil {
		return err
	}
	d.anchor = &h
	return nil
}

func (d *Dir) loadFloor() error {
	name := filepath.Join(d.path, floorFile)
	b, err := os.ReadFile(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: reading %s: %w", name, err)
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return fmt.Errorf("store: %s does not hold an epoch number: %w", name, err)
	}
	d.floor = v
	return nil
}

func (d *Dir) EpochFloor() (uint64, error) { return d.floor, nil }

// SetEpochFloor raises the floor and fsyncs before returning. Its entire
// purpose is to survive a crash, so an unsynced write would defeat it.
func (d *Dir) SetEpochFloor(epoch uint64) error {
	if epoch <= d.floor {
		return nil
	}
	name := filepath.Join(d.path, floorFile)
	if err := writeFileSync(name, []byte(strconv.FormatUint(epoch, 10)+"\n")); err != nil {
		return err
	}
	d.floor = epoch
	return nil
}

// checkNotSharedWritable refuses a store directory that group or other can
// write to.
//
// The log itself is not secret — every member holds it — so readability is not
// the concern. Writability is: the anchor and the epoch floor are the ratchets
// that stop this node being walked back past a checkpoint or an epoch it has
// seen, and anyone who can write here can lower them. Directories this package
// creates are 0700; one it inherits is checked rather than silently changed,
// because a store path is caller-supplied and quietly tightening the mode of
// somebody's home directory is worse than refusing.
func checkNotSharedWritable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("store: inspecting %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf(
			"store: %s is mode %o, writable by group or other; anyone who can write there can "+
				"roll this node's log back. Run: chmod 700 %s", path, perm, path)
	}
	return nil
}

// writeSync writes a file and fsyncs its contents, without the intermediate
// rename [writeFileSync] does.
//
// Add stages record bodies with it. Staging them through writeFileSync instead
// would put a second temporary name in the records directory for every record
// written, and a crash in that window leaves a file under a prefix that is not
// the one Add's own cleanup is written around — which is how an interrupted
// write turns into a store that will not open. The rename Add does afterwards
// is what publishes the record, so there is nothing for a second one to add.
func writeSync(name string, body []byte) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return fmt.Errorf("store: creating %s: %w", name, err)
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		return fmt.Errorf("store: writing %s: %w", name, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("store: syncing %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("store: closing %s: %w", name, err)
	}
	return nil
}

// writeFileSync writes a file and fsyncs it, replacing any existing content
// atomically via a temporary file in the same directory.
func writeFileSync(name string, body []byte) error {
	dir := filepath.Dir(name)
	tmp, err := os.CreateTemp(dir, tmpPrefix+"*")
	if err != nil {
		return fmt.Errorf("store: creating a temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()
	if err := tmp.Chmod(fileMode); err != nil {
		return fmt.Errorf("store: setting mode on %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(body); err != nil {
		return fmt.Errorf("store: writing %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("store: syncing %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: closing %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, name); err != nil {
		return fmt.Errorf("store: renaming %s to %s: %w", tmpName, name, err)
	}
	return fsyncDir(dir)
}

// fsyncDir makes a rename durable. Without it the file contents survive a
// power loss but the name pointing at them may not.
func fsyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("store: opening %s to sync: %w", dir, err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("store: syncing %s: %w", dir, err)
	}
	return nil
}
