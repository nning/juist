package store

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// network builds a real one-admin network in a fresh store directory.
type network struct {
	t     *testing.T
	dir   string
	admin types.PrivateIdentity
	store *Dir
	auth  *log.Authority
}

func newNetwork(t *testing.T) *network {
	t.Helper()
	n := &network{t: t, dir: t.TempDir()}
	// t.TempDir hands out 0755 directories; the store refuses a
	// group-writable one, which 0755 is not, but tighten anyway so the mode
	// assertions below describe a realistic deployment.
	if err := os.Chmod(n.dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	admin, err := types.GenerateIdentity()
	if err != nil {
		t.Fatalf("generating admin key: %v", err)
	}
	n.admin = admin
	secret := sha256.Sum256([]byte("disablement"))
	genesis, err := log.Genesis("store-net", 1,
		[]types.AdminKey{{Public: admin.Public(), Signing: new(admin.SigningKey()), Endorsement: admin.Endorsement(), Votes: 1}},
		[]types.Hash{types.DisablementCommit(secret[:])}, nil, n.sealer())
	if err != nil {
		t.Fatalf("building genesis: %v", err)
	}
	if err := genesis.Sign(admin); err != nil {
		t.Fatalf("signing genesis: %v", err)
	}
	n.reopen()
	auth, err := log.Create(n.store, genesis)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	n.auth = auth
	return n
}

func (n *network) sealer() log.Sealer {
	return func(epoch uint64, members []types.NodeRecord) (*types.EpochRecord, error) {
		_, rec, err := secrets.NewEpoch(epoch, members)
		return rec, err
	}
}

func (n *network) reopen() {
	n.t.Helper()
	st, err := Open(n.dir)
	if err != nil {
		n.t.Fatalf("Open: %v", err)
	}
	n.store = st
}

func (n *network) addNode(name string) types.NodeRecord {
	n.t.Helper()
	id, err := types.GenerateIdentity()
	if err != nil {
		n.t.Fatalf("generating identity: %v", err)
	}
	keys, err := secrets.GenerateKeys()
	if err != nil {
		n.t.Fatalf("generating keys: %v", err)
	}
	x, m, err := keys.Public()
	if err != nil {
		n.t.Fatalf("public keys: %v", err)
	}
	wg := sha256.Sum256([]byte(name))
	key := id.SigningKey()
	rec := types.NodeRecord{Identity: id.Public(), Name: name, X25519: x, MLKEM: m, Signing: &key}
	copy(rec.WireGuard[:], wg[:])

	aum, err := n.auth.Builder().AddNode(rec, n.sealer())
	if err != nil {
		n.t.Fatalf("AddNode: %v", err)
	}
	if err := aum.Sign(n.admin); err != nil {
		n.t.Fatalf("signing: %v", err)
	}
	if err := n.auth.Inform(aum); err != nil {
		n.t.Fatalf("Inform: %v", err)
	}
	return rec
}

// tempNames are every prefix this package can leave a non-record file under
// inside the records directory.
var tempNames = []string{tempPrefix, tmpPrefix}

func TestPersistsAcrossReopen(t *testing.T) {
	n := newNetwork(t)
	n.addNode("alpha")
	n.addNode("bravo")
	want := n.auth.State().Snapshot().Encode()
	wantHead := n.auth.Head()
	wantFloor, err := n.store.EpochFloor()
	if err != nil {
		t.Fatalf("EpochFloor: %v", err)
	}

	n.reopen()
	auth, err := log.Open(n.store)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if auth.Head() != wantHead {
		t.Fatal("reopening produced a different head")
	}
	if string(auth.State().Snapshot().Encode()) != string(want) {
		t.Fatal("reopening produced different state")
	}
	if got, err := n.store.EpochFloor(); err != nil || got != wantFloor {
		t.Fatalf("epoch floor is %d (err %v), want %d", got, err, wantFloor)
	}
	if wantFloor != auth.State().Epoch() {
		t.Fatalf("epoch floor %d does not match the adopted epoch %d", wantFloor, auth.State().Epoch())
	}
}

func TestFileModesAreOwnerOnly(t *testing.T) {
	n := newNetwork(t)
	n.addNode("alpha")
	// Everything this package creates: the records directory and every file
	// inside the store.
	records := filepath.Join(n.dir, recordsDir)
	info, err := os.Stat(records)
	if err != nil {
		t.Fatalf("stat %s: %v", records, err)
	}
	if perm := info.Mode().Perm(); perm != dirMode {
		t.Errorf("%s is mode %o, want %o", records, perm, dirMode)
	}
	err = filepath.WalkDir(n.dir, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("file %s is mode %o; group and other must have no access", path, perm)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the store: %v", err)
	}
}

// TestSharedWritableDirRefused covers the local-privilege case: a state
// directory anyone can write to is a state directory anyone can roll back, so
// it is refused rather than silently accepted or silently tightened.
func TestSharedWritableDirRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err := Open(dir)
	if err == nil {
		t.Fatal("opened a world-writable store directory")
	}
	if !strings.Contains(err.Error(), "chmod 700") {
		t.Errorf("error should say how to fix it: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := Open(dir); err != nil {
		t.Fatalf("Open after tightening the mode: %v", err)
	}
}

// TestCorruptRecordRefusesToOpen: a damaged log makes the node refuse to
// start, with an error naming the file. It must never repair itself, and never
// fall back to creating a fresh network.
func TestCorruptRecordRefusesToOpen(t *testing.T) {
	n := newNetwork(t)
	n.addNode("alpha")
	head := n.auth.Head()

	name := filepath.Join(n.dir, recordsDir, head.String()+recordExt)
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	body[len(body)-1] ^= 0x01
	if err := os.WriteFile(name, body, 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}

	_, err = Open(n.dir)
	if err == nil {
		t.Fatal("opened a store with a corrupt record")
	}
	if !strings.Contains(err.Error(), head.String()) {
		t.Errorf("error does not name the damaged file: %v", err)
	}
}

// TestSubstitutedRecordRefusesToOpen covers deliberate editing rather than bit
// rot: a valid record filed under another record's name. Content addressing is
// what catches it.
func TestSubstitutedRecordRefusesToOpen(t *testing.T) {
	n := newNetwork(t)
	n.addNode("alpha")
	head := n.auth.Head()
	anchor := n.auth.Anchor()

	genesisBody, err := os.ReadFile(filepath.Join(n.dir, recordsDir, anchor.String()+recordExt))
	if err != nil {
		t.Fatalf("reading the genesis record: %v", err)
	}
	target := filepath.Join(n.dir, recordsDir, head.String()+recordExt)
	if err := os.WriteFile(target, genesisBody, 0o600); err != nil {
		t.Fatalf("writing %s: %v", target, err)
	}
	if _, err := Open(n.dir); err == nil {
		t.Fatal("opened a store where one record was filed under another's name")
	}
}

func TestTruncatedRecordRefusesToOpen(t *testing.T) {
	n := newNetwork(t)
	n.addNode("alpha")
	head := n.auth.Head()
	name := filepath.Join(n.dir, recordsDir, head.String()+recordExt)
	if err := os.WriteFile(name, []byte{0xa1}, 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	if _, err := Open(n.dir); err == nil {
		t.Fatal("opened a store with a truncated record")
	}
}

func TestMissingAnchorTargetRefusesToOpen(t *testing.T) {
	n := newNetwork(t)
	n.addNode("alpha")
	anchor := n.auth.Anchor()
	if err := os.Remove(filepath.Join(n.dir, recordsDir, anchor.String()+recordExt)); err != nil {
		t.Fatalf("removing the anchor record: %v", err)
	}
	_, err := Open(n.dir)
	if err == nil {
		t.Fatal("opened a store whose anchor record is gone")
	}
	if !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("error should say the log is incomplete: %v", err)
	}
}

// TestLostRecordsDoNotRegressTheEpoch is the case the epoch floor exists for on
// the storage side: if records vanish, the node refuses to serve the older
// state they resolve to, and says why.
func TestLostRecordsDoNotRegressTheEpoch(t *testing.T) {
	n := newNetwork(t)
	a := n.addNode("alpha")
	n.addNode("bravo")
	head := n.auth.Head()
	if !n.auth.State().IsMember(a.Identity) {
		t.Fatal("alpha should be a member")
	}
	if err := os.Remove(filepath.Join(n.dir, recordsDir, head.String()+recordExt)); err != nil {
		t.Fatalf("removing the head record: %v", err)
	}
	n.reopen()
	auth, err := log.Open(n.store)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := auth.TrustedState(); err == nil || auth.Rollback() == nil {
		t.Fatalf("served a shorter chain after records were lost: %v", err)
	}
}

func TestUnknownFormatVersionRefusesToOpen(t *testing.T) {
	n := newNetwork(t)
	n.addNode("alpha")
	name := filepath.Join(n.dir, versionFile)
	if err := os.WriteFile(name, []byte("juist-log-v99\n"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	if _, err := Open(n.dir); err == nil {
		t.Fatal("opened a store written by an unknown format version")
	}
}

func TestRefusesToCreateOverExistingNetwork(t *testing.T) {
	n := newNetwork(t)
	n.addNode("alpha")
	genesis, err := n.store.AUM(n.auth.Anchor())
	if err != nil {
		t.Fatalf("reading genesis: %v", err)
	}
	n.reopen()
	if _, err := log.Create(n.store, genesis); err == nil {
		t.Fatal("created a network over an existing one")
	}
}

func TestCompactionRemovesFilesAndSurvivesReopen(t *testing.T) {
	n := newNetwork(t)
	checkpoint := func() {
		t.Helper()
		cp, err := n.auth.Builder().Checkpoint()
		if err != nil {
			t.Fatalf("Checkpoint: %v", err)
		}
		if err := cp.Sign(n.admin); err != nil {
			t.Fatalf("signing: %v", err)
		}
		if err := n.auth.Inform(cp); err != nil {
			t.Fatalf("Inform: %v", err)
		}
	}
	n.addNode("alpha")
	n.addNode("bravo")
	checkpoint()
	n.addNode("charlie")
	checkpoint()
	// The first compaction, to the checkpoint before the newest, keeps the
	// chain from the genesis, its anchor before, and the second drops it.
	if removed, err := n.auth.Compact(); err != nil || removed != 0 {
		t.Fatalf("Compact: %d removed, %v", removed, err)
	}
	n.addNode("delta")
	checkpoint()
	want := n.auth.State().Snapshot().Encode()

	before, err := n.store.Hashes()
	if err != nil {
		t.Fatalf("Hashes: %v", err)
	}
	removed, err := n.auth.Compact()
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if removed == 0 {
		t.Fatal("compaction removed nothing")
	}
	after, err := n.store.Hashes()
	if err != nil {
		t.Fatalf("Hashes: %v", err)
	}
	if len(after) != len(before)-removed {
		t.Fatalf("index says %d records after removing %d of %d", len(after), removed, len(before))
	}
	entries, err := os.ReadDir(filepath.Join(n.dir, recordsDir))
	if err != nil {
		t.Fatalf("reading records dir: %v", err)
	}
	if len(entries) != len(after) {
		t.Fatalf("%d files on disk but %d in the index", len(entries), len(after))
	}

	n.reopen()
	auth, err := log.Open(n.store)
	if err != nil {
		t.Fatalf("Open after compaction: %v", err)
	}
	if string(auth.State().Snapshot().Encode()) != string(want) {
		t.Fatal("compaction changed the state")
	}
}

func TestStrayFileRefusesToOpen(t *testing.T) {
	n := newNetwork(t)
	n.addNode("alpha")
	stray := filepath.Join(n.dir, recordsDir, "not-a-record.txt")
	if err := os.WriteFile(stray, []byte("hello"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", stray, err)
	}
	if _, err := Open(n.dir); err == nil {
		t.Fatal("opened a store containing an unexplained file")
	}
}

// TestInterruptedWriteIsCleanedUp: a leftover temporary file from a crash
// mid-Add must not make the store unopenable, and is swept once it is old
// enough to be debris rather than a write in flight. Both prefixes are
// covered, since a store written by an older build can hold either.
func TestInterruptedWriteIsCleanedUp(t *testing.T) {
	for _, prefix := range tempNames {
		t.Run(prefix, func(t *testing.T) {
			n := newNetwork(t)
			n.addNode("alpha")
			leftover := filepath.Join(n.dir, recordsDir, prefix+"ABCDEF")
			if err := os.WriteFile(leftover, []byte("partial"), 0o600); err != nil {
				t.Fatalf("writing %s: %v", leftover, err)
			}
			st, err := Open(n.dir)
			if err != nil {
				t.Fatalf("a leftover temporary file made the store unopenable: %v", err)
			}
			if _, err := log.Open(st); err != nil {
				t.Fatalf("Open: %v", err)
			}
			// The writer is what sweeps: opening tolerates the file, and the
			// next record written through this store clears it.
			n.addNode("beta")
			if _, err := os.Stat(leftover); !os.IsNotExist(err) {
				t.Error("a write did not sweep the leftover temporary file")
			}
		})
	}
}

// TestOpenLeavesAWriteInFlightAlone: opening is not exclusive, and a daemon
// may be mid-Add on the same directory. A sweep that removed a fresh staged
// file would fail its rename, and Inform being atomic, cost it the batch.
func TestOpenLeavesAWriteInFlightAlone(t *testing.T) {
	for _, prefix := range tempNames {
		t.Run(prefix, func(t *testing.T) {
			n := newNetwork(t)
			n.addNode("alpha")
			inflight := filepath.Join(n.dir, recordsDir, prefix+"ABCDEF")
			if err := os.WriteFile(inflight, []byte("staged"), 0o600); err != nil {
				t.Fatalf("writing %s: %v", inflight, err)
			}
			st, err := Open(n.dir)
			if err != nil {
				t.Fatalf("a staged file made the store unopenable: %v", err)
			}
			if _, err := log.Open(st); err != nil {
				t.Fatalf("Open: %v", err)
			}
			if _, err := os.Stat(inflight); err != nil {
				t.Errorf("opening the store destroyed another process's write in flight: %v", err)
			}
		})
	}
}

// TestSchemaFloorSurvivesReopen: the schema ratchet is only worth having if it
// outlives the process. Without it, restarting under an older build would read
// a network that has moved on as one that never did.
func TestSchemaFloorSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if v, err := d.SchemaFloor(); err != nil || v != 0 {
		t.Fatalf("a fresh store reports schema floor %v (err %v), want 0", v, err)
	}
	if err := d.SetSchemaFloor(4); err != nil {
		t.Fatalf("SetSchemaFloor: %v", err)
	}
	// Lowering is refused rather than obeyed: it is a ratchet.
	if err := d.SetSchemaFloor(2); err != nil {
		t.Fatalf("SetSchemaFloor(lower): %v", err)
	}
	if v, _ := d.SchemaFloor(); v != 4 {
		t.Fatalf("floor is %v after being handed a lower value, want 4", v)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	if v, err := reopened.SchemaFloor(); err != nil || v != 4 {
		t.Errorf("reopened store reports schema floor %v (err %v), want 4", v, err)
	}
}

// Staging a record follows no link someone else planted under its name: the
// CLI may run as root over a directory the daemon's user owns, and the name
// is predictable from the record.
func TestStagingFollowsNoLink(t *testing.T) {
	n := newNetwork(t)
	id, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := secrets.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	x, m, err := keys.Public()
	if err != nil {
		t.Fatal(err)
	}
	key := id.SigningKey()
	rec := types.NodeRecord{Identity: id.Public(), Name: "alpha", X25519: x, MLKEM: m, Signing: &key}
	rec.WireGuard[0] = 1
	aum, err := n.auth.Builder().AddNode(rec, n.sealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := aum.Sign(n.admin); err != nil {
		t.Fatal(err)
	}
	precious := filepath.Join(t.TempDir(), "precious")
	if err := os.WriteFile(precious, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(precious, filepath.Join(n.store.records, tempPrefix+aum.Hash().String())); err != nil {
		t.Fatal(err)
	}
	if err := n.auth.Inform(aum); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	if b, _ := os.ReadFile(precious); string(b) != "keep" {
		t.Fatalf("staging wrote %d bytes through the planted link", len(b))
	}
}

// A store whose directory, or records directory, is a link someone planted
// is refused rather than written through.
func TestAStoreIsNoLink(t *testing.T) {
	victim := t.TempDir()
	dir := filepath.Join(t.TempDir(), "log")
	if err := os.Symlink(victim, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("a store opened through a link")
	}
	if entries, _ := os.ReadDir(victim); len(entries) != 0 {
		t.Fatalf("opening wrote %d entries through the link", len(entries))
	}
	real := filepath.Join(t.TempDir(), "log")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(real, recordsDir)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(real); err == nil {
		t.Fatal("a store opened with its records directory a link")
	}
}

// A crash between a batch's renames must not leave a store that refuses to
// open. Here the batch is a fork that revokes: its first record wins fork
// choice alone, at an epoch below the floor the rest of the batch clears.
func TestABatchCutShortIsFinishedAtOpen(t *testing.T) {
	n := newNetwork(t)
	victim := n.addNode("victim")
	fork := n.auth.State()
	for range 3 {
		bump, err := n.auth.Builder().EpochBump(n.sealer())
		if err != nil {
			t.Fatal(err)
		}
		if err := bump.Sign(n.admin); err != nil {
			t.Fatal(err)
		}
		if err := n.auth.Inform(bump); err != nil {
			t.Fatal(err)
		}
	}
	floor := n.auth.State().Epoch()

	b := log.NewBuilder(fork)
	var batch []types.AUM
	next := func(build func() (types.AUM, error)) {
		t.Helper()
		rec, err := build()
		if err != nil {
			t.Fatal(err)
		}
		if err := rec.Sign(n.admin); err != nil {
			t.Fatal(err)
		}
		st, err := b.Dry(&rec)
		if err != nil {
			t.Fatal(err)
		}
		b = log.NewBuilder(st)
		batch = append(batch, rec)
	}
	next(func() (types.AUM, error) { return b.RemoveNode(victim.Identity, n.sealer()) })
	for range 4 {
		next(func() (types.AUM, error) { return b.EpochBump(n.sealer()) })
	}
	want := b.State()
	if want.Epoch() <= floor || batch[0].Epoch.Epoch >= floor {
		t.Fatalf("the fork does not straddle the floor: %d then %d, floor %d", batch[0].Epoch.Epoch, want.Epoch(), floor)
	}

	// The crash that hurts: the revocation is published, the rest are not.
	revocation := batch[0].Hash()
	rename = func(string, string) error {
		if err := os.Rename(filepath.Join(n.dir, recordsDir, tempPrefix+revocation.String()),
			filepath.Join(n.dir, recordsDir, revocation.String()+recordExt)); err != nil {
			t.Fatal(err)
		}
		panic("crashed")
	}
	func() {
		defer func() { _ = recover() }()
		_ = n.auth.Inform(batch...)
	}()
	rename = os.Rename

	n.reopen()
	auth, err := log.Open(n.store)
	if err != nil {
		t.Fatalf("a batch cut short left a store that does not open: %v", err)
	}
	if got := auth.State(); got.Head() != want.Head() || got.Epoch() != want.Epoch() {
		t.Fatalf("after reopening: head %v epoch %d, want %v epoch %d", got.Head(), got.Epoch(), want.Head(), want.Epoch())
	}
}

// A journal naming a record that is neither staged nor stored is a store that
// lost it, and one that is not a journal is not guessed at: both refuse.
func TestABrokenBatchJournalRefusesToOpen(t *testing.T) {
	for name, body := range map[string]string{
		"a lost record": batchHeader + "\n" + types.Hash{7}.String() + "\n",
		"no header":     types.Hash{7}.String() + "\n",
		"not a hash":    batchHeader + "\nnot-a-hash\n",
	} {
		t.Run(name, func(t *testing.T) {
			n := newNetwork(t)
			if err := os.WriteFile(filepath.Join(n.dir, batchFile), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(n.dir); err == nil {
				t.Fatal("the store opened over a broken batch journal")
			}
		})
	}
}

// A batch that completes leaves no journal behind.
func TestACompletedBatchLeavesNoJournal(t *testing.T) {
	n := newNetwork(t)
	n.addNode("alpha")
	if _, err := os.Stat(filepath.Join(n.dir, batchFile)); !os.IsNotExist(err) {
		t.Fatalf("a completed batch left its journal: %v", err)
	}
}
