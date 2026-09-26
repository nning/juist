// Package keys is the on-disk layout of a juist state directory and the format
// of the key files in it. The CLI and the daemon share it because they read
// the same directory, but not equally: admin signing keys live in the
// operator's keystore and never in the daemon, so the daemon uses [LoadNode]
// and nothing else, and admins/ is the CLI's alone.
package keys

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// Layout of a juist home directory.
const (
	// LogDir holds the membership log; see trust/store.
	LogDir = "log"

	// AdminsDir holds admin signing keys. The daemon never reads it.
	AdminsDir = "admins"

	// NodeKeysFile holds this device's identity, recipient and WireGuard
	// keys: everything it needs to be a member and nothing that authorizes
	// a change.
	NodeKeysFile = "node.keys"

	// StagedSuffix names replacement key material that a rotation record has
	// not yet made live.
	StagedSuffix = ".next"

	// AbandonedSuffix starts the names of staged keys whose rotation was
	// abandoned, one file per key set. They are kept: the record already
	// carries this device's signature, and an admin may still approve it.
	AbandonedSuffix = ".abandoned"

	// FileMode and DirMode are what key material is written with.
	FileMode fs.FileMode = 0o600
	DirMode  fs.FileMode = 0o700
)

// Tags on key files. A tag makes it impossible to load an admin key where a
// node key belongs, which matters because both are 32-byte Ed25519 seeds and
// they carry very different authority.
const (
	IdentityTag  = "juist-identity-v1"
	RecipientTag = "juist-recipient-v1"
	WireGuardTag = "juist-wireguard-v1"
	NameTag      = "juist-name-v1"
	RecordTag    = "juist-record-v1"
)

// B64 is the encoding every field in a key file uses.
var B64 = base64.RawURLEncoding

// RefuseSharedWritable rejects a state directory that group or other can write
// to. Key-file modes are not enough: anyone who can write to the directory can
// replace a key file, or drop a new one into admins/, where every .key file is
// loaded and used to sign. An inherited directory is refused rather than
// silently tightened.
func RefuseSharedWritable(path string) error {
	if err := refuseWritableDir(path); err != nil {
		return err
	}
	// admins/ too: one restored from a backup keeps whatever mode it was
	// stored with, and the check on the parent does not see it. Losing admin
	// keys below quorum is unrecoverable by design.
	admins := filepath.Join(path, AdminsDir)
	if _, err := os.Stat(admins); err == nil {
		return refuseWritableDir(admins)
	}
	return nil
}

func refuseWritableDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspecting %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf(
			"%s is mode %o, writable by group or other; anyone who can write there can replace "+
				"this keystore's signing keys. Run: chmod 700 %s", path, perm, path)
	}
	return nil
}

// WriteSecret writes key material with owner-only permissions, refusing to
// overwrite: silently replacing a key is how a network loses an admin. The
// write is crash-atomic — temporary file, fsync, rename — so an interruption
// cannot leave a truncated key file at the real name. The refusal is an
// explicit existence check before the rename; this is the operator's own 0700
// directory, so the gap is not an attacker's to race.
func WriteSecret(path string, lines []string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite key material", path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspecting %s: %w", path, err)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-key-*")
	if err != nil {
		return fmt.Errorf("creating a temporary key file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()
	if err := tmp.Chmod(FileMode); err != nil {
		return fmt.Errorf("setting mode on %s: %w", tmpName, err)
	}
	if _, err := tmp.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return fmt.Errorf("writing %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("syncing %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", tmpName, path, err)
	}
	// The name is only durable once the directory entry is: a log that
	// survives a power cut while the key file it names does not is a member
	// that can never open its own epoch wrap again.
	return SyncDir(dir)
}

// SyncDir makes renames and creations in a directory durable. Without it the
// file contents survive a power loss but the name pointing at them may not.
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

// ReadTagged reads a key file and returns each tag's base64 fields, decoded. A
// repeated tag is an error: a file with two identity lines has no single
// answer to "which key is this device's".
func ReadTagged(path string) (map[string][][]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s is mode %o; key material must not be readable by others. Run: chmod 600 %s",
			path, perm, path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string][][]byte{}
	for line := range strings.Lines(string(b)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		tag := parts[0]
		if _, dup := out[tag]; dup {
			return nil, fmt.Errorf("%s: more than one %s line", path, tag)
		}
		fields := make([][]byte, 0, len(parts)-1)
		for _, field := range parts[1:] {
			v, err := B64.DecodeString(field)
			if err != nil {
				return nil, fmt.Errorf("%s: decoding a %s field: %w", path, tag, err)
			}
			fields = append(fields, v)
		}
		out[tag] = fields
	}
	return out, nil
}

// TakeFields returns a tag's fields, checking how many there are.
func TakeFields(path string, file map[string][][]byte, tag string, n int) ([][]byte, error) {
	fields, ok := file[tag]
	if !ok {
		return nil, fmt.Errorf("%s: no %s line", path, tag)
	}
	if len(fields) != n {
		return nil, fmt.Errorf("%s: %s has %d fields, want %d", path, tag, len(fields), n)
	}
	return fields, nil
}

// Missing reports whether err means a key file is simply not there, which is
// an ordinary state. A file that exists and cannot be loaded is not: reporting
// that as absence tells the operator to create keys that already exist while
// the real fault stays invisible.
func Missing(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// NestedLog reports whether a log directory contains another one. Copying a
// log with "cp -r src/log dst/log" nests it when dst/log already exists — and
// it does exist as soon as anything has opened the store, including the daemon
// whose error message asks for the copy. Nothing reads the inner directory, so
// without naming it the device simply looks like one that was never enrolled.
func NestedLog(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, LogDir))
	return err == nil && info.IsDir()
}

// A Node is everything this device needs to be a member. All three secrets
// live in one file, so replacing them is one rename: a device holding a new
// encryption key but an old WireGuard key can neither handshake nor read the
// group secret.
type Node struct {
	Identity  types.PrivateIdentity
	Recipient *secrets.PrivateKeys
	WGPrivate *ecdh.PrivateKey

	// Public is the same material as the log records it.
	Public types.NodeKeys

	// Name is the member name this device proposes at enrollment: a
	// suggestion, which the admin may change before signing. Old key files
	// carry no name line and load with it empty.
	Name string
}

// NewNode assembles a node's key material and derives its public halves.
func NewNode(id types.PrivateIdentity, recipient *secrets.PrivateKeys, wg *ecdh.PrivateKey) (*Node, error) {
	k := &Node{Identity: id, Recipient: recipient, WGPrivate: wg}
	x, m, err := recipient.Public()
	if err != nil {
		return nil, err
	}
	k.Public.X25519, k.Public.MLKEM = x, m
	if err := k.Public.WireGuard.UnmarshalBinary(wg.PublicKey().Bytes()); err != nil {
		return nil, err
	}
	return k, nil
}

// GenerateNode draws fresh key material for a device.
func GenerateNode() (*Node, error) {
	id, err := types.GenerateIdentity()
	if err != nil {
		return nil, err
	}
	recipient, err := secrets.GenerateKeys()
	if err != nil {
		return nil, err
	}
	// WireGuard static keys are Curve25519, which is what crypto/ecdh's X25519
	// produces: the public value is the scalar times the base point, in the
	// same encoding WireGuard uses.
	wg, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating a WireGuard key: %w", err)
	}
	return NewNode(id, recipient, wg)
}

// WireGuardPrivate returns the WireGuard static private key in the raw form
// the connectivity layer takes.
func (k *Node) WireGuardPrivate() [32]byte {
	var out [32]byte
	copy(out[:], k.WGPrivate.Bytes())
	return out
}

// Lines renders the key file, header first.
func (k *Node) Lines(header string) []string {
	x, m := k.Recipient.Bytes()
	lines := []string{
		"# " + header,
		"# identity  " + k.Identity.Public().String(),
		"# wireguard " + k.Public.WireGuard.String(),
		IdentityTag + " " + B64.EncodeToString(k.Identity.Seed()),
		RecipientTag + " " + B64.EncodeToString(x) + " " + B64.EncodeToString(m),
		WireGuardTag + " " + B64.EncodeToString(k.WGPrivate.Bytes()),
	}
	if k.Name != "" {
		lines = append(lines, NameTag+" "+B64.EncodeToString([]byte(k.Name)))
	}
	return lines
}

// NamedBy reports whether a member record names exactly this key set's public
// halves — the condition under which staged keys may replace live ones.
func (k *Node) NamedBy(rec *types.NodeRecord) bool {
	return rec.WireGuard == k.Public.WireGuard &&
		rec.X25519 == k.Public.X25519 &&
		rec.MLKEM == k.Public.MLKEM
}

// MaybePromote promotes whichever staged or abandoned key set the log names,
// and returns it, or nil when the log names none. lookup is the log's member
// lookup, passed as a function so this package stays out of the trust
// layer's import graph. The test is on the resulting state, not on which
// records were applied: a rotation can be authorized and still lose fork
// choice, and promoting then would cut the device off.
func MaybePromote(home string, lookup func(types.Identity) (types.NodeRecord, bool)) (*Node, error) {
	abandoned, err := filepath.Glob(filepath.Join(globEscape(home), NodeKeysFile+AbandonedSuffix+"*"))
	if err != nil {
		return nil, err
	}
	stagedPath := filepath.Join(home, NodeKeysFile+StagedSuffix)
	for _, path := range append([]string{stagedPath}, abandoned...) {
		staged, err := LoadNode(path)
		switch {
		case Missing(err):
			continue
		case err != nil && path != stagedPath:
			// A damaged archive is one rotation that can no longer be
			// adopted; it must not stop the device adopting any other.
			continue
		case err != nil:
			return nil, err
		}
		rec, ok := lookup(staged.Identity.Public())
		if !ok || !staged.NamedBy(&rec) {
			continue
		}
		if err := os.Rename(path, filepath.Join(home, NodeKeysFile)); err != nil {
			return nil, fmt.Errorf("promoting %s: %w", path, err)
		}
		return staged, SyncDir(home)
	}
	return nil, nil
}

// MaxAbandoned is how many abandoned key sets are kept. Every one is
// re-read whenever the log changes, and nothing else bounds how many an
// operator can make; a rotation abandoned this many rotations ago is
// unlikely to be approved still, and if it is, the device is removed and
// invited again.
const MaxAbandoned = 8

// Abandon archives the staged keys under a name of their own, so abandoning
// a second rotation cannot overwrite the first's keys while its record may
// still be approved. Nothing staged is nothing to do. Beyond [MaxAbandoned]
// archives, the oldest go.
func Abandon(home string) error {
	path := filepath.Join(home, NodeKeysFile+StagedSuffix)
	staged, err := LoadNode(path)
	if Missing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	id, pub := staged.Identity.Public(), staged.Public
	sum := sha256.Sum256(slices.Concat(id[:], pub.WireGuard[:], pub.X25519[:]))
	archived := filepath.Join(home, NodeKeysFile+AbandonedSuffix+"-"+hex.EncodeToString(sum[:6]))
	if err := os.Rename(path, archived); err != nil {
		return fmt.Errorf("archiving %s: %w", path, err)
	}
	if err := pruneAbandoned(home); err != nil {
		return err
	}
	return SyncDir(home)
}

func pruneAbandoned(home string) error {
	paths, err := filepath.Glob(filepath.Join(globEscape(home), NodeKeysFile+AbandonedSuffix+"*"))
	if err != nil || len(paths) <= MaxAbandoned {
		return err
	}
	type archive struct {
		path string
		mod  time.Time
	}
	var all []archive
	for _, p := range paths {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		all = append(all, archive{p, info.ModTime()})
	}
	slices.SortFunc(all, func(a, b archive) int { return a.mod.Compare(b.mod) })
	for _, a := range all[:len(all)-MaxAbandoned] {
		if err := os.Remove(a.path); err != nil {
			return fmt.Errorf("removing %s: %w", a.path, err)
		}
	}
	return nil
}

// globEscape quotes a directory for filepath.Glob.
func globEscape(dir string) string {
	var b strings.Builder
	for _, r := range dir {
		if strings.ContainsRune(`*?[\`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// LoadNode reads a node key file.
func LoadNode(path string) (*Node, error) {
	file, err := ReadTagged(path)
	if err != nil {
		return nil, err
	}
	idFields, err := TakeFields(path, file, IdentityTag, 1)
	if err != nil {
		return nil, err
	}
	id, err := types.NewPrivateIdentity(idFields[0])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	recFields, err := TakeFields(path, file, RecipientTag, 2)
	if err != nil {
		return nil, err
	}
	recipient, err := secrets.NewPrivateKeys(recFields[0], recFields[1])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	wgFields, err := TakeFields(path, file, WireGuardTag, 1)
	if err != nil {
		return nil, err
	}
	wg, err := ecdh.X25519().NewPrivateKey(wgFields[0])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	k, err := NewNode(id, recipient, wg)
	if err != nil {
		return nil, err
	}
	if nameFields, ok := file[NameTag]; ok {
		if len(nameFields) != 1 {
			return nil, fmt.Errorf("%s: %s has %d fields, want 1", path, NameTag, len(nameFields))
		}
		// Checked on the way in as well as out: this is printed to a terminal,
		// and a hand-edited file bypasses the CLI's own validation.
		if err := types.ValidateName(string(nameFields[0])); err != nil {
			return nil, fmt.Errorf("%s: %s: %w", path, NameTag, err)
		}
		k.Name = string(nameFields[0])
	}
	return k, nil
}
