package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/nning/juist/internal/statedir"

	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

// Layout of a juist home directory. Admin signing keys live in admins/ and
// never reach the daemon; node.keys is what makes this device a member. This
// tool holds both, juistd reads only the second, and internal/keys is where
// they share the format.
const (
	logDir       = keys.LogDir
	adminsDir    = keys.AdminsDir
	nodeKeysFile = keys.NodeKeysFile
	stagedSuffix = keys.StagedSuffix

	keyFileMode fs.FileMode = keys.FileMode
	keyDirMode  fs.FileMode = keys.DirMode
)

// Tags on key files, re-exported at their old names for readability at the
// call sites in this package.
const (
	identityTag = keys.IdentityTag
	nameTag     = keys.NameTag
	recordTag   = keys.RecordTag
)

var b64 = keys.B64

// nodeKeys is this device's key material; see [keys.Node].
type nodeKeys = keys.Node

// home is a juist state directory.
type home struct{ path string }

func openHome(path string) (*home, error) {
	if err := os.MkdirAll(path, keyDirMode); err != nil {
		return nil, fmt.Errorf("creating %s: %w", path, err)
	}
	if err := keys.RefuseSharedWritable(path); err != nil {
		return nil, err
	}
	return &home{path: path}, nil
}

func (h *home) join(parts ...string) string {
	return filepath.Join(append([]string{h.path}, parts...)...)
}

func (h *home) writeSecret(name string, lines []string) error {
	if statedir.HomeInUse(h.path) {
		return fmt.Errorf("%s is juistd's state directory, not a keystore\nhint: drop --home", h.path)
	}
	return keys.WriteSecret(h.join(name), lines)
}

// --- admin keys ------------------------------------------------------------

// An adminKeyFile is an admin key under its file's name: "alice@home" for one
// filed under its network, and "alice" for one from before keys were named
// for networks, or one made before its network, which is unfiled.
type adminKeyFile struct {
	name    string
	priv    types.PrivateIdentity
	unfiled bool
}

// network is the network the key is filed under, "" for none.
func (k adminKeyFile) network() string {
	_, network, _ := strings.Cut(k.name, "@")
	return network
}

// adminKeyName names the key person holds for network: from the name it had
// then, so that a rename moves nothing.
func adminKeyName(person, network string) string {
	if network == "" {
		return person
	}
	return person + "@" + fileSafe(network)
}

// keyPersonOf is the admin an admin key's file is named for.
func keyPersonOf(name string) string {
	person, _, _ := strings.Cut(name, "@")
	return person
}

func checkKeyName(name string) error {
	if name == "" || strings.ContainsAny(name, `/\`) || strings.HasPrefix(name, ".") {
		return fmt.Errorf("%q cannot name an admin key file", name)
	}
	return nil
}

func adminKeyLines(priv types.PrivateIdentity, unfiled bool) []string {
	lines := []string{
		"# juist admin signing key: " + priv.Public().String(),
		"# Keep this file secret and off the daemon's machine if you can.",
		identityTag + " " + b64.EncodeToString(priv.Seed()),
	}
	if unfiled {
		lines = append(lines, keys.UnfiledTag)
	}
	return lines
}

// createAdminKey creates the admin key name; an unfiled one is filed under
// the first network whose log names it.
func (h *home) createAdminKey(name string, unfiled bool) (types.PrivateIdentity, error) {
	if err := checkKeyName(name); err != nil {
		return types.PrivateIdentity{}, err
	}
	priv, err := types.GenerateIdentity()
	if err != nil {
		return priv, err
	}
	return priv, h.writeSecret(filepath.Join(adminsDir, name+".key"), adminKeyLines(priv, unfiled))
}

// adminKeyFiles loads every admin key in the keystore, by name.
func (h *home) adminKeyFiles() ([]adminKeyFile, error) {
	files, err := h.loadAdminKeyFiles()
	// An unfiled key beside its filed copy is a filing cut short.
	filed := map[types.Identity]bool{}
	for _, k := range files {
		if !k.unfiled {
			filed[k.priv.Public()] = true
		}
	}
	return slices.DeleteFunc(files, func(k adminKeyFile) bool { return k.unfiled && filed[k.priv.Public()] }), err
}

func (h *home) loadAdminKeyFiles() ([]adminKeyFile, error) {
	entries, err := os.ReadDir(h.join(adminsDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", h.join(adminsDir), err)
	}
	var out []adminKeyFile
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".key")
		if e.IsDir() || !ok {
			continue
		}
		priv, unfiled, err := loadAdminKey(h.join(adminsDir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, adminKeyFile{name: name, priv: priv, unfiled: unfiled})
	}
	return out, nil
}

// adminKeys loads every admin key in the keystore, sorted by public key.
func (h *home) adminKeys() ([]types.PrivateIdentity, error) {
	files, err := h.adminKeyFiles()
	if err != nil {
		return nil, err
	}
	return privateKeys(files), nil
}

func privateKeys(files []adminKeyFile) []types.PrivateIdentity {
	var out []types.PrivateIdentity
	for _, k := range files {
		out = append(out, k.priv)
	}
	slices.SortFunc(out, func(a, b types.PrivateIdentity) int {
		x, y := a.Public(), b.Public()
		return x.Compare(y)
	})
	return out
}

// adminKey loads the admin key called name, if the keystore has one.
func (h *home) adminKey(name string) (types.PrivateIdentity, bool, error) {
	if err := checkKeyName(name); err != nil {
		return types.PrivateIdentity{}, false, err
	}
	priv, _, err := loadAdminKey(h.join(adminsDir, name+".key"))
	if keys.Missing(err) {
		return types.PrivateIdentity{}, false, nil
	}
	return priv, err == nil, err
}

// fileAdminKeys files each unfiled key that governs network under it. It is
// best effort: a key left unfiled signs all the same.
func (h *home) fileAdminKeys(network string, governs func(types.Identity) bool) {
	// Another user's keystore, as a person's is to root under sudo: a key
	// filed there would be one they cannot read.
	if !ownedByUs(h.join(adminsDir)) {
		return
	}
	files, err := h.loadAdminKeyFiles()
	if err != nil {
		return
	}
	filed := map[types.Identity]bool{}
	for _, k := range files {
		if !k.unfiled {
			filed[k.priv.Public()] = true
		}
	}
	for _, k := range files {
		id := k.priv.Public()
		if !k.unfiled || !filed[id] && !governs(id) {
			continue
		}
		if !filed[id] {
			name := adminKeyName(k.name, network)
			if h.writeSecret(filepath.Join(adminsDir, name+".key"), adminKeyLines(k.priv, false)) != nil {
				continue
			}
			filed[id] = true
		}
		_ = os.Remove(h.join(adminsDir, k.name+".key"))
	}
}

func loadAdminKey(path string) (priv types.PrivateIdentity, unfiled bool, err error) {
	file, err := keys.ReadTagged(path)
	if err != nil {
		return priv, false, err
	}
	fields, err := keys.TakeFields(path, file, identityTag, 1)
	if err != nil {
		return priv, false, err
	}
	if priv, err = types.NewPrivateIdentity(fields[0]); err != nil {
		return priv, false, fmt.Errorf("%s: %w", path, err)
	}
	_, unfiled = file[keys.UnfiledTag]
	return priv, unfiled, nil
}

// foundedFile marks a network founded from this keystore; genesisFileFor holds
// its genesis record while that collects signatures: not secret, since every
// admin in the ceremony has to see it; breakGlassFile holds the break-glass
// secrets of a network that has such a file. All are per network, so one
// keystore can found several.
func foundedFile(network string) string { return "founded-" + fileSafe(network) }

func breakGlassFile(network string) string { return "break-glass-" + fileSafe(network) + ".secrets" }

func genesisFileFor(network string) string { return "genesis-" + fileSafe(network) + ".rec" }

// --- node keys -------------------------------------------------------------

// createNodeKeys generates this device's key material and writes it. name is
// the member name it proposes at enrollment, defaulting to the hostname; the
// admin sees it in the record they sign and may change it.
func (h *home) createNodeKeys(name string) (*nodeKeys, error) {
	if name != "" {
		// Refuse here rather than storing it: otherwise the failure lands on
		// the admin's machine, against a limit this device never mentioned.
		if err := checkName("member name", name); err != nil {
			return nil, err
		}
	} else {
		name = defaultMemberName()
	}
	k, err := keys.GenerateNode()
	if err != nil {
		return nil, err
	}
	k.Name = name
	if err := h.writeSecret(nodeKeysFile, k.Lines("juist node keys")); err != nil {
		return nil, err
	}
	return k, nil
}

// canStageNodeKeys reports whether staging would be refused, without writing
// anything. A rotation asks this before it builds the record and stages after
// it has emitted one, so that a refusal is never delivered to an operator who
// is already holding a record naming keys this device did not keep.
func (h *home) canStageNodeKeys() error {
	staged := h.join(nodeKeysFile + stagedSuffix)
	if _, err := os.Stat(staged); err == nil {
		return fmt.Errorf("%s: an earlier rotation is staged\nhint: apply its record, or juist rotate abandon", staged)
	}
	return nil
}

// stageNodeKeys writes replacement key material under a staged name, leaving
// the live keys untouched. Until the rotation record applies, the log still
// names the old keys, so promoting early would cut the device off — and the
// record may never be authorized at all.
func (h *home) stageNodeKeys(k *nodeKeys) error {
	// Re-checked rather than trusted from [home.canStageNodeKeys]: this is the
	// call that must not write over key material, whoever asked for it.
	if err := h.canStageNodeKeys(); err != nil {
		return err
	}
	return h.writeSecret(nodeKeysFile+stagedSuffix, k.Lines("juist node keys, staged for rotation"))
}

// rotatedKeys returns new encryption and WireGuard keys under this device's
// existing identity: a key rotation keeps the node the same node. Nothing is
// written, because staging is the step that can be regretted —
// [home.stageNodeKeys] refuses to stage over an earlier rotation, so a file
// written for a failed proposal must be deleted by hand.
func (h *home) rotatedKeys() (*nodeKeys, error) {
	cur, err := h.nodeKeys()
	if err != nil {
		return nil, err
	}
	fresh, err := keys.GenerateNode()
	if err != nil {
		return nil, err
	}
	rotated, err := keys.NewNode(cur.Identity, fresh.Recipient, fresh.WGPrivate)
	if err != nil {
		return nil, err
	}
	rotated.Name = cur.Name
	return rotated, nil
}

// rotatedIdentity returns a new identity over this device's existing
// encryption and WireGuard keys: it changes which member this is, and its
// derived address, but nothing about the data plane. Nothing is written.
func (h *home) rotatedIdentity() (*nodeKeys, error) {
	cur, err := h.nodeKeys()
	if err != nil {
		return nil, err
	}
	id, err := types.GenerateIdentity()
	if err != nil {
		return nil, err
	}
	rotated, err := keys.NewNode(id, cur.Recipient, cur.WGPrivate)
	if err != nil {
		return nil, err
	}
	rotated.Name = cur.Name
	return rotated, nil
}

func (h *home) nodeKeys() (*nodeKeys, error) { return keys.LoadNode(h.join(nodeKeysFile)) }

// optionalNodeKeys is nodeKeys for callers to whom a device without keys is an
// ordinary state: it returns nil for absent keys, and an error only for keys
// that are there and cannot be loaded, which must never pass for "no keys".
func (h *home) optionalNodeKeys() (*nodeKeys, error) {
	k, err := h.nodeKeys()
	if keys.Missing(err) {
		return nil, nil
	}
	return k, err
}

// defaultMemberName is the name a device proposes when the operator did not
// choose one: its hostname, if the log would accept it. A fully qualified name
// can run past [types.MaxNameLen]; with none, the inviting admin names it.
func defaultMemberName() string {
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	return memberName(host)
}

// displayName returns the member name to present at enrollment, falling back
// to the hostname for key files created before the name was persisted.
func displayName(k *nodeKeys) string {
	if k.Name != "" {
		return k.Name
	}
	return defaultMemberName()
}

func (h *home) stagedNodeKeys() (*nodeKeys, error) {
	return keys.LoadNode(h.join(nodeKeysFile + stagedSuffix))
}

// --- record envelopes ------------------------------------------------------

// encodeRecord wraps a record's canonical CBOR in a text envelope: records
// travel between machines by mail or chat during a ceremony, and the header
// shows what is being signed without a tool. Only the tagged line is read
// back; the comments are covered by nothing.
func encodeRecord(a *types.AUM) (string, error) {
	body, err := a.Encode()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# juist record: %v\n", a.Kind)
	if a.Prev != nil {
		fmt.Fprintf(&b, "# parent:    %v\n", *a.Prev)
	}
	fmt.Fprintf(&b, "# signers:   %d\n", len(a.Signatures))
	for _, sig := range a.Signatures {
		fmt.Fprintf(&b, "#            %v\n", sig.KeyID)
	}
	fmt.Fprintf(&b, "%s %s\n", recordTag, b64.EncodeToString(body))
	return b.String(), nil
}

// readRecordFile reads a record envelope, including unsigned ones: that is the
// state a record is in while a quorum is collected. Authorization is decided
// by trust/log when the record is applied, never here.
func readRecordFile(path string) (types.AUM, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return types.AUM{}, err
	}
	for line := range strings.Lines(string(b)) {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, recordTag+" ") {
			continue
		}
		raw, err := b64.DecodeString(strings.TrimPrefix(line, recordTag+" "))
		if err != nil {
			return types.AUM{}, fmt.Errorf("%s: decoding the record: %w", path, err)
		}
		// Decoding validates: a file that is not the canonical encoding of a
		// structurally valid record is rejected here rather than after a
		// ceremony has been spent on it.
		aum, err := types.DecodeUnsignedAUM(raw)
		if err != nil {
			return types.AUM{}, fmt.Errorf("%s: %w", path, err)
		}
		return aum, nil
	}
	return types.AUM{}, fmt.Errorf("%s: no %s line", path, recordTag)
}

// writeRecordFile replaces a record file with the record as it is now,
// through a fresh temporary file and a rename: a record file often sits in a
// directory others can write to, and writing in place would follow a symlink
// planted under its name.
func writeRecordFile(path string, a *types.AUM) error {
	text, err := encodeRecord(a)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	defer os.Remove(f.Name()) // a no-op once renamed
	err = f.Chmod(0o644)
	if err == nil {
		_, err = f.WriteString(text)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// writeNewRecordFile writes a record to a path that must not already exist. A
// record collects signatures in place, so overwriting one silently discards
// the ceremony it was holding.
func writeNewRecordFile(path string, a *types.AUM) error {
	text, err := encodeRecord(a)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s exists; a change still collecting approvals? %w", path, err)
	}
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if _, err := f.WriteString(text); err != nil {
		// Removed rather than left truncated: half a record is not a record,
		// and the next attempt would refuse the path it left behind.
		f.Close()
		os.Remove(path)
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// --- the log ---------------------------------------------------------------

// openAuthorityAllowingNone opens the log, treating "there is no network here"
// as a result rather than an error. Only that: a store that fails to open is
// an error, or a damaged log becomes a device that never had one.
//
// A home without a log directory has no network, and reading it creates
// none: an empty store would make the home look like a device of its own.
func (h *home) openAuthorityAllowingNone() (*store.Dir, *log.Authority, bool, error) {
	if _, err := os.Stat(h.join(logDir)); keys.Missing(err) {
		return nil, nil, false, nil
	}
	st, err := store.Open(h.join(logDir))
	if err != nil {
		return nil, nil, false, err
	}
	if _, ok, err := st.Anchor(); err != nil {
		return nil, nil, false, err
	} else if !ok {
		return st, nil, false, nil
	}
	auth, err := log.Open(st)
	if err != nil {
		return nil, nil, false, err
	}
	return st, auth, true, nil
}

// ownedByUs reports whether this process's user owns path.
func ownedByUs(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
