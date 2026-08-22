package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nning/wg-p2p/trust/secrets"
	"github.com/nning/wg-p2p/types"
)

// Layout of a wg-p2p home directory.
//
// The split between admins/ and node.key is the one from
// docs/04-architecture.md: admin signing keys live in the operator's CLI
// keystore and never in the daemon, while the node's identity and recipient
// keys are what the daemon needs to be a member. This tool holds both because
// M1 has no daemon yet; the directories are already separate so that the
// daemon can be given one and not the other.
const (
	logDir          = "log"
	adminsDir       = "admins"
	nodeKeysFile    = "node.keys"
	stagedSuffix    = ".next"
	disablementFile = "disablement.secrets"

	// genesisFile holds a genesis record that is still collecting signatures.
	// It is not key material and not secret — it is the record every admin in
	// the ceremony has to see — so it is written like any other record
	// envelope.
	genesisFile = "genesis.rec"

	keyFileMode fs.FileMode = 0o600
	keyDirMode  fs.FileMode = 0o700
)

// Tags on key files. A tag makes it impossible to load an admin key where a
// node key belongs, which matters because both are 32-byte Ed25519 seeds and
// they carry very different authority.
const (
	identityTag  = "wgp2p-identity-v1"
	recipientTag = "wgp2p-recipient-v1"
	wireguardTag = "wgp2p-wireguard-v1"
	nameTag      = "wgp2p-name-v1"
	recordTag    = "wgp2p-record-v1"
)

var b64 = base64.RawURLEncoding

// home is a wg-p2p state directory.
type home struct{ path string }

func openHome(path string) (*home, error) {
	if err := os.MkdirAll(path, keyDirMode); err != nil {
		return nil, fmt.Errorf("creating %s: %w", path, err)
	}
	if err := refuseSharedWritable(path); err != nil {
		return nil, err
	}
	return &home{path: path}, nil
}

// refuseSharedWritable rejects a home directory that group or other can write
// to.
//
// The individual key files are 0600 and their mode is checked when they are
// read, but that is not enough: anyone who can write to the directory can
// replace a key file wholesale, or drop a new one into admins/, where every
// .key file is loaded and used to sign. trust/store already refuses a
// shared-writable log directory for the same reason — a writable directory
// undoes the protection its contents' modes provide — and leaving the keystore
// unchecked made that guarantee arbitrary.
//
// Directories this tool creates are 0700. One it inherits is refused rather
// than silently tightened, because the path is caller-supplied and quietly
// changing the mode of somebody's existing directory is worse than saying so.
func refuseSharedWritable(path string) error {
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

func (h *home) join(parts ...string) string {
	return filepath.Join(append([]string{h.path}, parts...)...)
}

// writeSecret writes key material with owner-only permissions, refusing to
// overwrite: silently replacing a key is how a network loses an admin.
func (h *home) writeSecret(name string, lines []string) error {
	path := h.join(name)
	if err := os.MkdirAll(filepath.Dir(path), keyDirMode); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, keyFileMode)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists; refusing to overwrite key material", path)
		}
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("syncing %s: %w", path, err)
	}
	return nil
}

// readTaggedFile reads a key file and returns each tag's base64 fields,
// decoded. A repeated tag is an error: a file with two identity lines has no
// single answer to "which key is this device's".
func readTaggedFile(path string) (map[string][][]byte, error) {
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
			v, err := b64.DecodeString(field)
			if err != nil {
				return nil, fmt.Errorf("%s: decoding a %s field: %w", path, tag, err)
			}
			fields = append(fields, v)
		}
		out[tag] = fields
	}
	return out, nil
}

func takeFields(path string, file map[string][][]byte, tag string, n int) ([][]byte, error) {
	fields, ok := file[tag]
	if !ok {
		return nil, fmt.Errorf("%s: no %s line", path, tag)
	}
	if len(fields) != n {
		return nil, fmt.Errorf("%s: %s has %d fields, want %d", path, tag, len(fields), n)
	}
	return fields, nil
}

// --- admin keys ------------------------------------------------------------

func (h *home) createAdminKey(name string) (types.PrivateIdentity, error) {
	priv, err := types.GenerateIdentity()
	if err != nil {
		return priv, err
	}
	err = h.writeSecret(filepath.Join(adminsDir, name+".key"), []string{
		"# wg-p2p admin signing key: " + priv.Public().String(),
		"# Keep this file secret and off the daemon's machine if you can.",
		identityTag + " " + b64.EncodeToString(priv.Seed()),
	})
	return priv, err
}

// adminKeys loads every admin key in the keystore, sorted by public key.
func (h *home) adminKeys() ([]types.PrivateIdentity, error) {
	entries, err := os.ReadDir(h.join(adminsDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", h.join(adminsDir), err)
	}
	var out []types.PrivateIdentity
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".key") {
			continue
		}
		path := h.join(adminsDir, e.Name())
		file, err := readTaggedFile(path)
		if err != nil {
			return nil, err
		}
		fields, err := takeFields(path, file, identityTag, 1)
		if err != nil {
			return nil, err
		}
		priv, err := types.NewPrivateIdentity(fields[0])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, priv)
	}
	slices.SortFunc(out, func(a, b types.PrivateIdentity) int {
		x, y := a.Public(), b.Public()
		return x.Compare(y)
	})
	return out, nil
}

// --- node keys -------------------------------------------------------------

// nodeKeys is everything this device needs to be a member.
//
// All three secrets live in one file, so replacing them is one rename. That
// matters: a device holding a new encryption key but an old WireGuard key, or
// the reverse, is a device that either cannot handshake or cannot read the
// group secret, and it would be in that state until someone noticed.
type nodeKeys struct {
	identity  types.PrivateIdentity
	recipient *secrets.PrivateKeys
	wgPrivate *ecdh.PrivateKey

	// public is the same material as the log records it.
	public types.NodeKeys

	// Name is the member name this device proposes at enrollment. It is a
	// suggestion, not a fact: the admin sees it in the AddNode record and may
	// change it before signing. Old key files carry no name line; they load
	// with Name empty and fall back to the hostname at display time.
	Name string
}

func newNodeKeys(id types.PrivateIdentity, recipient *secrets.PrivateKeys, wg *ecdh.PrivateKey) (*nodeKeys, error) {
	k := &nodeKeys{identity: id, recipient: recipient, wgPrivate: wg}
	x, m, err := recipient.Public()
	if err != nil {
		return nil, err
	}
	k.public.X25519, k.public.MLKEM = x, m
	if err := k.public.WireGuard.UnmarshalBinary(wg.PublicKey().Bytes()); err != nil {
		return nil, err
	}
	return k, nil
}

func generateNodeKeys() (*nodeKeys, error) {
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
	return newNodeKeys(id, recipient, wg)
}

func (k *nodeKeys) lines(header string) []string {
	x, m := k.recipient.Bytes()
	lines := []string{
		"# " + header,
		"# identity  " + k.identity.Public().String(),
		"# wireguard " + k.public.WireGuard.String(),
		identityTag + " " + b64.EncodeToString(k.identity.Seed()),
		recipientTag + " " + b64.EncodeToString(x) + " " + b64.EncodeToString(m),
		wireguardTag + " " + b64.EncodeToString(k.wgPrivate.Bytes()),
	}
	if k.Name != "" {
		lines = append(lines, nameTag+" "+b64.EncodeToString([]byte(k.Name)))
	}
	return lines
}

// createNodeKeys generates this device's key material and writes it.
//
// The WireGuard key is generated here even though the data plane arrives in M2,
// so that enrolling a device needs nothing but this tool. It is the one key
// that must live in process memory to be usable at all — wireguard-go cannot
// take it from a keyring — which docs/04-architecture.md notes under key
// custody.
//
// name is the member name the device proposes at enrollment; an empty name
// defaults to the hostname. The admin still sees the name in the record it
// signs and may change it.
func (h *home) createNodeKeys(name string) (*nodeKeys, error) {
	if name != "" {
		// Refuse here rather than storing it. A name the log will not accept
		// costs nothing to catch now and is expensive to catch later: the
		// device persists it, prints an enrollment command built around it,
		// and the failure lands on the admin's machine, against a limit the
		// device never mentioned.
		if err := types.ValidateName(name); err != nil {
			return nil, fmt.Errorf("member name: %w", err)
		}
	} else {
		name = defaultMemberName()
	}
	k, err := generateNodeKeys()
	if err != nil {
		return nil, err
	}
	k.Name = name
	if err := h.writeSecret(nodeKeysFile, k.lines("wg-p2p node keys")); err != nil {
		return nil, err
	}
	return k, nil
}

// stageNodeKeys writes replacement key material under a staged name, leaving
// the live keys untouched.
//
// Staging is not caution, it is correctness: until the rotation record is
// applied, the log still names the old WireGuard key and the current epoch's
// wrap is still sealed to the old recipient key. Promoting early would cut the
// device off, and the record may never be authorized at all.
func (h *home) stageNodeKeys(k *nodeKeys) error {
	staged := h.join(nodeKeysFile + stagedSuffix)
	if _, err := os.Stat(staged); err == nil {
		return fmt.Errorf(
			"%s already holds staged keys from an earlier rotation; apply that record, "+
				"or remove the file to abandon it", staged)
	}
	return h.writeSecret(nodeKeysFile+stagedSuffix, k.lines("wg-p2p node keys, staged for rotation"))
}

// rotatedKeys returns new encryption and WireGuard keys under this device's
// existing identity: a key rotation keeps the node the same node.
//
// Nothing is written. Staging is a separate step because it is the step that
// can be regretted: [home.stageNodeKeys] refuses to stage over an earlier
// rotation, so a file written for a proposal that then failed is one an
// operator has to delete by hand before any rotation can be proposed again.
// Callers stage once they hold the record the keys belong to.
func (h *home) rotatedKeys() (*nodeKeys, error) {
	cur, err := h.nodeKeys()
	if err != nil {
		return nil, err
	}
	fresh, err := generateNodeKeys()
	if err != nil {
		return nil, err
	}
	rotated, err := newNodeKeys(cur.identity, fresh.recipient, fresh.wgPrivate)
	if err != nil {
		return nil, err
	}
	rotated.Name = cur.Name
	return rotated, nil
}

// rotatedIdentity returns a new identity over this device's existing
// encryption and WireGuard keys: an identity rotation changes which member
// this is, and with it the derived overlay address, but nothing about the data
// plane. Nothing is written; see [home.rotatedKeys].
func (h *home) rotatedIdentity() (*nodeKeys, error) {
	cur, err := h.nodeKeys()
	if err != nil {
		return nil, err
	}
	id, err := types.GenerateIdentity()
	if err != nil {
		return nil, err
	}
	rotated, err := newNodeKeys(id, cur.recipient, cur.wgPrivate)
	if err != nil {
		return nil, err
	}
	rotated.Name = cur.Name
	return rotated, nil
}

// promoteStagedNodeKeys replaces the live keys with the staged ones. One
// rename, so there is no state in which the device holds half of each.
func (h *home) promoteStagedNodeKeys() error {
	staged := h.join(nodeKeysFile + stagedSuffix)
	if err := os.Rename(staged, h.join(nodeKeysFile)); err != nil {
		return fmt.Errorf("promoting %s: %w", staged, err)
	}
	return nil
}

// keyFileMissing reports whether err means a key file is simply not there.
//
// "This device has no keys" is an ordinary state: a keystore that only ever
// signs holds admin keys and nothing else, and a device with no rotation in
// flight has nothing staged. Every caller here has a sensible answer for it.
//
// A key file that exists and cannot be loaded is not that. It is readable by
// others, or truncated, or holds material this build cannot parse — and
// reporting it as absence tells the operator to create keys that are already
// there while the fault that needs fixing stays invisible.
func keyFileMissing(err error) bool { return errors.Is(err, fs.ErrNotExist) }

func (h *home) nodeKeys() (*nodeKeys, error) { return h.loadNodeKeys(nodeKeysFile) }

// defaultMemberName is the name a device proposes when the operator did not
// choose one: its hostname, if that is a name the log would accept.
//
// A hostname is not guaranteed to be one. Fully qualified names run well past
// [types.MaxNameLen], and nothing stops one carrying bytes the schema rejects.
// Falling back to no name at all is the honest outcome — "wgp2p key" then
// prints the enrollment command with a NAME placeholder, which is a question
// the operator can answer, rather than a command that fails when it is run.
func defaultMemberName() string {
	host, err := os.Hostname()
	if err != nil || types.ValidateName(host) != nil {
		return ""
	}
	return host
}

// displayName returns the member name to present at enrollment, falling back
// to the hostname for key files created before the name was persisted.
func (k *nodeKeys) displayName() string {
	if k.Name != "" {
		return k.Name
	}
	return defaultMemberName()
}

func (h *home) stagedNodeKeys() (*nodeKeys, error) {
	return h.loadNodeKeys(nodeKeysFile + stagedSuffix)
}

func (h *home) loadNodeKeys(name string) (*nodeKeys, error) {
	path := h.join(name)
	file, err := readTaggedFile(path)
	if err != nil {
		return nil, err
	}
	idFields, err := takeFields(path, file, identityTag, 1)
	if err != nil {
		return nil, err
	}
	id, err := types.NewPrivateIdentity(idFields[0])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	recFields, err := takeFields(path, file, recipientTag, 2)
	if err != nil {
		return nil, err
	}
	recipient, err := secrets.NewPrivateKeys(recFields[0], recFields[1])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	wgFields, err := takeFields(path, file, wireguardTag, 1)
	if err != nil {
		return nil, err
	}
	wg, err := ecdh.X25519().NewPrivateKey(wgFields[0])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	k, err := newNodeKeys(id, recipient, wg)
	if err != nil {
		return nil, err
	}
	if nameFields, ok := file[nameTag]; ok {
		if len(nameFields) != 1 {
			return nil, fmt.Errorf("%s: %s has %d fields, want 1", path, nameTag, len(nameFields))
		}
		// Checked on the way in as well as on the way out: this is the value
		// printed to a terminal and pasted into a command, and a file edited
		// by hand is the one path that reaches here without passing
		// createNodeKeys.
		if err := types.ValidateName(string(nameFields[0])); err != nil {
			return nil, fmt.Errorf("%s: %s: %w", path, nameTag, err)
		}
		k.Name = string(nameFields[0])
	}
	return k, nil
}

// --- record envelopes ------------------------------------------------------

// encodeRecord wraps a record's canonical CBOR in a text envelope.
//
// Text because a record travels between machines during a signing ceremony —
// mail, chat, a USB stick — and because the header lets whoever is asked to
// sign see what they are signing without a tool. Only the tagged line is read
// back; the comments are decoration and are not covered by anything.
func encodeRecord(a *types.AUM) (string, error) {
	body, err := a.Encode()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# wg-p2p record: %v\n", a.Kind)
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

// readRecordFile reads a record envelope.
//
// It accepts records that are not yet signed, because that is the state a
// record is in for as long as a quorum is being collected across machines.
// Whether a record is authorized is decided by trust/log when it is applied,
// never here.
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

func writeRecordFile(path string, a *types.AUM) error {
	text, err := encodeRecord(a)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
