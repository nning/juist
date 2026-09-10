package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nning/juist/internal/keys"
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

	disablementFile = "disablement.secrets"

	// genesisFile holds a genesis record still collecting signatures. Not
	// secret — every admin in the ceremony has to see it.
	genesisFile = "genesis.rec"

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
	return keys.WriteSecret(h.join(name), lines)
}

// --- admin keys ------------------------------------------------------------

func (h *home) createAdminKey(name string) (types.PrivateIdentity, error) {
	priv, err := types.GenerateIdentity()
	if err != nil {
		return priv, err
	}
	err = h.writeSecret(filepath.Join(adminsDir, name+".key"), []string{
		"# juist admin signing key: " + priv.Public().String(),
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
		file, err := keys.ReadTagged(path)
		if err != nil {
			return nil, err
		}
		fields, err := keys.TakeFields(path, file, identityTag, 1)
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

// createNodeKeys generates this device's key material and writes it. name is
// the member name it proposes at enrollment, defaulting to the hostname; the
// admin sees it in the record they sign and may change it.
func (h *home) createNodeKeys(name string) (*nodeKeys, error) {
	if name != "" {
		// Refuse here rather than storing it: otherwise the failure lands on
		// the admin's machine, against a limit this device never mentioned.
		if err := types.ValidateName(name); err != nil {
			return nil, fmt.Errorf("member name: %w", err)
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
		return fmt.Errorf(
			"%s already holds staged keys from an earlier rotation; apply that record, "+
				"or remove the file to abandon it", staged)
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

// defaultMemberName is the name a device proposes when the operator did not
// choose one: its hostname, if the log would accept it. A fully qualified name
// can run past [types.MaxNameLen], and falling back to none leaves "juist key"
// printing a NAME placeholder rather than a command that fails.
func defaultMemberName() string {
	host, err := os.Hostname()
	if err != nil || types.ValidateName(host) != nil {
		return ""
	}
	return host
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
		return fmt.Errorf("%s already exists; it may be a record still collecting "+
			"signatures, so pick another path or remove it deliberately", path)
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
