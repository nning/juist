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

// Layout of a juist home directory.
//
// The split between admins/ and node.keys is the one from
// docs/04-architecture.md: admin signing keys live in the operator's CLI
// keystore and never in the daemon, while the node's identity and recipient
// keys are what the daemon needs to be a member. This tool holds both; juistd
// reads only the second, which is why the file format lives in internal/keys
// where both can share it.
const (
	logDir       = keys.LogDir
	adminsDir    = keys.AdminsDir
	nodeKeysFile = keys.NodeKeysFile
	stagedSuffix = keys.StagedSuffix

	disablementFile = "disablement.secrets"

	// genesisFile holds a genesis record that is still collecting signatures.
	// It is not key material and not secret — it is the record every admin in
	// the ceremony has to see — so it is written like any other record
	// envelope.
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
	return h.writeSecret(nodeKeysFile+stagedSuffix, k.Lines("juist node keys, staged for rotation"))
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
	rotated, err := keys.NewNode(id, cur.Recipient, cur.WGPrivate)
	if err != nil {
		return nil, err
	}
	rotated.Name = cur.Name
	return rotated, nil
}

func (h *home) nodeKeys() (*nodeKeys, error) { return keys.LoadNode(h.join(nodeKeysFile)) }

// defaultMemberName is the name a device proposes when the operator did not
// choose one: its hostname, if that is a name the log would accept.
//
// A hostname is not guaranteed to be one. Fully qualified names run well past
// [types.MaxNameLen], and nothing stops one carrying bytes the schema rejects.
// Falling back to no name at all is the honest outcome — "juist key" then
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
