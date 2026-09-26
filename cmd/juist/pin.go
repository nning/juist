package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// The keystore's own anchor on each network it has seen through a daemon.
//
// The daemon is the less trusted side of the socket, and without an anchor
// of its own the CLI could only check that the log a daemon hands it is
// consistent in itself. A compromised juistd could then answer with a
// counterfeit: a checkpoint signed by keys of its own that claims the real
// network's genesis hash, or a network of its own altogether. The admin
// would approve against it, and a device invited from it would be anchored
// in it for good.
//
// So the keystore remembers, per network, the head it last verified, and per
// daemon socket which network it held. A later log must contain that head —
// or, if the head lost fork choice since, as it does to a concurrent
// removal, the daemon must hand over the branch it lost on, and this side's
// own fork choice over the chain and that branch must pick the same winner.
// A daemon that truncated the log to an older head fails that: the later
// history it left out would win. A daemon that turns up holding another
// network is refused until the person says so, by deleting the file that
// names the old one.
const pinsDir = "networks"

// A pin is what the keystore last verified of one network.
type pin struct {
	Head types.Hash `cbor:"1,keyasint"`
}

func (h *home) pinPath(genesis types.Hash) string {
	return h.join(pinsDir, fmt.Sprintf("%x", genesis[:]))
}

// daemonPinnedNetwork is the network this keystore last saw the daemon at
// sock hold, if it recorded one.
func (h *home) daemonPinnedNetwork(sock string) (types.Hash, bool) {
	b, err := os.ReadFile(h.daemonPinPath(sock))
	if err != nil {
		return types.Hash{}, false
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != len(types.Hash{}) {
		return types.Hash{}, false
	}
	return types.Hash(raw), true
}

// daemonPinPath names the file recording which network a daemon socket held,
// by a hash of the socket's absolute path: one name per socket, whatever
// characters its path has.
func (h *home) daemonPinPath(sock string) string {
	if abs, err := filepath.Abs(sock); err == nil {
		sock = abs
	}
	sum := sha256.Sum256([]byte(sock))
	return h.join(pinsDir, "daemon-"+hex.EncodeToString(sum[:12]))
}

func (h *home) loadPin(genesis types.Hash) (*pin, error) {
	b, err := os.ReadFile(h.pinPath(genesis))
	if keys.Missing(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p pin
	if err := cbor.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("%s damaged: %w\nhint: delete it to trust the log afresh", h.pinPath(genesis), err)
	}
	return &p, nil
}

// checkPin refuses a verified log that does not continue what this keystore
// last verified of its network through the daemon at sock, and remembers it
// otherwise. orphans fetches the daemon's records off the active chain, which
// is asked for only when the pinned head is not on it.
func (h *home) checkPin(sock string, auth *log.Authority, records []types.AUM,
	orphans func() ([]types.AUM, error)) error {
	state := auth.State()
	genesis := state.GenesisHash()
	dpath := h.daemonPinPath(sock)
	if b, err := os.ReadFile(dpath); err == nil {
		if held := strings.TrimSpace(string(b)); held != fmt.Sprintf("%x", genesis[:]) {
			return fmt.Errorf("juistd at %s now holds network %q, not the %s… this keystore saw; juistd may be "+
				"compromised\nhint: if this device switched networks, delete %s", sock, state.Network(), short(held), dpath)
		}
	} else if !keys.Missing(err) {
		return err
	}
	p, err := h.loadPin(genesis)
	if err != nil {
		return err
	}
	if p != nil {
		chain, err := auth.Chain()
		if err != nil {
			return err
		}
		if !slices.Contains(chain, p.Head) {
			lost, err := lostForkChoice(p.Head, auth, records, orphans)
			if err != nil {
				return fmt.Errorf("juistd's log for %q lacks the head this keystore verified, and does not "+
					"say where it went: %w", state.Network(), err)
			}
			if !lost {
				return fmt.Errorf("juistd's log for %q does not continue the one this keystore verified "+
					"(head %v); juistd is behind, or compromised\nhint: retry once it caught up; to accept "+
					"the change, delete %s", state.Network(), short(p.Head.String()), h.pinPath(genesis))
			}
		}
	}
	next := pin{Head: auth.Head()}
	b, err := cbor.Marshal(next)
	if err != nil {
		return err
	}
	if err := h.pinsReady(); err != nil {
		return err
	}
	if err := writeFileAtomic(h.pinPath(genesis), b); err != nil {
		return err
	}
	return writeFileAtomic(dpath, []byte(fmt.Sprintf("%x\n", genesis[:])))
}

// pinsReady creates the pins directory, and refuses one others could write
// to: a pin anyone can replace anchors nothing.
func (h *home) pinsReady() error {
	dir := h.join(pinsDir)
	if err := os.MkdirAll(dir, keyDirMode); err != nil {
		return err
	}
	return keys.RefuseSharedWritable(dir)
}

// expectNetwork records that the daemon at sock is to hold the network with
// this genesis — the one just created through it — so that the first log it
// hands back is held to it rather than trusted on first sight.
func (h *home) expectNetwork(sock string, genesis types.Hash) error {
	if err := h.pinsReady(); err != nil {
		return err
	}
	// The genesis itself is the first head: a log that does not contain it
	// is not this network, whatever genesis hash it claims.
	b, err := cbor.Marshal(pin{Head: genesis})
	if err != nil {
		return err
	}
	if err := writeFileAtomic(h.pinPath(genesis), b); err != nil {
		return err
	}
	return writeFileAtomic(h.daemonPinPath(sock), []byte(fmt.Sprintf("%x\n", genesis[:])))
}

// expectAdmitted is [home.expectNetwork] for a join by a link that names its
// admin: the log the daemon at sock hands back is held to the network, and
// to a head on it, that the admin signed this device's admission into.
// Otherwise the first log would be trusted on sight, and a juistd
// compromised before it could have the keystore anchor a network of its own,
// in which its admins' signatures would then admit whoever it liked.
//
// A pin this keystore already holds for the network stays: it was verified
// here, and may be later than the admission.
func (h *home) expectAdmitted(sock string, admin types.Identity, a *enroll.Admission, self types.Identity) error {
	// The admission is of this device: an older one of another device by the
	// same admin would anchor the keystore at its older head.
	if a == nil || a.Admin != admin || a.Verify() != nil || a.Guest != self {
		return errors.New("juistd returned no admission by the link's admin; log not trusted, juistd may be " +
			"compromised")
	}
	if err := h.pinsReady(); err != nil {
		return err
	}
	p, err := h.loadPin(a.Network)
	if err != nil {
		return err
	}
	if p == nil {
		b, err := cbor.Marshal(pin{Head: a.Head})
		if err != nil {
			return err
		}
		if err := writeFileAtomic(h.pinPath(a.Network), b); err != nil {
			return err
		}
	}
	return writeFileAtomic(h.daemonPinPath(sock), []byte(fmt.Sprintf("%x\n", a.Network[:])))
}

// lostForkChoice reports whether head is on a branch that fork choice, run
// here over the chain and the daemon's orphaned records, rejects in favour of
// the chain the daemon holds: the only way a verified head may drop out of a
// log without that log being a rollback.
//
// It errs only where the daemon's orphans could not be had.
func lostForkChoice(head types.Hash, auth *log.Authority, chain []types.AUM,
	orphans func() ([]types.AUM, error)) (bool, error) {
	extra, err := orphans()
	if err != nil {
		return false, err
	}
	if len(extra) > maxOrphans {
		return false, nil
	}
	mem := log.NewMemStorage()
	redo, err := log.FromRecords(mem, chain)
	if err != nil {
		return false, nil
	}
	// Informed at once, parents first: the orphans come in no particular
	// order, and one resolution of the whole set costs what the log's own
	// bounds allow, where a pass per branch depth would not.
	if redo.Inform(parentsFirst(chain, extra)...) != nil {
		return false, nil
	}
	if _, err := mem.AUM(head); err != nil {
		return false, nil // the daemon did not show where the head went
	}
	return redo.Head() == auth.Head(), nil
}

// maxOrphans is as many records off the chain as the daemon sends; more is
// not an honest daemon's answer.
const maxOrphans = 4096

// parentsFirst orders records so that each follows its parent, starting from
// the chain; a record that does not descend from it is left out.
func parentsFirst(chain, records []types.AUM) []types.AUM {
	children := map[types.Hash][]types.AUM{}
	for _, r := range records {
		if r.Prev != nil {
			children[*r.Prev] = append(children[*r.Prev], r)
		}
	}
	var queue []types.Hash
	for i := range chain {
		queue = append(queue, chain[i].Hash())
	}
	var out []types.AUM
	seen := map[types.Hash]bool{}
	for len(queue) > 0 {
		h := queue[0]
		queue = queue[1:]
		for _, c := range children[h] {
			if ch := c.Hash(); !seen[ch] {
				seen[ch] = true
				out = append(out, c)
				queue = append(queue, ch)
			}
		}
	}
	return out
}

// writeFileAtomic writes a small file owner-only through a fresh temporary
// file and a rename.
func writeFileAtomic(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return errors.Join(err, os.Remove(f.Name()))
	}
	return keys.SyncDir(filepath.Dir(path))
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
