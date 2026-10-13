package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/internal/waiting"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// Bounds on the changes waiting for votes a daemon holds.
const (
	maxWaiting               = 64
	maxWaitingBytes          = 32 << 20
	maxWaitingPerSigner      = 8 << 20
	maxWaitingPerSignerCount = 16

	// waitingSkew is how far ahead of this clock a change may say it was
	// handed on.
	waitingSkew = 5 * time.Minute

	// waitingResend is how soon a copy is handed again to a peer that does
	// not say what it holds, as an admin device does not to one without the
	// role.
	waitingResend = 10 * time.Minute
)

// A heldChange is one copy of a change waiting for votes, as it arrived, and
// when it was last handed to each peer that does not say what it holds.
type heldChange struct {
	c      *waiting.Change
	raw    []byte
	handed map[types.Identity]time.Time
}

// waitingAdapter presents the daemon's waiting changes as a
// [gossip.Waiting].
type waitingAdapter Daemon

var _ gossip.Waiting = (*waitingAdapter)(nil)

func (w *waitingAdapter) daemon() *Daemon { return (*Daemon)(w) }

// Held says what this device holds to an admin device, where it is one.
func (w *waitingAdapter) Held(peer types.Identity) []types.Hash {
	d := w.daemon()
	state, err := d.TrustedState()
	if err != nil || !d.adminDevice(state, d.self) || !d.adminDevice(state, peer) {
		return nil
	}
	d.waitMu.Lock()
	defer d.waitMu.Unlock()
	out := make([]types.Hash, 0, len(d.waiting))
	for h := range d.waiting {
		out = append(out, h)
	}
	slices.SortFunc(out, types.Hash.Compare)
	return out
}

// For hands a current admin device the changes it lacks, but those about it.
func (w *waitingAdapter) For(id types.Identity, held []types.Hash) [][]byte {
	d := w.daemon()
	state, err := d.TrustedState()
	if err != nil || id == d.self || !d.adminDevice(state, id) {
		return nil
	}
	now := d.now()
	d.waitMu.Lock()
	defer d.waitMu.Unlock()
	var out [][]byte
	for h, hc := range d.waiting {
		if slices.Contains(held, h) || hc.c.IsAbout(id) || hc.c.Expires <= now.Unix() {
			continue
		}
		if at, ok := hc.handed[id]; ok && held == nil && now.Sub(at) < waitingResend {
			continue
		}
		out = append(out, hc.raw)
	}
	return out
}

func (w *waitingAdapter) Handed(id types.Identity, changes [][]byte) {
	d := w.daemon()
	now := d.now()
	d.waitMu.Lock()
	defer d.waitMu.Unlock()
	for _, raw := range changes {
		if hc, ok := d.waiting[waiting.Hash(raw)]; ok {
			hc.handed[id] = now
		}
	}
}

// adminDevice reports whether id is a live member with the admin role.
func (d *Daemon) adminDevice(state *log.State, id types.Identity) bool {
	n, ok := state.Node(id)
	return ok && !n.Expired(d.now().Unix()) && n.HasRole(types.RoleAdmin)
}

func (w *waitingAdapter) Take(changes [][]byte) bool {
	added, _ := w.daemon().offerWaiting(changes, false)
	return added > 0
}

// OfferWaiting takes changes an admin on this device hands on, and reports
// why one is refused.
func (d *Daemon) OfferWaiting(changes [][]byte) error {
	added, err := d.offerWaiting(changes, true)
	if added > 0 {
		d.MarkDirty()
	}
	return err
}

// offerWaiting takes the changes that fit the log and the bounds, reporting
// how many were new, and why the last refused one was. Only an admin device
// takes them from its peers; any device takes its own admins'.
func (d *Daemon) offerWaiting(changes [][]byte, local bool) (int, error) {
	state, err := d.TrustedState()
	if err != nil {
		return 0, err
	}
	now := d.now()
	if !local && !d.adminDevice(state, d.self) {
		return 0, errors.New("this device is no admin device")
	}
	added, refused := 0, error(nil)
	defer func() {
		if added > 0 {
			d.saveWaiting()
		}
	}()
	d.waitMu.Lock()
	defer d.waitMu.Unlock()
	for _, raw := range changes {
		c, err := waiting.Decode(raw)
		if err == nil {
			err = fits(c, state, now)
		}
		if err == nil {
			err = d.holdLocked(c, raw)
		}
		switch {
		case errors.Is(err, errHeld):
		case err != nil:
			refused = err
		default:
			added++
		}
	}
	return added, refused
}

var errHeld = errors.New("held already")

// fits reports whether a change can still apply to the log as it is, handed
// on by a current admin key and not expired.
func fits(c *waiting.Change, state *log.State, now time.Time) error {
	switch {
	case c.Network != state.GenesisHash():
		return errors.New("a change to another network")
	case c.Prev != state.Head():
		return errors.New("a change that no longer fits the log")
	case c.Expires <= now.Unix():
		return errors.New("a change that has expired")
	case c.Issued > now.Add(waitingSkew).Unix():
		return errors.New("a change handed on in the future")
	}
	if _, ok := state.Admin(c.Signer); !ok {
		return fmt.Errorf("a change handed on by %v, which is no admin key", c.Signer.ShortString())
	}
	if state.PQ() {
		return c.VerifyPQ(state.SigningKey(c.Signer))
	}
	return nil
}

// holdLocked adds a change, replacing an older copy by the same signer, within
// the bounds. The caller holds waitMu.
func (d *Daemon) holdLocked(c *waiting.Change, raw []byte) error {
	h := waiting.Hash(raw)
	if _, ok := d.waiting[h]; ok {
		return errHeld
	}
	var replaces []types.Hash
	total, signer, signed := len(raw), len(raw), 1
	for held, hc := range d.waiting {
		if hc.c.ID == c.ID && hc.c.Signer == c.Signer {
			// The later copy wins, and of two alike the lower hash, so that
			// every device settles on the same one.
			if hc.c.Issued > c.Issued || hc.c.Issued == c.Issued && held.Compare(h) < 0 {
				return errHeld
			}
			replaces = append(replaces, held)
			continue
		}
		total += len(hc.raw)
		if hc.c.Signer == c.Signer {
			signer += len(hc.raw)
			signed++
		}
	}
	switch {
	case len(d.waiting)-len(replaces) >= maxWaiting:
		return fmt.Errorf("%d changes wait here already", maxWaiting)
	case total > maxWaitingBytes:
		return errors.New("the changes waiting here fill their room")
	case signer > maxWaitingPerSigner || signed > maxWaitingPerSignerCount:
		return fmt.Errorf("the changes %v handed on fill its room", c.Signer.ShortString())
	}
	for _, held := range replaces {
		delete(d.waiting, held)
	}
	d.waiting[h] = heldChange{c: c, raw: raw, handed: map[types.Identity]time.Time{}}
	return nil
}

// pruneWaiting drops the changes that no longer fit the log.
func (d *Daemon) pruneWaiting(state *log.State) {
	now := d.now()
	d.waitMu.Lock()
	dropped := false
	for h, hc := range d.waiting {
		if fits(hc.c, state, now) != nil {
			delete(d.waiting, h)
			dropped = true
		}
	}
	d.waitMu.Unlock()
	if dropped {
		d.saveWaiting()
	}
}

// Waiting returns the encoded changes waiting for votes this device holds.
func (d *Daemon) Waiting() [][]byte {
	if state, err := d.TrustedState(); err == nil {
		d.pruneWaiting(state)
	}
	d.waitMu.Lock()
	defer d.waitMu.Unlock()
	out := make([][]byte, 0, len(d.waiting))
	for _, hc := range d.waiting {
		out = append(out, hc.raw)
	}
	slices.SortFunc(out, func(a, b []byte) int { return waiting.Hash(a).Compare(waiting.Hash(b)) })
	return out
}

func (d *Daemon) loadWaiting() {
	if d.waitingPath == "" {
		return
	}
	b, err := os.ReadFile(d.waitingPath)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	var raw [][]byte
	if err == nil {
		err = waitingFileMode.Unmarshal(b, &raw)
	}
	if err != nil {
		d.logf("daemon: %s was ignored: %v", d.waitingPath, err)
		return
	}
	// Checked again as they are taken: the file grants nothing.
	if state, err := d.TrustedState(); err == nil {
		d.waitMu.Lock()
		defer d.waitMu.Unlock()
		for _, r := range raw {
			if c, err := waiting.Decode(r); err == nil && fits(c, state, d.now()) == nil {
				_ = d.holdLocked(c, r)
			}
		}
	}
}

// saveWaiting writes the held changes out, outside waitMu: the file may be
// tens of megabytes.
func (d *Daemon) saveWaiting() {
	if d.waitingPath == "" {
		return
	}
	// Serialized, and the snapshot taken inside, so a writer holding an older
	// set cannot rename over a newer one.
	d.waitSaveMu.Lock()
	defer d.waitSaveMu.Unlock()
	d.waitMu.Lock()
	raw := make([][]byte, 0, len(d.waiting))
	for _, hc := range d.waiting {
		raw = append(raw, hc.raw)
	}
	d.waitMu.Unlock()
	b, err := cbor.Marshal(raw)
	if err == nil {
		err = statedir.WriteFilePrivate(d.waitingPath, b)
	}
	if err != nil {
		d.logf("daemon: writing %s: %v", d.waitingPath, err)
	}
}

var waitingFileMode = func() cbor.DecMode {
	m, err := cbor.DecOptions{MaxArrayElements: maxWaiting}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()
