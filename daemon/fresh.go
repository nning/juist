package daemon

import (
	"cmp"
	"errors"
	"io/fs"
	"os"
	"slices"
	"time"

	"github.com/nning/juist/internal/statedir"

	"github.com/nning/juist/ipc"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

const (
	// DefaultFreshnessTTL is how long a node acts on its view of the network
	// after the threshold of admin devices last vouched for it. It is the bound on how long
	// a partitioned node can miss a removal: the knob docs/02-threat-model.md
	// names, and one the acceptor sets.
	DefaultFreshnessTTL = 48 * time.Hour

	// DefaultLeaseInterval is how often an admin device vouches.
	DefaultLeaseInterval = time.Hour
)

// offerLeases takes leases from a peer or from this node, keeping the newest
// per signer among those that vouch for this node's state now. A lease naming
// a head this node does not hold yet is dropped rather than kept: the peer
// resends it every session, by which time the records have arrived.
//
// Checking a lease against the log takes authMu, which reconciliation and
// IPC also need, and anyone holding a group secret can send a frame of them,
// so the cheap tests come first: only the newest lease per signer in a frame
// is looked at, and the one already held is not checked again.
func (d *Daemon) offerLeases(raw [][]byte) {
	now := d.now().Unix()
	newest := map[types.Identity]types.Lease{}
	for _, b := range raw {
		l, err := types.DecodeLease(b)
		if err != nil {
			continue
		}
		if cur, ok := newest[l.Signer]; !ok || l.Issued > cur.Issued {
			newest[l.Signer] = l
		}
	}
	changed := false
	for _, l := range newest {
		d.leaseMu.Lock()
		held, ok := d.leases[l.Signer]
		d.leaseMu.Unlock()
		if ok && sameLease(&held, &l) {
			continue
		}
		d.authMu.Lock()
		err := d.authority.CheckLease(&l, now)
		// A held lease that no longer vouches — dated ahead by a clock since
		// corrected, say — must not shadow a current one.
		shadowed := err == nil && ok && held.Issued >= l.Issued && d.authority.CheckLease(&held, now) == nil
		d.authMu.Unlock()
		if err != nil || shadowed {
			continue
		}
		d.leaseMu.Lock()
		// Another session may have stored a newer one since held was read.
		if cur, ok := d.leases[l.Signer]; !ok || cur == held || cur.Issued < l.Issued {
			d.leases[l.Signer] = l
			changed = true
		}
		d.leaseMu.Unlock()
	}
	if changed {
		d.saveLeases()
		d.MarkDirty()
	}
}

// encodedLeases returns the held leases for a peer, newest first.
func (d *Daemon) encodedLeases() [][]byte {
	held := d.heldLeases()
	slices.SortFunc(held, func(a, b types.Lease) int { return cmp.Compare(b.Issued, a.Issued) })
	out := make([][]byte, 0, len(held))
	for i := range held {
		if b, err := held[i].Encode(); err == nil {
			out = append(out, b)
		}
		if len(out) == gossip.MaxLeasesPerFrame {
			break
		}
	}
	return out
}

func (d *Daemon) heldLeases() []types.Lease {
	d.leaseMu.Lock()
	defer d.leaseMu.Unlock()
	out := make([]types.Lease, 0, len(d.leases))
	for _, l := range d.leases {
		out = append(out, l)
	}
	return out
}

// maybeIssueLease vouches for this node's state if it is an admin device and
// its last lease is due for renewal or names an older head.
//
// A node stopped at a schema upgrade it does not implement holds a chain that
// ends before the upgrade, and every removal after it is one it cannot see.
// Vouching for that head would keep every other node on it fresh for as long
// as the admin device runs the old build, so it vouches for nothing and takes
// back its own lease: nodes that were not upgraded go stale one TTL later,
// which is the direction to fail in.
func (d *Daemon) maybeIssueLease(state *log.State, now time.Time) {
	d.authMu.Lock()
	schema := d.authority.SchemaAlarm()
	d.authMu.Unlock()
	if schema != nil {
		d.leaseMu.Lock()
		_, held := d.leases[d.self]
		delete(d.leases, d.self)
		d.leaseMu.Unlock()
		if held {
			d.saveLeases()
		}
		return
	}
	signer := false
	for _, n := range state.LeaseSigners(now.Unix()) {
		if n.Identity == d.self {
			signer = true
		}
	}
	if !signer {
		return
	}
	d.leaseMu.Lock()
	last, held := d.leases[d.self]
	d.leaseMu.Unlock()
	issued := time.Unix(int64(last.Issued), 0)
	if held && last.Head == state.Head() && !issued.After(now) && now.Sub(issued) < d.leaseEvery {
		return
	}
	// Strictly after the last one, which a head that moved within the same
	// second — or while the last is dated ahead within the allowed skew —
	// would otherwise not replace.
	stamp := uint64(now.Unix())
	if held && last.Issued >= stamp && last.Issued-stamp < log.MaxLeaseSkew {
		stamp = last.Issued + 1
	}
	l := types.Lease{Network: state.GenesisHash(), Head: state.Head(), Issued: stamp}
	if err := l.Sign(d.identity, state.PQ()); err != nil {
		d.logf("daemon: signing a freshness lease: %v", err)
		return
	}
	b, err := l.Encode()
	if err != nil {
		d.logf("daemon: encoding a freshness lease: %v", err)
		return
	}
	d.offerLeases([][]byte{b})
}

// pruneLeases drops held leases that vouch for nothing now: a signer that
// lost the role, a head that is not on the chain, a date too far ahead —
// which would count once the clock caught up, but so will its signer's next
// lease. Under an alarm nothing is pruned, since nothing checks.
func (d *Daemon) pruneLeases(now time.Time) {
	held := d.heldLeases()
	var drop []types.Lease
	d.authMu.Lock()
	if d.authority.Alarm() == nil {
		for i := range held {
			if d.authority.CheckLease(&held[i], now.Unix()) != nil {
				drop = append(drop, held[i])
			}
		}
	}
	d.authMu.Unlock()
	if len(drop) == 0 {
		return
	}
	d.leaseMu.Lock()
	for _, l := range drop {
		// Only the lease that was checked: a session may have stored its
		// signer's next one since.
		if d.leases[l.Signer] == l {
			delete(d.leases, l.Signer)
		}
	}
	d.leaseMu.Unlock()
	d.saveLeases()
}

// freshness is what the held leases say about this node's state now.
func (d *Daemon) freshness(now time.Time) log.Freshness {
	held := d.heldLeases()
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return d.authority.Freshness(held, now.Unix(), int64(d.ttl/time.Second))
}

func (d *Daemon) loadLeases() {
	if d.leasePath == "" {
		return
	}
	b, err := os.ReadFile(d.leasePath)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		d.logf("daemon: reading %s: %v", d.leasePath, err)
		return
	}
	raw, err := statedir.DecodeLeaseFile(b)
	if err != nil {
		// A hint that does not decode costs freshness until the next lease
		// arrives, which is the fail-closed direction.
		d.logf("daemon: %s did not decode and was ignored: %v", d.leasePath, err)
		return
	}
	d.leaseMu.Lock()
	defer d.leaseMu.Unlock()
	for _, r := range raw {
		l, err := types.DecodeLease(r)
		if err != nil {
			continue
		}
		if held, ok := d.leases[l.Signer]; !ok || held.Issued < l.Issued {
			d.leases[l.Signer] = l
		}
	}
}

func (d *Daemon) saveLeases() {
	if d.leasePath == "" {
		return
	}
	// Serialized, and the snapshot taken inside, so a writer holding an older
	// set cannot rename over a newer one.
	d.leaseSaveMu.Lock()
	defer d.leaseSaveMu.Unlock()
	b, err := statedir.EncodeLeaseFile(d.encodedLeases())
	if err != nil {
		d.logf("daemon: encoding leases: %v", err)
		return
	}
	if err := statedir.WriteFilePrivate(d.leasePath, b); err != nil {
		d.logf("daemon: writing %s: %v", d.leasePath, err)
	}
}

// bootstrapHints is what a new member is handed at enrollment: every
// announcement this node holds for a member, its own included, and its leases.
func (d *Daemon) bootstrapHints() *ipc.Bootstrap {
	var eps [][]byte
	if mine, ok := d.announcement(); ok {
		if b, err := mine.Encode(); err == nil {
			eps = append(eps, b)
		}
	}
	for _, e := range d.endpoints.All() {
		if e.Identity == d.self || !d.endpoints.IsMember(e.Identity) {
			continue
		}
		if b, err := e.Encode(); err == nil {
			eps = append(eps, b)
		}
		if len(eps) == types.MaxNodes {
			break
		}
	}
	return &ipc.Bootstrap{Endpoints: eps, Leases: d.encodedLeases()}
}

// sameLease reports whether a and b are one lease, signatures and all.
func sameLease(a, b *types.Lease) bool {
	return a.Network == b.Network && a.Head == b.Head && a.Issued == b.Issued && a.Signer == b.Signer &&
		a.Sig == b.Sig && (a.MLDSA == nil) == (b.MLDSA == nil) && (a.MLDSA == nil || *a.MLDSA == *b.MLDSA)
}
