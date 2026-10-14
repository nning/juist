package log

import (
	"errors"
	"fmt"
	"slices"

	"github.com/nning/juist/types"
)

// Freshness leases bound how long a node acts on a view of the network that
// may be missing a removal: a node fails closed unless the state's threshold
// of distinct admin devices has each vouched for it within the TTL. See
// docs/11-enrollment-and-freshness-notes.md.

// MaxLeaseSkew is how far in the future a lease may be dated and still count,
// in seconds. Clocks disagree; a lease from far ahead would stretch a
// partition past the TTL on one clock's word.
const MaxLeaseSkew = 5 * 60

// LeaseSigners returns the members that may issue leases at now: the live
// ones holding the admin role.
func (s *State) LeaseSigners(now int64) []types.NodeRecord {
	var out []types.NodeRecord
	for _, n := range s.NodesWithRole(types.RoleAdmin) {
		if !n.Expired(now) {
			out = append(out, n)
		}
	}
	return out
}

// CheckLease reports whether l vouches for this node's state at now: signed
// by a live admin device of the trusted state, for this network, naming a
// record on the active chain — so this node holds at least what the signer
// held — and not dated beyond [MaxLeaseSkew] ahead.
func (a *Authority) CheckLease(l *types.Lease, now int64) error {
	state, err := a.TrustedState()
	if err != nil {
		return err
	}
	if l.Network != state.GenesisHash() {
		return errors.New("log: the lease is for another network")
	}
	signer, ok := state.Node(l.Signer)
	if !ok || signer.Expired(now) || !signer.HasRole(types.RoleAdmin) {
		return fmt.Errorf("log: %v is not an admin device of this network", l.Signer.ShortString())
	}
	if now < 0 || l.Issued > uint64(now)+MaxLeaseSkew {
		return errors.New("log: the lease is dated in the future")
	}
	if !a.onChain[l.Head] {
		return errors.New("log: the lease names a head this node's chain does not contain")
	}
	if err := l.VerifyPQ(state.SigningKey(l.Signer)); err != nil {
		return fmt.Errorf("log: %w", err)
	}
	return l.Verify()
}

// A Freshness is what a node's leases say about its view of the network.
type Freshness struct {
	// Signers is how many admin devices the state names. With none,
	// freshness is not enforced: the network never asked for it.
	Signers int

	// Needed is how many admin devices must vouch, and Vouching how many
	// have with a lease that still counts.
	Needed, Vouching int

	// Since is when the lease that completed the threshold was issued — the
	// Needed-th newest among distinct signers — or 0 if too few vouch; Until
	// is Since plus the TTL.
	Since, Until int64
}

// Enforced reports whether the state names anyone who could vouch for it.
func (f Freshness) Enforced() bool { return f.Signers > 0 }

// Fresh reports whether the node may act on its state at now.
func (f Freshness) Fresh(now int64) bool { return !f.Enforced() || now < f.Until }

// Freshness evaluates leases against the current state at now with a TTL of
// ttl seconds. Leases are re-checked every time, since a change to the state
// can withdraw a signer, and a lease from a device that is no longer an admin
// device vouches for nothing. Under an alarm nothing vouches.
//
// A node is fresh while the state's threshold of distinct admin devices have
// each vouched within the TTL. A signer vouches for what it holds, and one
// that lies — naming the anchor, which is on every chain — cannot be told
// from one that is behind; the threshold is what makes one dishonest admin
// device not enough.
func (a *Authority) Freshness(leases []types.Lease, now, ttl int64) Freshness {
	state, err := a.TrustedState()
	if err != nil {
		return Freshness{Signers: 1}
	}
	// Enforcement counts every admin device, expired or not: a network whose
	// admin devices have all expired has nobody left to vouch, which must
	// read as stale rather than as a network that never asked.
	f := Freshness{Signers: len(state.NodesWithRole(types.RoleAdmin)), Needed: int(state.Vouchers())}
	newest := map[types.Identity]int64{}
	for i := range leases {
		if a.CheckLease(&leases[i], now) != nil {
			continue
		}
		if issued := int64(leases[i].Issued); issued > newest[leases[i].Signer] {
			newest[leases[i].Signer] = issued
		}
	}
	times := make([]int64, 0, len(newest))
	for _, t := range newest {
		times = append(times, t)
	}
	slices.Sort(times)
	slices.Reverse(times)
	for _, t := range times {
		if now < t+ttl {
			f.Vouching++
		}
	}
	if len(times) >= f.Needed {
		f.Since = times[f.Needed-1]
		f.Until = f.Since + ttl
	}
	return f
}
