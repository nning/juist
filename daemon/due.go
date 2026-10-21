package daemon

import (
	"time"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/pairkey"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// reconcileGap is the least time between two reconciles a deadline brings.
const reconcileGap = time.Second

// A soonest is the earliest of the times given to it that lie past now.
type soonest struct {
	now, at time.Time
}

func (s *soonest) add(t time.Time) {
	if t.After(s.now) && (s.at.IsZero() || t.Before(s.at)) {
		s.at = t
	}
}

// unix adds a time in Unix seconds, zero for none.
func (s *soonest) unix(sec int64) {
	if sec > 0 {
		s.add(time.Unix(sec, 0))
	}
}

// noteDue keeps when the next reconcile is due by what the log, the leases,
// the announcements and the routing of the host's DNS name: a membership's
// expiry, a renumbering's deadline, the view going stale, a lease to renew,
// a share's end, an exchange of preshared keys put off. What changes at no
// known time waits for the backstop, [Daemon.reconcileEvery].
func (d *Daemon) noteDue(s snapshot, fresh log.Freshness, held map[types.Identity]gossip.Endpoint) {
	next := soonest{now: time.Unix(s.now, 0)}
	for i := range s.members {
		n := &s.members[i]
		next.unix(int64(min(n.Expiry, 1<<62)))
		if n.Retiring != nil {
			next.unix(int64(min(n.Retiring.Until, 1<<62)))
		}
	}
	if r, ok := s.state.V4Retiring(); ok {
		next.unix(int64(min(r.Until, 1<<62)))
	}
	if fresh.Enforced() {
		next.unix(fresh.Until)
	}
	for _, ep := range held {
		if ep.Share != nil {
			next.unix(ep.Share.Until)
		}
	}
	if l, ok := d.ownLease(); ok {
		next.add(time.Unix(int64(min(l.Issued, 1<<62)), 0).Add(d.leaseEvery))
	}
	d.readPairs(func(p *pairkey.Store) {
		if at, ok := p.PutOffUntil(); ok {
			next.add(at)
		}
	})
	next.add(d.dnsDue())
	d.mu.Lock()
	if !d.behindSince.IsZero() {
		next.add(d.behindSince.Add(overtakenAfter))
	}
	d.mu.Unlock()
	d.reconcileDue.Store(&next.at)
	// A reconcile off the loop, as an IPC request's, may find one sooner
	// than the loop's timer.
	if armed := d.reconcileArmed.Load(); !next.at.IsZero() && armed != nil && next.at.Before(*armed) {
		select {
		case d.rearm <- struct{}{}:
		default:
		}
	}
}

// reconcileWait is how long the loop waits for the next reconcile: until the
// deadline [Daemon.noteDue] kept, at the backstop's pace at most.
func (d *Daemon) reconcileWait() time.Duration {
	wait := d.pace.every(d.reconcileEvery, d.saving.reconcile)
	if due := d.reconcileDue.Load(); due != nil && !due.IsZero() {
		wait = min(wait, due.Sub(d.now()))
	}
	return max(wait, reconcileGap)
}

// ownLease is this device's own lease, where it holds one.
func (d *Daemon) ownLease() (types.Lease, bool) {
	return d.leases.get(d.self)
}
