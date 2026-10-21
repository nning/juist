package conn

import (
	"maps"
	"slices"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

// keyingSettle is how long after a peer is given a preshared key its reset
// is repeated: past any lookup the engine made with the key it had.
const keyingSettle = 2 * time.Second

// noteKeying records the peers next gives a key prev gave none, forgets
// those gone or keyless again, and has their resets repeated. The caller
// holds m.apply.
func (m *tsManager) noteKeying(prev, next map[key.NodePublic]Peer) {
	for nk := range m.keying {
		if p, ok := next[nk]; !ok || p.PSK == [32]byte{} {
			delete(m.keying, nk)
		}
	}
	added := false
	for nk, p := range next {
		if old, ok := prev[nk]; ok && keyed(old, p) {
			if m.keying == nil {
				m.keying = map[key.NodePublic]time.Time{}
			}
			m.keying[nk], added = time.Now(), true
			m.logf("conn: %v newly given a preshared key: nothing passes until it is reset again", nk.ShortString())
		}
	}
	if added {
		time.AfterFunc(keyingSettle, m.settleKeying)
	}
}

// settleKeying resets again each peer keyed keyingSettle ago, so no session
// made without its key outlives the first, and gives it its access.
func (m *tsManager) settleKeying() {
	m.apply.Lock()
	defer m.apply.Unlock()
	if m.closed {
		return
	}
	for nk, since := range m.keying {
		if time.Since(since) < keyingSettle {
			continue
		}
		m.evicting.Store(&nk)
		m.eng.SyncDevicePeer(nk)
		m.evicting.Store(nil)
		m.eng.SyncDevicePeer(nk)
		delete(m.keying, nk)
		m.logf("conn: %v keyed: reset again", nk.ShortString())
	}
	m.confiner.set(m.keptConfined(slices.Collect(maps.Values(m.state.Load().peers))), m.self.Addrs)
}

// warmPaths starts NAT-traversal discovery towards new peers before anything
// sends to them: without it the first handshake has no path, is dropped, and
// WireGuard's five-second retry dominates in both directions. Probes repeat on
// [warmSchedule], since a disco ping to a peer not yet told about us is
// discarded. Failures are ignored. The caller must hold m.apply, which is what
// makes the WaitGroup handshake with Close safe.
func (m *tsManager) warmPaths(fresh []key.NodePublic) {
	if len(fresh) == 0 || m.closed {
		return
	}
	m.warm.Add(1)
	go func() {
		defer m.warm.Done()
		for i, delay := range warmSchedule {
			if i > 0 {
				select {
				case <-m.done:
					return
				case <-time.After(delay):
				}
			}
			// Re-read the snapshot each round: a peer removed in the
			// meantime is gone from it, and must not be probed.
			st := m.state.Load()
			for _, nk := range fresh {
				nv, ok := st.nodes[nk]
				if !ok {
					continue
				}
				m.magic.Ping(nv, new(ipnstate.PingResult), 0, func(r *ipnstate.PingResult) {
					if r.Err == "" {
						m.unproven.Delete(nk)
					}
				})
			}
		}
	}()
}

// warmSchedule is when warm-up probes are sent, measured from the reconcile
// that introduced the peer. Over within a few seconds: past that WireGuard's
// own retry has taken over.
var warmSchedule = []time.Duration{0, 250 * time.Millisecond, 1 * time.Second, 3 * time.Second}

// newPaths reports the peers that need a path established: those that were not
// in the set before, and those whose disco key changed, which means the peer
// restarted and whatever path was known to it is stale.
func newPaths(prev, next map[key.NodePublic]Peer) (fresh []key.NodePublic) {
	for nk, cur := range next {
		if old, had := prev[nk]; !had || old.DiscoKey != cur.DiscoKey {
			fresh = append(fresh, nk)
		}
	}
	return fresh
}

// peerDelta reports which device peers must be reset, discarding session keys:
// those that left the set, those whose disco key rotated, since that means
// a restart and waiting out the rekey timers would blackhole traffic, and
// those newly given a preshared key, whose session mixes in none.
func peerDelta(prev, next map[key.NodePublic]Peer) (resets []key.NodePublic) {
	for nk, old := range prev {
		if cur, still := next[nk]; !still || cur.DiscoKey != old.DiscoKey || keyed(old, cur) {
			resets = append(resets, nk)
		}
	}
	return resets
}

// keyed reports whether a peer that had no preshared key is given one: its
// session carries none, so it goes, and what the peer may open widens only
// once it has.
func keyed(old, cur Peer) bool { return old.PSK == [32]byte{} && cur.PSK != [32]byte{} }
