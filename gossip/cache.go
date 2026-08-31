package gossip

import (
	"slices"
	"sync"

	"github.com/nning/juist/types"
)

// maxCachedEndpoints bounds the announcement cache.
//
// Two per member, so that the cache can hold every member of a full network
// plus announcements for members this node has not yet learned about from the
// log — a node that syncs endpoints before records is the normal order, not an
// error. Past the bound, a member's announcement displaces a non-member's and
// everything else is refused; see [Cache.Add].
const maxCachedEndpoints = 2 * types.MaxNodes

// A Cache holds the newest endpoint announcement seen for each node.
//
// It is deliberately not filtered by membership. Gossip learns announcements
// before it learns the log records that make their subjects members, and
// dropping the ones that arrive early would make a joining node invisible
// until the next anti-entropy round. What consumes the cache — the reconciler
// — joins it onto the log's member set and ignores everything else, so an
// announcement for a non-member is inert rather than dangerous.
//
// The cache does hold a *view* of membership ([Cache.SetMembers]), for one
// purpose: deciding who wins when the bound is hit. An announcement only needs
// a signature by the key it names, and identity keys cost nothing to mint —
// so any holder of an epoch secret, including a revoked device inside the
// keyring window, could otherwise fill the cache with signature-valid records
// for invented identities and leave no room for a genuinely joining member,
// silently and until a restart. Membership decides *eviction*, never entry:
// early announcements still wait in whatever room the bound leaves.
//
// Safe for concurrent use.
type Cache struct {
	mu     sync.Mutex
	by     map[types.Identity]Endpoint
	member map[types.Identity]bool
	former map[types.Identity]bool
}

// NewCache returns an empty cache.
func NewCache() *Cache { return &Cache{by: map[types.Identity]Endpoint{}} }

// SetMembership gives the cache the reconciler's view of the log: who is a
// member now, and who this node has seen the log carry and drop.
//
// Members decide who may displace whom when the cache is full. Former members
// are refused outright — a device that was revoked or expired keeps announcing
// until it learns of its own removal, legitimately from its side, and every
// one of those announcements would otherwise be cached, reported as new, and
// pruned again on the next reconcile: a reconcile and a push round per member
// per announcement interval, for as long as the device is powered on.
//
// A subject in neither set is accepted, which is the case that must not be
// broken: gossip and discovery routinely deliver an announcement before the
// record admitting its subject.
//
// One rule in one place, because there are two ways in — LAN discovery, and a
// peer relaying its cache in a gossip session — and a rule enforced on only
// one of them is not enforced.
func (c *Cache) SetMembership(members, former []types.Identity) {
	m := make(map[types.Identity]bool, len(members))
	for _, id := range members {
		m[id] = true
	}
	f := make(map[types.Identity]bool, len(former))
	for _, id := range former {
		f[id] = true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.member, c.former = m, f
}

// Add records an announcement if it is newer than what is held, reporting
// whether anything changed.
//
// The record must already be verified; [DecodeEndpoint] and the session code
// do that. Passing an unverified one would let any peer speak for any node.
func (c *Cache) Add(e Endpoint) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.former[e.Identity] {
		return false
	}
	cur, held := c.by[e.Identity]
	switch {
	case held && e.Seq <= cur.Seq:
		// A replay, or the same record arriving from two peers.
		return false
	case !held && len(c.by) >= maxCachedEndpoints:
		// Full. A member's announcement makes room by displacing a
		// non-member's — the member's is the one the reconciler will
		// actually use, and a full cache necessarily holds a non-member,
		// since the bound is twice the member limit. Anything else waits
		// for room.
		if !c.member[e.Identity] || !c.evictNonMemberLocked() {
			return false
		}
	}
	c.by[e.Identity] = *e.Clone()
	return true
}

// evictNonMemberLocked drops the cached announcement of one non-member,
// choosing the lowest identity so the choice is deterministic, and reports
// whether it freed a slot. The caller holds c.mu.
func (c *Cache) evictNonMemberLocked() bool {
	var victim types.Identity
	found := false
	for id := range c.by {
		if c.member[id] {
			continue
		}
		if !found || id.Compare(victim) < 0 {
			victim, found = id, true
		}
	}
	if found {
		delete(c.by, victim)
	}
	return found
}

// IsMember reports whether the log's last-seen view carries this node as a
// live member. It is the reconciler's view, refreshed by [Cache.SetMembership].
func (c *Cache) IsMember(id types.Identity) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.member[id]
}

// IsFormer reports whether this node was seen as a member and has since been
// dropped from the log — revoked or expired.
func (c *Cache) IsFormer(id types.Identity) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.former[id]
}

// Get returns the announcement held for a node.
func (c *Cache) Get(id types.Identity) (Endpoint, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.by[id]
	if !ok {
		return Endpoint{}, false
	}
	return *e.Clone(), true
}

// All returns every announcement held: members first, then the rest, each
// group sorted by identity.
//
// Members lead for the same reason [Cache.Add] prefers them: the relaying
// hello truncates this list at [MaxEndpointsPerFrame], and a flood of
// announcements for invented identities must not be able to crowd the members
// out of what gets relayed. Within a membership view the order is still
// deterministic, so two nodes holding the same set produce the same frame.
func (c *Cache) All() []Endpoint {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Endpoint, 0, len(c.by))
	for _, e := range c.by {
		out = append(out, *e.Clone())
	}
	slices.SortFunc(out, func(a, b Endpoint) int {
		if am, bm := c.member[a.Identity], c.member[b.Identity]; am != bm {
			if am {
				return -1
			}
			return 1
		}
		return a.Identity.Compare(b.Identity)
	})
	return out
}

// Forget drops a node's announcement. The reconciler calls it on removal, so
// that a revoked device's last known address does not linger as something this
// node keeps dialing.
func (c *Cache) Forget(id types.Identity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.by, id)
}

// Len reports how many announcements are held.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.by)
}
