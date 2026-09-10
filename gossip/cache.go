package gossip

import (
	"slices"
	"sync"

	"github.com/nning/juist/types"
)

// maxCachedEndpoints bounds the announcement cache: two per member, so it
// holds a full network plus announcements for subjects this node has not yet
// learned from the log. Past the bound, a member's announcement displaces a
// non-member's and everything else is refused.
const maxCachedEndpoints = 2 * types.MaxNodes

// A Cache holds the newest endpoint announcement seen for each node. It is
// deliberately not filtered by membership: announcements arrive before the
// records that admit their subjects, and the reconciler ignores every subject
// the log does not carry, so an early one is inert rather than dangerous.
//
// The membership view it does hold decides only who wins when the bound is
// hit. Identity keys cost nothing to mint, so any holder of an epoch secret
// could otherwise fill the cache with signature-valid records for invented
// identities. Membership decides eviction, never entry.
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
// member now, and who this node has seen it carry and drop. Members decide who
// displaces whom when the cache is full. Former members are refused outright —
// a removed device keeps announcing until it learns of its removal, and each
// beacon would otherwise be cached, reported as new and pruned again. A
// subject in neither set is accepted, which is the early-join case.
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
// whether anything changed. The record must already be verified: passing an
// unverified one would let any peer speak for any node.
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
		// Full: a member's announcement displaces a non-member's, and a full
		// cache necessarily holds one, since the bound is twice the member
		// limit. Anything else waits for room.
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
// group sorted by identity. Members lead because the relaying hello truncates
// at [MaxEndpointsPerFrame], and invented identities must not crowd them out;
// the order stays deterministic, so equal sets produce equal frames.
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
