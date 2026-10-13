package gossip

import (
	"slices"
	"sync"
	"time"

	"github.com/nning/juist/types"
)

// maxCachedEndpoints bounds the announcement cache: two per member, so it
// holds a full network plus announcements for subjects this node has not yet
// learned from the log. Past the bound, a member's announcement displaces a
// non-member's and everything else is refused.
const maxCachedEndpoints = 2 * types.MaxNodes

// maxHintAhead bounds how far past now a hint may number itself: its author
// numbers by its clock, and a forger's number far ahead would pin it.
const maxHintAhead = 10 * time.Minute

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
// Past the cut-over it holds hints apart: announcements whose ML-DSA
// signature does not verify, which a quantum computer forges. See
// [Cache.Add].
//
// Safe for concurrent use.
type Cache struct {
	mu     sync.Mutex
	by     map[types.Identity]Endpoint
	hints  map[types.Identity]Endpoint
	keys   map[types.Identity]AddrKey // members' alone
	renews map[types.Identity]bool
	member map[types.Identity]bool
	former map[types.Identity]bool
	// noRelayNames refuses relay names, below [types.SchemaRelayName], noPQ
	// an epoch and pair store, below [types.SchemaPQ], and noSchemas a
	// build's schema, below [types.SchemaPadded]: older members refuse a
	// whole frame that carries one.
	noRelayNames bool
	noPQ         bool
	noSchemas    bool

	// signing are the members' signing keys, past the cut-over to
	// [types.SchemaMLDSA]; nil before it.
	signing map[types.Identity]types.SigningKey

	now func() time.Time
}

// NewCache returns an empty cache.
func NewCache() *Cache {
	return &Cache{by: map[types.Identity]Endpoint{}, hints: map[types.Identity]Endpoint{},
		keys: map[types.Identity]AddrKey{}, renews: map[types.Identity]bool{}, now: time.Now}
}

// SetClock replaces time.Now, which bounds a hint's number.
func (c *Cache) SetClock(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// Renews reports whether a node has been seen signing its announcement again
// with nothing changed, as a build that renews does.
func (c *Cache) Renews(id types.Identity) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.renews[id]
}

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
	for id := range c.keys {
		if !m[id] {
			delete(c.keys, id)
		}
	}
}

// SetSigningKeys gives the cache the members' signing keys, once the network
// is past the cut-over, nil before it. Past it an announcement is held as a
// hint unless its ML-DSA signature verifies against its author's key, and an
// address key is refused unless it does.
func (c *Cache) SetSigningKeys(keys map[types.Identity]types.SigningKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.signing = keys
	for id, e := range c.by {
		if c.hintLocked(&e) {
			delete(c.by, id)
			if h, held := c.hints[id]; !held || h.Seq < e.Seq {
				c.hints[id] = asHint(e)
			}
		}
	}
	for id, k := range c.keys {
		if !c.keyVerifiesLocked(&k) {
			delete(c.keys, id)
		}
	}
}

// hintLocked reports whether e is no more than a hint: past the cut-over,
// one whose ML-DSA signature does not verify against its author's key. The
// caller holds c.mu.
func (c *Cache) hintLocked(e *Endpoint) bool {
	if c.signing == nil {
		return false
	}
	key, ok := c.signing[e.Identity]
	return !ok || e.VerifyPQ(&key) != nil
}

// asHint is e without what only its author may say: its ML-DSA signature,
// and its consent to serve as an exit, route subnets, answer DNS, serve
// published names or share.
func asHint(e Endpoint) Endpoint {
	h := *e.Clone()
	h.MLDSA = nil
	h.Exit, h.Subnets, h.DNS, h.Published, h.Share = false, false, 0, false, nil
	return h
}

// keyVerifiesLocked reports whether an address key may be held: past the
// cut-over, only one its owner signed by ML-DSA. The caller holds c.mu.
func (c *Cache) keyVerifiesLocked(k *AddrKey) bool {
	if c.signing == nil {
		return true
	}
	key, ok := c.signing[k.Owner]
	return ok && k.VerifyPQ(&key) == nil
}

// IsHint reports whether what is held for id is a hint alone, with no
// announcement beside it.
func (c *Cache) IsHint(id types.Identity) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, full := c.by[id]
	_, hint := c.hints[id]
	return hint && !full
}

// dropLocked drops what is held for id where drop says so. The caller holds
// c.mu.
func (c *Cache) dropLocked(drop func(*Endpoint) bool) {
	for id, e := range c.by {
		if drop(&e) {
			delete(c.by, id)
			delete(c.renews, id)
		}
	}
	for id, e := range c.hints {
		if drop(&e) {
			delete(c.hints, id)
		}
	}
}

// SetRelayNames says whether the network's schema lets announcements name
// a relay on 443; where not, those held are dropped and others refused.
func (c *Cache) SetRelayNames(ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.noRelayNames = !ok
	if !ok {
		c.dropLocked(func(e *Endpoint) bool { return e.Relay != nil && e.Relay.Name != "" })
	}
}

// SetPQ says whether the network's schema lets announcements name an epoch
// and a pair store; where not, those held are dropped and others refused.
func (c *Cache) SetPQ(ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.noPQ = !ok
	if !ok {
		c.dropLocked((*Endpoint).PQ)
	}
}

// SetSchemas says whether the network's schema lets announcements name
// their build's schema; where not, those held are dropped and others refused.
func (c *Cache) SetSchemas(ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.noSchemas = !ok
	if !ok {
		c.dropLocked(func(e *Endpoint) bool { return e.Schema != 0 })
	}
}

// Add records an announcement if it is newer than what is held, reporting
// whether it says anything new. One that only renews the signature is kept,
// so what is held stays as fresh as its author made it, but reported as
// nothing new: acting on it would cost every member a reconcile and a push
// for each renewal. The record must already be verified ([Endpoint.Verify]):
// passing an unverified one would let any peer speak for any node.
//
// Past the cut-over one whose ML-DSA signature does not verify is a hint: a
// quantum computer forges its Ed25519 one. A hint is held beside the
// announcement, never in its place, and is relayed to no one. Where it is
// newer, [Cache.Get] dials where it says; what only its author may say
// ([asHint]) comes from the announcement alone.
func (c *Cache) Add(e Endpoint) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.former[e.Identity] || c.noRelayNames && e.Relay != nil && e.Relay.Name != "" || c.noPQ && e.PQ() ||
		c.noSchemas && e.Schema != 0 {
		return false
	}
	if full, held := c.by[e.Identity]; held && e.Seq <= full.Seq {
		// A replay, or older: refused before its signature costs anything.
		return false
	}
	before, _ := c.getLocked(e.Identity)
	if c.hintLocked(&e) {
		h := asHint(e)
		if h.Seq > uint64(c.now().Add(maxHintAhead).Unix()) {
			return false
		}
		if cur, held := c.hints[e.Identity]; held && h.Seq <= cur.Seq {
			return false
		} else if !held && !c.roomLocked(c.hints, e.Identity) {
			return false
		}
		c.hints[e.Identity] = h
	} else {
		cur, held := c.by[e.Identity]
		if !held && !c.roomLocked(c.by, e.Identity) {
			return false
		}
		c.by[e.Identity] = *e.Clone()
		if h, held := c.hints[e.Identity]; held && h.Seq <= e.Seq {
			delete(c.hints, e.Identity)
		}
		if held && cur.SameAs(&e) {
			c.renews[e.Identity] = true
		}
	}
	after, _ := c.getLocked(e.Identity)
	return !before.SameAs(&after)
}

// roomLocked reports whether m has room for id: below the bound, or full
// with a non-member's to evict for a member's, which a full map necessarily
// holds, since the bound is twice the member limit. The caller holds c.mu.
func (c *Cache) roomLocked(m map[types.Identity]Endpoint, id types.Identity) bool {
	if len(m) < maxCachedEndpoints {
		return true
	}
	if !c.member[id] {
		return false
	}
	var victim types.Identity
	found := false
	for other := range m {
		if !c.member[other] && (!found || other.Compare(victim) < 0) {
			victim, found = other, true
		}
	}
	if found {
		delete(m, victim)
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

// Get returns the announcement held for a node, dialed where a newer hint
// says ([Cache.Add]), or the hint alone where no announcement is held.
func (c *Cache) Get(id types.Identity) (Endpoint, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.getLocked(id)
}

func (c *Cache) getLocked(id types.Identity) (Endpoint, bool) {
	e, full := c.by[id]
	h, hint := c.hints[id]
	switch {
	case full && hint && h.Seq > e.Seq:
		out := *e.Clone()
		// Its number too, the newest heard, which maxHintAhead bounds.
		out.Seq, out.Disco, out.Addrs, out.Sealed, out.GossipPort = h.Seq, h.Disco, slices.Clone(h.Addrs), slices.Clone(h.Sealed), h.GossipPort
		out.Relay, out.HomeRelay = h.Clone().Relay, h.HomeRelay
		// A hint never lowers the epoch a pair's preshared key comes from.
		if h.Epoch > e.Epoch {
			out.Epoch, out.PairStore = h.Epoch, h.PairStore
		}
		out.MLDSA = nil // what it signed is not this
		return out, true
	case full:
		return *e.Clone(), true
	case hint:
		return *h.Clone(), true
	}
	return Endpoint{}, false
}

// All returns every announcement held but hints: members first, then the
// rest, each group sorted by identity. Members lead because the relaying
// hello truncates at [MaxEndpointsPerFrame], and invented identities must not
// crowd them out; the order stays deterministic, so equal sets produce equal
// frames.
func (c *Cache) All() []Endpoint { return c.all(false) }

// WithHints is [Cache.All] with the hints held for nodes it holds no
// announcement of.
func (c *Cache) WithHints() []Endpoint { return c.all(true) }

func (c *Cache) all(hints bool) []Endpoint {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Endpoint, 0, len(c.by))
	for _, e := range c.by {
		out = append(out, *e.Clone())
	}
	for id, h := range c.hints {
		if _, full := c.by[id]; hints && !full {
			out = append(out, *h.Clone())
		}
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
	delete(c.hints, id)
}

// Len reports how many announcements are held, hints aside.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.by)
}

// AddKey records a member's address key if it is newer than what is held,
// reporting whether it is. A non-member's is refused: a key opens nothing
// before the log admits its owner, and refusing it bounds the set. The
// record must already be verified.
func (c *Cache) AddKey(k AddrKey) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cur, held := c.keys[k.Owner]; !c.member[k.Owner] || held && k.Seq <= cur.Seq || !c.keyVerifiesLocked(&k) {
		return false
	}
	k.Wraps = slices.Clone(k.Wraps)
	c.keys[k.Owner] = k
	return true
}

// KeepKey is AddKey for a key this node persisted, before it knows who is
// a member; [Cache.SetMembership] drops it where its owner is none.
func (c *Cache) KeepKey(k AddrKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cur, held := c.keys[k.Owner]; (!held || k.Seq > cur.Seq) && c.keyVerifiesLocked(&k) {
		k.Wraps = slices.Clone(k.Wraps)
		c.keys[k.Owner] = k
	}
}

// Key returns the address key held for a member.
func (c *Cache) Key(id types.Identity) (AddrKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k, ok := c.keys[id]
	k.Wraps = slices.Clone(k.Wraps)
	return k, ok
}

// Keys returns every address key held, sorted by owner.
func (c *Cache) Keys() []AddrKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]AddrKey, 0, len(c.keys))
	for _, k := range c.keys {
		k.Wraps = slices.Clone(k.Wraps)
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b AddrKey) int { return a.Owner.Compare(b.Owner) })
	return out
}
