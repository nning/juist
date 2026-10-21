// Package admit bounds the connections a server holds before they have
// proved anything, per source and overall, and says what a source is.
package admit

import (
	"net"
	"net/netip"
	"sync"
)

// Source reduces a remote address to the host it came from, unmapped. An
// address that does not parse is the zero Addr: one shared source, which is
// the safe direction, since it shares a budget rather than escaping one.
func Source(a net.Addr) netip.Addr {
	switch t := a.(type) {
	case nil:
		return netip.Addr{}
	case *net.TCPAddr:
		if ip, ok := netip.AddrFromSlice(t.IP); ok {
			return ip.Unmap()
		}
	case *net.UDPAddr:
		if ip, ok := netip.AddrFromSlice(t.IP); ok {
			return ip.Unmap()
		}
	}
	return ParseSource(a.String())
}

// ParseSource is [Source] for an address written as host:port, such as
// [net/http.Request.RemoteAddr].
func ParseSource(hostport string) netip.Addr {
	if ap, err := netip.ParseAddrPort(hostport); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// Host is the prefix one host holds: an IPv4 address, an IPv6 /64.
func Host(a netip.Addr) netip.Prefix { return prefixOf(a, 32, 64) }

// Group is the prefix one customer holds: an IPv4 address, an IPv6 /56.
func Group(a netip.Addr) netip.Prefix { return prefixOf(a, 32, 56) }

// Site is the prefix one site's hosts hold together: an IPv4 /24, an IPv6
// /48.
func Site(a netip.Addr) netip.Prefix { return prefixOf(a, 24, 48) }

// prefixOf is a's prefix of v4 or v6 bits, unmapped; the zero Prefix for the
// zero Addr.
func prefixOf(a netip.Addr, v4, v6 int) netip.Prefix {
	a = a.Unmap()
	bits := v6
	if a.Is4() {
		bits = v4
	}
	p, _ := a.Prefix(bits)
	return p
}

// HostsAndSites bounds what one [Host] holds at perHost, and one [Site]'s
// hosts together at perHost*sitePerHost, refusing past either. Its sources
// are hosts.
func HostsAndSites(perHost int) *Set[netip.Prefix] {
	return NewNested(Limits{PerSource: perHost, Within: []Bound{{Max: perHost * sitePerHost}}},
		func(host netip.Prefix) []netip.Prefix { return []netip.Prefix{Site(host.Addr())} })
}

// sitePerHost is how many hosts' bounds one site's together are.
const sitePerHost = 4

// A Policy is what a full bound does with a newcomer.
type Policy uint8

const (
	// Refuse turns the newcomer away.
	Refuse Policy = iota
	// EvictOldest admits the newcomer and evicts the oldest entry the bound
	// counts, so what a flood displaces is what has waited longest.
	EvictOldest
	// EvictLargest admits the newcomer and evicts, of the entries the bound
	// counts, the oldest of the source holding the most within the groups
	// [NewNested] names holding the most, ties going to the oldest at every
	// level: a flood displaces its own first. For a source it is EvictOldest.
	EvictLargest
)

// A Bound is how many entries one source, group or the whole set may hold,
// and what a full one does with a newcomer. A zero Max is no bound.
type Bound struct {
	Max int
	On  Policy
}

// Limits are a [Set]'s bounds. A zero bound is no bound.
type Limits struct {
	PerSource int
	OnSource  Policy
	Total     int
	OnTotal   Policy
	// Within bounds each group [NewNested] names, widest first.
	Within []Bound
}

// A Set counts admitted entries by source, and by the groups a source is
// within. The zero value is not usable; see [New]. Safe for concurrent use.
type Set[K comparable] struct {
	lim    Limits
	within func(K) []K
	mu     sync.Mutex
	root   *node[K]
	leaves map[K]*node[K]
}

// A node is the whole set, a group or a source: the entries it holds, oldest
// first, linked through each ticket's links at the node's level so that one
// leaves in constant time, and how many of its children hold each count.
type node[K comparable] struct {
	key        K
	children   map[K]*node[K]
	head, tail *Ticket[K]
	held       int
	sizes      map[int]int
	most       int
}

// A Ticket is one admitted entry.
type Ticket[K comparable] struct {
	set   *Set[K]
	path  []*node[K] // the whole set, the groups, then the source
	links []link[K]  // its neighbours in each of path's queues
	evict func()
	gone  bool
}

type link[K comparable] struct{ prev, next *Ticket[K] }

// push appends t to n's queue, n being at level.
func (n *node[K]) push(t *Ticket[K], level int) {
	t.links[level].prev = n.tail
	if n.tail != nil {
		n.tail.links[level].next = t
	} else {
		n.head = t
	}
	n.tail = t
	n.held++
}

// unlink takes t out of n's queue, n being at level.
func (n *node[K]) unlink(t *Ticket[K], level int) {
	l := t.links[level]
	if l.prev != nil {
		l.prev.links[level].next = l.next
	} else {
		n.head = l.next
	}
	if l.next != nil {
		l.next.links[level].prev = l.prev
	} else {
		n.tail = l.prev
	}
	t.links[level] = link[K]{}
	n.held--
}

// New returns an empty set with the given bounds.
func New[K comparable](lim Limits) *Set[K] { return NewNested[K](lim, nil) }

// NewNested is [New] where within names the groups a source is within,
// widest first, which [Limits.Within] bounds and [EvictLargest] weighs
// before the sources. within must name as many groups for every source.
func NewNested[K comparable](lim Limits, within func(K) []K) *Set[K] {
	return &Set[K]{lim: lim, within: within, root: newNode[K](*new(K)), leaves: map[K]*node[K]{}}
}

func newNode[K comparable](key K) *node[K] {
	return &node[K]{key: key, children: map[K]*node[K]{}, sizes: map[int]int{}}
}

// bounds is the bound on each level of a path, the whole set first.
func (s *Set[K]) bounds(depth int) []Bound {
	b := make([]Bound, depth)
	b[0] = Bound{s.lim.Total, s.lim.OnTotal}
	copy(b[1:depth-1], s.lim.Within)
	b[depth-1] = Bound{s.lim.PerSource, s.lim.OnSource}
	return b
}

// Admit counts an entry from src, or reports false if a [Refuse] bound is
// full. Where an evicting bound is full, entries it counts are taken off the
// set and their evict called, after the set's lock is released and before
// Admit returns. evict may be nil. Admit never blocks on anything but the
// set's lock.
func (s *Set[K]) Admit(src K, evict func()) (*Ticket[K], bool) {
	var keys []K
	if s.within != nil {
		keys = s.within(src)
	}
	keys = append(keys, src)
	s.mu.Lock()
	path := s.pathLocked(keys)
	bounds := s.bounds(len(path))
	// Decided before anything is evicted, so a refusal costs nobody a slot:
	// each level frees what the levels below it evict.
	freed := make([]int, len(path))
	planned := 0
	for i := len(path) - 1; i >= 0; i-- {
		b := bounds[i]
		held := 0
		if path[i] != nil {
			held = path[i].held
		}
		if b.Max <= 0 || held-planned < b.Max {
			continue
		}
		if b.On == Refuse {
			s.mu.Unlock()
			return nil, false
		}
		freed[i] = held - planned - b.Max + 1
		planned += freed[i]
	}
	var evicted []*Ticket[K]
	for i := len(path) - 1; i >= 0; i-- {
		for ; freed[i] > 0; freed[i]-- {
			v := path[i].victim(bounds[i].On, i, len(path))
			s.removeLocked(v)
			evicted = append(evicted, v)
		}
	}
	t := &Ticket[K]{set: s, evict: evict}
	s.addLocked(t, keys)
	s.mu.Unlock()
	for _, v := range evicted {
		if v.evict != nil {
			v.evict()
		}
	}
	return t, true
}

// pathLocked is the nodes keys name now, the whole set first, nil past the
// first that holds nothing.
func (s *Set[K]) pathLocked(keys []K) []*node[K] {
	path := make([]*node[K], len(keys)+1)
	path[0] = s.root
	for i, k := range keys {
		if path[i] != nil {
			path[i+1] = path[i].children[k]
		}
	}
	return path
}

// victim is the entry a full bound on n evicts: n's oldest, or under
// [EvictLargest] the oldest of the child holding the most, level by level
// down to a source, ties going to the oldest. n is at level of depth levels.
func (n *node[K]) victim(p Policy, level, depth int) *Ticket[K] {
	for p == EvictLargest && level < depth-1 {
		next := n.head.path[level+1]
		for t := n.head; t != nil; t = t.links[level].next {
			if c := t.path[level+1]; c.held == n.most {
				next = c
				break
			}
		}
		n, level = next, level+1
	}
	return n.head
}

func (s *Set[K]) addLocked(t *Ticket[K], keys []K) {
	t.path = make([]*node[K], len(keys)+1)
	t.links = make([]link[K], len(keys)+1)
	n := s.root
	t.path[0] = n
	for i, k := range keys {
		c := n.children[k]
		if c == nil {
			c = newNode(k)
			n.children[k] = c
		}
		n.resize(c.held, c.held+1)
		t.path[i+1] = c
		n = c
	}
	for i, n := range t.path {
		n.push(t, i)
	}
	s.leaves[keys[len(keys)-1]] = n
}

// removeLocked takes t off the set.
func (s *Set[K]) removeLocked(t *Ticket[K]) {
	for i := len(t.path) - 1; i >= 0; i-- {
		n := t.path[i]
		n.unlink(t, i)
		if i == 0 {
			continue
		}
		parent := t.path[i-1]
		parent.resize(n.held+1, n.held)
		if n.held == 0 {
			delete(parent.children, n.key)
			if i == len(t.path)-1 {
				delete(s.leaves, n.key)
			}
		}
	}
	t.gone = true
}

// resize moves one of n's children from holding from to holding to.
func (n *node[K]) resize(from, to int) {
	if from > 0 {
		if n.sizes[from]--; n.sizes[from] == 0 {
			delete(n.sizes, from)
		}
	}
	if to > 0 {
		n.sizes[to]++
	}
	n.most = max(n.most, to)
	for n.most > 0 && n.sizes[n.most] == 0 {
		n.most--
	}
}

// Release takes the entry off the set. Safe on a nil ticket, more than once,
// and after the entry was evicted.
func (t *Ticket[K]) Release() {
	if t == nil {
		return
	}
	s := t.set
	s.mu.Lock()
	defer s.mu.Unlock()
	if !t.gone {
		s.removeLocked(t)
	}
}

// Len reports how many entries the set holds.
func (s *Set[K]) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.root.held
}

// Count reports how many entries the set holds from src.
func (s *Set[K]) Count(src K) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.leaves[src]; n != nil {
		return n.held
	}
	return 0
}
