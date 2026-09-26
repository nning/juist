// Package admit bounds the connections a server holds before they have
// proved anything, per source and overall, and says what a source is.
package admit

import (
	"net"
	"net/netip"
	"slices"
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

// A Policy is what a full bound does with a newcomer.
type Policy uint8

const (
	// Refuse turns the newcomer away.
	Refuse Policy = iota
	// EvictOldest admits the newcomer and evicts the oldest entry the bound
	// counts, so what a flood displaces is what has waited longest.
	EvictOldest
)

// Limits are a [Set]'s bounds. A zero bound is no bound.
type Limits struct {
	PerSource int
	OnSource  Policy
	Total     int
	OnTotal   Policy
}

// A Set counts admitted entries by source. The zero value is not usable; see
// [New]. Safe for concurrent use.
type Set[K comparable] struct {
	lim   Limits
	mu    sync.Mutex
	order []*Ticket[K] // oldest first
	count map[K]int
}

// A Ticket is one admitted entry.
type Ticket[K comparable] struct {
	set   *Set[K]
	src   K
	evict func()
}

// New returns an empty set with the given bounds.
func New[K comparable](lim Limits) *Set[K] {
	return &Set[K]{lim: lim, count: map[K]int{}}
}

// Admit counts an entry from src, or reports false if a [Refuse] bound is
// full. Where an [EvictOldest] bound is full, the oldest entry it counts is
// taken off the set and its evict called, after the set's lock is released
// and before Admit returns. evict may be nil. Admit never blocks on anything
// but the set's lock.
func (s *Set[K]) Admit(src K, evict func()) (*Ticket[K], bool) {
	s.mu.Lock()
	// Decided before anything is evicted, so a refusal costs nobody a slot.
	freed := 0
	if s.lim.PerSource > 0 && s.count[src] >= s.lim.PerSource {
		if s.lim.OnSource == Refuse {
			s.mu.Unlock()
			return nil, false
		}
		freed = s.count[src] - s.lim.PerSource + 1
	}
	if s.lim.Total > 0 && len(s.order)-freed >= s.lim.Total && s.lim.OnTotal == Refuse {
		s.mu.Unlock()
		return nil, false
	}
	var evicted []*Ticket[K]
	for range freed {
		evicted = append(evicted, s.removeLocked(slices.IndexFunc(s.order, func(t *Ticket[K]) bool { return t.src == src })))
	}
	for s.lim.Total > 0 && len(s.order) >= s.lim.Total {
		evicted = append(evicted, s.removeLocked(0))
	}
	t := &Ticket[K]{set: s, src: src, evict: evict}
	s.order = append(s.order, t)
	s.count[src]++
	s.mu.Unlock()
	s.run(evicted)
	return t, true
}

// run calls the evicted entries' evict funcs. The caller must not hold s.mu:
// they are other code, typically a Close and a log line.
func (s *Set[K]) run(evicted []*Ticket[K]) {
	for _, t := range evicted {
		if t.evict != nil {
			t.evict()
		}
	}
}

// removeLocked takes s.order[i] off the set and returns it.
func (s *Set[K]) removeLocked(i int) *Ticket[K] {
	t := s.order[i]
	s.order = slices.Delete(s.order, i, i+1)
	if s.count[t.src]--; s.count[t.src] <= 0 {
		delete(s.count, t.src)
	}
	return t
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
	if i := slices.Index(s.order, t); i >= 0 {
		s.removeLocked(i)
	}
}

// Len reports how many entries the set holds.
func (s *Set[K]) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.order)
}

// Count reports how many entries the set holds from src.
func (s *Set[K]) Count(src K) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count[src]
}
