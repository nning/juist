package admit

import (
	"container/list"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Rates limits how often each source may act, at a rate with a burst, for at
// most max sources at once: past them a source not seen takes the place of
// the one seen longest ago, which starts over with a full burst, so whoever
// uses Rates against spoofed sources bounds the rate in all as well. The zero
// value is not usable; see [NewRates]. Safe for concurrent use.
type Rates[K comparable] struct {
	limit rate.Limit
	burst int
	max   int

	mu   sync.Mutex
	seen *list.List // of *rateOf[K], the latest first
	by   map[K]*list.Element
}

type rateOf[K comparable] struct {
	src K
	*rate.Limiter
}

// NewRates returns rates of limit and burst for at most max sources.
func NewRates[K comparable](limit rate.Limit, burst, max int) *Rates[K] {
	return &Rates[K]{limit: limit, burst: burst, max: max, seen: list.New(), by: map[K]*list.Element{}}
}

// Allow reports whether src may act now, taking one from its budget.
func (r *Rates[K]) Allow(src K) bool { return r.AllowAt(src, time.Now()) }

// AllowAt is [Rates.Allow] at now.
func (r *Rates[K]) AllowAt(src K, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.by[src]
	if e == nil {
		if r.seen.Len() >= r.max {
			delete(r.by, r.seen.Remove(r.seen.Back()).(*rateOf[K]).src)
		}
		e = r.seen.PushFront(&rateOf[K]{src, rate.NewLimiter(r.limit, r.burst)})
		r.by[src] = e
	} else {
		r.seen.MoveToFront(e)
	}
	return e.Value.(*rateOf[K]).AllowN(now, 1)
}

// Len reports how many sources the rates hold.
func (r *Rates[K]) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen.Len()
}

// Prune forgets the sources whose budget is full again, which lose nothing
// by starting over.
func (r *Rates[K]) Prune() { r.pruneAt(time.Now()) }

func (r *Rates[K]) pruneAt(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for e := r.seen.Front(); e != nil; {
		next := e.Next()
		if s := e.Value.(*rateOf[K]); s.TokensAt(now) >= float64(r.burst) {
			delete(r.by, s.src)
			r.seen.Remove(e)
		}
		e = next
	}
}
