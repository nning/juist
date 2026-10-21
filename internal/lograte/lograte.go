// Package lograte says a kind of log line at most once an interval, and how
// many it left out, so that what a client may repeat at will cannot flood a
// log.
package lograte

import (
	"sync"
	"time"
)

// Every lets a kind of line through once an interval. The zero value lets
// every line through; safe for concurrent use.
type Every struct {
	Interval time.Duration

	mu   sync.Mutex
	last time.Time
	left int
}

// Allow reports whether a line is said at now, and if so how many were left
// out since the last said, at last.
func (e *Every) Allow(now time.Time) (left int, last time.Time, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.last.IsZero() && now.Sub(e.last) < e.Interval {
		e.left++
		return 0, time.Time{}, false
	}
	left, last = e.left, e.last
	e.last, e.left = now, 0
	return left, last, true
}

// ByKey is [Every] for each key apart, for at most max keys: past them the
// keys start over.
type ByKey[K comparable] struct {
	Interval time.Duration
	Max      int

	mu   sync.Mutex
	keys map[K]*Every
}

// Allow is [Every.Allow] for key.
func (b *ByKey[K]) Allow(key K, now time.Time) (left int, last time.Time, ok bool) {
	b.mu.Lock()
	e := b.keys[key]
	if e == nil {
		if b.keys == nil || len(b.keys) >= b.Max {
			b.keys = map[K]*Every{}
		}
		e = &Every{Interval: b.Interval}
		b.keys[key] = e
	}
	b.mu.Unlock()
	return e.Allow(now)
}
