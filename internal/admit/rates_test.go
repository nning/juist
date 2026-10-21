package admit

import (
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// A source spends its own burst alone, and past the bound on sources the one
// seen longest ago gives way, not one seen since.
func TestRatesBoundEachSourceAndHowMany(t *testing.T) {
	r := NewRates[int](rate.Every(time.Hour), 2, 3)
	now := time.Unix(1000, 0)
	for i, want := range []bool{true, true, false} {
		if r.AllowAt(1, now) != want {
			t.Fatalf("a source's act %d of a burst of two: %v", i+1, !want)
		}
	}
	r.AllowAt(2, now)
	r.AllowAt(3, now)
	r.AllowAt(1, now) // seen again, so 2 is seen longest ago
	r.AllowAt(4, now)
	if r.Len() != 3 {
		t.Fatalf("%d sources held, past 3", r.Len())
	}
	if r.AllowAt(1, now) {
		t.Fatal("source 1 gave way though 2 was seen longer ago")
	}
	if !r.AllowAt(2, now) {
		t.Fatal("source 2 kept a spent budget it gave way with")
	}
}

// Prune forgets a source whose budget is full again, and keeps one that spent.
func TestRatesPruneTheFull(t *testing.T) {
	r := NewRates[int](rate.Every(time.Second), 2, 10)
	t0 := time.Unix(1000, 0)
	r.AllowAt(1, t0)
	r.AllowAt(2, t0)
	r.AllowAt(2, t0)
	t1 := t0.Add(5 * time.Second)
	r.AllowAt(3, t1)
	r.AllowAt(3, t1)
	r.pruneAt(t1)
	if r.Len() != 1 {
		t.Fatalf("%d sources held after pruning, want the one that just spent", r.Len())
	}
}
