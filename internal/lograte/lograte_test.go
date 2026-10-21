package lograte

import (
	"testing"
	"time"
)

// The first line is said, those within the interval after it are counted,
// and the next past it says how many and since when.
func TestEverySaysOnceAnInterval(t *testing.T) {
	e := Every{Interval: time.Minute}
	t0 := time.Unix(1000, 0)
	if left, _, ok := e.Allow(t0); !ok || left != 0 {
		t.Fatalf("the first line: %v, %d left", ok, left)
	}
	for i := range 3 {
		if _, _, ok := e.Allow(t0.Add(time.Duration(i+1) * time.Second)); ok {
			t.Fatal("a line within the interval was said")
		}
	}
	left, last, ok := e.Allow(t0.Add(time.Minute))
	if !ok || left != 3 || !last.Equal(t0) {
		t.Fatalf("past the interval: %v, %d left since %v", ok, left, last)
	}
	var b ByKey[string]
	b.Interval, b.Max = time.Minute, 1
	if _, _, ok := b.Allow("a", t0); !ok {
		t.Fatal("a key's first line was not said")
	}
	if _, _, ok := b.Allow("b", t0); !ok {
		t.Fatal("another key's first line was not said")
	}
	if _, _, ok := b.Allow("b", t0); ok {
		t.Fatal("a key's second line within the interval was said")
	}
}
