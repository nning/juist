package admit

import (
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
)

var (
	srcA = netip.MustParseAddr("192.0.2.1")
	srcB = netip.MustParseAddr("192.0.2.2")
)

// admitted admits n entries from src, recording each one's eviction.
func admitted(t *testing.T, s *Set[netip.Addr], src netip.Addr, n int, evicted *[]int, base int) []*Ticket[netip.Addr] {
	t.Helper()
	var out []*Ticket[netip.Addr]
	for i := range n {
		id := base + i
		tk, ok := s.Admit(src, func() { *evicted = append(*evicted, id) })
		if !ok {
			t.Fatalf("entry %d from %v refused", id, src)
		}
		out = append(out, tk)
	}
	return out
}

func TestRefusePerSource(t *testing.T) {
	s := New[netip.Addr](Limits{PerSource: 2})
	var evicted []int
	admitted(t, s, srcA, 2, &evicted, 0)
	if _, ok := s.Admit(srcA, nil); ok {
		t.Fatal("a third entry from one source was admitted over a bound of two")
	}
	admitted(t, s, srcB, 2, &evicted, 10)
	if len(evicted) != 0 || s.Len() != 4 || s.Count(srcA) != 2 {
		t.Fatalf("evicted %v, len %d, count %d", evicted, s.Len(), s.Count(srcA))
	}
}

func TestEvictOldestOfTheSameSource(t *testing.T) {
	s := New[netip.Addr](Limits{PerSource: 2, OnSource: EvictOldest})
	var evicted []int
	admitted(t, s, srcB, 1, &evicted, 100)
	admitted(t, s, srcA, 2, &evicted, 0)
	admitted(t, s, srcA, 3, &evicted, 2)
	// The oldest entry overall is srcB's, and it is not srcA's to displace.
	if want := []int{0, 1, 2}; !slices.Equal(evicted, want) {
		t.Fatalf("evicted %v, want %v", evicted, want)
	}
	if s.Count(srcA) != 2 || s.Count(srcB) != 1 {
		t.Fatalf("counts %d and %d", s.Count(srcA), s.Count(srcB))
	}
}

func TestRefuseOverall(t *testing.T) {
	s := New[netip.Addr](Limits{PerSource: 4, Total: 3})
	var evicted []int
	admitted(t, s, srcA, 2, &evicted, 0)
	admitted(t, s, srcB, 1, &evicted, 2)
	if _, ok := s.Admit(srcB, nil); ok {
		t.Fatal("admitted over the total")
	}
	if len(evicted) != 0 {
		t.Fatalf("a refusing bound evicted %v", evicted)
	}
}

func TestEvictOldestOverall(t *testing.T) {
	s := New[netip.Addr](Limits{PerSource: 3, Total: 3, OnTotal: EvictOldest})
	var evicted []int
	admitted(t, s, srcA, 1, &evicted, 0)
	admitted(t, s, srcB, 2, &evicted, 1)
	admitted(t, s, srcB, 1, &evicted, 3)
	if want := []int{0}; !slices.Equal(evicted, want) {
		t.Fatalf("evicted %v, want the oldest overall", evicted)
	}
	// Over its own bound, a source is refused before it can displace anyone.
	if _, ok := s.Admit(srcB, nil); ok {
		t.Fatal("admitted over the per-source bound")
	}
	if want := []int{0}; !slices.Equal(evicted, want) || s.Len() != 3 {
		t.Fatalf("evicted %v, want %v", evicted, want)
	}
}

func TestReleaseIsIdempotentAndSafeAfterEviction(t *testing.T) {
	s := New[netip.Addr](Limits{PerSource: 1, OnSource: EvictOldest})
	var evicted []int
	first := admitted(t, s, srcA, 1, &evicted, 0)[0]
	second := admitted(t, s, srcA, 1, &evicted, 1)[0]
	first.Release()
	first.Release()
	if s.Count(srcA) != 1 {
		t.Fatalf("releasing an evicted entry took %d others with it", 1-s.Count(srcA))
	}
	second.Release()
	second.Release()
	var none *Ticket[netip.Addr]
	none.Release()
	if s.Len() != 0 || s.Count(srcA) != 0 {
		t.Fatalf("len %d, count %d after releasing everything", s.Len(), s.Count(srcA))
	}
}

// An evict func runs outside the set's lock, so it may call back into it —
// as a Close that ends a session that releases its ticket does.
func TestEvictRunsOutsideTheLock(t *testing.T) {
	s := New[netip.Addr](Limits{Total: 1, OnTotal: EvictOldest})
	var first *Ticket[netip.Addr]
	first, _ = s.Admit(srcA, func() { first.Release(); _ = s.Len() })
	if _, ok := s.Admit(srcB, nil); !ok {
		t.Fatal("refused")
	}
	if s.Len() != 1 || s.Count(srcB) != 1 {
		t.Fatalf("len %d", s.Len())
	}
}

func TestConcurrentUseKeepsTheBounds(t *testing.T) {
	s := New[netip.Addr](Limits{PerSource: 3, OnSource: EvictOldest, Total: 5, OnTotal: EvictOldest})
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			src := netip.AddrFrom4([4]byte{192, 0, 2, byte(g % 3)})
			for range 500 {
				tk, ok := s.Admit(src, func() {})
				if !ok {
					t.Error("refused under eviction policies")
					return
				}
				if s.Len() > 5 || s.Count(src) > 3 {
					t.Errorf("bounds exceeded: len %d, count %d", s.Len(), s.Count(src))
				}
				tk.Release()
			}
		})
	}
	wg.Wait()
	if s.Len() != 0 {
		t.Fatalf("%d entries left after every one was released", s.Len())
	}
}

func TestSourceUnmapsAndSharesTheUnparseable(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.7")
	mapped := net.ParseIP("::ffff:192.0.2.7")
	for _, tc := range []struct {
		name string
		a    net.Addr
		want netip.Addr
	}{
		{"tcp", &net.TCPAddr{IP: v4.AsSlice(), Port: 1}, v4},
		{"tcp mapped", &net.TCPAddr{IP: mapped, Port: 1}, v4},
		{"udp mapped", &net.UDPAddr{IP: mapped, Port: 1}, v4},
		{"v6", &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1}, netip.MustParseAddr("2001:db8::1")},
		{"other", &net.UnixAddr{Name: "[::ffff:192.0.2.7]:9", Net: "unix"}, v4},
		{"unparseable", &net.UnixAddr{Name: "/run/x", Net: "unix"}, netip.Addr{}},
		{"nil", nil, netip.Addr{}},
	} {
		if got := Source(tc.a); got != tc.want {
			t.Errorf("%s: Source = %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := ParseSource("[::ffff:192.0.2.7]:80"); got != v4 {
		t.Errorf("ParseSource = %v", got)
	}
	if got := ParseSource("not an address"); got.IsValid() {
		t.Errorf("ParseSource of junk = %v", got)
	}
}

// A newcomer the total bound refuses evicts nobody from its own source first.
func TestARefusalEvictsNobody(t *testing.T) {
	s := New[int](Limits{PerSource: 1, OnSource: EvictOldest, Total: 2, OnTotal: Refuse})
	evicted := 0
	for src := range 2 {
		if _, ok := s.Admit(src, func() { evicted++ }); !ok {
			t.Fatalf("source %d was refused below the bounds", src)
		}
	}
	if _, ok := s.Admit(2, func() { evicted++ }); ok {
		t.Fatal("a third source was admitted over the total")
	}
	if _, ok := s.Admit(0, func() { evicted++ }); !ok || evicted != 1 || s.Len() != 2 {
		t.Fatalf("a source over its own bound: admitted=%v evicted=%d len=%d, want its oldest replaced", ok, evicted, s.Len())
	}
	if evicted != 1 {
		t.Fatalf("%d entries evicted", evicted)
	}
}
