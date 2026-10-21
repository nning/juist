package admit

import (
	"maps"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
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

func TestHostGroupAndSite(t *testing.T) {
	for _, tc := range []struct{ addr, host, group, site string }{
		{"192.0.2.7", "192.0.2.7/32", "192.0.2.7/32", "192.0.2.0/24"},
		{"::ffff:192.0.2.7", "192.0.2.7/32", "192.0.2.7/32", "192.0.2.0/24"},
		{"2001:db8:1:2ff:a::1", "2001:db8:1:2ff::/64", "2001:db8:1:200::/56", "2001:db8:1::/48"},
		{"fe80::1%eth0", "fe80::/64", "fe80::/56", "fe80::/48"},
	} {
		a := netip.MustParseAddr(tc.addr)
		if got := []string{Host(a).String(), Group(a).String(), Site(a).String()}; !slices.Equal(got, []string{tc.host, tc.group, tc.site}) {
			t.Errorf("%s: host, group, site %v", tc.addr, got)
		}
	}
	if p := Host(netip.Addr{}); p.IsValid() {
		t.Errorf("the zero address is host %v", p)
	}
}

// Past the total, EvictLargest takes the oldest of the source holding the
// most within the group holding the most, ties going to the oldest, so a
// lone older entry outlasts a flood.
func TestEvictLargestOverall(t *testing.T) {
	group := func(a netip.Addr) []netip.Addr { return []netip.Addr{netip.AddrFrom4([4]byte{a.As4()[0]})} }
	s := NewNested(Limits{PerSource: 3, OnSource: EvictOldest, Total: 6, OnTotal: EvictLargest}, group)
	lone, f1, f2, other := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("20.0.0.1"), netip.MustParseAddr("20.0.0.2"), netip.MustParseAddr("30.0.0.1")
	var evicted []int
	admitted(t, s, lone, 1, &evicted, 0)
	admitted(t, s, other, 2, &evicted, 10)
	admitted(t, s, f1, 2, &evicted, 20)
	admitted(t, s, f2, 1, &evicted, 30)
	// Group 20 holds three, f1 the most of it.
	admitted(t, s, f2, 1, &evicted, 31)
	// Group 20 holds three again, now f2 the most of it.
	admitted(t, s, other, 1, &evicted, 12)
	// Group 30 holds three.
	admitted(t, s, f1, 1, &evicted, 22)
	if want := []int{20, 30, 10}; !slices.Equal(evicted, want) {
		t.Fatalf("evicted %v, want %v", evicted, want)
	}
	if s.Count(lone) != 1 || s.Len() != 6 {
		t.Fatalf("count %d, len %d", s.Count(lone), s.Len())
	}

	tied := New[netip.Addr](Limits{Total: 2, OnTotal: EvictLargest})
	evicted = nil
	admitted(t, tied, srcA, 1, &evicted, 0)
	admitted(t, tied, srcB, 1, &evicted, 1)
	admitted(t, tied, lone, 1, &evicted, 2)
	if want := []int{0}; !slices.Equal(evicted, want) {
		t.Fatalf("a tie evicted %v, want the oldest", evicted)
	}
}

// After any admissions, evictions and releases every level's counts agree,
// each knows how many of its children hold each count, and no bound is
// passed.
func TestTheIndexesAgree(t *testing.T) {
	within := func(a netip.Addr) []netip.Addr {
		b := a.As4()
		return []netip.Addr{netip.AddrFrom4([4]byte{b[0]}), netip.AddrFrom4([4]byte{b[0], b[1]})}
	}
	s := NewNested(Limits{PerSource: 3, OnSource: EvictOldest, Total: 12, OnTotal: EvictLargest,
		Within: []Bound{{Max: 7, On: EvictLargest}, {Max: 5, On: EvictOldest}}}, within)
	r := rand.New(rand.NewPCG(1, 2))
	var held []*Ticket[netip.Addr]
	for step := range 20000 {
		if r.IntN(3) > 0 || len(held) == 0 {
			a := netip.AddrFrom4([4]byte{byte(r.IntN(3)), byte(r.IntN(3)), byte(r.IntN(3))})
			tk, ok := s.Admit(a, func() {})
			if !ok {
				t.Fatalf("step %d: refused under evicting bounds", step)
			}
			held = append(held, tk)
		} else {
			i := r.IntN(len(held))
			held[i].Release()
			held[i].Release()
			held = slices.Delete(held, i, i+1)
		}
		var check func(n *node[netip.Addr], level int)
		check = func(n *node[netip.Addr], level int) {
			bound := []int{12, 7, 5, 3}[level]
			if n.held > bound || level > 0 && n.held == 0 {
				t.Fatalf("step %d: level %d holds %d", step, level, n.held)
			}
			sum, most, sizes := 0, 0, map[int]int{}
			for k, c := range n.children {
				if c.key != k {
					t.Fatalf("step %d: a child is filed under another key", step)
				}
				sum += c.held
				most = max(most, c.held)
				sizes[c.held]++
				check(c, level+1)
			}
			if level < 3 && (sum != n.held || most != n.most || !maps.Equal(sizes, n.sizes)) {
				t.Fatalf("step %d: level %d holds %d, its children %d; most %d, counted %d", step, level, n.held, sum, most, n.most)
			}
			if level == 3 && s.leaves[n.key] != n {
				t.Fatalf("step %d: a source is not filed as one", step)
			}
		}
		check(s.root, 0)
	}
}

// One host's connections are bounded, and one site's, its hosts together.
func TestHostsAndSites(t *testing.T) {
	s := HostsAndSites(2)
	var given *Ticket[netip.Prefix]
	for _, tc := range []struct {
		addr string
		ok   bool
	}{
		{"2001:db8:1:1::1", true}, {"2001:db8:1:1::2", true}, {"2001:db8:1:1::3", false},
		{"2001:db8:1:2::1", true}, {"2001:db8:1:3::1", true}, {"2001:db8:1:4::1", true},
		{"2001:db8:1:5::1", true}, {"2001:db8:1:6::1", true}, {"2001:db8:1:6::2", true},
		{"2001:db8:1:7::1", false}, {"2001:db8:2::1", true},
		{"192.0.2.1", true}, {"192.0.2.1", true}, {"192.0.2.1", false},
		{"192.0.2.2", true}, {"192.0.2.2", true}, {"192.0.2.3", true}, {"192.0.2.3", true},
		{"192.0.2.4", true}, {"192.0.2.4", true}, {"192.0.2.5", false}, {"198.51.100.1", true},
	} {
		tk, got := s.Admit(Host(netip.MustParseAddr(tc.addr)), nil)
		if got != tc.ok {
			t.Errorf("a connection from %s taken %v, want %v", tc.addr, got, tc.ok)
		}
		if tc.addr == "192.0.2.4" {
			given = tk
		}
	}
	given.Release()
	if _, ok := s.Admit(Host(netip.MustParseAddr("192.0.2.5")), nil); !ok {
		t.Error("a site's connection given back is not taken again")
	}
}

// Releasing an entry costs the same however many the set holds, as a closed
// connection does at an ingress holding many.
func TestReleaseDoesNotGrowWithTheSet(t *testing.T) {
	if testing.Short() {
		t.Skip("timing")
	}
	type held struct {
		s       *Set[netip.Prefix]
		tickets []*Ticket[netip.Prefix]
		srcs    []netip.Prefix
	}
	fill := func(n int) *held {
		h := &held{s: HostsAndSites(n), tickets: make([]*Ticket[netip.Prefix], n), srcs: make([]netip.Prefix, n)}
		for i := range n {
			h.srcs[i] = Host(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
			h.tickets[i], _ = h.s.Admit(h.srcs[i], nil)
		}
		return h
	}
	// Windows of tens of milliseconds, interleaved, so that a time slice
	// lost to another process does not decide.
	churn := func(h *held) time.Duration {
		start := time.Now()
		for i := range 10000 {
			j := i * 7919 % len(h.tickets)
			h.tickets[j].Release()
			h.tickets[j], _ = h.s.Admit(h.srcs[j], nil)
		}
		return time.Since(start)
	}
	s, l := fill(1<<10), fill(1<<17)
	small, large := time.Duration(1<<62), time.Duration(1<<62)
	for range 5 {
		small, large = min(small, churn(s)), min(large, churn(l))
	}
	if large > 10*small {
		t.Errorf("releasing and admitting again took %v holding %d, %v holding %d", large, 1<<17, small, 1<<10)
	}
}
