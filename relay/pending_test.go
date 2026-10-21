package relay

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/nning/juist/internal/admit"
)

type evictions []string

func (ev *evictions) admit(p *admit.Set[netip.Prefix], addr, name string) *admit.Ticket[netip.Prefix] {
	t, _ := p.Admit(admit.Host(netip.MustParseAddr(addr)), func() { *ev = append(*ev, name) })
	return t
}

// TestAFloodInAMembersSiteDisplacesItsOwn: past a site's bound the host
// holding the most there gives way, not a member's older lone connection.
func TestAFloodInAMembersSiteDisplacesItsOwn(t *testing.T) {
	var ev evictions
	p := newPendingSet(3, 100)
	ev.admit(p, "192.0.2.1", "member")
	ev.admit(p, "192.0.2.9", "a")
	ev.admit(p, "192.0.2.9", "b")
	ev.admit(p, "192.0.2.9", "c")
	if len(ev) != 1 || ev[0] != "a" {
		t.Fatalf("evicted %v, want the flooding host's oldest", ev)
	}
}

// TestPastTheBoundInAllTheLargestSiteGivesWay: past the bound in all the
// site holding the most gives way, and among sites tied the oldest.
func TestPastTheBoundInAllTheLargestSiteGivesWay(t *testing.T) {
	var ev evictions
	p := newPendingSet(100, 3)
	ev.admit(p, "198.51.100.1", "member")
	ev.admit(p, "203.0.113.1", "a")
	ev.admit(p, "203.0.113.2", "b")
	ev.admit(p, "203.0.113.3", "c")
	if len(ev) != 1 || ev[0] != "a" {
		t.Fatalf("evicted %v, want the largest site's oldest", ev)
	}
	ev = nil
	q := newPendingSet(100, 3)
	for i := range 4 {
		ev.admit(q, fmt.Sprintf("10.0.%d.1", i), fmt.Sprint(i))
	}
	if len(ev) != 1 || ev[0] != "0" {
		t.Fatalf("evicted %v among tied sites, want the oldest", ev)
	}
}

// TestANeighboursPrefixesDisplaceTheirOwn: in an IPv6 site the /56 holding
// the most gives way, however many /64s it spreads over, and not a member's
// older connection from a /56 of its own.
func TestANeighboursPrefixesDisplaceTheirOwn(t *testing.T) {
	var ev evictions
	p := newPendingSet(4, 100)
	ev.admit(p, "2001:db8:1700:aa00::1", "member")
	for i := range 4 {
		ev.admit(p, fmt.Sprintf("2001:db8:1700:bb%02x::1", i), fmt.Sprint(i))
	}
	if len(ev) != 1 || ev[0] != "0" {
		t.Fatalf("evicted %v, want the neighbour's oldest", ev)
	}
}
