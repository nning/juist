package relay

import (
	"net/netip"
	"testing"

	"golang.org/x/time/rate"
)

// Spoofed sources do not grow the hosts tracked past their bound; past it,
// the rate in all still answers.
func TestSTUNTracksBoundedHosts(t *testing.T) {
	s := &stunResponder{answers: rate.NewLimiter(rate.Inf, 0), perSource: newSTUNRates()}
	base := netip.MustParseAddr("10.0.0.0").As4()
	for i := range stunSources + 100 {
		a := base
		a[1], a[2], a[3] = byte(i>>16), byte(i>>8), byte(i)
		s.allow(netip.AddrFrom4(a))
	}
	if n := s.perSource.Len(); n > stunSources {
		t.Fatalf("%d hosts tracked, past %d", n, stunSources)
	}
	if !s.allow(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("a new host past the bound went unanswered")
	}
}

// An IPv6 host is its /64, which one host holds entire.
func TestSTUNCountsAnIPv6HostByItsPrefix(t *testing.T) {
	s := &stunResponder{answers: rate.NewLimiter(rate.Inf, 0), perSource: newSTUNRates()}
	for range 2 * stunPerSource {
		s.allow(netip.MustParseAddr("2001:db8::1"))
	}
	if s.allow(netip.MustParseAddr("2001:db8::2")) {
		t.Fatal("another address in the /64 was answered past the host's burst")
	}
	if !s.allow(netip.MustParseAddr("2001:db8:0:1::1")) {
		t.Fatal("another /64 went unanswered")
	}
}
