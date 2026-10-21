package relay

import (
	"net/netip"

	"github.com/nning/juist/internal/admit"
)

// newPendingSet counts the connections a relay holds that nothing admitted
// yet, by site (an IPv4 /24, an IPv6 /48), group (an IPv4 address, an IPv6
// /56, as one customer holds) and host (an IPv4 address, an IPv6 /64). Past a
// site's bound a newcomer closes the oldest of the host holding the most in
// the group holding the most there, and past the bound in all the same in
// the site holding the most, ties going to the oldest at every level: a
// flood displaces its own (who can still churn a member out:
// 02-threat-model.md, residual weakness 15).
func newPendingSet(perSite, total int) *admit.Set[netip.Prefix] {
	return admit.NewNested(admit.Limits{Total: total, OnTotal: admit.EvictLargest,
		Within: []admit.Bound{{Max: perSite, On: admit.EvictLargest}}}, siteAndGroup)
}

// siteAndGroup are the site and the group host is within.
func siteAndGroup(host netip.Prefix) []netip.Prefix {
	return []netip.Prefix{admit.Site(host.Addr()), admit.Group(host.Addr())}
}
