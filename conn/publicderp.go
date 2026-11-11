package conn

import (
	"cmp"
	"slices"
	"sync"

	"tailscale.com/net/dnsfallback"
	"tailscale.com/tailcfg"
)

// publicRegionBase numbers Tailscale's public regions in the map, region n
// as publicRegionBase+n: below the STUN servers' region, apart from the
// regions member relays derive, which win a collision.
const publicRegionBase = MaxRegionID - 512

// publicRegionScore makes a public region a home below any member relay's:
// the data plane picks its home by latency times score, and a member relay
// scores one.
const publicRegionScore = 1e3

// tailscaleRegions are Tailscale's public DERP regions as the build embeds
// them, renumbered from publicRegionBase, in order.
var tailscaleRegions = sync.OnceValue(func() []*tailcfg.DERPRegion {
	var out []*tailcfg.DERPRegion
	for id, r := range dnsfallback.GetDERPMap().Regions {
		if id <= 0 || int(id) >= MaxRegionID-publicRegionBase {
			continue
		}
		r = r.Clone()
		r.RegionID = publicRegionBase + id
		r.RegionCode = "ts-" + r.RegionCode
		for _, n := range r.Nodes {
			n.RegionID = r.RegionID
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b *tailcfg.DERPRegion) int { return cmp.Compare(a.RegionID, b.RegionID) })
	return out
})

// publicRegionCities are where Tailscale's regions stand, by its numbers,
// which the embedded map names r1, r2 and on.
var publicRegionCities = map[int]string{1: "New York", 2: "San Francisco", 3: "Singapore", 4: "Frankfurt",
	5: "Sydney", 6: "Bangalore", 7: "Tokyo", 8: "London", 9: "Dallas", 10: "Seattle", 11: "São Paulo",
	12: "Chicago"}

// PublicRegions names Tailscale's public DERP regions by the region number
// the data plane gives them, for a peer's home and the status.
func PublicRegions() map[int]string {
	out := map[int]string{}
	for _, r := range tailscaleRegions() {
		out[int(r.RegionID)] = "Tailscale " + cmp.Or(publicRegionCities[int(r.RegionID-publicRegionBase)], r.RegionName)
	}
	return out
}
