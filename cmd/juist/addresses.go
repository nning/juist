package main

import (
	"fmt"
	"net/netip"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
	"go4.org/netipx"
)

// nextV4 returns the lowest overlay IPv4 address in the network's range that
// is not [givenOut]: handing on one a removed device still believes it holds
// would have members route one device's traffic to another. history includes
// the records off the chain, whose admissions may yet be reissued.
func nextV4(state *log.State, history []types.AUM) (netip.Addr, error) {
	taken := map[netip.Addr]bool{}
	for v4 := range givenOut(state, history) {
		taken[v4] = true
	}
	v4, err := firstFreeV4(state.V4Range(), taken)
	if err != nil && len(state.Nodes()) < types.MaxNodes {
		// Full by history rather than by members: every address has been
		// given out once. A range of its own is 1022 addresses for good.
		return netip.Addr{}, fmt.Errorf("%w: every address in it went to a device once, and none is "+
			"handed out twice\nhint: juist network renumber PREFIX, into a larger range", err)
	}
	return v4, err
}

// firstFreeV4 skips r's first and last address, which some systems treat as
// the network and broadcast address.
func firstFreeV4(r netip.Prefix, taken map[netip.Addr]bool) (netip.Addr, error) {
	last := netipx.PrefixLastIP(r)
	for a := r.Addr().Next(); a.Less(last); a = a.Next() {
		if !taken[a] {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("IPv4 range %v full", r)
}
