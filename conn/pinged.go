package conn

import (
	"context"
	"maps"
	"slices"
	"sync"

	"tailscale.com/net/netcheck"
	"tailscale.com/tailcfg"
)

// netcheck's lines for a region answering ICMP, and for one HTTPS did not
// reach; a test holds both to the pinned module's.
const (
	icmpLatencyLine = "netcheck: [v1] ICMP latency of %v (%d): %v"
	httpsFailedLine = "netcheck: [v1] netcheck: measuring HTTPS latency of %v (%d): %v"
)

// pinged holds the regions netcheck measured by ICMP and not by HTTPS,
// whose latency says nothing of TCP: those of the report under way, and of
// the last one finished.
type pinged struct {
	mu          sync.Mutex
	icmp, https map[int]bool
	last        map[int]bool
	held        int // the home netcheck is held at, 0 for none
}

// read takes one of netcheck's lines, and the end of a report.
func (p *pinged) read(format string, args []any) {
	region := func() (int, bool) {
		if len(args) != 3 {
			return 0, false
		}
		r, ok := args[1].(tailcfg.DERPRegionID)
		return int(r), ok
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch format {
	case icmpLatencyLine:
		if r, ok := region(); ok {
			mark(&p.icmp, r)
		}
	case httpsFailedLine:
		if r, ok := region(); ok {
			mark(&p.https, r)
		}
	case netcheckReport:
		p.last = nil
		for r := range p.icmp {
			if p.https[r] {
				mark(&p.last, r)
			}
		}
		p.icmp, p.https = nil, nil
	}
}

func mark(m *map[int]bool, r int) {
	if *m == nil {
		*m = map[int]bool{}
	}
	(*m)[r] = true
}

// lastAlone are the regions the last report reached by ICMP alone.
func (p *pinged) lastAlone() map[int]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return maps.Clone(p.last)
}

// homeToHold is the region netcheck is to be held at after report r, whose
// regions alone were reached by ICMP alone: its own choice where HTTPS
// reached that, else the nearest relay HTTPS reached, 0 for none; hold is
// false where nothing was pinged alone, as with UDP, and netcheck chooses.
func homeToHold(r *netcheck.Report, alone map[int]bool, stun map[tailcfg.DERPRegionID]bool) (region int, hold bool) {
	if r == nil || r.UDP || len(alone) == 0 {
		return 0, false
	}
	if p := r.PreferredDERP; p != 0 && !alone[int(p)] && !stun[p] {
		return int(p), true
	}
	best := tailcfg.DERPRegionID(0)
	for id, d := range r.RegionLatency {
		if alone[int(id)] || stun[id] {
			continue
		}
		if best == 0 || d < r.RegionLatency[best] || d == r.RegionLatency[best] && id < best {
			best = id
		}
	}
	return int(best), true
}

// holdHome keeps netcheck from taking a relay pinged alone for a home: it is
// held at the nearest one HTTPS reached, and let go once nothing is pinged
// alone. It reports whether the last report reached no relay but by ICMP.
func (m *tsManager) holdHome() (none bool) {
	r := m.magic.GetLastNetcheckReport(context.Background())
	alone := m.pinged.lastAlone()
	region, hold := homeToHold(r, alone, *m.stunRegions.Load())
	m.pinged.mu.Lock()
	moved := region != m.pinged.held
	m.pinged.held = region
	m.pinged.mu.Unlock()
	if moved {
		if hold {
			m.logf("conn: relays %v answered ICMP alone; home held at %d", slices.Sorted(maps.Keys(alone)), region)
		} else {
			m.logf("conn: home no longer held")
		}
		m.magic.DebugForcePreferDERP(tailcfg.DERPRegionID(region))
		if region != 0 && r != nil && int(r.PreferredDERP) != region {
			m.magic.ReSTUN("juist-pinged-home")
		}
	}
	return hold && region == 0
}
