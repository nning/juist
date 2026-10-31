package conn

import (
	"testing"
	"time"

	"tailscale.com/net/netcheck"
	"tailscale.com/tailcfg"
)

// A relay that answered ICMP and not HTTPS in a report counts as pinged
// alone, read from netcheck's lines, and one HTTPS reached does not.
func TestARelayPingedAloneIsReadFromNetchecksLines(t *testing.T) {
	n := newNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	m := n.mgr.(*tsManager)
	m.logf(icmpLatencyLine, "j8", tailcfg.DERPRegionID(8), time.Millisecond)
	m.logf(icmpLatencyLine, "j9", tailcfg.DERPRegionID(9), time.Millisecond)
	m.logf(httpsFailedLine, "j8", tailcfg.DERPRegionID(8), "connection refused")
	m.logf(httpsFailedLine, "j10", tailcfg.DERPRegionID(10), "connection refused")
	if got := m.pinged.lastAlone(); len(got) != 0 {
		t.Errorf("pinged alone before the report ended: %v", got)
	}
	m.logf(netcheckReport, "report")
	if got := m.pinged.lastAlone(); len(got) != 1 || !got[8] {
		t.Errorf("pinged alone %v, want 8 alone", got)
	}
	m.logf(netcheckReport, "report")
	if got := m.pinged.lastAlone(); len(got) != 0 {
		t.Errorf("a report without ICMP left %v pinged alone", got)
	}
}

// netcheck is held at its own choice where HTTPS reached it, else at the
// nearest relay HTTPS reached, and at none where it reached none; it chooses
// itself where nothing was pinged alone, or UDP was answered.
func TestAHomePingedAloneIsHeldAtOneHTTPSReached(t *testing.T) {
	stun := map[tailcfg.DERPRegionID]bool{100: true}
	lat := map[tailcfg.DERPRegionID]time.Duration{7: 30 * time.Millisecond, 8: 20 * time.Millisecond, 9: 5 * time.Millisecond, 100: time.Millisecond}
	for _, c := range []struct {
		name  string
		r     *netcheck.Report
		alone map[int]bool
		want  int
		hold  bool
	}{
		{"nothing pinged alone", &netcheck.Report{PreferredDERP: 9, RegionLatency: lat}, nil, 0, false},
		{"UDP", &netcheck.Report{UDP: true, PreferredDERP: 9, RegionLatency: lat}, map[int]bool{9: true}, 0, false},
		{"its choice reached", &netcheck.Report{PreferredDERP: 7, RegionLatency: lat}, map[int]bool{9: true}, 7, true},
		{"its choice pinged alone", &netcheck.Report{PreferredDERP: 9, RegionLatency: lat}, map[int]bool{9: true}, 8, true},
		{"none reached", &netcheck.Report{PreferredDERP: 9, RegionLatency: lat}, map[int]bool{7: true, 8: true, 9: true}, 0, true},
	} {
		got, hold := homeToHold(c.r, c.alone, stun)
		if got != c.want || hold != c.hold {
			t.Errorf("%s: held at %d, %v; want %d, %v", c.name, got, hold, c.want, c.hold)
		}
	}
	if _, hold := homeToHold(nil, map[int]bool{9: true}, stun); hold {
		t.Error("held without a report")
	}
}
