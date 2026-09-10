package mdns

import (
	"slices"
	"testing"
)

// TestSkipInterfaceLeavesOverlayDeviceAlone pins [Options.SkipInterface]: the
// named interface is neither joined nor written to. groupConn sends every
// announcement out of every interface it joined, and a Linux TUN carries
// IFF_MULTICAST, so without this discovery pushes beacons into the tunnel.
//
// rejoin is driven directly rather than through listenMulticast, so the
// assertion holds on a host with only one multicast interface, where skipping
// it leaves none and listenMulticast reports a startup failure.
func TestSkipInterfaceLeavesOverlayDeviceAlone(t *testing.T) {
	c, err := listenMulticast(Group, "")
	if err != nil {
		t.Skipf("cannot open the multicast socket here: %v", err)
	}
	defer c.Close()
	// Safe here and only here: no Beacon is running, so nothing else calls
	// rejoin or WriteTo concurrently.
	gc := c.(*groupConn)

	before := gc.names()
	if len(before) == 0 {
		t.Skip("no multicast-capable interface on this host")
	}

	// An unknown name changes nothing: the filter must match on the name, not
	// merely shorten the list.
	gc.skipIface = "juist-no-such-device"
	gc.rejoin()
	if got := gc.names(); !slices.Equal(got, before) {
		t.Errorf("skipping an absent interface changed the join set: %v -> %v", before, got)
	}

	// The real one disappears, and only it.
	skip := before[0]
	gc.skipIface = skip
	gc.rejoin()
	got := gc.names()
	if slices.Contains(got, skip) {
		t.Errorf("SkipInterface %q was joined anyway; joined %v", skip, got)
	}
	want := slices.DeleteFunc(slices.Clone(before), func(n string) bool { return n == skip })
	if !slices.Equal(got, want) {
		t.Errorf("joined %v skipping %q, want %v", got, skip, want)
	}
}

// names is the joined interface names, for tests.
func (c *groupConn) names() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.ifaces))
	for _, ifi := range c.ifaces {
		out = append(out, ifi.Name)
	}
	return out
}
