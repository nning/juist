//go:build linux && !android

package conn

import (
	"maps"
	"testing"

	"github.com/tailscale/netlink"
)

type fakeNIC map[string]map[string]bool

func (f fakeNIC) Features(dev string) (map[string]bool, error) { return maps.Clone(f[dev]), nil }
func (f fakeNIC) Change(dev string, c map[string]bool) error {
	maps.Copy(f[dev], c)
	return nil
}
func (fakeNIC) Close() {}

// Serving sets UDP GRO forwarding on the uplink, where the device segments
// UDP, and stopping gives the uplink back what it had.
func TestServingForwardsUDPInBatchesWhileItServes(t *testing.T) {
	nic := fakeNIC{
		"juist0": {txUDPSegmentation: true},
		"eth0":   {rxUDPGROForwarding: false, rxGROList: true, "rx-gro": true},
	}
	defer func(o func() (nicFeatures, error)) { openNICFeatures = o }(openNICFeatures)
	openNICFeatures = func() (nicFeatures, error) { return nic, nil }
	r := &linuxRouter{logf: t.Logf, link: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "juist0"}}}
	r.forwardUDPInBatchesOn("eth0")
	if !nic["eth0"][rxUDPGROForwarding] || nic["eth0"][rxGROList] || !nic["eth0"]["rx-gro"] {
		t.Fatalf("serving left eth0 with %v", nic["eth0"])
	}
	r.restoreUplink()
	if nic["eth0"][rxUDPGROForwarding] || !nic["eth0"][rxGROList] {
		t.Fatalf("stopping left eth0 with %v", nic["eth0"])
	}

	// Set already, or of no use to the device, nothing changes, and
	// nothing is given back.
	nic["eth0"][rxUDPGROForwarding], nic["eth0"][rxGROList] = true, false
	r.forwardUDPInBatchesOn("eth0")
	nic["eth0"][rxUDPGROForwarding] = false
	r.restoreUplink()
	if nic["eth0"][rxUDPGROForwarding] {
		t.Error("an uplink juist did not change was changed back")
	}
	nic["juist0"][txUDPSegmentation] = false
	r.forwardUDPInBatchesOn("eth0")
	if nic["eth0"][rxUDPGROForwarding] {
		t.Error("set for a device that does not segment UDP")
	}
}
