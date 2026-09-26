package underlay

import "testing"

// TestInternalInterface: what leads only into this host is left out of what a
// device announces, and what may carry its LAN address is not.
func TestInternalInterface(t *testing.T) {
	for name, want := range map[string]bool{
		"juist0":          true,
		"tailscale0":      true,
		"ztabcdef12":      true,
		"docker0":         true,
		"br-3f2a9c0d1e4b": true,
		"veth1a2b3c":      true,
		"virbr0":          true,
		"lxcbr0":          true,
		"podman0":         true,
		"eth0":            false,
		"enp3s0":          false,
		"wlp2s0":          false,
		"br0":             false,
		"br-lan":          false,
		"br-3F2A9C0D1E4B": false,
	} {
		if got := InternalInterface(name); got != want {
			t.Errorf("InternalInterface(%q) = %v, want %v", name, got, want)
		}
	}
}
