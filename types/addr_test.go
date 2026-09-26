package types

import (
	"net/netip"
	"testing"
)

func TestValidateV4Prefix(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		ok     bool
	}{
		{"10.111.0.0/24", true},
		{"172.20.0.0/16", true},
		{"192.168.77.0/24", true},
		{"198.18.4.0/22", true},
		{"100.64.0.0/10", true},
		{"10.0.0.0/8", true},
		{"10.111.0.1/24", false},   // not masked
		{"8.8.8.0/24", false},      // public
		{"192.168.0.0/15", false},  // wider than private space
		{"198.18.0.0/14", false},   // wider than the benchmarking block
		{"10.111.0.0/29", false},   // too small
		{"0.0.0.0/0", false},       // everything
		{"fd00::/64", false},       // not IPv4
		{"169.254.0.0/16", false},  // link-local
		{"127.0.0.0/8", false},     // loopback
		{"224.0.0.0/8", false},     // multicast
		{"172.15.255.0/24", false}, // just outside 172.16/12
	} {
		err := ValidateV4Prefix(netip.MustParsePrefix(tc.prefix))
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v, want ok=%v", tc.prefix, err, tc.ok)
		}
	}
}
