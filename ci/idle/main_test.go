package main

import (
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/discovery/mdns"
)

// What the budget counts: juist's flows, not the link's own or what Android
// sends for itself.
func TestTheBudgetCountsJuistsTrafficAlone(t *testing.T) {
	text := `reading from file /data/local/tmp/idle.pcap, link-type EN10MB (Ethernet), snapshot length 262144
1792249667.713984 IP 172.21.0.2.41743 > 10.0.2.16.41643: UDP, length 124
1792249667.714193 IP 10.0.2.16.41643 > 172.21.0.2.41743: UDP, length 110
1792249667.814193 IP 10.0.2.16.40000 > 172.21.0.2.41754: tcp 0
1792248895.436945 IP 10.0.2.16.5353 > 224.0.0.251.5353: UDP, length 207
1792248908.563620 ARP, Request who-has 10.0.2.2 tell 10.0.2.16, length 28
1792248895.438121 IP6 fe80::2 > fe80::b869:4d27:898:cc15: ICMP6, destination unreachable, unreachable route ff02::fb, length 263
1792249060.503435 IP 203.0.113.77 > 10.0.2.16: ICMP 172.21.0.2 udp port 41743 unreachable, length 160
1792249061.000000 IP 10.0.2.16.33333 > 10.0.2.3.53: UDP, length 40
1792249062.000000 IP6 fe80::2 > fe80::1: ICMP6, destination unreachable, unreachable port, fe80::1 udp port 41643, length 60
`
	counts, sizes := classify(text, []int{41743, 41753})
	want := map[string]int{
		"members' data plane": 2, "members' log sync": 1, "mDNS": 1, "DNS": 1, "ICMP": 2,
		"ARP" + uncounted: 1, "ICMP" + uncounted: 1,
	}
	for k, v := range want {
		if counts[k] != v {
			t.Errorf("%s: %d, want %d (all: %v)", k, counts[k], v, counts)
		}
	}
	if sizes["members' data plane"] != 234 {
		t.Errorf("the members' data plane carried %d bytes, want 234", sizes["members' data plane"])
	}
	r := &report{counts: counts, length: time.Hour}
	if r.total() != 7 {
		t.Errorf("the budget counts %d, want 7", r.total())
	}
}

// Android's own mDNS and lookups are told from juist's by what they name.
func TestAndroidsOwnRecordsAreToldApart(t *testing.T) {
	verbose := `15:17:09.548223 IP (tos 0x0, ttl 255, id 32592, offset 0, flags [DF], proto UDP (17), length 235)
    10.0.2.16.5353 > 224.0.0.251.5353: [udp sum ok] 0 [5q] [5n] ANY (QU)? adb-EMULATOR37X2X12X0._adb._tcp.local.
1792250230.298287 IP (tos 0x0, ttl 255, id 32657, offset 0, flags [DF], proto UDP (17), length 664)
    10.0.2.16.5353 > 224.0.0.251.5353: [udp sum ok] 0*- [0q] 1/0/0 abcdefgh._juist._udp.local. TXT "x"
`
	if n := notOurs(verbose, func(r string) bool { return strings.Contains(r, mdns.Service) }); n != 1 {
		t.Errorf("%d records taken for Android's, want 1", n)
	}
}

// juist's own lookups are the STUN servers' and the DHT's routers'.
func TestJuistsLookupsAreItsOwn(t *testing.T) {
	for rec, want := range map[string]bool{
		"A? stun.l.google.com.":             true,
		"A? router.bittorrent.com.":         true,
		"A? connectivitycheck.gstatic.com.": false,
	} {
		if oursDNS(rec) != want {
			t.Errorf("%q taken for juist's: %v", rec, !want)
		}
	}
}
