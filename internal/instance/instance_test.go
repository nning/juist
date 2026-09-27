package instance

import (
	"strings"
	"testing"
)

func TestNames(t *testing.T) {
	for n := 1; n <= Max; n++ {
		got, err := Parse(Name(n))
		if err != nil || got != n {
			t.Fatalf("Parse(%q) = %d, %v", Name(n), got, err)
		}
		if !IsName(Name(n)) || !IsDevice(Name(n)) {
			t.Fatalf("%q is not an instance's name", Name(n))
		}
	}
	if _, err := Parse("juist0"); err == nil || !strings.Contains(err.Error(), "default") {
		t.Fatalf("juist0 parsed as an instance of its own: %v", err)
	}
	if !IsDevice("juist0") || IsName("juist0") {
		t.Fatal("juist0 is the default's device, and no instance of its own")
	}
	for _, bad := range []string{"", "juist", "juist10", "juist01", "juist-1", "juist+1", "Juist1", "juist1 ", "1", "juista"} {
		if IsName(bad) || IsDevice(bad) {
			t.Errorf("%q reads as an instance", bad)
		}
	}
}

// Every instance's ports stay clear of every other's, so none gives way to
// another at start.
func TestPortsDoNotMeet(t *testing.T) {
	const invite, data, gossip, relay = 41642, 41643, 41644, 41645
	seen := map[uint16]string{}
	for n := 0; n <= Max; n++ {
		for _, p := range []uint16{invite, data, gossip, relay} {
			got := Port(p, n)
			if other, taken := seen[got]; taken {
				t.Fatalf("instance %d's port %d is %s's too", n, got, other)
			}
			seen[got] = Name(n)
		}
	}
}
