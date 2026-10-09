package gossip

import (
	"testing"

	"github.com/nning/juist/types"
)

// A cache told relay names are not yet the network's drops those it holds
// and refuses more.
func TestACacheRefusesRelayNamesItIsToldOf(t *testing.T) {
	c := NewCache()
	named := Endpoint{Identity: types.Identity{1}, Seq: 1, Relay: &RelayInfo{Port: 1, Name: "relay.example.org"}}
	plain := Endpoint{Identity: types.Identity{2}, Seq: 1, Relay: &RelayInfo{Port: 1}}
	if !c.Add(named) || !c.Add(plain) {
		t.Fatal("not taken")
	}
	c.SetRelayNames(false)
	if _, ok := c.Get(named.Identity); ok {
		t.Error("a relay name held is kept")
	}
	if _, ok := c.Get(plain.Identity); !ok {
		t.Error("an announcement without a relay name went too")
	}
	named.Seq = 2
	if c.Add(named) {
		t.Error("a relay name was taken")
	}
	c.SetRelayNames(true)
	if !c.Add(named) {
		t.Error("a relay name was refused once the schema has it")
	}
}
