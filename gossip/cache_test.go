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

// A cache told preshared keys are not yet the network's drops the
// announcements naming what they need, and refuses more.
func TestACacheRefusesPQAnnouncementsItIsToldOf(t *testing.T) {
	c := NewCache()
	pq := Endpoint{Identity: types.Identity{1}, Seq: 1, Epoch: 3, PairStore: 9}
	plain := Endpoint{Identity: types.Identity{2}, Seq: 1}
	if !c.Add(pq) || !c.Add(plain) {
		t.Fatal("not taken")
	}
	c.SetPQ(false)
	if _, ok := c.Get(pq.Identity); ok {
		t.Error("an announcement naming an epoch is kept")
	}
	if _, ok := c.Get(plain.Identity); !ok {
		t.Error("one naming none went too")
	}
	pq.Seq = 2
	if c.Add(pq) {
		t.Error("an announcement naming an epoch was taken")
	}
	c.SetPQ(true)
	if !c.Add(pq) {
		t.Error("one was refused once the schema has it")
	}
}
