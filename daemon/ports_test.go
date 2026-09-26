package daemon

import (
	"net"
	"testing"

	"github.com/nning/juist/conn"
)

// A taken gossip port gives way where fallback is allowed, and otherwise
// fails New with what it had started closed again.
func TestATakenGossipPortGivesWayOnlyWhereAllowed(t *testing.T) {
	taken, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	port := uint16(portOf(taken.Addr()))

	for _, fallback := range []bool{false, true} {
		nw := newNetwork(t, 1)
		auth, st := nw.authorityFor(t)
		dev := nw.devices[0]
		mgr := &fakeManager{}
		d, err := New(Options{
			Authority: auth, Storage: st, Identity: dev.identity, Recipient: dev.recipient, WireGuard: dev.wgPrivate,
			Connect:          func(conn.Options) (conn.Manager, error) { return mgr, nil },
			GossipPort:       port,
			PortFallback:     fallback,
			DisableDiscovery: true, DisableDHT: true,
			Logf: safeLogf(t, ""),
		})
		switch {
		case !fallback && err == nil:
			d.Close()
			t.Fatal("New took a port another program holds")
		case !fallback && !mgr.closed:
			t.Error("a failed New left the data plane open")
		case fallback && err != nil:
			t.Fatalf("New with fallback: %v", err)
		case fallback:
			if got := d.Status().GossipPort; got == port || got == 0 {
				t.Errorf("gossip listens on port %d with %d taken", got, port)
			}
			d.Close()
		}
	}
}
