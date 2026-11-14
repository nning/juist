package daemon

import (
	"testing"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/ipc"
)

// A status carries each peer's last handshake and bytes as the data plane
// has them when asked; a reader gets the handshake but not the bytes.
func TestStatusCarriesTunnelFigures(t *testing.T) {
	f := newReconcileFixture(t, 3)
	f.learn(t, f.nw.devices[1], 7001)
	f.learn(t, f.nw.devices[2], 7002)
	if err := f.d.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.d.refreshReach(t.Context())
	live := f.installed(t, 1)
	at := time.Unix(1_700_000_123, 0)
	f.mgr.mu.Lock()
	f.mgr.tunnels = map[uint64]conn.Tunnel{live.ID: {LastHandshake: at, RxBytes: 4096, TxBytes: 512}}
	f.mgr.mu.Unlock()

	before := f.d.Status().Reach
	got := f.d.tunnelFigures(before)
	if len(got) != 2 {
		t.Fatalf("%d peers in the status, want 2", len(got))
	}
	for i, r := range got {
		switch r.Identity {
		case f.nw.devices[1].record.Identity:
			if r.Handshake != at.Unix() || r.RxBytes != 4096 || r.TxBytes != 512 {
				t.Errorf("live peer: handshake %d, rx %d, tx %d", r.Handshake, r.RxBytes, r.TxBytes)
			}
		case f.nw.devices[2].record.Identity:
			if r.Handshake != 0 || r.RxBytes != 0 || r.TxBytes != 0 {
				t.Errorf("peer without a handshake: handshake %d, rx %d, tx %d", r.Handshake, r.RxBytes, r.TxBytes)
			}
		default:
			t.Errorf("unknown peer at %d", i)
		}
		if before[i].Handshake != 0 {
			t.Error("the daemon's own status was changed")
		}
	}

	st := ipc.Status{Tunnels: ipc.Tunnels{Reach: got}}
	var handshake bool
	for _, r := range st.ForReader().Reach {
		handshake = handshake || r.Handshake == at.Unix()
		if r.RxBytes != 0 || r.TxBytes != 0 {
			t.Errorf("a reader sees %d bytes received, %d sent", r.RxBytes, r.TxBytes)
		}
	}
	if !handshake {
		t.Error("a reader does not see the handshake")
	}
}
