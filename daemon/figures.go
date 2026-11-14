package daemon

import (
	"slices"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// tunnelFigures is rs with each peer's last handshake and bytes read from the
// data plane now, as the check that fills the rest runs every 30 s.
func (d *Daemon) tunnelFigures(rs []ipc.PeerReach) []ipc.PeerReach {
	if len(rs) == 0 {
		return rs
	}
	d.mu.Lock()
	ids := make(map[types.Identity]uint64, len(d.installed))
	for _, p := range d.installed {
		ids[p.id] = p.peer.ID
	}
	d.mu.Unlock()
	tunnels := d.manager.Tunnels()
	out := slices.Clone(rs)
	for i := range out {
		id, ok := ids[out[i].Identity]
		if !ok {
			continue
		}
		t, ok := tunnels[id]
		if !ok {
			continue
		}
		if !t.LastHandshake.IsZero() {
			out[i].Handshake = t.LastHandshake.Unix()
		}
		out[i].RxBytes, out[i].TxBytes = t.RxBytes, t.TxBytes
	}
	return out
}
