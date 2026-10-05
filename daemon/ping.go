package daemon

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// NetworkChanged tells the data plane that the host's networks changed, so
// that it finds its paths again at once, where its monitor would not notice.
func (d *Daemon) NetworkChanged() {
	if n, ok := d.manager.(interface{ NetworkChanged() }); ok {
		n.NetworkChanged()
	}
}

// pingWait bounds a ping: the engine may never answer.
const pingWait = 5 * time.Second

var errNotInstalled = errors.New("no tunnel to that member is installed")

// Ping sends one TSMP ping through the tunnel to member id, at its IPv4
// address where it has one, and reports the round trip or why none came back.
// The member's data plane answers it, so a host without a stack of its own,
// or one whose firewall drops ICMP, answers as well.
func (d *Daemon) Ping(ctx context.Context, id types.Identity) (*ipc.Ping, error) {
	var to netip.Addr
	d.mu.Lock()
	for _, p := range d.installed {
		if p.id != id {
			continue
		}
		for _, a := range p.peer.Addrs {
			if !to.IsValid() || a.Addr().Is4() && !to.Is4() {
				to = a.Addr()
			}
		}
	}
	d.mu.Unlock()
	if !to.IsValid() {
		return nil, errNotInstalled
	}
	got := make(chan conn.PingResult, 1)
	d.manager.Echo(to, func(r conn.PingResult) {
		select {
		case got <- r:
		default:
		}
	})
	t := time.NewTimer(pingWait)
	defer t.Stop()
	select {
	case r := <-got:
		if r.Err != "" {
			return &ipc.Ping{Err: r.Err}, nil
		}
		return &ipc.Ping{Micros: max(r.Latency.Microseconds(), 1)}, nil
	case <-t.C:
		return &ipc.Ping{Err: "no answer within " + pingWait.String()}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
