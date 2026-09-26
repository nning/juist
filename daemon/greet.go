package daemon

import (
	"context"
	"net/netip"
	"time"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/types"
)

// welcome takes the announcement a guest sent with its join, which the host
// holds no other way while it sits behind NAT and the guest does not, and
// greets the guest where it sent none that verifies.
func (d *Daemon) welcome(id types.Identity, announcement []byte, from string) {
	if len(announcement) > 0 {
		e, err := gossip.DecodeEndpoint(announcement)
		switch {
		case err != nil:
			d.logf("daemon: the announcement %v sent with its join: %v", id.ShortString(), err)
		case e.Identity != id:
			d.logf("daemon: %v sent another device's announcement with its join", id.ShortString())
		default:
			if err := d.Learn(e); err == nil {
				return
			}
			d.logf("daemon: the announcement %v sent with its join: %v", id.ShortString(), err)
		}
	}
	d.greet(id, from)
}

// defaultGreetAfter is when a device that just admitted a member tries to reach it,
// counted from the admission, until it holds the member's announcement.
var defaultGreetAfter = []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute}

// greet reaches a member this device just admitted, at the address the
// admission ran from. A new member is announced to the others only by gossip
// or the DHT, and where it has a public address and this device sits behind
// NAT, only this side can open the session: without it, neither holds the
// other's announcement and no tunnel comes up. The DHT is asked sooner too,
// for a member no session reaches.
func (d *Daemon) greet(id types.Identity, from string) {
	var at netip.AddrPort
	// Where log sync runs through the tunnel alone, nothing listens there.
	if ap, err := netip.ParseAddrPort(from); err == nil && !d.overlayOnly && d.usableUnderlay(ap.Addr().Unmap()) {
		at = netip.AddrPortFrom(ap.Addr().Unmap(), DefaultGossipPort)
	}
	d.greetAt(id, at)
}

// greetAt is [Daemon.greet] with the member's gossip address given, invalid
// for none.
func (d *Daemon) greetAt(id types.Identity, at netip.AddrPort) {
	if !d.waits.track() {
		return
	}
	go func() {
		defer d.waits.done()
		// Closing the daemon ends a session under way rather than waiting it
		// out: Close, and a reset holding the service, wait for this.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			select {
			case <-d.closed:
				cancel()
			case <-ctx.Done():
			}
		}()
		var waited time.Duration
		for _, after := range d.greetAfter {
			select {
			case <-ctx.Done():
				return
			case <-time.After(after - waited):
			}
			waited = after
			if _, held := d.endpoints.Get(id); held {
				return
			}
			// A session through a relay's address reaches the relay member,
			// not the guest: only holding the guest's announcement counts.
			if at.IsValid() && d.gossip.SyncWith(ctx, at, id) == nil {
				if _, held := d.endpoints.Get(id); held {
					d.MarkDirty()
					return
				}
			}
			if d.dht != nil {
				d.dht.Kick()
			}
		}
	}()
}
