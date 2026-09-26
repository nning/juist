package daemon

import (
	"context"
	"errors"
	"time"

	"github.com/nning/juist/internal/firewalld"
)

// firewallWait bounds asking the host firewall.
const firewallWait = 2 * time.Second

// recheckFirewall asks the host firewall again, apart from the tunnel check
// and without its probes, where a warning of it is up. One question runs at a
// time.
func (d *Daemon) recheckFirewall() {
	d.mu.Lock()
	if d.status.Firewalled == "" || d.askingFirewall || !d.waits.track() {
		d.mu.Unlock()
		return
	}
	d.askingFirewall = true
	gen := d.reachGen
	d.mu.Unlock()
	go func() {
		defer d.waits.done()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			select {
			case <-d.closed:
				cancel()
			case <-ctx.Done():
			}
		}()
		blocked, _ := d.firewalled(ctx, d.tunName, d.gossipPort)
		d.mu.Lock()
		defer d.mu.Unlock()
		d.askingFirewall = false
		if d.reachGen == gen && !blocked {
			d.status.Firewalled, d.status.FirewallUnsure = "", false
		}
	}()
}

// firewalled reports whether firewalld keeps TCP to port from arriving on
// iface; false where it does not run or will not say. A zone other than
// trusted whose ports it will not tell counts as keeping it out, unsure.
func firewalled(ctx context.Context, iface string, port uint16) (blocked, unsure bool) {
	ctx, cancel := context.WithTimeout(ctx, firewallWait)
	defer cancel()
	c, err := firewalld.Dial(ctx)
	if err != nil {
		return false, false
	}
	defer c.Close()
	zone, err := c.Zone(iface)
	if err != nil {
		return false, false
	}
	open, err := c.Admits(zone, port, "tcp")
	if errors.Is(err, firewalld.ErrNotAuthorized) {
		return true, true
	}
	return err == nil && !open, false
}
