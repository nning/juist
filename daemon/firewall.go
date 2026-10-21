package daemon

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
		blocked, _ := d.firewalled(d.ctx, d.tunName, d.gossipPort)
		d.mu.Lock()
		defer d.mu.Unlock()
		d.askingFirewall = false
		if d.reachGen == gen && !blocked {
			d.status.Firewalled, d.status.FirewallUnsure = "", false
		}
	}()
}
