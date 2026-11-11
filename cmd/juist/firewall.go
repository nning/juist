package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nning/juist/internal/firewalld"
	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// Host firewalls juist knows how to ask about. Nothing here changes one: the
// packages let juist0 through at install, and a port an invite needs for its
// few minutes is the operator's to open, so juist only says how.

func ufwEnabled() bool {
	b, err := os.ReadFile("/etc/ufw/ufw.conf")
	if err != nil {
		return false
	}
	for line := range strings.Lines(string(b)) {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k == "ENABLED" {
			return strings.Trim(v, `"' `) == "yes"
		}
	}
	return false
}

// invitePortHint says how to let an invite in through this host's firewall,
// or returns "" where no firewall is on or it is known to let the port in.
func invitePortHint(port uint16) string {
	p := strconv.Itoa(int(port)) + "/tcp"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if c, err := firewalld.Dial(ctx); err == nil {
		defer c.Close()
		if firewalldAdmitsInvite(c, port) {
			return ""
		}
		return "sudo firewall-cmd --add-port=" + p
	}
	if ufwEnabled() {
		return "sudo ufw allow " + p
	}
	return ""
}

// firewalldAdmitsInvite reports whether firewalld's default zone is known to
// let an invite on port in.
func firewalldAdmitsInvite(c *firewalld.Client, port uint16) bool {
	zone, err := c.Zone("")
	if err != nil {
		return false
	}
	if open, err := c.Admits(zone, port, "tcp"); err == nil && open {
		return true
	}
	if port != DefaultInvitePort {
		return false
	}
	open, err := c.HasService(zone, "juist-invite")
	return err == nil && open
}

// firewalldZones is what firewalldUDP asks of firewalld.
type firewalldZones interface {
	Zone(iface string) (string, error)
	Admits(zone string, port uint16, proto string) (bool, error)
	HasService(zone, service string) (bool, error)
}

// firewalldBlocksUDP asks a running firewalld, as [firewalldUDP] does, about
// UDP to port arriving on the default route's interface.
func firewalldBlocksUDP(ctx context.Context, port uint16) (zone string, service, unsure bool) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	c, err := firewalld.Dial(ctx)
	if err != nil {
		return "", false, false
	}
	defer c.Close()
	return firewalldUDP(c, uplink(os.ReadFile), port)
}

// firewalldUDP returns the zone that keeps UDP to port from arriving on
// iface, "" where none is known to; whether its service "juist" is defined,
// which the default port's hint then names; and unsure where the zone's
// ports could not be read.
func firewalldUDP(c firewalldZones, iface string, port uint16) (zone string, service, unsure bool) {
	zone, err := c.Zone(iface)
	if err != nil || zone == "" {
		return "", false, false
	}
	open, err := c.Admits(zone, port, "udp")
	if errors.Is(err, firewalld.ErrNotAuthorized) {
		return zone, false, true
	}
	if err != nil || open {
		return "", false, false
	}
	if port != serviceDataPort {
		return zone, false, false
	}
	open, err = c.HasService(zone, "juist")
	switch {
	case err == nil && !open:
		return zone, true, false
	case err != nil && strings.Contains(err.Error(), "INVALID_SERVICE"):
		return zone, false, false // undefined, so it lets nothing in
	}
	return "", false, false
}

// pastableZone reports whether zone is a firewalld zone name a shell reads
// as one word: letters, digits, - and _, at most 17 of them.
func pastableZone(zone string) bool {
	if len(zone) == 0 || len(zone) > 17 || zone[0] == '-' {
		return false
	}
	for _, c := range []byte(zone) {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// uplink is the interface of the IPv4 default route with the lowest
// metric, from /proc/net/route as read reads it; "" where none is known.
func uplink(read func(string) ([]byte, error)) string {
	b, err := read("/proc/net/route")
	if err != nil {
		return ""
	}
	best, metric := "", uint64(math.MaxUint64)
	for line := range strings.Lines(string(b)) {
		f := strings.Fields(line)
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		if m, err := strconv.ParseUint(f[6], 10, 32); err == nil && m < metric && pastableIfName(f[0]) {
			best, metric = f[0], m
		}
	}
	return best
}

// pastableIfName reports whether dev, as juistd names its device, is an
// interface name Linux and FreeBSD both take and a shell reads as one word:
// what the daemon reports goes into commands run as root.
func pastableIfName(dev string) bool {
	if len(dev) == 0 || len(dev) > 15 || dev == "." || dev == ".." || dev[0] == '-' {
		return false
	}
	for _, c := range []byte(dev) {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// warnFirewalled warns where the host firewall keeps ports, which this
// device serves on, from arriving on its juist device: the package lets the
// device through at its first install alone.
func (a *app) warnFirewalled(st *ipc.Status, ports ...uint16) {
	if a.host.firewalled == nil || st == nil || len(ports) == 0 {
		return
	}
	dev := cmp.Or(st.Device, instance.Name(st.Instance))
	if !pastableIfName(dev) {
		return
	}
	ports = slices.Compact(slices.Sorted(slices.Values(ports)))
	var blocked []string
	unsure := false
	for _, port := range ports {
		if b, u := a.host.firewalled(a.ctx, dev, port); b {
			blocked = append(blocked, fmt.Sprintf("tcp/%d", port))
			unsure = unsure || u
		}
	}
	if len(blocked) == 0 {
		return
	}
	what := strings.Join(blocked, ", ")
	if unsure {
		a.warn("firewalld may block %s on %s: its zone is not trusted, and juist cannot read its ports", what, dev)
	} else {
		a.warn("firewalld blocks %s on %s: ingresses and members cannot reach it", what, dev)
	}
	a.hint("sudo firewall-cmd --permanent --zone=trusted --change-interface=%s && sudo firewall-cmd --reload", dev)
}

// warnServedFirewalled warns, as warnFirewalled, of the ports the names
// published on this device are served on.
func (a *app) warnServedFirewalled() {
	d, err := a.daemon()
	if err != nil {
		return
	}
	st := d.st
	auth, err := a.networkLog()
	if err != nil {
		return
	}
	if self, ok := auth.State().Node(st.Self); ok {
		a.warnFirewalled(st, publishedPorts(self.Published)...)
	}
}

// publishedPorts are the ports names are published on.
func publishedPorts(names []types.PublishedName) []uint16 {
	var ports []uint16
	for _, p := range names {
		ports = append(ports, p.Port)
	}
	return ports
}
