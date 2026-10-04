package main

import (
	"cmp"
	"context"
	"fmt"
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

// warnFirewalled warns where the host firewall keeps ports, which this
// device serves on, from arriving on its juist device: the package lets the
// device through at its first install alone.
func (a *app) warnFirewalled(st *ipc.Status, ports ...uint16) {
	if a.host.firewalled == nil || st == nil || len(ports) == 0 {
		return
	}
	dev := cmp.Or(st.Device, instance.Name(st.Instance))
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
		a.warn("firewalld may block %s on %s: its zone is not trusted, and juist may not read its ports", what, dev)
	} else {
		a.warn("firewalld blocks %s on %s, so the ingresses and members reach nothing served there", what, dev)
	}
	a.hint("sudo firewall-cmd --permanent --zone=trusted --change-interface=%s && sudo firewall-cmd --reload", dev)
}

// warnServedFirewalled warns, as warnFirewalled, of the ports the names
// published on this device are served on.
func (a *app) warnServedFirewalled() {
	st, err := a.daemonStatus()
	if err != nil {
		return
	}
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
