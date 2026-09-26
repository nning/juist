package main

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nning/juist/internal/firewalld"
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
