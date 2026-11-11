package main

import (
	"strings"
	"testing"

	"github.com/nning/juist/types"
)

// juist network derp on and off turn Tailscale's public DERP servers on and off, and
// juist network shows which; a network below schema 24 says how to raise it.
func TestNetworkDERPSetsThePublicServers(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.mustRun("create", "home")
	if strings.Contains(c.mustRun("network"), "Public DERP") {
		t.Error("a network created on the command line names public DERP servers")
	}
	mustContain(t, c.mustRun("network", "derp", "on"), "public DERP on")
	mustContain(t, c.mustRun("network"), "Public DERP")
	mustContain(t, c.mustRun("network", "derp", "on"), "unchanged")
	if out := c.mustRun("network", "derp", "off"); strings.Contains(out, "unchanged") || !strings.Contains(out, "public DERP off") {
		t.Errorf("turning it off says %q", out)
	}
	if strings.Contains(c.mustRun("network"), "Public DERP") {
		t.Error("turned off, the network still names public DERP servers")
	}
	if _, err := c.run("network", "derp", "tailscale"); err == nil || !strings.Contains(err.Error(), "\"tailscale\" is not on or off\nusage: juist network derp") {
		t.Errorf("a server's operator named rather than on or off: %v", err)
	}
	if _, err := c.run("network", "derp", "derp.example.org"); err == nil {
		t.Error("a server by name was taken")
	}

	old := newCLI(t)
	old.genesisSchema = types.SchemaPublicDERP - 1
	old.mustRun("create", "home")
	if _, err := old.run("network", "derp", "on"); err == nil || !strings.Contains(err.Error(), "juist log upgrade") {
		t.Errorf("below schema 24: %v", err)
	}
}
