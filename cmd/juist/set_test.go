package main

import (
	"strings"
	"testing"
)

// juist set says what it set of 443, and what keeps it from working: HTTPS
// alone where juistd has no device, a relay's name where the device does
// not relay, a proxy where the device does not go by HTTPS alone.
func TestSetSaysWhatItSetOf443(t *testing.T) {
	t.Parallel()
	laptop, vps := homeAndVPS(t)
	if out, err := laptop.run("set", "--https-only"); err == nil || !strings.Contains(err.Error(), `--tun ""`) {
		t.Errorf("HTTPS alone without a device (%v):\n%s", err, out)
	}
	mustContain(t, vps.mustRun("set", "--relay-name", "Relay.Example.org"), "relay name relay.example.org",
		"hint: this device serves the name once it relays: juist grant vps relay")
	if out, err := vps.run("set", "--relay-name", "relay"); err == nil || !strings.Contains(err.Error(), "no public name") {
		t.Errorf("a relay name of one label (%v):\n%s", err, out)
	}
	laptop.mustRun("grant", "vps", "relay")
	eventually(t, "vps relays", func() bool { return statusOfDaemon(t, vps).Relaying })
	eventually(t, "the status names the relay on 443", func() bool {
		return strings.Contains(vps.mustRun("status"), "relay.example.org, ")
	})
	mustContain(t, vps.mustRun("set", "--relay-name", ""), "relay name cleared")
	if strings.Contains(vps.mustRun("status"), "relay.example.org") {
		t.Error("the status names a relay name cleared")
	}
	mustContain(t, laptop.mustRun("set", "--proxy", "http://user:secret@proxy.example:3128"),
		"proxy http://user:xxxxx@proxy.example:3128", "hint: the proxy is used with --https-only alone")
	if out, err := laptop.run("set", "--proxy", "socks5://proxy.example:1080"); err == nil {
		t.Errorf("a SOCKS proxy was taken:\n%s", out)
	}
	mustContain(t, laptop.mustRun("set", "--proxy", ""), "proxy cleared")
}
