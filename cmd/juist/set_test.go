package main

import (
	"os"
	"path/filepath"
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
	// Off the command line, which every user may read.
	out, err := laptop.cli.answer("http://user:secret@proxy.example:3128", "--socket", laptop.sock, "set", "--proxy", "-")
	if err != nil {
		t.Fatalf("--proxy - (%v):\n%s", err, out)
	}
	mustContain(t, out, "proxy http://user:xxxxx@proxy.example:3128")
	if _, err := laptop.cli.answer("", "--socket", laptop.sock, "set", "--proxy", "-"); err == nil {
		t.Error("--proxy - took an empty stdin")
	}
}

// A grant of 443 that outlived its relay name, as where relay.sh off found
// no root, is warned of, and taken back by a reset.
func TestAGrantOf443WithoutANameIsTakenBack(t *testing.T) {
	t.Parallel()
	h := newHost(t)
	h.mustRun("create", "home", "--device", "laptop")
	calls := filepath.Join(t.TempDir(), "calls")
	h.layout.relayScript = filepath.Join(t.TempDir(), "relay.sh")
	if err := os.WriteFile(h.layout.relayScript, []byte("#!/bin/sh\necho \"$*\" >> "+calls+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.layout.relayGrant = filepath.Join(t.TempDir(), "juist-relay-443.conf")
	if err := os.WriteFile(h.layout.relayGrant, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	mustContain(t, h.mustRun("health"), "warning: juistd may bind any port below 1024",
		h.layout.relayScript+" off")
	// Another juistd, by its socket, is none of the grant's.
	other := newDaemonDevice(t, nil)
	other.cli.host = h.layout
	if out := other.mustRun("health"); strings.Contains(out, "below 1024") {
		t.Errorf("another juistd is warned of the host's grant:\n%s", out)
	}
	h.mustRun("reset", "--yes", "--force")
	if b, _ := os.ReadFile(calls); string(b) != "off\n" {
		t.Errorf("relay.sh ran %q, want off", b)
	}
}
