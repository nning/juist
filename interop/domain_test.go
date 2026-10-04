//go:build interop && linux

package interop

import (
	"strings"
	"testing"
	"time"
)

// domainItself is M9d in the lab, exit criterion (7): fb publishes the
// network's domain itself on lx, whose terminator ends its TLS with a
// certificate from Pebble, which a client on the LAN fetches through fb, the
// ingress; a second device publishing the domain, and a name pointed at a
// member equal to it, are refused; and lx, as every member, sends the domain
// to juistd, which resolves it to its target and passes the domain's other
// names on upstream.
func domainItself(t *testing.T, fb, lx *vm) {
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := lx.try("juist status; juist publish; resolvectl status juist0; journalctl -u juist-serve --no-pager | tail -20",
				time.Minute)
			t.Logf("lx:\n%s", out)
			hold(t, fb, lx)
		}
	})
	fb.run(t, "juist publish add lx pub.example.org")
	lx.eventually(t, "ending TLS for the domain itself", 3*time.Minute, "juist publish add pub.example.org 127.0.0.1:80",
		has("ending TLS for pub.example.org to 127.0.0.1:80"))
	fb.eventually(t, "fetching the domain itself through itself", 3*time.Minute,
		"/tmp/probe hello "+fb.lanAddr+":443 pub.example.org /tmp/root.pem", has("lx-web from 127.0.0.1"))
	for refused, why := range map[string]string{
		"juist publish add fb pub.example.org 8443": "pub.example.org is published on lx already",
		"juist names add fb pub.example.org":        "publishes pub.example.org",
	} {
		if out, err := fb.try(refused, time.Minute); err == nil || !strings.Contains(out, why) {
			t.Errorf("%s: %v\n%s", refused, err, out)
		}
	}
	lx4 := strings.TrimSpace(lx.run(t, `juist status 2>/dev/null | awk '$1 == "This" && $2 == "device" {print $4}'`))
	lx.eventually(t, "sending the domain to juistd", 2*time.Minute, "resolvectl domain juist0", has("~pub.example.org"))
	lx.eventually(t, "resolving the domain itself to its target", 2*time.Minute,
		"resolvectl flush-caches; resolvectl query --cache=no -4 pub.example.org", has(lx4))
	// Another name of the domain goes on upstream: to the lab's resolver,
	// which the host routes example.org to and answers every name with
	// 203.0.113.7.
	lx.run(t, "resolvectl domain vt0 '~lab.example' '~example.org'")
	defer lx.try("resolvectl domain vt0 '~lab.example'", time.Minute)
	lx.eventually(t, "passing another name of the domain on upstream", 2*time.Minute,
		"resolvectl flush-caches; timeout 10 resolvectl query --cache=no -4 other.pub.example.org", has("203.0.113.7"))
	mustHave(t, lx.run(t, "cat /tmp/dns.log"), "A other.pub.example.org.")
	if out := lx.run(t, "resolvectl query --cache=no -4 pub.example.org"); !strings.Contains(out, lx4) {
		t.Errorf("with example.org routed elsewhere, the domain itself is %s", out)
	}
	fb.run(t, "juist publish remove lx pub.example.org")
}
