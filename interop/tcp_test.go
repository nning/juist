//go:build interop && linux

package interop

import (
	"testing"
	"time"
)

// tcpPorts is M11a in the lab, exit criterion (1) and (3) at the ingress:
// fb, the ingress, passes TCP on public ports of its own to lx, to a
// service that speaks first on lx's overlay address, and to one juist
// passes on to on loopback, behind --proxy, which is told the client on
// the LAN; fb listens on them by its root parent, and a name withdrawn
// closes its port.
func tcpPorts(t *testing.T, fb, lx *vm) {
	t.Cleanup(func() {
		lx.try("pkill -f '[p]robe serve lx-tcp'; pkill -f '[p]robe proxied lx-proxied'", time.Minute)
		if t.Failed() {
			out, _ := fb.try("juist ingress; juist status; juist health; tail -30 /var/log/juist-ingress.log; sockstat -4 -6 -l", time.Minute)
			t.Logf("fb:\n%s", out)
			out, _ = lx.try("juist publish; juist status; juist health; journalctl -u juist-serve --no-pager | tail -20", time.Minute)
			t.Logf("lx:\n%s", out)
			hold(t, fb, lx)
		}
	})
	lx.run(t, `set -e
setsid -f /tmp/probe serve lx-tcp 7001 >/dev/null 2>&1 < /dev/null
setsid -f /tmp/probe proxied lx-proxied 7002 >/dev/null 2>&1 < /dev/null`)
	fb.run(t, `set -e
juist publish add lx game 7001 --tcp=25565
juist publish add lx pp 2222 --tcp --proxy`)
	lx.eventually(t, "passing what fb published on it to its own service", 3*time.Minute,
		"juist publish add pp 127.0.0.1:7002 --tcp --proxy", has("passing pp.pub.example.org to 127.0.0.1:7002"))
	fb.eventually(t, "listening on both public ports", 3*time.Minute, "juist status", has("by TCP on 2222, 25565"))
	mustHave(t, fb.run(t, "juist ingress"), "game.pub.example.org", "25565/tcp", "pp.pub.example.org", "2222/tcp")
	fb.run(t, "sockstat -46l -p 25565 | grep -q juistd && sockstat -46l -p 2222 | grep -q juistd")
	// A client on the LAN, outside the network.
	lx.eventually(t, "reaching lx's service through fb's public port", 2*time.Minute,
		"/tmp/probe get "+fb.lanAddr+":25565", has("lx-tcp from "))
	lx.eventually(t, "the service behind --proxy told the client", 2*time.Minute,
		"/tmp/probe get "+fb.lanAddr+":2222", has("lx-proxied from "+lx.lanAddr))
	mustHave(t, fb.run(t, "cat /var/log/juist-ingress.log"), "access: tcp "+lx.lanAddr+":", ` 25565 "game.pub.example.org" spliced`)

	fb.run(t, "juist publish rm lx game")
	fb.eventually(t, "closing the withdrawn name's port", 2*time.Minute,
		"! sockstat -46l -p 25565 | grep -q juistd", func(string) bool { return true })
	lx.run(t, "! /tmp/probe get "+fb.lanAddr+":25565")
	lx.run(t, "/tmp/probe get "+fb.lanAddr+":2222 | grep -q 'lx-proxied from '"+lx.lanAddr)
	fb.run(t, "juist publish rm lx pp")
	fb.eventually(t, "closing the last public port", 2*time.Minute,
		"! sockstat -46l -p 2222 | grep -q juistd", func(string) bool { return true })
}
