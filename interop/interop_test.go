//go:build interop && linux

package interop

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// A side is what one VM serves the other: a target on a public address a
// hop behind it, as the internet is, since an exit node carries nothing to
// its own networks; a private subnet on it with another; and the address it
// masquerades the target's traffic to.
type side struct {
	target, nat   string
	subnet, inner string
}

var (
	fbSide = side{target: "9.9.9.9", nat: "10.99.1.1", subnet: "192.168.71.0/24", inner: "192.168.71.2"}
	lxSide = side{target: "9.9.8.9", nat: "10.99.2.1", subnet: "192.168.72.0/24", inner: "192.168.72.2"}
)

func TestLinuxAndFreeBSD(t *testing.T) {
	work := need(t, "JUIST_INTEROP_WORK")
	deb := need(t, "JUIST_INTEROP_DEB")
	pkg := need(t, "JUIST_INTEROP_PKG")
	cache := need(t, "JUIST_INTEROP_CACHE")
	os.RemoveAll(work)
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(work, "key")
	sh(t, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
	pub, _ := os.ReadFile(key + ".pub")
	for _, goos := range []string{"linux", "freebsd"} {
		cmd := exec.Command(env("GO", "go"), "build", "-trimpath", "-o", filepath.Join(work, "probe-"+goos), "./probe")
		cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=amd64", "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("building the probe: %v\n%s", err, out)
		}
	}
	pebble := buildPebble(t)
	fbBase, lxBase := base(t, cache, work, freebsdImage), base(t, cache, work, debianImage)

	fb := &vm{name: "fb", freebsd: true, lanAddr: "10.77.0.1", mac: "52:54:00:77:00:01", net: "10.0.4.0/24", dir: work, key: key}
	lx := &vm{name: "lx", lanAddr: "10.77.0.3", mac: "52:54:00:77:00:03", net: "10.0.3.0/24", dir: work, key: key}
	vms := []*vm{fb, lx}
	pa, pb := freePort(t, "udp"), freePort(t, "udp")
	fb.boot(t, fbBase, pa, pb, "")
	lx.boot(t, lxBase, pb, pa, fmt.Sprintf("http://10.0.3.2:%d/", seedServer(t, "lx", string(pub))))
	both(t, vms, func(v *vm) error { return v.up(20 * time.Minute) })

	t.Log("installing the packages")
	fb.put(t, pkg, "/tmp/juist.pkg", 0o644)
	fb.put(t, filepath.Join(work, "probe-freebsd"), "/tmp/probe", 0o755)
	lx.put(t, deb, "/tmp/juist.deb", 0o644)
	lx.put(t, filepath.Join(work, "probe-linux"), "/tmp/probe", 0o755)
	both(t, vms, func(v *vm) error {
		script := `set -e
hostname fb; sysrc -q hostname=fb >/dev/null
ifconfig vtnet1 inet 10.77.0.1/24 up
pkg -N >/dev/null 2>&1 || env ASSUME_ALWAYS_YES=yes pkg bootstrap -f >/dev/null
pkg add /tmp/juist.pkg >/dev/null
sysrc -q juistd_enable=YES >/dev/null; service juistd start >/dev/null
# the target: a VNET jail on an epair, the subnet on it, 9.9.9.9 routed to it
a=$(ifconfig epair create); b=${a%a}b
ifconfig $a inet 10.99.1.1/30 up; ifconfig $a inet 192.168.71.1/24 alias
jail -c name=tgt vnet persist path=/ host.hostname=tgt vnet.interface=$b
jexec tgt ifconfig lo0 up; jexec tgt ifconfig lo0 inet 9.9.9.9/32 alias
jexec tgt ifconfig $b inet 10.99.1.2/30 up; jexec tgt ifconfig $b inet 192.168.71.2/24 alias
route -q add -net 9.9.9.0/24 10.99.1.2
jexec tgt daemon -f /tmp/probe serve fb-target
daemon -f /tmp/probe serve fb-host`
		if !v.freebsd {
			script = `set -e
cloud-init status --wait >/dev/null || true
dev=$(ip -br link | awk '$3 == "52:54:00:77:00:03" {print $1}')
ip link set $dev up; ip addr add 10.77.0.3/24 dev $dev
# conntrack follows connections from the start, as beside firewalld or Docker
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
dpkg -i /tmp/juist.deb >/dev/null
systemctl is-active juistd >/dev/null
ip netns add tgt; ip link add vt0 type veth peer name vt1 netns tgt
ip addr add 10.99.2.1/30 dev vt0; ip addr add 192.168.72.1/24 dev vt0; ip link set vt0 up
ip -n tgt link set lo up; ip -n tgt addr add 9.9.8.9/32 dev lo
ip -n tgt addr add 10.99.2.2/30 dev vt1; ip -n tgt addr add 192.168.72.2/24 dev vt1; ip -n tgt link set vt1 up
ip route add 9.9.8.0/24 via 10.99.2.2
ip netns exec tgt setsid -f /tmp/probe serve lx-target >/dev/null 2>&1 < /dev/null
setsid -f /tmp/probe serve lx-host >/dev/null 2>&1 < /dev/null`
		}
		out, err := v.try(script, 15*time.Minute)
		if err != nil {
			return fmt.Errorf("%s: setting up: %v\n%s", v.name, err, out)
		}
		return nil
	})
	fb.eventually(t, "its target answers", time.Minute, "/tmp/probe get 9.9.9.9:80", has("fb-target from 10.99.1.1"))
	lx.eventually(t, "its target answers", time.Minute, "/tmp/probe get 9.9.8.9:80", has("lx-target from 10.99.2.1"))

	t.Run("pages", func(t *testing.T) {
		// Rendered on Linux by the freebsdman tag, as FreeBSD's binaries write them.
		fb.run(t, `zcat /usr/local/share/man/man1/juist.1.gz > /tmp/a; juist __manpage > /tmp/b; cmp /tmp/a /tmp/b
zcat /usr/local/share/man/man8/juistd.8.gz > /tmp/a; juistd __manpage > /tmp/b; cmp /tmp/a /tmp/b`)
	})

	t.Log("joining")
	fb.eventually(t, "juistd answers", 2*time.Minute, "juist status", func(string) bool { return true })
	lx.eventually(t, "juistd answers", 2*time.Minute, "juist status", func(string) bool { return true })
	fb.run(t, "juist create interop --device fb")
	invite(t, fb, lx, "juist join '%s'")

	fb4 := strings.TrimSpace(fb.run(t, `ifconfig juist0 inet | awk '/inet / {print $2; exit}'`))
	fb6 := strings.TrimSpace(fb.run(t, `ifconfig juist0 inet6 | awk '/inet6 / && !/fe80/ {print $2; exit}'`))
	lx4 := strings.TrimSpace(lx.run(t, `ip -4 -br addr show juist0 | awk '{print $3}' | cut -d/ -f1`))
	lx6 := strings.TrimSpace(lx.run(t, `ip -6 -br addr show juist0 scope global | awk '{print $3}' | cut -d/ -f1`))
	t.Logf("fb %s %s, lx %s %s", fb4, fb6, lx4, lx6)

	t.Run("tunnel", func(t *testing.T) {
		ok := func(string) bool { return true }
		lx.eventually(t, "reaching fb over IPv4", 3*time.Minute, "ping -c1 -W2 "+fb4, ok)
		lx.eventually(t, "reaching fb over IPv6", time.Minute, "ping -c1 -W2 "+fb6, ok)
		fb.eventually(t, "reaching lx over IPv4", time.Minute, "ping -c1 -t2 "+lx4, ok)
		fb.eventually(t, "reaching lx over IPv6", time.Minute, "timeout 5 ping6 -c1 "+lx6, ok)
	})
	t.Run("FreeBSD serves Linux", func(t *testing.T) {
		serve(t, fb, fb, lx, fbSide, lxSide, fb4, fb6)
	})
	t.Run("Linux serves FreeBSD", func(t *testing.T) {
		serve(t, fb, lx, fb, lxSide, fbSide, lx4, lx6)
	})
	t.Run("names", func(t *testing.T) {
		names(t, fb, lx, fb4, fb6)
	})
	t.Run("ingress", func(t *testing.T) {
		ingress(t, fb, lx, fb4)
	})
	t.Run("TLS at the target", func(t *testing.T) {
		tlsAtTheTarget(t, fb, lx, work, pebble)
	})
	t.Run("service member", func(t *testing.T) {
		serviceMember(t, fb, lx)
	})
	t.Run("share", func(t *testing.T) {
		share(t, fb, lx, work)
	})
	t.Run("domain itself", func(t *testing.T) {
		domainItself(t, fb, lx)
	})
	if image := os.Getenv("JUIST_INTEROP_IMAGE"); image != "" && os.Getenv("JUIST_INTEROP_DOCKER") != "" {
		t.Run("service member in a container", func(t *testing.T) {
			containerMember(t, fb, lx, image)
		})
	}
	fb.try("juist publish serve --stop; juist ingress serve --stop; pkill -f '[p]ebble'; pkill -f '[p]robe answer'; "+
		"pkill -f '[p]robe serve fb-web'; sysrc -x juist_serve_env juist_serve_args", time.Minute)
	t.Run("rename", func(t *testing.T) {
		rename(t, fb, lx, fb4, fb6)
	})
	t.Run("removal", func(t *testing.T) {
		fb.run(t, "pkg delete -y juist")
		fb.run(t, `! ifconfig juist0 >/dev/null 2>&1
pfctl -s info | grep -q 'Status: Disabled'
[ "$(sysctl -n net.inet.ip.forwarding)" = 0 ]
! pgrep -x juistd`)
		lx.run(t, "dpkg --purge juist")
		lx.run(t, `! ip link show juist0 >/dev/null 2>&1
! systemctl is-active --quiet juist-ingress
getent passwd juist-ingress >/dev/null
[ "$(sysctl -n net.ipv4.ip_forward)" = 0 ]
! ip rule | grep -q -E '^5(1[89]|2[0-9])[0-9]:'
! pgrep -x juistd`)
	})
}

// ingress has lx, granted the role, take connections on 443 for a name fb
// publishes and pass them to fb through the tunnel, while fb's operator
// agrees; fb takes nothing else from lx once it is an ingress, and a
// withdrawn name reaches nothing.
func ingress(t *testing.T, fb, lx *vm, fb4 string) {
	t.Cleanup(func() {
		if t.Failed() {
			for _, v := range []*vm{fb, lx} {
				out, _ := v.try(diagnose(v)+"; juist devices; juist publish; juist ingress", 2*time.Minute)
				t.Logf("%s:\n%s", v.name, out)
			}
			out, _ := lx.try("systemctl status juist-ingress --no-pager; journalctl -u juist-ingress --no-pager | tail -20", time.Minute)
			t.Logf("lx's ingress:\n%s", out)
			hold(t, fb, lx)
		}
	})
	ok := func(string) bool { return true }
	fb.run(t, "daemon -f /tmp/probe tls fb-tls 8443")
	lx.eventually(t, "reaching fb as a member", time.Minute, "/tmp/probe get "+fb4+":80", has("fb-host from"))
	// An ingress is no exit node and routes no subnet: what serving fb gave lx
	// goes first, and so does the probe holding lx's port 80.
	lx.run(t, "juist exit serve --stop; juist subnet serve --stop; pkill -f '[p]robe serve lx-host'; true")
	fb.run(t, `set -e
juist revoke lx exit --yes
juist subnet remove lx `+lxSide.subnet+`
juist network domain pub.example.org
juist grant lx ingress
juist publish add fb web 8443`)
	// Published on fb by its operator, the name is served at once.
	lx.eventually(t, "learning it is the ingress", 3*time.Minute, "juist ingress serve", has("serving 1 name on 443 and 80"))
	lx.run(t, "systemctl is-active --quiet juist-ingress && getent passwd juist-ingress >/dev/null")
	lx.eventually(t, "being confined by fb", 2*time.Minute, "! /tmp/probe get "+fb4+":80", ok)
	// Without fb's word, lx is told no name.
	fb.run(t, "juist publish serve --stop")
	lx.eventually(t, "being told no name", 2*time.Minute, "juist ingress serve", has("serving 0 names on 443 and 80"))
	lx.eventually(t, "taking the name no longer", time.Minute,
		`[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: web.pub.example.org' http://127.0.0.1/)" = 404 ]`, ok)
	lx.run(t, "! /tmp/probe hello 127.0.0.1:443 web.pub.example.org")
	fb.run(t, "juist publish serve")
	lx.eventually(t, "reaching fb's published port through itself", 2*time.Minute,
		"/tmp/probe hello 127.0.0.1:443 web.pub.example.org", has("fb-tls from"))
	lx.run(t, "juist status | grep -q 'Ingress *serving web.pub.example.org on 443 and 80'")
	lx.run(t, "! /tmp/probe get "+fb4+":80")
	lx.run(t, `[ "$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: web.pub.example.org' http://127.0.0.1/)" = "308 https://web.pub.example.org/" ]`)
	fb.run(t, "juist publish rm fb web")
	lx.eventually(t, "the withdrawn name reaching nothing", 2*time.Minute,
		"! /tmp/probe hello 127.0.0.1:443 web.pub.example.org", ok)
	lx.run(t, "juist ingress serve --stop && ! systemctl is-active --quiet juist-ingress")
}

func has(want string) func(string) bool {
	return func(out string) bool { return strings.Contains(out, want) }
}

// serve has server serve client as an exit node and subnet router, admin
// granting it that, and takes it back; s is the server's side, and back the
// client's, from whose public target the client is reached.
func serve(t *testing.T, admin, server, client *vm, s, back side, addr4, addr6 string) {
	t.Cleanup(func() {
		if t.Failed() {
			for _, v := range []*vm{server, client} {
				out, _ := v.try(diagnose(v), 2*time.Minute)
				t.Logf("%s:\n%s", v.name, out)
			}
			hold(t, server, client)
		}
		client.try("juist exit off", 2*time.Minute)
		server.try("juist exit serve --stop; juist subnet serve --stop", 2*time.Minute)
	})
	admin.run(t, fmt.Sprintf("juist grant %s exit && juist subnet add %s %s", server.name, server.name, s.subnet))
	ok := func(string) bool { return true }
	server.eventually(t, "serving as exit node", 3*time.Minute, "juist exit serve", ok)
	server.eventually(t, "routing the subnet", 3*time.Minute, "juist subnet serve", ok)
	client.eventually(t, "hearing it serves", 3*time.Minute, "juist exit", has("serving"))
	// A connection from the internet older than the choice, as the ssh
	// session making it, goes on through it: made, then the choice, then
	// used again.
	inTarget := "ip netns exec tgt"
	if client.freebsd {
		inTarget = "jexec tgt"
	}
	detach := "setsid -f"
	if client.freebsd {
		detach = "/usr/sbin/daemon -f"
	}
	client.run(t, fmt.Sprintf("rm -f /tmp/hold.out; %s %s sh -c '/tmp/probe hold %s:80 %s 40 > /tmp/hold.out 2>&1'",
		inTarget, detach, back.nat, back.target))
	client.run(t, "juist exit use "+server.name)

	name := server.name + "-target from "
	client.eventually(t, "reaching the internet through it", 2*time.Minute,
		"/tmp/probe get "+s.target+":80", has(name+s.nat))
	client.eventually(t, "reaching the subnet through it", 2*time.Minute,
		"/tmp/probe get "+s.inner+":80", has(name))
	client.eventually(t, "its DNS answered on 53", 2*time.Minute, "/tmp/probe dns "+addr4, ok)
	// resolved asks juistd's own resolver on juist0 for every name, which
	// asks the exit node; FreeBSD's resolv.conf names the exit node itself.
	route, dns := "ip route get "+s.target, "resolvectl domain juist0"
	through := func(out string) bool { return strings.Contains(out, "~.") }
	if client.freebsd {
		route, dns = "route -n get "+s.target, "cat /etc/resolv.conf"
		through = func(out string) bool { return strings.Contains(out, addr4) || strings.Contains(out, addr6) }
	}
	client.eventually(t, "routing the internet into the tunnel", time.Minute, route, has("juist0"))

	client.eventually(t, "keeping the connection older than the choice", 2*time.Minute, "cat /tmp/hold.out",
		has("again"))

	// Reached from the internet, the client answers the way it was reached;
	// isolated, through the exit node, where the answer is lost.
	reach := fmt.Sprintf("%s /tmp/probe get %s:80 %s", inTarget, back.nat, back.target)
	client.eventually(t, "answering what the internet asks", time.Minute, reach,
		has(client.name+"-host from "+back.target))
	client.run(t, "juist exit use "+server.name+" --isolate")
	if out, err := client.try(reach, time.Minute); err == nil {
		t.Errorf("%s: isolated, answered the internet the way it was reached:\n%s", client.name, out)
	}
	client.run(t, "juist exit use "+server.name)
	client.eventually(t, "answering again, not isolated", time.Minute, reach, has(client.name+"-host from "+back.target))
	client.eventually(t, "resolving through it", time.Minute, dns, through)

	if !client.freebsd {
		// Debian's cloud image has resolv.conf list every link's servers,
		// which leaks; resolved's stub, as the hint says, does not.
		client.eventually(t, "hinting at resolved's stub", time.Minute, "juist status 2>&1", has("stub-resolv.conf"))
		client.run(t, "ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf")
		client.eventually(t, "its DNS through the exit node, unwarned", 3*time.Minute, "juist status 2>&1",
			func(out string) bool { return !strings.Contains(out, "warning: DNS") })
	}
	client.run(t, "juist exit off")
	client.eventually(t, "resolving as before", time.Minute, dns, func(out string) bool { return !through(out) })
}

// names has lx, whose resolved routes domains, resolve fb by its name, and a
// public name the network points at fb to fb, once agreed and while fb is
// reachable, without asking the public resolver for it; fb's resolvconf
// routes no domains. The public resolver is lx's target, for lab.example.
func names(t *testing.T, fb, lx *vm, fb4, fb6 string) {
	t.Cleanup(func() {
		if t.Failed() {
			for _, v := range []*vm{fb, lx} {
				out, _ := v.try(diagnose(v)+"; cat /tmp/dns.log 2>/dev/null | tail -20", 2*time.Minute)
				t.Logf("%s:\n%s", v.name, out)
			}
			hold(t, fb, lx)
		}
		fb.try("service juistd start", 2*time.Minute)
	})
	lx.run(t, `ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
ip netns exec tgt setsid -f /tmp/probe resolve 10.99.2.2 /tmp/dns.log >/dev/null 2>&1 < /dev/null
resolvectl dns vt0 10.99.2.2; resolvectl domain vt0 '~lab.example'`)
	lx.eventually(t, "resolving fb by its name", 2*time.Minute, "getent ahosts fb.interop.juist", func(out string) bool {
		return strings.Contains(out, fb4) && strings.Contains(out, fb6)
	})
	lx.eventually(t, "resolving fb by its name alone", time.Minute, "getent hosts fb", has(fb6))
	mustHave(t, lx.run(t, "juist status"), "Names", "interop.juist")
	mustHave(t, fb.run(t, "juist status"), "not resolved here: this host's resolver routes no domains")

	public := "203.0.113.7"
	fb.run(t, "juist names add fb svc.lab.example")
	lx.eventually(t, "hearing of the public name", 2*time.Minute, "juist status", has("1 public name, off on this device"))
	lx.eventually(t, "not agreed, resolving it publicly", time.Minute, "getent ahosts svc.lab.example", has(public))
	if !slices.Contains(strings.Split(lx.run(t, "cat /tmp/dns.log"), "\n"), "A svc.lab.example.") {
		t.Error("not agreed, the public resolver was not asked for the name")
	}

	mustHave(t, lx.run(t, "juist names on"), "public names on: svc.lab.example at fb")
	lx.eventually(t, "resolving it to fb", 2*time.Minute, "getent ahosts svc.lab.example", func(out string) bool {
		return strings.Contains(out, fb4) && strings.Contains(out, fb6) && !strings.Contains(out, public)
	})
	lx.run(t, "resolvectl flush-caches; : > /tmp/dns.log")
	lx.eventually(t, "reaching it through the tunnel", time.Minute, "/tmp/probe get svc.lab.example:80", has("fb-host from "))
	mustHave(t, lx.run(t, "ip route get "+strings.TrimSpace(lx.run(t, "getent ahostsv4 svc.lab.example | awk 'NR==1 {print $1}'"))), "juist0")
	lx.run(t, "getent ahosts other.lab.example | grep -q "+public+"; resolvectl query --cache=no -t HTTPS svc.lab.example || true")
	log := lx.run(t, "cat /tmp/dns.log")
	asked := strings.Split(log, "\n")
	for _, typ := range []string{"A", "AAAA", "HTTPS"} {
		if slices.Contains(asked, typ+" svc.lab.example.") {
			t.Errorf("the public resolver was asked %s svc.lab.example:\n%s", typ, log)
		}
	}
	if !slices.Contains(asked, "A other.lab.example.") {
		t.Errorf("the public resolver was not asked for the name beside it:\n%s", log)
	}

	fb.run(t, "service juistd stop")
	lx.eventually(t, "fb gone, resolving it publicly", 4*time.Minute,
		"resolvectl flush-caches; getent ahosts svc.lab.example", has(public))
	mustHave(t, lx.run(t, "juist status"), "svc.lab.example at fb (resolved publicly: fb is not reachable)")
	fb.run(t, "service juistd start")
	lx.eventually(t, "fb back, resolving it to fb", 4*time.Minute,
		"resolvectl flush-caches; getent ahosts svc.lab.example", has(fb4))

	fb.run(t, "juist names remove fb svc.lab.example")
	lx.eventually(t, "withdrawn, resolving it publicly", 3*time.Minute,
		"resolvectl flush-caches; getent ahosts svc.lab.example", has(public))
	lx.run(t, "juist names off")
}

func mustHave(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Fatalf("output lacks %q:\n%s", w, out)
		}
	}
}

// diagnose is what says why v did not carry or reach what it should.
func diagnose(v *vm) string {
	if v.freebsd {
		return `juist status; netstat -rn | head -40; for a in $(pfctl -a juist -s Anchors 2>/dev/null); do
echo "== $a"; pfctl -a $a -s nat; pfctl -a $a -s rules; done; pfctl -s info | head -2
sysctl net.inet.ip.forwarding; cat /etc/resolv.conf; tail -30 /var/log/juistd.log`
	}
	return `juist status; ip rule; ip route show table all | grep -v -e '^local' -e '^broadcast' -e '^multicast' | head -40
sysctl net.ipv4.ip_forward; iptables-save | head -60; resolvectl status juist0; journalctl -u juistd -n 30 --no-pager`
}

// hold keeps the VMs up after a failure while JUIST_INTEROP_HOLD names a
// file that exists, for a look by hand.
func hold(t *testing.T, vms ...*vm) {
	f := os.Getenv("JUIST_INTEROP_HOLD")
	if f == "" {
		return
	}
	os.WriteFile(f, nil, 0o644)
	for _, v := range vms {
		t.Logf("held: ssh -i %s -p %d root@127.0.0.1  # %s", v.key, v.ssh, v.name)
	}
	t.Logf("held until %s is removed", f)
	for {
		if _, err := os.Stat(f); err != nil {
			return
		}
		time.Sleep(5 * time.Second)
	}
}

// invite has inviter invite a device and joiner run join, a command with %s
// for the link, until the invite ends.
func invite(t *testing.T, inviter, joiner *vm, join string) {
	t.Helper()
	link := make(chan string, 1)
	invited := make(chan error, 1)
	go func() {
		cmd := exec.Command("ssh", inviter.sshArgs("juist invite --yes --no-dht --expires 15m")...)
		stdout, _ := cmd.StdoutPipe()
		cmd.Stderr = cmd.Stdout
		if err := cmd.Start(); err != nil {
			invited <- err
			return
		}
		var all strings.Builder
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			all.WriteString(sc.Text() + "\n")
			if m := regexp.MustCompile(`juist:[^\s']+`).FindString(sc.Text()); m != "" {
				select {
				case link <- m:
				default:
				}
			}
		}
		if err := cmd.Wait(); err != nil {
			invited <- fmt.Errorf("invite: %v\n%s", err, all.String())
			return
		}
		invited <- nil
	}()
	select {
	case l := <-link:
		joiner.run(t, fmt.Sprintf(join, l))
	case err := <-invited:
		t.Fatalf("the invite ended with no link: %v", err)
	case <-time.After(5 * time.Minute):
		t.Fatal("the invite printed no link")
	}
	select {
	case err := <-invited:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Minute):
		t.Fatal("the invite did not end")
	}
}
