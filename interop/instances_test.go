//go:build interop && linux

package interop

import (
	"strings"
	"testing"
	"time"
)

// instanceUsers is M24's exit criterion (1): a second network on a host,
// made as the CLI makes it, runs its juistd as a user of its own, juist1, in
// a home of its own, and neither network's juistd reads the other's device
// keys. Reset, the instance goes, and its user stays, as the package's.
func instanceUsers(t *testing.T, fb, lx *vm) {
	const env = "HOME=/tmp/second "
	diagnoseSecond(t, fb, lx)
	for _, v := range []*vm{lx, fb} {
		v.run(t, "mkdir -p /tmp/second")
		t.Cleanup(func() { v.try(env+"juist reset second --force --yes", 2*time.Minute) })
		v.run(t, env+"juist create second --device "+v.name+"2")
		v.eventually(t, "running a second network", 2*time.Minute, "juist status", has("second"))
	}

	lx.run(t, `[ "$(ps -o user= -p "$(systemctl show -p MainPID --value juistd@juist1)")" = juist1 ]`)
	lx.run(t, `[ "$(stat -c %U:%a /var/lib/juist1)" = juist1:700 ] && [ "$(stat -c %U /var/lib/juist1/node.keys)" = juist1 ]`)
	lx.run(t, `! runuser -u juist1 -- cat /var/lib/juist/node.keys >/dev/null 2>&1
! runuser -u juist -- cat /var/lib/juist1/node.keys >/dev/null 2>&1
[ -S /run/juist1/juistd.sock ]`)

	fb.run(t, `pgrep -U juist1 -x juistd >/dev/null`)
	fb.run(t, `[ "$(stat -f %Su:%Lp /var/db/juist1)" = juist1:700 ] && [ "$(stat -f %Su /var/db/juist1/node.keys)" = juist1 ]`)
	fb.run(t, `! su -m juist1 -c 'cat /var/db/juist/node.keys' >/dev/null 2>&1
! su -m juist -c 'cat /var/db/juist1/node.keys' >/dev/null 2>&1
[ -S /var/run/juist1/juistd.sock ]`)

	for _, v := range []*vm{lx, fb} {
		v.run(t, env+"juist reset second --force --yes")
	}
	lx.eventually(t, "the second network's instance gone", time.Minute,
		"systemctl is-active juistd@juist1 || true", has("inactive"))
	fb.eventually(t, "the second network's instance gone", time.Minute,
		"pgrep -U juist1 -x juistd || echo gone", has("gone"))
	lx.run(t, "id juist1 >/dev/null")
	fb.run(t, "id juist1 >/dev/null")
}

// secondOnPrevious makes a second network on v on the previous release, whose
// instance keeps its home in the default's.
func secondOnPrevious(t *testing.T, v *vm) {
	const env = "HOME=/tmp/second "
	v.run(t, "mkdir -p /tmp/second")
	t.Cleanup(func() { v.try(env+"juist reset second --force --yes", 2*time.Minute) })
	v.run(t, env+"juist create second --device "+v.name+"2")
	v.eventually(t, "running a second network, on the previous release", 2*time.Minute, "juist status", has("second"))
	home := "/var/lib/juist/juist1"
	if v.freebsd {
		home = "/var/db/juist/juist1"
	}
	v.run(t, "[ -f "+home+"/node.keys ]")
}

// secondMoved is M24's upgrade of an instance: its home moved out of the
// default's, to its own user, and it runs on as that user, in its network.
// The second network then goes, so that what follows names none.
func secondMoved(t *testing.T, v *vm) {
	diagnoseSecond(t, v)
	v.eventually(t, "the second network back, upgraded", 2*time.Minute, "juist status", has("second"))
	if v.freebsd {
		v.run(t, `[ ! -e /var/db/juist/juist1 ] && [ "$(stat -f %Su /var/db/juist1/node.keys)" = juist1 ] && pgrep -U juist1 -x juistd >/dev/null`)
	} else {
		v.run(t, `[ ! -e /var/lib/juist/juist1 ] && [ "$(stat -c %U /var/lib/juist1/node.keys)" = juist1 ] && `+
			`[ "$(ps -o user= -p "$(systemctl show -p MainPID --value juistd@juist1)")" = juist1 ]`)
	}
	v.run(t, "HOME=/tmp/second juist reset second --force --yes")
	v.eventually(t, "the second network gone", time.Minute, "juist status",
		func(out string) bool { return !strings.Contains(out, "second") })
}

// diagnoseSecond logs, where t fails, how the second network's instance runs
// on each of vms, and where its homes are.
func diagnoseSecond(t *testing.T, vms ...*vm) {
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, v := range vms {
			script := `systemctl status juistd@juist1 --no-pager -n 0; journalctl -u juistd@juist1 -n 30 --no-pager -o short-precise
ls -la /var/lib/juist /var/lib/juist1 /var/lib/juist1/juist1 /run/juist1 2>&1; id juist1`
			if v.freebsd {
				script = `ps -axo user,pid,command | grep '[j]uistd'; tail -30 /var/log/juistd.juist1.log
ls -la /var/db/juist /var/db/juist1 /var/db/juist1/juist1 /var/run/juist1 2>&1; id juist1`
			}
			out, _ := v.try(script, time.Minute)
			t.Logf("%s, the second network's instance:\n%s", v.name, out)
		}
	})
}
