//go:build interop && linux

package interop

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// desktop has user turn juist tray on with their session, and starts a
// headless sway for them, whose bar shows the icon, the tray started by its
// autostart entry's Exec.
func desktop(t *testing.T, lx *vm, user string) {
	t.Helper()
	lx.run(t, fmt.Sprintf(`set -e
u=%s; run=/tmp/$u-run
id -u $u >/dev/null 2>&1 || useradd -m $u
install -d -o $u -m 0700 $run
su $u -s /bin/sh -c 'juist tray --autostart' >/dev/null
cat > /tmp/$u-sway.conf <<EOF
bar {
	status_command true
	tray_output *
}
exec sh -c 'echo "\$DBUS_SESSION_BUS_ADDRESS" > $run/bus'
exec $(sed -n 's/^Exec=//p' /home/$u/.config/autostart/juist-tray.desktop)
EOF
su $u -s /bin/sh -c "cd /tmp && XDG_RUNTIME_DIR=$run WLR_BACKENDS=headless WLR_HEADLESS_OUTPUTS=1 \
	WLR_LIBINPUT_NO_DEVICES=1 WLR_RENDERER=pixman setsid -f dbus-run-session -- sway -c /tmp/$u-sway.conf \
	> /tmp/$u-sway.log 2>&1 < /dev/null"`, user))
}

// asUser is script run by user in their desktop's session.
func asUser(user, script string) string {
	return fmt.Sprintf(`su %s -s /bin/sh -c 'DBUS_SESSION_BUS_ADDRESS=$(cat /tmp/%[1]s-run/bus) %s'`, user, script)
}

// tray has lx's operator choose fb as its exit node in juist tray's menu,
// in a headless sway, and another user see the state without the switches;
// juistd stopping and starting turns the icon off and back.
func tray(t *testing.T, fb, lx *vm) {
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := lx.try("tail -n 40 /tmp/desk-sway.log /tmp/guest-sway.log; juist status", time.Minute)
			t.Logf("lx:\n%s", out)
		}
		lx.try("systemctl start juistd; pkill -u desk; pkill -u guest; juist exit off; juist set --operator=", 2*time.Minute)
		fb.try("juist exit serve --stop", 2*time.Minute)
	})
	ok := func(string) bool { return true }
	fb.run(t, "juist grant fb exit")
	fb.eventually(t, "serving as exit node", 3*time.Minute, "juist exit serve", ok)
	lx.eventually(t, "hearing it serves", 3*time.Minute, "juist exit", has("serving"))
	lx.run(t, "useradd -m desk && juist set --operator=desk")

	desktop(t, lx, "desk")
	desk := func(script string) string { return asUser("desk", script) }
	lx.eventually(t, "the icon in the bar", time.Minute, desk("/tmp/probe tray title"), has("juist: connected"))
	icon := func() string { return strings.TrimSpace(lx.run(t, desk("/tmp/probe tray icon"))) }
	connected := icon()
	lx.eventually(t, "the exit nodes granted", time.Minute, desk("/tmp/probe tray menu"), has("  [x] None\n  [ ] fb\n"))
	lx.run(t, desk("/tmp/probe tray click fb"))
	lx.eventually(t, "the icon saying so", time.Minute, desk("/tmp/probe tray title"), has("juist: connected, exit node fb"))
	exiting := icon()
	if exiting == connected {
		t.Error("the icon is the same through an exit node")
	}
	lx.eventually(t, "reaching the internet through it", 2*time.Minute, "/tmp/probe get "+fbSide.target+":80",
		has("fb-target from "+fbSide.nat))

	desktop(t, lx, "guest")
	menu := lx.eventually(t, "another user's menu", time.Minute, asUser("guest", "/tmp/probe tray menu"),
		has("Read-only: desk manages this device"))
	if strings.Contains(menu, "[") || !strings.Contains(menu, "Exit node: member ") {
		t.Errorf("another user than the operator has switches:\n%s", menu)
	}

	lx.run(t, "systemctl stop juistd")
	lx.eventually(t, "the icon off", time.Minute, desk("/tmp/probe tray title"), has("juist: juistd not running"))
	if off := icon(); off == connected || off == exiting {
		t.Error("the icon did not turn off")
	}
	lx.run(t, "systemctl start juistd")
	lx.eventually(t, "the state back", 2*time.Minute, desk("/tmp/probe tray title"), has("juist: connected, exit node fb"))

	lx.run(t, desk("/tmp/probe tray click None"))
	lx.eventually(t, "the exit node given up", time.Minute, "juist status", func(out string) bool {
		return !strings.Contains(out, "Exit node")
	})
	lx.run(t, "pkill -u desk; pkill -u guest; su desk -s /bin/sh -c 'juist tray --autostart=false' && "+
		"! test -e /home/desk/.config/autostart/juist-tray.desktop")
}
