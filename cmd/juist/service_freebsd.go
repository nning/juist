package main

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/ipc"
)

// rcScript is the package's rc.d script, which runs every instance; sysrc
// and service are base's, by their paths, not whatever PATH finds for root.
const (
	rcScript = "/usr/local/etc/rc.d/juistd"
	sysrc    = "/usr/sbin/sysrc"
	service  = "/usr/sbin/service"
)

func systemLayout() *hostLayout {
	return &hostLayout{
		runDir:       filepath.Dir(ipc.SystemSocket),
		stateDir:     systemHome,
		unitDirs:     []string{filepath.Dir(rcScript)},
		instanceUnit: filepath.Base(rcScript),
		start:        startRC,
		stop:         stopRC,
		enabledBy:    enabledRC,
		firewall:     func(context.Context, string, int) error { return nil },
		dockerNets:   func() map[string][]netip.Prefix { return nil },

		ingressScript:  "/usr/local/libexec/juist/ingress.sh",
		serveScript:    "/usr/local/libexec/juist/serve.sh",
		relayScript:    "/usr/local/libexec/juist/relay.sh",
		relayGrant:     "/usr/local/etc/juist/relay-443",
		answers:        answersSoon,
		answersTLS:     endsTLSSoon,
		terminatorOn:   terminatorOnRC,
		caaWait:        15 * time.Second,
		terminatorWait: 15 * time.Second,
	}
}

// instanceNeed is what another network's instance needs installed.
const instanceNeed = "the juistd rc.d script"

// unitOf is instance n as rc.d names it.
func unitOf(n int) string {
	if n == 0 {
		return "juistd"
	}
	return "juistd " + instance.Name(n)
}

// startCmd, enableCmd, disableCmd and logCmd are what starts instance n,
// enables the default's, disables n and shows n's log, as hints give them.
// The base system has no sudo: they say "as root". The default's start
// enables it too, since rc refuses to start it while juistd_enable is NO.
func startCmd(n int) string {
	if n == 0 {
		return enableCmd()
	}
	return "service " + strings.Join(rcArgs(n, "start"), " ") + ", as root"
}
func enableCmd() string { return "sysrc juistd_enable=YES, then service juistd start, as root" }

func disableCmd(n int) string {
	if n == 0 {
		return "service juistd stop, then sysrc juistd_enable=NO, as root"
	}
	return "service juistd stop " + instance.Name(n) + ", then sysrc juistd_instances-=" + instance.Name(n) + ", as root"
}

func logCmd(n int) string {
	if n == 0 {
		return "tail /var/log/juistd.log"
	}
	return "tail /var/log/juistd." + instance.Name(n) + ".log"
}

// asRoot is cmd as a hint says to run it as root.
func asRoot(cmd string) string { return cmd + ", as root" }

// helperLog is what shows the log of the ingress, juist-ingress, or the
// terminator, juist-serve.
func helperLog(name string) string { return "tail /var/log/" + name + ".log" }

// startRC enables instance n in rc.conf and starts it.
func startRC(ctx context.Context, n int) error {
	enable := "juistd_enable=YES"
	if n > 0 {
		if enabledRC(n) {
			enable = ""
		} else {
			enable = "juistd_instances+=" + instance.Name(n)
		}
	}
	if enable != "" {
		if err := runCmd(ctx, sysrc, enable); err != nil {
			return err
		}
	}
	return runCmd(ctx, service, rcArgs(n, "start")...)
}

// stopRC stops instance n and disables it in rc.conf, one not running as
// well: removing an instance that does not answer is how it goes.
func stopRC(ctx context.Context, n int) error {
	stopErr := runCmd(ctx, service, rcArgs(n, "stop")...)
	disable := "juistd_instances-=" + instance.Name(n)
	if n == 0 {
		disable = "juistd_enable=NO"
	}
	if err := runCmd(ctx, sysrc, disable); err != nil {
		return err
	}
	if stopErr != nil && runCmd(ctx, service, rcArgs(n, "status")...) == nil {
		return stopErr
	}
	return nil
}

// terminatorOnRC reports whether rc.conf starts juist_serve and it runs.
func terminatorOnRC(ctx context.Context) bool {
	return runCmd(ctx, service, "juist_serve", "enabled") == nil &&
		runCmd(ctx, service, "juist_serve", "status") == nil
}

// enabledRC reports whether rc.conf starts instance n with the host.
func enabledRC(n int) bool {
	if n == 0 {
		return runCmd(context.Background(), service, "juistd", "enabled") == nil
	}
	out, err := rcOutput(sysrc, "-n", "juistd_instances")
	return err == nil && slices.Contains(strings.Fields(out), instance.Name(n))
}

func rcArgs(n int, verb string) []string {
	if n == 0 {
		return []string{"juistd", verb}
	}
	return []string{"juistd", verb, instance.Name(n)}
}

// runCmd and rcOutput run rc's tools; tests replace them.
var runCmd = func(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

var rcOutput = func(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

// servesHere is whether this host can serve as an exit node or subnet
// router, and helperSetsUpHost whether juistd's helper forwards and lets the
// traffic through itself, rather than exit-node.sh under sudo.
const (
	servesHere       = true
	helperSetsUpHost = true
)
