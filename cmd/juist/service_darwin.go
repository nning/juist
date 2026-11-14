package main

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/ipc"
)

// launchdLabel is the LaunchDaemon that runs juistd, and launchdPlist its
// file; launchctl by its path, not whatever PATH finds for root.
const (
	launchdLabel = "io.nning.juist.juistd"
	launchdPlist = "/Library/LaunchDaemons/" + launchdLabel + ".plist"
	launchctl    = "/bin/launchctl"
)

func systemLayout() *hostLayout {
	return &hostLayout{
		runDir:       filepath.Dir(ipc.SystemSocket),
		stateDir:     systemHome,
		unitDirs:     []string{filepath.Dir(setupScript)},
		instanceUnit: "juistd-launch",
		start:        startLaunchd,
		stop:         stopLaunchd,
		enabledBy:    func(n int) bool { return launchdLoaded(context.Background(), n) },
		firewall:     func(context.Context, string, int) error { return nil },
		dockerNets:   func() map[string][]netip.Prefix { return nil },
	}
}

// setupScript is the install's own script, which starts and stops the
// other networks' instances.
const setupScript = "/Library/juist/setup.sh"

// instanceNeed says what another network's instance needs installed.
const instanceNeed = "another network needs juist installed in /Library/juist"

// instanceLeave begins the hint that leaving a network makes room.
const instanceLeave = "or leave"

// installHint says how juist and its daemon get installed.
const installHint = "install juist: curl -fsSL https://juist.nning.io/install | sh"

// unitOf is instance n's LaunchDaemon.
func unitOf(n int) string {
	if n == 0 {
		return launchdLabel
	}
	return launchdLabel + "." + instance.Name(n)
}

// startCmd, enableCmd, disableCmd and logCmd are what starts instance n,
// enables the default's, disables n and shows n's log, as hints give them.
func startCmd(n int) string {
	if n == 0 {
		return enableCmd()
	}
	return "sudo " + setupScript + " instance start " + instance.Name(n)
}
func enableCmd() string {
	return "sudo " + launchctl + " enable system/" + launchdLabel + " && sudo " + launchctl + " bootstrap system " + launchdPlist
}
func disableCmd(n int) string {
	if n != 0 {
		return "sudo " + setupScript + " instance stop " + instance.Name(n)
	}
	return "sudo " + launchctl + " disable system/" + launchdLabel + " && sudo " + launchctl + " bootout system/" + launchdLabel
}
func logCmd(n int) string {
	if n == 0 {
		return "tail /var/log/juistd.log"
	}
	return "tail /var/log/juistd." + instance.Name(n) + ".log"
}

// asRoot is cmd as a hint says to run it as root.
func asRoot(cmd string) string { return "sudo " + cmd }

func helperLog(name string) string { return "tail /var/log/" + name + ".log" }

// startLaunchd enables and starts instance n: the default's by its plist,
// another's by setup.sh, which makes its user and LaunchDaemon.
func startLaunchd(ctx context.Context, n int) error {
	if n != 0 {
		return runSetup(ctx, "instance", "start", instance.Name(n))
	}
	if err := runLaunchctl(ctx, "enable", "system/"+launchdLabel); err != nil {
		return err
	}
	if launchdLoaded(ctx, 0) {
		return runLaunchctl(ctx, "kickstart", "system/"+launchdLabel)
	}
	return runLaunchctl(ctx, "bootstrap", "system", launchdPlist)
}

// stopLaunchd disables and unloads instance n, which then stays stopped
// across reboots until started again.
func stopLaunchd(ctx context.Context, n int) error {
	if n != 0 {
		return runSetup(ctx, "instance", "stop", instance.Name(n))
	}
	if err := runLaunchctl(ctx, "disable", "system/"+launchdLabel); err != nil {
		return err
	}
	if !launchdLoaded(ctx, 0) {
		return nil
	}
	return runLaunchctl(ctx, "bootout", "system/"+launchdLabel)
}

func launchdLoaded(ctx context.Context, n int) bool {
	return exec.CommandContext(ctx, launchctl, "print", "system/"+unitOf(n)).Run() == nil
}

func runLaunchctl(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, launchctl, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runSetup(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, "/bin/sh", append([]string{setupScript}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", setupScript, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// usesExitHere is whether this host can send its traffic through an exit
// node.
const usesExitHere = true

// servesHere is whether this host can serve as an exit node or subnet
// router, and helperSetsUpHost whether juistd's helper forwards and lets the
// traffic through itself, rather than exit-node.sh under sudo.
const (
	servesHere       = false
	helperSetsUpHost = false
)
