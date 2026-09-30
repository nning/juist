//go:build !freebsd

package main

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/ipc"
)

func systemLayout() *hostLayout {
	return &hostLayout{
		runDir:       filepath.Dir(ipc.SystemSocket),
		stateDir:     systemHome,
		wantsDir:     "/etc/systemd/system/multi-user.target.wants",
		unitDirs:     []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"},
		instanceUnit: "juistd@.service",
		systemd:      "/run/systemd/system",
		start:        func(ctx context.Context, n int) error { return systemctl(ctx, "enable", "--now", unitOf(n)) },
		stop:         func(ctx context.Context, n int) error { return systemctl(ctx, "disable", "--now", unitOf(n)) },
		firewall:     runFirewallScript,

		exitScript: "/usr/lib/juist/exit-node.sh",
		dockerNets: dockerNets,
	}
}

// instanceNeed is what another network's instance needs installed.
const instanceNeed = "juistd@.service beside juistd"

// unitOf is instance n's systemd unit.
func unitOf(n int) string {
	if n == 0 {
		return "juistd.service"
	}
	return "juistd@" + instance.Name(n) + ".service"
}

// startCmd, enableCmd, disableCmd and logCmd are what starts instance n,
// enables the default's, disables n and shows n's log, as hints give them.
func startCmd(n int) string   { return "sudo systemctl start " + unitOf(n) }
func enableCmd() string       { return "sudo systemctl enable --now juistd" }
func disableCmd(n int) string { return "sudo systemctl disable --now " + unitOf(n) }
func logCmd(n int) string     { return "journalctl -u " + unitOf(n) }

// asRoot is cmd as a hint says to run it as root.
func asRoot(cmd string) string { return "sudo " + cmd }

func systemctl(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// servesHere is whether this host can serve as an exit node or subnet
// router, and helperSetsUpHost whether juistd's helper forwards and lets the
// traffic through itself, rather than exit-node.sh under sudo.
const (
	servesHere       = runtime.GOOS == "linux"
	helperSetsUpHost = false
)
