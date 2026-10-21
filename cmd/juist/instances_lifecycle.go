package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/ipc"
)

// newInstance makes another instance for a network beside those in, having
// asked where the host is not root's to change without sudo.
func (a *app) newInstance(in []hostInstance) (hostInstance, error) {
	var labels []string
	for _, i := range in {
		labels = append(labels, fmt.Sprintf("%q", i.st.NetworkName))
	}
	already := "this device is in " + strings.Join(labels, " and ")
	if !a.host.canMakeInstances() {
		return hostInstance{}, fmt.Errorf("%s, and another network needs %s, which "+
			"the juist package installs\nhint: or leave %s first: juist reset %s --force", already, instanceNeed,
			labels[0], in[0].word())
	}
	if a.asRoot() {
		n, err := a.makeInstance(operatorChoice{})
		if err != nil {
			return hostInstance{}, err
		}
		a.made = n
		a.printf("%s\n", a.dim(fmt.Sprintf("%s; this network gets a juistd of its own, %s", already, instance.Name(n))))
		return a.instanceNumber(n)
	}
	if !a.interactive && !a.yes {
		hint := "run it with sudo"
		if a.purpose == forFounding {
			hint = "add --yes, which runs sudo for it"
		}
		return hostInstance{}, fmt.Errorf("%s; another network beside it takes a juistd of its own, which "+
			"takes sudo to start\nhint: %s", already, hint)
	}
	if !a.yes {
		ok, err := a.ask(a.ctx, question{text: already + "; start a juistd for this network beside it (sudo)?",
			yes: true})
		if err != nil {
			return hostInstance{}, err
		}
		if !ok {
			return hostInstance{}, errAborted
		}
	}
	args := []string{"__instance", "new"}
	if me, err := user.Current(); err == nil {
		args = append(args, "--operator="+me.Username)
	}
	var out strings.Builder
	if err := a.sudo(args, &out); err != nil {
		return hostInstance{}, err
	}
	n, err := instance.Parse(strings.TrimSpace(out.String()))
	if err != nil {
		return hostInstance{}, fmt.Errorf("sudo juist __instance new answered %q", strings.TrimSpace(out.String()))
	}
	a.hostChanged()
	a.made = n
	a.printf("%s\n", a.dim(fmt.Sprintf("this network gets a juistd of its own, %s", instance.Name(n))))
	return a.instanceNumber(n)
}

// sudo runs this juist again under sudo with args, its output to out, or to
// the terminal where out is nil.
func (a *app) sudo(args []string, out *strings.Builder) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if _, err := exec.LookPath("sudo"); err != nil {
		// FreeBSD's base system has none.
		return errors.New("this takes root, and there is no sudo here\nhint: run it as root")
	}
	cmd := exec.CommandContext(a.ctx, "sudo", append([]string{self}, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, a.out, a.errOut
	if out != nil {
		cmd.Stdout = out
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sudo juist %s: %w", strings.Join(args[:min(len(args), 2)], " "), err)
	}
	return nil
}

// instanceStartWait bounds how long a new instance may take to answer.
const instanceStartWait = 15 * time.Second

// makeInstance starts the lowest free instance and appoints op its
// operator: one that neither answers nor is enabled, with no network in a
// home left behind. One that fails to come up is taken back. It needs root.
func (a *app) makeInstance(op operatorChoice) (int, error) {
	n := 0
	for c := 1; c <= instance.Max && n == 0; c++ {
		if a.instanceStatus(c) == nil && !a.host.enabled(c) && !fileExists(filepath.Join(a.host.home(c), logDir, "anchor")) {
			n = c
		}
	}
	if n == 0 {
		return 0, fmt.Errorf("this host runs %d juistds already, the most it may: one per network", instance.Max+1)
	}
	undo := func() {
		ctx, cancel := context.WithTimeout(context.Background(), instanceStartWait)
		defer cancel()
		_ = a.host.stop(ctx, n)
		_ = os.RemoveAll(a.host.home(n))
	}
	if err := a.host.start(a.ctx, n); err != nil {
		undo()
		return 0, err
	}
	ctx, cancel := context.WithTimeout(a.ctx, instanceStartWait)
	defer cancel()
	for a.instanceStatus(n) == nil {
		select {
		case <-ctx.Done():
			undo()
			return 0, fmt.Errorf("%s did not answer on %s\nhint: %s", unitOf(n), a.host.socket(n), logCmd(n))
		case <-time.After(100 * time.Millisecond):
		}
	}
	// As the package does for juist0 at install: log sync runs in the
	// tunnel, and a firewall that drops it there loses removals too.
	if err := a.host.firewall(a.ctx, "allow", n); err != nil {
		a.warn("letting %s through the firewall: %v", instance.Name(n), err)
	}
	if op.set {
		if _, err := ipc.Call(a.host.socket(n), ipc.Request{Command: ipc.CmdSetOperator, SetOperator: true,
			OperatorUID: op.uid}); err != nil {
			undo()
			return 0, fmt.Errorf("appointing %s's operator: %w", instance.Name(n), err)
		}
	}
	a.hostChanged()
	return n, nil
}

// removeInstance stops instance n for good and deletes its home, which a
// reset has emptied of everything but the device's fresh keys. One that
// still holds a network is left alone. It needs root.
func (a *app) removeInstance(n int) error {
	if n == 0 {
		return errors.New("the default juistd stays; juist reset leaves it in no network")
	}
	if st := a.instanceStatus(n); st != nil && st.InNetwork {
		return fmt.Errorf("%s still holds %q\nhint: juist reset %s --force first", instance.Name(n),
			st.NetworkName, instance.Name(n))
	}
	// One that does not answer is judged by its home: a log in it is a
	// network's, and its keys that network's device.
	if fileExists(filepath.Join(a.host.home(n), logDir, "anchor")) {
		return fmt.Errorf("%s holds a network's log in %s\nhint: %s, then juist reset %s --force",
			instance.Name(n), a.host.home(n), startCmd(n), instance.Name(n))
	}
	if err := a.host.stop(a.ctx, n); err != nil {
		return err
	}
	if err := a.host.firewall(a.ctx, "revoke", n); err != nil {
		a.warn("revoking %s's firewall rule: %v", instance.Name(n), err)
	}
	home := a.host.home(n)
	if err := os.RemoveAll(home); err != nil {
		return fmt.Errorf("removing %s: %w", home, err)
	}
	// The next network this number goes to must not read as a juistd that
	// swapped networks under a keystore that saw this one: this keystore,
	// root's, and the sudo user's.
	_ = removeIfPresent(a.home.daemonPinPath(a.host.socket(n)))
	a.forgetSudoUsersPin(n)
	a.hostChanged()
	return nil
}

// forgetSudoUsersPin removes, from the keystore of the user who ran sudo, the
// record of which network instance n's socket held: the next network the
// number goes to would otherwise read there as a juistd swapping networks
// under it. The keystore of root, which ran the reset, forgot it already.
// A keystore that $JUIST_HOME moves elsewhere is not found.
func (a *app) forgetSudoUsersPin(n int) {
	name := os.Getenv("SUDO_USER")
	if name == "" || name == "root" {
		return
	}
	u, err := user.Lookup(name)
	if err != nil {
		return
	}
	h := &home{path: filepath.Join(u.HomeDir, ".config", "juist")}
	if fileExists(h.path) {
		_ = removeIfPresent(h.daemonPinPath(a.host.socket(n)))
	}
}

// unmake removes the instance this invocation made for a network it then
// did not get into, so that a mistyped code leaves no juistd behind.
func (a *app) unmake() {
	if a.made == 0 {
		return
	}
	// One that got a network after all, by a step that failed only later,
	// stays: it is that network's device now.
	if st := a.instanceStatus(a.made); st != nil && st.InNetwork {
		return
	}
	n := a.made
	a.made = 0
	if a.asRoot() {
		if err := a.removeInstance(n); err != nil {
			a.warn("%s stays, in no network: %v", unitOf(n), err)
		}
		return
	}
	// sudo -n: the one just asked for is likely still valid, and a second
	// password prompt after a failure would be one too many.
	self, err := os.Executable()
	if err == nil {
		err = exec.Command("sudo", "-n", self, "__instance", "remove", instance.Name(n)).Run()
	}
	if err != nil {
		a.hint("%s stays, in no network, for the next one; %s removes it", unitOf(n), disableCmd(n))
		return
	}
	a.hostChanged()
}

// runFirewallScript lets a juist device through the host firewall, or takes
// that back; see packaging/firewall.sh. Without the package's script there
// is no firewall juist knows how to change.
func runFirewallScript(ctx context.Context, action string, n int) error {
	const script = "/usr/lib/juist/firewall.sh"
	if !fileExists(script) {
		return nil
	}
	if out, err := exec.CommandContext(ctx, script, action, instance.Name(n)).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s %s: %v: %s", script, action, instance.Name(n), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// cmdInstance is "juist __instance", which the CLI runs under sudo to make
// or remove an instance for a user who is not root: new prints the new
// instance's name, remove NAME removes one. It is not a command of its own.
func cmdInstance(a *app, args []string) error {
	if !a.asRoot() {
		return errors.New("juist __instance needs root")
	}
	switch {
	case len(args) >= 1 && args[0] == "new":
		op := operatorChoice{}
		for _, arg := range args[1:] {
			name, ok := strings.CutPrefix(arg, "--operator=")
			if !ok {
				return fmt.Errorf("juist __instance new: unexpected %q", arg)
			}
			var err error
			if op, err = operatorFor(name); err != nil {
				return err
			}
		}
		n, err := a.makeInstance(op)
		if err != nil {
			return err
		}
		a.printf("%s\n", instance.Name(n))
		return nil
	case len(args) == 2 && args[0] == "remove":
		n, err := instance.Parse(args[1])
		if err != nil {
			return err
		}
		return a.removeInstance(n)
	}
	return errors.New("usage: juist __instance new [--operator=USER] | remove NAME")
}

// dropInstance removes instance n after a reset left it in no network: as
// root at once, else with sudo once asked, or told to by yes. Where it may
// not ask, the instance stays: a juistd in no network does no harm, and the
// next network takes it.
func (a *app) dropInstance(n int, yes bool) error {
	if a.asRoot() {
		if err := a.removeInstance(n); err != nil {
			return err
		}
		a.ok("removed %s", unitOf(n))
		return nil
	}
	if !a.interactive && !yes {
		a.hint("%s stays, in no network, for the next one; %s removes it", unitOf(n), disableCmd(n))
		return nil
	}
	if !a.interactive {
		// Told to, with nobody to type a password: sudo -n, or the hint.
		self, err := os.Executable()
		if err == nil {
			err = exec.Command("sudo", "-n", self, "__instance", "remove", instance.Name(n)).Run()
		}
		if err != nil {
			a.hint("%s stays, in no network, for the next one; %s removes it", unitOf(n), disableCmd(n))
			return nil
		}
		a.hostChanged()
		a.ok("removed %s", unitOf(n))
		return nil
	}
	if !yes {
		ok, err := a.ask(a.ctx, question{text: fmt.Sprintf("remove %s too (sudo)?", unitOf(n)), yes: true})
		if err != nil || !ok {
			return err
		}
	}
	if err := a.sudo([]string{"__instance", "remove", instance.Name(n)}, nil); err != nil {
		return err
	}
	a.hostChanged()
	a.ok("removed %s", unitOf(n))
	return nil
}
