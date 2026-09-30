package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"

	"github.com/nning/juist/ipc"
)

func cmdSet(a *app, args []string) error {
	s := spec{name: "juist set", about: `
Change this device's settings. --operator names the local user who may
manage it without sudo, which needs root; --operator="" clears it.
--accept-names resolves the public names the network points at devices to
them; --accept-names=false stops.`}
	fs := newFlags(s.name)
	var op optionalString
	var accept optionalBool
	fs.Var(&op, "operator", "local `USER` who manages this device")
	fs.Var(&accept, "accept-names", "resolve the network's public names to its devices")
	if _, err := a.parse(s, fs, args); err != nil {
		return err
	}
	if !op.set && !accept.set {
		a.help(s, fs, a.errOut)
		return errSilent
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	if n.status() == nil {
		return errNoDaemon
	}
	if op.set {
		choice, err := operatorFor(op.value)
		if err != nil {
			return err
		}
		if err := n.setOperator(choice); err != nil {
			return err
		}
		if choice.uid == 0 {
			a.ok("operator cleared")
		} else {
			a.ok("operator %s", op.value)
		}
	}
	if accept.set {
		return setAcceptNames(a, accept.value)
	}
	return nil
}

// setAcceptNames has this device resolve the network's public names to its
// devices, or not, and says which it points where.
func setAcceptNames(a *app, on bool) error {
	st, err := a.daemonStatus()
	if err != nil {
		return err
	}
	word := map[bool]string{true: "public names accepted", false: "public names not accepted"}[on]
	// Sent either way: a status without a running mesh does not say.
	unchanged := st.Names != nil && st.Names.Accepted == on
	if err := a.requireOperator(); err != nil {
		return err
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	st, err = n.exit(ipc.Request{Command: ipc.CmdNames, AcceptNames: &on})
	if err != nil {
		return err
	}
	if unchanged {
		a.ok("unchanged: %s", word)
		return nil
	}
	if t := overridesList(st.Names, a.paint); on && t != "" {
		word += ": " + t
	}
	a.ok("%s", word)
	if n := st.Names; on && n != nil && !n.Resolved {
		a.warn("this host resolves none of them: %s", n.Not)
		if h := dnsHint(n.Not); h != "" {
			a.hint("%s", h)
		}
	}
	return nil
}

// optionalString is a string flag that knows whether it was given, so that
// an explicit empty value can mean "none".
type optionalString struct {
	value string
	set   bool
}

func (o *optionalString) String() string { return o.value }
func (o *optionalString) Set(v string) error {
	o.value, o.set = v, true
	return nil
}

var _ flag.Value = (*optionalString)(nil)

// optionalBool is a boolean flag that knows whether it was given, so that
// leaving it out changes nothing.
type optionalBool struct {
	value bool
	set   bool
}

func (o *optionalBool) String() string   { return strconv.FormatBool(o.value) }
func (o *optionalBool) IsBoolFlag() bool { return true }
func (o *optionalBool) Set(v string) error {
	b, err := strconv.ParseBool(v)
	if err != nil {
		return err
	}
	o.value, o.set = b, true
	return nil
}

// operatorFor resolves a user name, or a uid, to the operator it names. An
// empty name names none.
func operatorFor(name string) (operatorChoice, error) {
	if name == "" {
		return operatorChoice{set: true}, nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		if u, err = user.LookupId(name); err != nil {
			return operatorChoice{}, fmt.Errorf("no user %q", name)
		}
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return operatorChoice{}, fmt.Errorf("user %q has uid %q", name, u.Uid)
	}
	if uid == 0 {
		return operatorChoice{}, errors.New("root needs no appointment")
	}
	return operatorChoice{set: true, uid: uint32(uid)}, nil
}

// defaultOperator is who becomes the operator when a create or join is run
// with sudo and names nobody: the person who ran sudo, which grants them
// nothing they could not already do.
func defaultOperator(explicit optionalString, st *ipc.Status) (operatorChoice, error) {
	if explicit.set {
		return operatorFor(explicit.value)
	}
	if os.Geteuid() != 0 || st == nil || st.Operator != "" {
		return operatorChoice{}, nil
	}
	if u := os.Getenv("SUDO_USER"); u != "" && u != "root" {
		return operatorFor(u)
	}
	return operatorChoice{}, nil
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "$USER"
}

// requireOperator makes sure this invocation may manage the daemon. A user who
// may not is offered to become the operator, which takes sudo once; that is
// the one step that needs root, and it is done by asking, not by retrying the
// whole command as root.
func (a *app) requireOperator() error {
	n, err := a.openNode()
	if err != nil {
		return err
	}
	if st := n.status(); st == nil || st.CanOperate {
		return nil
	}
	me := currentUser()
	if !a.interactive {
		return errNotOperator()
	}
	ok, err := a.ask(a.ctx, question{text: fmt.Sprintf("not the operator; run sudo juist set --operator=%s?", me),
		yes: true})
	if err != nil {
		return err
	}
	if !ok {
		return errAborted
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(a.ctx, "sudo", self, "--socket", n.socket(), "set", "--operator="+me)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, a.out, a.errOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sudo juist set: %w", err)
	}
	st, err := n.restatus()
	if err != nil {
		return err
	}
	if !st.CanOperate {
		return errNotOperator()
	}
	return nil
}
