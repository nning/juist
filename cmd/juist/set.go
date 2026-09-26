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
manage it without sudo; --operator="" clears it. Needs root.`}
	fs := newFlags(s.name)
	var op optionalString
	fs.Var(&op, "operator", "local `USER` who manages this device")
	if _, err := a.parse(s, fs, args); err != nil {
		return err
	}
	if !op.set {
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
	choice, err := operatorFor(op.value)
	if err != nil {
		return err
	}
	if err := n.setOperator(choice); err != nil {
		return err
	}
	if choice.uid == 0 {
		a.ok("operator cleared")
		return nil
	}
	a.ok("operator %s", op.value)
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
