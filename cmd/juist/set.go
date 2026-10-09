package main

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/nning/juist/internal/cliflag"
	"github.com/nning/juist/ipc"
)

func cmdSet(a *app, args []string) error {
	s := spec{name: "juist set", about: `
Change this device's settings. --operator names the local user who may
manage it without sudo, as root; --operator="" clears it. --https-only
sends nothing but TLS to relays on 443, through --proxy where given;
--relay-name serves this device's relay on 443 under a public name.`}
	fs := newFlags(s.name)
	var op, proxy, relayName optionalString
	fs.Var(&op, "operator", "local `USER` who manages this device")
	httpsOnly := fs.Bool("https-only", false, "reach relays by TLS on 443 alone; =false undoes it")
	fs.Var(&proxy, "proxy", "HTTP proxy `URL` to reach them by, - to read it from stdin; \"\" for HTTPS_PROXY")
	fs.Var(&relayName, "relay-name", "public `NAME` of this device's relay on 443")
	if _, err := a.parse(s, fs, args); err != nil {
		return err
	}
	setHTTPS := cliflag.IsSet(fs, "https-only")
	if !op.set && !setHTTPS && !proxy.set && !relayName.set {
		a.help(s, fs, a.errOut)
		return errSilent
	}
	req := ipc.Request{Command: ipc.CmdSettings}
	if setHTTPS {
		req.HTTPSOnly = httpsOnly
	}
	if proxy.set && proxy.value == "-" {
		// Off the command line, which every user may read, and sudo logs.
		line, err := a.readSecretLine("proxy URL: ")
		if err != nil {
			return fmt.Errorf("--proxy -: %w", err)
		}
		proxy.value = strings.TrimSpace(line)
	}
	if proxy.set {
		if err := ipc.ValidProxy(proxy.value); err != nil {
			return fmt.Errorf("--proxy: %w", err)
		}
		req.Proxy = &proxy.value
	}
	if relayName.set {
		name := relayName.value
		if name != "" {
			var err error
			if name, err = parseHostName(name); err != nil {
				return fmt.Errorf("--relay-name: %w", err)
			}
		}
		req.RelayName = &name
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
	if req.HTTPSOnly == nil && req.Proxy == nil && req.RelayName == nil {
		return nil
	}
	if err := a.requireOperator(); err != nil {
		return err
	}
	naming := req.RelayName != nil && *req.RelayName != "" && a.host.relayScript != ""
	if naming && n.status().Instance != 0 {
		return errors.New("a relay on 443 serves the default network's instance alone, for now")
	}
	if naming {
		// Granted first, so the relay takes 443 as it starts under the
		// name; nothing is set where root does not grant it.
		if err := a.packageScript(a.host.relayScript, "on", "the relay's 443"); err != nil {
			return err
		}
		// The script restarts juistd where it grants it 443.
		if _, err := a.statusAgain(n, 15*time.Second); err != nil {
			return err
		}
	}
	st, err := n.exit(req)
	if err != nil {
		return err
	}
	if req.RelayName != nil && *req.RelayName == "" && st.Instance == 0 && a.relayGranted() {
		if err := a.packageScript(a.host.relayScript, "off", "giving the relay's 443 back"); err != nil {
			return err
		}
		if st, err = a.statusAgain(n, 15*time.Second); err != nil {
			return err
		}
	}
	a.saySettings(&req, st)
	return nil
}

// statusAgain is juistd's status once it answers again and has looked at
// its network, within wait.
func (a *app) statusAgain(n node, wait time.Duration) (*ipc.Status, error) {
	until := time.Now().Add(wait)
	for {
		st, err := n.restatus()
		if err == nil && (!st.InNetwork || st.LastReconcile > 0 || st.StartError != "") || time.Now().After(until) {
			return st, err
		}
		select {
		case <-a.ctx.Done():
			return nil, a.ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// saySettings says what req set, and what keeps it from working on the
// device whose status st is.
func (a *app) saySettings(req *ipc.Request, st *ipc.Status) {
	h := st.HTTPS
	if h == nil {
		h = &ipc.HTTPS{}
	}
	if req.HTTPSOnly != nil {
		a.ok("%s", map[bool]string{true: "https only", false: "https only off"}[*req.HTTPSOnly])
	}
	if req.Proxy != nil {
		if *req.Proxy == "" {
			a.ok("proxy cleared")
		} else {
			a.ok("proxy %s", ipc.RedactProxy(*req.Proxy))
		}
	}
	if req.RelayName != nil {
		if *req.RelayName == "" {
			a.ok("relay name cleared")
		} else {
			a.ok("relay name %s", *req.RelayName)
		}
	}
	switch {
	case !st.InNetwork:
	case h.Only && len(h.Relays) == 0:
		a.warn("no relay on 443/tcp")
		a.hint("a relay's operator names it there: juist set --relay-name NAME")
	case req.Proxy != nil && *req.Proxy != "" && !h.Only:
		a.hint("the proxy is used with --https-only alone")
	}
	if req.RelayName == nil || *req.RelayName == "" || !st.InNetwork {
		return
	}
	if !st.Relaying {
		a.hint("this device serves the name once it relays: juist grant %s relay", cmp.Or(st.SelfName, st.Self.ShortString()))
	} else if h.NotAnnounced != "" {
		a.warn("members are not told of %s: %s", *req.RelayName, h.NotAnnounced)
		a.hint("juist log upgrade")
	}
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

// name is the operator as the daemon's status names it, "" for none.
func (o operatorChoice) name() string {
	if o.uid == 0 {
		return ""
	}
	id := strconv.FormatUint(uint64(o.uid), 10)
	if u, err := user.LookupId(id); err == nil {
		return u.Username
	}
	return id
}

// defaultOperator is who becomes the operator when a create or join is run
// with sudo and names nobody: the person who ran sudo, which grants them
// nothing they could not already do.
func defaultOperator(explicit optionalString, st *ipc.Status) (operatorChoice, error) {
	if explicit.set {
		// One who is the operator already asks for no appointment, which
		// only root may make: requireOperator may just have made them so.
		op, err := operatorFor(explicit.value)
		if err == nil && st != nil && st.Operator == op.name() {
			return operatorChoice{}, nil
		}
		return op, err
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
