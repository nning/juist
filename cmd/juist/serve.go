package main

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/nning/juist/ipc"
)

func publishServe(a *app, args []string) error {
	s := spec{name: "juist publish serve", about: `
Serve the names the network publishes on this device. The ingresses then
pass their connections to this device's ports. The service ends TLS there,
or juist does if told to by juist publish add NAME HOST:PORT. --stop undoes
it and keeps where the names go.`}
	fs := newFlags(s.name)
	stop := fs.Bool("stop", false, "stop serving")
	if _, err := a.parse(s, fs, args); err != nil {
		if name, addr, ok := cutServeTo(args); ok {
			return fmt.Errorf("unexpected argument %q\nhint: juist publish add %s %s", name+"="+addr, name, addr)
		}
		return err
	}
	d, err := a.daemon()
	if err != nil {
		return err
	}
	st := d.st
	if err := a.requireOperator(); err != nil {
		return err
	}
	pub := cmp.Or(st.Publish, &ipc.Publish{})
	if *stop {
		// A terminator a share left running stops here too.
		running := st.Terminator != nil && st.Terminator.Running && len(st.Shares) == 0
		if !pub.Consent && !running {
			a.ok("unchanged: not serving")
			return nil
		}
		if pub.Consent {
			if _, err := d.request(ipc.Request{Command: ipc.CmdPublish, ServePublished: new(bool)}); err != nil {
				return err
			}
		}
		if len(pub.To) > 0 || running {
			if err := a.stopTerminator(); err != nil {
				return err
			}
		}
		a.ok("stopped serving")
		return nil
	}
	return a.serveHere(d, cmp.Or(st.SelfName, st.Self.ShortString()))
}

// cutServeTo finds an argument of the form NAME=ADDR among args.
func cutServeTo(args []string) (name, addr string, ok bool) {
	for _, arg := range args {
		if name, addr, ok := strings.Cut(arg, "="); ok && !strings.HasPrefix(arg, "-") {
			return name, addr, true
		}
	}
	return "", "", false
}

// serveHere gives the operator's word to serve what is published on this
// device, named self, to its juistd d.
func (a *app) serveHere(d *daemonNode, self string) error {
	on := true
	after, err := d.request(ipc.Request{Command: ipc.CmdPublish, ServePublished: &on})
	if err != nil {
		return err
	}
	pub := cmp.Or(after.Publish, &ipc.Publish{})
	// Started once told where names go, so that it is there when they are
	// published or the view is fresh again.
	if len(pub.To) > 0 {
		if err := a.startTerminator(""); err != nil {
			return err
		}
	}
	switch {
	case len(pub.Serving) > 0:
		a.ok("serving %s", strings.Join(pub.Serving, ", "))
	case pub.NotServing == notPublishedHere:
		a.ok("will serve once an admin publishes a name on this device")
		a.hint("juist publish add %s NAME", self)
		return nil
	default:
		return fmt.Errorf("not serving: %s", pub.NotServing)
	}
	var names []string
	for _, e := range pub.Ending {
		name, to, _ := strings.Cut(e, " to ")
		a.ok("ending TLS for %s to %s", name, describeTo(to))
		names = append(names, name)
	}
	for _, e := range pub.Passing {
		name, to, _ := strings.Cut(e, " to ")
		a.ok("passing %s to %s", name, to)
	}
	a.showCAA(names...)
	a.showHTTPS(pub.Ending, names...)
	a.warnServedFirewalled()
	a.warnServing()
	return nil
}

// warnServing is said once an operator agrees to serve on a full member.
func (a *app) warnServing() {
	a.warn("a server published from this device reaches the network and its LAN once compromised")
	a.hint("a service member keeps it from them: juistd --serve NAME=ADDR beside it, granted service")
}

// startTerminator has the package's script start the terminator, and waits
// for it to answer where name, or the first name it serves, is listened for.
func (a *app) startTerminator(name string) error {
	if a.host.serveScript == "" {
		return errors.New("juist ends TLS on Linux and FreeBSD alone")
	}
	if !a.terminatorStarts() && (a.host.terminatorOn == nil || !a.host.terminatorOn(a.ctx)) {
		if err := a.packageScript(a.host.serveScript, "on", "the terminator's service"); err != nil {
			return err
		}
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	d := daemonOf(n)
	if d == nil {
		return errNoDaemon
	}
	if d.st.Instance != 0 {
		return errors.New("juist ends TLS for the default network's instance alone, for now")
	}
	self := cmp.Or(d.st.SelfName, d.st.Self.ShortString())
	serving, err := d.serving()
	if err != nil || serving == nil || a.host.answersTLS == nil {
		return err
	}
	t := servedAs(serving, name)
	if len(t.Addrs) == 0 {
		return nil
	}
	at := netip.AddrPortFrom(t.Addrs[0], t.Port).String()
	// The terminator says where it listens; what answers there may be
	// another program's.
	for deadline := time.Now().Add(a.host.terminatorWait); a.host.terminatorWait > 0; {
		var said *ipc.Terminator
		if now, _ := d.restatus(); now != nil {
			said = now.Terminator
		}
		listening, err := terminatorAt(said, at, t)
		if err != nil && t.Public != 0 {
			// A service on every address of the device is reached there.
			return fmt.Errorf("%v\nhint: where the service listens on every address, publish the device's port: "+
				"juist publish add %s %s %d --tcp", err, self, t.Name, t.Port)
		}
		if err != nil {
			return fmt.Errorf("%v\nhint: %s", err, helperLog("juist-serve"))
		}
		if listening {
			break
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("the terminator does not say it listens on %s\nhint: %s", at, helperLog("juist-serve"))
		}
		select {
		case <-a.ctx.Done():
			return a.ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	// A service passed by TCP speaks no protocol to ask.
	if t.Public != 0 {
		return nil
	}
	if err := a.host.answersTLS(a.ctx, at); err != nil {
		return fmt.Errorf("the terminator does not answer on %s: %v\nhint: %s", at, err, helperLog("juist-serve"))
	}
	return nil
}

// servedAs is how p serves name, or the first name it serves where none is
// called so.
func servedAs(p *ipc.Published, name string) ipc.PublishedTarget {
	all := slices.Concat(p.Names, p.TCP)
	if i := slices.IndexFunc(all, func(t ipc.PublishedTarget) bool { return t.Name == name }); i >= 0 {
		return all[i]
	}
	if len(all) > 0 {
		return all[0]
	}
	return ipc.PublishedTarget{}
}

// terminatorAt reports whether the terminator, as it last said, listens at
// at for n, and why it cannot where another program holds the port.
func terminatorAt(t *ipc.Terminator, at string, n ipc.PublishedTarget) (bool, error) {
	switch {
	case t == nil || !t.Running:
		return false, nil
	case slices.Contains(t.Unbound, at) && n.Public != 0:
		ap := netip.MustParseAddrPort(at)
		return false, fmt.Errorf("another program holds port %d on %s, where juist would pass %s by TCP",
			ap.Port(), ap.Addr(), n.Name)
	case slices.Contains(t.Unbound, at):
		ap := netip.MustParseAddrPort(at)
		return false, fmt.Errorf("another program holds port %d on %s, where juist would end TLS", ap.Port(), ap.Addr())
	}
	return slices.Contains(t.Listening, at), nil
}

// terminatorStarts reports whether systemd starts the terminator once juistd
// needs it, which needs no root, and juistd stops it.
func (a *app) terminatorStarts() bool {
	return a.host.terminatorStarts != nil && a.host.terminatorStarts(a.ctx)
}

// stopTerminator has the package's script stop the terminator, where there
// is one and no share needs it.
func (a *app) stopTerminator() error {
	if a.host.serveScript == "" || a.terminatorStarts() {
		return nil
	}
	if n, err := a.openNode(); err == nil {
		if st := liveStatus(n); st != nil && len(st.Shares) > 0 {
			return nil
		}
	}
	return a.packageScript(a.host.serveScript, "off", "the terminator's service")
}

// showCAA prints the CAA records that bind names, whose TLS juist ends, to
// the terminator's ACME account, once it has one.
func (a *app) showCAA(names ...string) {
	if len(names) == 0 {
		return
	}
	deadline := time.Now().Add(a.host.caaWait)
	d, err := a.daemon()
	for {
		var records []string
		if err == nil && d.st.Publish != nil {
			records = slices.DeleteFunc(slices.Clone(d.st.Publish.CAA), func(r string) bool {
				f := strings.Fields(r)
				return len(f) == 0 || !slices.Contains(names, strings.TrimSuffix(f[0], "."))
			})
		}
		if len(records) > 0 {
			for _, r := range records {
				a.printf("%s\n", r)
			}
			a.hint("at the domain's DNS, these records keep the names' certificates to this device")
			a.hintOwnRecords()
			return
		}
		if err != nil || a.host.caaWait == 0 {
			return
		}
		if !time.Now().Before(deadline) {
			a.hint("the terminator's log names the CAA records once the CA answers: %s", helperLog("juist-serve"))
			return
		}
		select {
		case <-a.ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
		_, _ = d.restatus() // d.st stays as it was where juistd does not answer
	}
}
