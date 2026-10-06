package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

func ingressFamily() family {
	return family{name: "juist ingress", intro: "Take connections from the internet for the names devices publish.",
		subs: []subcommand{
			{name: "list", aliases: []string{"ls"}, run: ingressList, forms: [][2]string{{"", "what this ingress serves"}}},
			{name: "serve", run: ingressServe, forms: [][2]string{{"serve [--stop]", "serve as the network's ingress, on 443\nand 80, and the ports names are published\non by TCP"}}},
		}, footer: `An ingress is a device with a public address the network granted the role
(juist grant DEVICE ingress). It reads the name a client asks for, or takes
the port a name is published on by TCP, and passes the connection to the
device, through the tunnel, ending no TLS.`}
}

func cmdIngress(a *app, args []string) error { return ingressFamily().run(a, args) }

func ingressList(a *app, args []string) error {
	s := spec{name: "juist ingress", args: "[SUBCOMMAND]", about: ingressFamily().about()}
	if _, err := a.parse(s, newFlags(s.name), args); err != nil {
		return err
	}
	st, err := a.daemonStatus()
	if err != nil {
		return err
	}
	if err := a.requireOperator(); err != nil {
		return err
	}
	if !isIngress(st) {
		a.ok("this device is no ingress")
		a.hint("an admin grants it: juist grant %s ingress", cmp.Or(st.SelfName, st.Self.ShortString()))
		return nil
	}
	p, err := a.published()
	if err != nil {
		return err
	}
	if len(p.Names) == 0 && len(p.TCP) == 0 {
		a.ok("nothing to serve")
		if st.Stale {
			a.hint("this device's view of the network is stale, and a stale ingress serves nothing")
		}
		return nil
	}
	tw := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tPORT\tTO")
	for _, t := range slices.Concat(p.Names, p.TCP) {
		to := "-"
		if len(t.Addrs) > 0 {
			to = netip.AddrPortFrom(t.Addrs[0], t.Port).String()
		}
		port := "443"
		if t.Public != 0 {
			port = strconv.Itoa(int(t.Public)) + "/tcp"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", t.Name, port, to)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if in := st.Ingress; in != nil && len(heldPorts(in)) > 0 {
		a.warn("another program holds %s here, which the ingress cannot listen on", portsPhrase(heldPorts(in)))
	}
	return nil
}

func ingressServe(a *app, args []string) error {
	s := spec{name: "juist ingress serve", about: `
Serve as the network's ingress: the juist-ingress service, on 443, 443/udp
for HTTP/3, 80 and the ports names are published on by TCP, let through
firewalld or ufw where one runs. --stop undoes it.`}
	fs := newFlags(s.name)
	stop := fs.Bool("stop", false, "stop serving")
	if _, err := a.parse(s, fs, args); err != nil {
		return err
	}
	st, err := a.daemonStatus()
	if err != nil {
		return err
	}
	if err := a.requireOperator(); err != nil {
		return err
	}
	if a.host.ingressScript == "" {
		return errors.New("an ingress runs on Linux and FreeBSD alone")
	}
	if st.Instance != 0 {
		return errors.New("an ingress serves the default network's instance alone, for now")
	}
	if *stop {
		if err := a.packageScript(a.host.ingressScript, "off", "the ingress's service and firewall"); err != nil {
			return err
		}
		a.ok("stopped serving")
		return nil
	}
	if !isIngress(st) {
		return fmt.Errorf("this device is no ingress\nhint: an admin grants it: juist grant %s ingress",
			cmp.Or(st.SelfName, st.Self.ShortString()))
	}
	return a.serveIngress(st.Stale)
}

// serveIngress has the package's script start the ingress, and waits for it
// to answer; stale says this device's view is.
func (a *app) serveIngress(stale bool) error {
	if err := a.packageScript(a.host.ingressScript, "on", "the ingress's service and firewall"); err != nil {
		return err
	}
	if a.host.answers != nil {
		if err := a.host.answers(a.ctx, "127.0.0.1:443"); err != nil {
			return fmt.Errorf("the ingress does not answer on 443: %v\nhint: %s", err, helperLog("juist-ingress"))
		}
	}
	p, err := a.published()
	if err != nil {
		return err
	}
	var ports []uint16
	names := len(p.Names)
	for _, t := range p.TCP {
		if len(t.Addrs) > 0 {
			ports = append(ports, t.Public)
			names++
		}
	}
	a.sayServing(names, ports, stale)
	return nil
}

// sayServing says how many names the ingress serves, and on which ports
// by TCP, and why none where this device's view is stale.
func (a *app) sayServing(names int, tcp []uint16, stale bool) {
	if len(tcp) > 0 {
		a.ok("serving %s on 443, 443/udp, 80 and by TCP on %s", count(names, "name"), strings.Join(portStrings(tcp), ", "))
	} else {
		a.ok("serving %s on 443, 443/udp and 80", count(names, "name"))
	}
	if names == 0 && stale {
		a.hint("this device's view of the network is stale, and a stale ingress serves nothing")
	}
}

// answersSoon waits a few seconds for a service just started to take
// connections at addr, as a started unit may yet fail.
func answersSoon(ctx context.Context, addr string) error {
	var err error
	for range 10 {
		var c net.Conn
		if c, err = (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", addr); err == nil {
			c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return err
}

// endsTLSSoon waits a few seconds for what answers at addr to end TLS: a
// handshake for a name it does not serve ends in a TLS alert, which a plain
// service holding the port does not send.
func endsTLSSoon(ctx context.Context, addr string) error {
	var err error
	for range 10 {
		if err = endsTLS(ctx, addr); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return err
}

func endsTLS(ctx context.Context, addr string) error {
	c, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	var got bytes.Buffer
	_ = tls.Client(teeConn{c, io.TeeReader(c, &got)}, &tls.Config{ServerName: "juist-probe.invalid"}).Handshake()
	switch b := got.Bytes(); {
	case len(b) == 0:
		return errors.New("nothing answers there")
	case b[0] != 0x15 && b[0] != 0x16: // an alert, or a handshake
		return errors.New("a service there speaks no TLS; another program holds the port")
	}
	return nil
}

// teeConn reads through r.
type teeConn struct {
	net.Conn
	r io.Reader
}

func (c teeConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// serveIngressNext follows the ingress role granted to target: on this
// device, for its operator, it serves at once where it can ask for root;
// elsewhere a hint names the command.
func (a *app) serveIngressNext(target types.NodeRecord) error {
	var st *ipc.Status
	if a.node != nil {
		st = a.node.status()
	}
	switch {
	case st == nil || st.Self != target.Identity || !st.CanOperate:
		a.hint("on %s, juist ingress serve", displayMember(target))
		return nil
	case a.host.ingressScript == "":
		a.warn("an ingress runs on Linux and FreeBSD alone")
		return nil
	case !a.asRoot() && !a.interactive:
		a.hint("juist ingress serve")
		return nil
	}
	if err := a.serveIngress(st.Stale); !errors.Is(err, errAborted) {
		return err
	}
	a.hint("juist ingress serve")
	return nil
}

// ingressSummary is the status line of this device's serving as an ingress;
// paint colours one that does not run, and the ports it cannot listen on.
func ingressSummary(in *ipc.Ingress, paint func(code, s string) string) string {
	switch {
	case in == nil:
		return ""
	case !in.Running:
		return paint("33", "not running on this device (juist ingress serve)")
	}
	text := "serving " + count(len(in.Names), "name")
	if n := len(in.Names); n > 0 && n <= 2 {
		text = "serving " + strings.Join(in.Names, ", ")
	}
	on := []string{"443", "443/udp", "80"}
	if in.NoQUIC {
		on = []string{"443", "80"}
	}
	if len(in.Ports) > 0 {
		text += " on " + strings.Join(on, ", ") + " and by TCP on " + strings.Join(portStrings(in.Ports), ", ")
	} else {
		text += " on " + strings.Join(on[:len(on)-1], ", ") + " and " + on[len(on)-1]
	}
	if held := heldPorts(in); len(held) > 0 {
		text += "; " + paint("33", "another program holds "+portsPhrase(held))
	}
	return text
}

// heldPorts are the ports another program holds on the ingress.
func heldPorts(in *ipc.Ingress) []string {
	held := portStrings(in.Unbound)
	if in.NoQUIC {
		held = append(held, "443/udp")
	}
	return held
}

// portsPhrase is "port 22", or "ports 22, 23".
func portsPhrase(ports []string) string {
	if len(ports) == 1 {
		return "port " + ports[0]
	}
	return "ports " + strings.Join(ports, ", ")
}

func portStrings(ports []uint16) []string {
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = strconv.Itoa(int(p))
	}
	return out
}

// isIngress reports whether the status's device holds the ingress role.
func isIngress(st *ipc.Status) bool {
	return slices.ContainsFunc(st.Devices, func(d ipc.Device) bool {
		return d.Identity == st.Self && slices.Contains(d.Roles, types.RoleIngress)
	})
}

// published is what this device's juistd tells its ingress.
func (a *app) published() (*ipc.Published, error) {
	n, err := a.openNode()
	if err != nil {
		return nil, err
	}
	resp, err := ipc.Call(n.socket(), ipc.Request{Command: ipc.CmdPublished})
	if err != nil {
		return nil, err
	}
	return cmp.Or(resp.Published, &ipc.Published{}), nil
}

// hasSudo reports whether sudo is there to ask for root by.
func hasSudo() bool {
	_, err := exec.LookPath("sudo")
	return err == nil
}

// packageScript runs one of the package's scripts with action, as root:
// directly where this is root, with sudo once asked where it may ask; needs
// says what for.
func (a *app) packageScript(script, action, needs string) error {
	line := asRoot(script + " " + action)
	if !fileExists(script) {
		return fmt.Errorf("no %s here; %s is the host's to set up", script, needs)
	}
	var cmd *exec.Cmd
	switch {
	case a.asRoot():
		cmd = exec.CommandContext(a.ctx, script, action)
	case !a.interactive || !hasSudo():
		return fmt.Errorf("%s needs root\nhint: %s", needs, line)
	default:
		ok, err := a.ask(a.ctx, question{text: needs + " needs root; run " + line + "?", yes: true})
		if err != nil {
			return err
		}
		if !ok {
			return errAborted
		}
		cmd = exec.CommandContext(a.ctx, "sudo", script, action)
		cmd.Stdin = os.Stdin
	}
	cmd.Stdout, cmd.Stderr = a.out, a.errOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", strings.Join(cmd.Args, " "), err)
	}
	return nil
}
