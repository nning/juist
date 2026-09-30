package main

import (
	"bufio"
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"go4.org/netipx"

	"github.com/nning/juist/conn"
	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

func exitFamily() family {
	return family{name: "juist exit", intro: "Send this device's internet traffic through another device, or serve as one.",
		subs: []subcommand{
			{name: "list", aliases: []string{"ls"}, run: exitList, forms: [][2]string{{"", "the exit nodes, and the one in use"}}},
			{name: "use", run: exitUse, forms: [][2]string{{"use DEVICE", "send internet traffic through DEVICE"}}},
			{name: "off", run: exitOff, forms: [][2]string{{"off", "send it directly again"}}},
			{name: "serve", run: exitServe, forms: [][2]string{
				{"serve", "carry the network's internet traffic;\n" + servesSetUp},
				{"serve --stop", "stop, and undo that"},
			}},
		}, footer: exitFooter}
}

func cmdExit(a *app, args []string) error { return exitFamily().run(a, args) }

// exitSysctl is the file packaging/exit-node.sh keeps, and the devices it
// set the host up to forward for.
const exitSysctl = "/etc/sysctl.d/60-juist-exit.conf"

func exitList(a *app, args []string) error {
	s := spec{name: "juist exit", args: "[SUBCOMMAND]", about: exitFamily().about()}
	if _, err := a.parse(s, newFlags(s.name), args); err != nil {
		return err
	}
	if listed, err := a.forEachNetwork(a.listExitNodes); listed {
		return err
	}
	return a.listExitNodes()
}

// listExitNodes is "juist exit" for one network.
func (a *app) listExitNodes() error {
	if _, err := a.daemonStatus(); err != nil {
		return err
	}
	// A reader's status names no devices, which would read as none.
	if err := a.requireOperator(); err != nil {
		return err
	}
	st, err := a.restatus()
	if err != nil {
		return err
	}
	ex := cmp.Or(st.Exit, &ipc.Exit{})
	rows := [][]string{{"NAME", "IPV4", "STATE"}}
	for _, d := range byAddress(st.Devices) {
		if !slices.Contains(d.Roles, types.RoleExit) {
			continue
		}
		name, state := cmp.Or(d.Name, d.Identity.ShortString()), "not serving"
		switch {
		case d.Identity == st.Self && ex.Serving:
			name, state = name+" (this device)", "serving"
		case d.Identity == st.Self && ex.Consent:
			name, state = name+" (this device)", a.paint("33", "not serving: "+ex.NotServing)
		case d.Identity == st.Self:
			name += " (this device)"
		case slices.Contains(ex.Offering, d.Identity):
			state = "serving"
		}
		if r := exitReach(st, d.Identity); r != "" && d.Identity != st.Self {
			state += ", " + a.paint("33", r)
		}
		if d.Identity == ex.Node {
			state += ", " + a.inUse(ex)
		}
		rows = append(rows, []string{name, cmp.Or(d.V4, "-"), state})
	}
	if len(rows) == 1 {
		a.ok("no exit nodes")
	} else {
		tw := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
		for _, row := range rows {
			fmt.Fprintln(tw, strings.Join(row, "\t"))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	switch {
	case ex.Failed != "":
		a.alarm("internet traffic may leave directly: %s", ex.Failed)
	case ex.Refused != "" && ex.Node.IsZero():
		a.warn("internet traffic refused: %s", ex.Refused)
		a.hint("juist exit use DEVICE, or juist exit off")
	case ex.Refused != "":
		a.warn("internet traffic refused: %s is in use, and %s", exitName(ex), ex.Refused)
		a.hint("juist exit off")
	case len(rows) == 1:
		a.hint("an admin makes one: juist grant DEVICE exit")
	}
	return nil
}

// exitName names the exit node ex chose.
// inUse is how the list shows the exit node in use.
func (a *app) inUse(ex *ipc.Exit) string {
	switch {
	case ex.Failed != "":
		return a.paint("1;31", "in use, failing")
	case ex.Refused != "":
		return a.paint("1;31", "in use, refused")
	case ex.Partly != "":
		return a.paint("32", "in use") + ", " + a.paint("33", ex.Partly)
	}
	return a.paint("32", "in use")
}

// warnPartly warns of a family the exit node in use refuses.
func (a *app) warnPartly(ex *ipc.Exit) {
	if ex.Partly != "" {
		a.warn("%s", ex.Partly)
	}
}

func exitName(ex *ipc.Exit) string {
	if ex.Node.IsZero() {
		return "an exit node"
	}
	return cmp.Or(ex.Name, ex.Node.ShortString())
}

// exitChosen reports whether ex is of an exit node chosen, usable or not.
func exitChosen(ex *ipc.Exit) bool {
	return ex != nil && (!ex.Node.IsZero() || ex.Refused != "" || ex.Failed != "")
}

// exitReach is how the last tunnel check found id, where it did not answer.
func exitReach(st *ipc.Status, id types.Identity) string {
	for _, r := range st.Reach {
		switch {
		case r.Identity != id || r.Live:
		case r.Absent:
			return "offline"
		default:
			return "not answering"
		}
	}
	return ""
}

// daemonStatus is the status of the network's juistd, which exit nodes need.
func (a *app) daemonStatus() (*ipc.Status, error) {
	n, err := a.openNode()
	if err != nil {
		return nil, err
	}
	st := n.status()
	switch {
	case st == nil:
		return nil, errors.New("juistd not running\nhint: " + startCmd(0))
	case !st.InNetwork:
		return nil, errNoNetwork
	}
	return st, nil
}

// restatus asks the network's juistd for its status again, as it answers
// this user now.
func (a *app) restatus() (*ipc.Status, error) {
	n, err := a.openNode()
	if err != nil {
		return nil, err
	}
	return n.restatus()
}

func exitUse(a *app, args []string) error {
	s := spec{name: "juist exit use", args: "DEVICE", min: 1, max: 1, about: exitUseAbout}
	fs := newFlags(s.name)
	force := fs.Bool("force", false, "choose it though it does not serve, or would end this ssh session")
	isolate := fs.Bool("isolate", false, "send answers to connections from the internet through it too")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	if st, err := a.daemonStatus(); err != nil {
		return err
	} else if other, serves := a.otherEgress(st.Instance, true); serves {
		return fmt.Errorf("%s serves as an exit node, and a host routes the internet through one network\n"+
			"hint: juist exit serve --stop %s", other.label(), other.word())
	} else if other != nil {
		return fmt.Errorf("%s uses an exit node already, and a host routes the internet through one network\n"+
			"hint: juist exit off %s", other.label(), other.word())
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	st, err := a.restatus()
	if err != nil {
		return err
	}
	state := auth.State()
	target, err := resolveDevice(state, pos[0])
	if err != nil {
		return err
	}
	name := displayMember(target)
	ex := cmp.Or(st.Exit, &ipc.Exit{})
	switch {
	case target.Identity == st.Self:
		return errors.New("this device cannot be its own exit node")
	case !target.HasRole(types.RoleExit):
		return fmt.Errorf("%s is not an exit node\nhint: an admin makes it one: juist grant %s exit", name, name)
	case !servesHere:
		return errors.New("exit nodes are used on Linux and FreeBSD alone")
	case ex.Node == target.Identity && ex.Refused == "" && ex.Failed == "" && ex.Isolated == *isolate:
		a.ok("unchanged: internet via %s%s", name, isolation(*isolate))
		a.warnPartly(ex)
		return nil
	case !slices.Contains(ex.Offering, target.Identity) && !*force:
		return fmt.Errorf("%s does not serve as an exit node\nhint: on %s, juist exit serve; or --force", name, name)
	}
	overlay := dnsOverlay(st, append(slices.Clone(state.V4Ranges()), state.ULA()))
	for _, d := range st.Devices {
		overlay = append(overlay, d.Subnets...)
	}
	// Its answers would leave through the exit node, from another address.
	why := ex.AnswersThrough
	if *isolate {
		why = "isolated, answers to the internet go through " + name
	}
	if client, cut := a.cutsSSH(overlay); cut && why != "" && !*force {
		return fmt.Errorf("this ssh session, %s, would end: %s\n"+
			"hint: ssh to this device in the network%s, and run it there; or --force", client, why, overlayAddr(st))
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	after, err := n.exit(ipc.Request{Command: ipc.CmdExit, ExitNode: target.Identity, ExitIsolate: *isolate})
	if err != nil {
		return err
	}
	switch ex := after.Exit; {
	case ex == nil || ex.Node != target.Identity || ex.Isolated != *isolate:
		return errors.New("juistd did not take the choice; version mismatch?")
	case ex.Failed != "":
		return fmt.Errorf("chose %s, and internet traffic may leave directly: %s\nhint: juist exit off", name, ex.Failed)
	case ex.Refused != "":
		a.ok("chose %s", name)
		a.warn("internet traffic refused: %s", ex.Refused)
		if !*force {
			return errSilent
		}
		return nil
	}
	a.ok("internet via %s%s", name, isolation(*isolate))
	switch {
	case *isolate:
		a.warn("answers to connections from the internet go through %s too: this device's services are not reached at its own address", name)
	case ex.AnswersThrough != "":
		a.warn("answers to connections from the internet go through %s: %s", name, ex.AnswersThrough)
	}
	a.warnPartly(ex)
	if r := exitReach(after, target.Identity); r != "" {
		a.warn("%s is %s; internet traffic waits for it", name, r)
	}
	if ex.Serving {
		a.warn("this device stops serving as an exit node")
	}
	a.warnDNS(after.Exit, dnsOverlay(after, append(slices.Clone(state.V4Ranges()), state.ULA())))
	a.warnStrictRP(after.Exit)
	return nil
}

// warnStrictRP says where strict reverse-path filtering drops what the exit
// node answers: it arrives on a device the route back to it does not use.
func (a *app) warnStrictRP(ex *ipc.Exit) {
	var names []string
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifc := range ifs {
			names = append(names, ifc.Name)
		}
	}
	if ex != nil && ex.StrictRP6 {
		a.warn("firewalld's strict IPv6 reverse-path filter drops the exit node's IPv6 answers")
		a.hint("IPv6_rpfilter=loose in /etc/firewalld/firewalld.conf, then sudo systemctl reload firewalld")
	}
	strict := strictRP(a.system, names)
	if len(strict) == 0 {
		return
	}
	a.warn("strict reverse-path filtering on %s drops the exit node's answers", strings.Join(strict, ", "))
	set := []string{"net.ipv4.conf.all.rp_filter=2"}
	for _, n := range strict {
		set = append(set, "net.ipv4.conf."+n+".rp_filter=2")
	}
	a.hint("sudo sysctl -w %s", strings.Join(set, " "))
}

// strictRP is those of ifaces whose reverse-path filter is strict: the higher
// of all's and the interface's own is 1. Loopback and juist's devices aside.
func strictRP(read func(string) ([]byte, error), ifaces []string) []string {
	value := func(name string) int {
		b, err := read("/proc/sys/net/ipv4/conf/" + name + "/rp_filter")
		if err != nil {
			return 0
		}
		n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		return n
	}
	all := value("all")
	var out []string
	for _, n := range ifaces {
		if n == "lo" || strings.HasPrefix(n, "juist") {
			continue
		}
		if max(all, value(n)) == 1 {
			out = append(out, n)
		}
	}
	return out
}

// warnDNS says where the host's DNS leaves outside the tunnel, overlay aside,
// and why, where the exit node in use, ex, does not take it.
func (a *app) warnDNS(ex *ipc.Exit, overlay []netip.Prefix) {
	if ex != nil && ex.DNS {
		return
	}
	out := dnsOutside(a.system, overlay)
	switch {
	case len(out) == 0:
	case ex != nil && ex.DNSNot != "":
		a.warn("DNS goes to %s, outside the tunnel: %s", joinAddrs(out), ex.DNSNot)
		switch {
		case strings.Contains(ex.DNSNot, "refused juistd"):
			a.hint("the package's polkit rule allows juistd that: /usr/share/polkit-1/rules.d/60-juist.rules")
		case strings.Contains(ex.DNSNot, "uplink mode"):
			a.hint("%s", asRoot("ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf"))
		}
	default:
		a.warn("DNS goes to %s, outside the tunnel", joinAddrs(out))
	}
}

// dnsOverlay is the overlay as st knows it, with more, where it has it.
func dnsOverlay(st *ipc.Status, more []netip.Prefix) []netip.Prefix {
	out := slices.Concat(more, st.V4Claims)
	for _, p := range st.Addrs {
		if p.Addr().Is6() {
			out = append(out, netip.PrefixFrom(p.Addr(), 48).Masked())
		}
	}
	for _, d := range st.Devices {
		for _, addr := range []string{d.V4, d.V6} {
			if ip, err := netip.ParseAddr(addr); err == nil {
				out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
			}
		}
	}
	return out
}

// otherEgress is another of the host's networks whose juistd uses an exit
// node, or with serving, one that serves as one, and which of the two: the
// first to route the internet takes every network's, served ones' too.
func (a *app) otherEgress(self int, serving bool) (*hostInstance, bool) {
	if !a.hostScope() {
		return nil, false
	}
	for _, i := range a.hostInstances() {
		if i.n == self || i.st == nil {
			continue
		}
		if serving && i.st.Exit != nil && i.st.Exit.Consent {
			return &i, true
		}
		if exitChosen(i.st.Exit) {
			return &i, false
		}
	}
	return nil, false
}

func exitOff(a *app, args []string) error {
	s := spec{name: "juist exit off", about: `
Send this device's internet traffic directly again.`}
	if _, err := a.parse(s, newFlags(s.name), args); err != nil {
		return err
	}
	st, err := a.daemonStatus()
	if err != nil {
		return err
	}
	if !exitChosen(st.Exit) {
		a.ok("unchanged: internet direct")
		return nil
	}
	if err := a.requireOperator(); err != nil {
		return err
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	if _, err := n.exit(ipc.Request{Command: ipc.CmdExit, ExitOff: true}); err != nil {
		return err
	}
	a.ok("internet direct")
	return nil
}

func exitServe(a *app, args []string) error {
	s := spec{name: "juist exit serve", about: exitServeAbout}
	fs := newFlags(s.name)
	stop := fs.Bool("stop", false, "stop serving")
	if _, err := a.parse(s, fs, args); err != nil {
		return err
	}
	st, err := a.daemonStatus()
	if err != nil {
		return err
	}
	if !servesHere {
		return errors.New("an exit node runs on Linux and FreeBSD alone")
	}
	if err := a.requireOperator(); err != nil {
		return err
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	ex := cmp.Or(st.Exit, &ipc.Exit{})
	dev := instance.Name(st.Instance)
	if *stop {
		if ex.Consent {
			if _, err := n.exit(ipc.Request{Command: ipc.CmdExit, Serve: new(bool)}); err != nil {
				return err
			}
			a.ok("stopped serving")
		} else {
			a.ok("unchanged: not serving")
		}
		// Forwarding stays for as long as this device routes subnets.
		if !helperSetsUpHost && exitSetUp(a.system, dev) && (st.Subnets == nil || !st.Subnets.Consent) {
			return a.exitSetup("off", dev, "juist exit serve")
		}
		return nil
	}
	if exitChosen(ex) {
		return errors.New("this device uses an exit node itself\nhint: juist exit off")
	}
	if other, _ := a.otherEgress(st.Instance, false); other != nil {
		return fmt.Errorf("%s uses an exit node, which would take what this device serves\n"+
			"hint: juist exit off %s", other.label(), other.word())
	}
	if !helperSetsUpHost && (!exitSetUp(a.system, dev) || !forwarding(a.system)) {
		if err := a.exitSetup("on", dev, "juist exit serve"); err != nil {
			return err
		}
	}
	on := true
	after, err := n.exit(ipc.Request{Command: ipc.CmdExit, Serve: &on})
	if err != nil {
		return err
	}
	ex = cmp.Or(after.Exit, &ipc.Exit{})
	self := cmp.Or(st.SelfName, st.Self.ShortString())
	switch {
	case ex.Serving:
		a.ok("serving as an exit node")
	case !slices.ContainsFunc(st.Devices, func(d ipc.Device) bool {
		return d.Identity == st.Self && slices.Contains(d.Roles, types.RoleExit)
	}):
		a.ok("will serve once an admin makes this device an exit node")
		a.hint("juist grant %s exit", self)
	default:
		return fmt.Errorf("not serving: %s", ex.NotServing)
	}
	return nil
}

// forwarding reports whether the host forwards IPv4, and IPv6 where it has it.
func forwarding(read func(string) ([]byte, error)) bool {
	v4, err := read("/proc/sys/net/ipv4/conf/all/forwarding")
	if err != nil || strings.TrimSpace(string(v4)) != "1" {
		return false
	}
	v6, err := read("/proc/sys/net/ipv6/conf/all/forwarding")
	return errors.Is(err, os.ErrNotExist) || err == nil && strings.TrimSpace(string(v6)) == "1"
}

// exitSetUp reports whether the setup script's sysctl file names dev.
func exitSetUp(read func(string) ([]byte, error), dev string) bool {
	b, err := read(exitSysctl)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if devs, ok := strings.CutPrefix(l, "# for:"); ok && slices.Contains(strings.Fields(devs), dev) {
			return true
		}
	}
	return false
}

// exitSetup runs the setup script for dev, as root, through sudo where this
// is not root and a person can answer; again is the command to run after it.
func (a *app) exitSetup(action, dev, again string) error {
	script := a.host.exitScript
	line := fmt.Sprintf("sudo %s %s %s", script, action, dev)
	if script == "" || !fileExists(script) {
		if action == "on" {
			a.warn("no exit-node.sh here; forwarding and the firewall are the host's to set up")
		}
		return nil
	}
	var cmd *exec.Cmd
	switch {
	case a.asRoot():
		cmd = exec.CommandContext(a.ctx, script, action, dev)
	case !a.interactive && action == "off":
		return fmt.Errorf("undoing the host's forwarding needs root\nhint: %s", line)
	case !a.interactive:
		return fmt.Errorf("setting the host up to forward needs root\nhint: %s, then %s again", line, again)
	default:
		q := "forwarding needs root once; run " + line + "?"
		if action == "off" {
			q = "the host forwards for this device; undo that with " + line + "?"
		}
		ok, err := a.ask(a.ctx, question{text: q, yes: true})
		if err != nil {
			return err
		}
		if !ok {
			return errAborted
		}
		cmd = exec.CommandContext(a.ctx, "sudo", script, action, dev)
		cmd.Stdin = os.Stdin
	}
	cmd.Stdout, cmd.Stderr = a.out, a.errOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", line, err)
	}
	return nil
}

// dnsOutside is the resolvers this host asks, through systemd-resolved's
// where its stub is asked, that the internet an exit node carries does not
// hold, the overlay's aside: their lookups leave outside the tunnel.
func dnsOutside(read func(string) ([]byte, error), overlay []netip.Prefix) []netip.Addr {
	servers := nameservers(read, "/etc/resolv.conf")
	if slices.Equal(servers, []netip.Addr{netip.MustParseAddr("127.0.0.53")}) {
		servers = nameservers(read, "/run/systemd/resolve/resolv.conf")
	}
	var b netipx.IPSetBuilder
	for _, p := range conn.Internet(true, true, nil) {
		b.AddPrefix(p)
	}
	for _, p := range overlay {
		b.AddPrefix(p)
	}
	carried, _ := b.IPSet()
	var out []netip.Addr
	for _, s := range servers {
		if !s.IsLoopback() && !carried.Contains(s.WithZone("")) {
			out = append(out, s)
		}
	}
	return out
}

func nameservers(read func(string) ([]byte, error), path string) []netip.Addr {
	b, err := read(path)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "nameserver" {
			if addr, err := netip.ParseAddr(f[1]); err == nil {
				out = append(out, addr.Unmap())
			}
		}
	}
	return out
}

func joinAddrs(addrs []netip.Addr) string {
	s := make([]string, len(addrs))
	for i, a := range addrs {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}

// overlayAddr is ", at ADDR", this device's address in the network, IPv4
// first, or nothing where it has none.
func overlayAddr(st *ipc.Status) string {
	var v6 string
	for _, p := range st.Addrs {
		if p.Addr().Is4() {
			return ", at " + p.Addr().String()
		}
		if v6 == "" {
			v6 = ", at " + p.Addr().String()
		}
	}
	return v6
}

// isolation is ", isolated" where isolated.
func isolation(isolated bool) string {
	if isolated {
		return ", isolated"
	}
	return ""
}
