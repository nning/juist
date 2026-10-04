package main

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

func publishFamily() family {
	return family{name: "juist publish", intro: "Publish devices' services on the internet, through an ingress.",
		subs: []subcommand{
			{name: "list", aliases: []string{"ls"}, run: publishList, forms: [][2]string{{"", "the published names, and where\nthis device sends them on"}}},
			{name: "add", run: publishAdd, forms: [][2]string{
				{"add NAME HOST:PORT", "publish NAME.DOMAIN on this device,\nending TLS and sending it on to HOST:PORT"},
				{"add DEVICE NAME [PORT]", "publish NAME.DOMAIN on DEVICE's PORT"},
			}},
			{name: "status-page", run: publishStatusPage, forms: [][2]string{{"status-page NAME [--public WHAT]",
				"serve the network's status page as\nNAME.DOMAIN on this device"}}},
			{name: "remove", aliases: []string{"rm"}, run: publishRemove, forms: [][2]string{{"remove [DEVICE] NAME", "stop publishing NAME"}}},
			{name: "serve", run: publishServe, forms: [][2]string{{"serve [--stop]", "serve what is published on this\ndevice to the ingresses"}}},
		}, footer: `A name is one label under the network's domain (juist network domain), or
the domain itself, spelled out, whose DNS points at the ingresses (juist
grant DEVICE ingress). The ingresses read the name a client asks for and
pass the connection to the device, where juist ends TLS (juist publish add
NAME HOST:PORT) or the service does. juist publish PORT publishes this
host's PORT under the device's own name at once, as the publish role lets it.`}
}

func cmdPublish(a *app, args []string) error {
	if publishesPort(a, args) {
		return publishPort(a, args)
	}
	return publishFamily().run(a, args)
}

func publishList(a *app, args []string) error {
	s := spec{name: "juist publish", args: "[SUBCOMMAND]", about: publishFamily().about()}
	if _, err := a.parse(s, newFlags(s.name), args); err != nil {
		return err
	}
	if listed, err := a.forEachNetwork(a.listPublished); listed {
		return err
	}
	return a.listPublished()
}

// listPublished is "juist publish" for one network.
func (a *app) listPublished() error {
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	type row struct {
		name, device, port, to string
	}
	var rows []row
	node, err := a.openNode()
	if err != nil {
		return err
	}
	var self types.NodeRecord
	var to []ipc.ServeTo
	if st := node.status(); st != nil {
		self, _ = state.Node(st.Self)
		if st.Publish != nil {
			to = st.Publish.To
		}
	}
	for _, n := range state.Nodes() {
		for _, p := range n.Published {
			r := row{name: p.Under(state.Domain()), device: displayMember(n), port: strconv.Itoa(int(p.Port))}
			if p.Proxy {
				r.port += " (proxy protocol)"
			}
			if i := slices.IndexFunc(to, func(t ipc.ServeTo) bool { return t.Label == p.Label }); i >= 0 && n.Identity == self.Identity {
				r.to = describeTo(to[i].To)
			}
			rows = append(rows, r)
		}
	}
	for _, t := range to {
		if !slices.ContainsFunc(self.Published, func(p types.PublishedName) bool { return p.Label == t.Label }) {
			rows = append(rows, row{name: nameUnder(t.Label, state.Domain()), device: displayMember(self), port: "not published",
				to: describeTo(t.To)})
		}
	}
	if len(rows) == 0 {
		a.ok("no published names")
		if state.Domain() == "" {
			a.hint("an admin sets the domain first: juist network domain pub.example.org")
		} else {
			a.hint("an admin adds one: juist publish add DEVICE NAME")
		}
		return nil
	}
	slices.SortFunc(rows, func(x, y row) int { return strings.Compare(x.name, y.name) })
	tw := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
	if len(to) > 0 {
		fmt.Fprintln(tw, "NAME\tDEVICE\tPORT\tTO")
	} else {
		fmt.Fprintln(tw, "NAME\tDEVICE\tPORT")
	}
	for _, r := range rows {
		if len(to) > 0 {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.name, r.device, r.port, r.to)
		} else {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", r.name, r.device, r.port)
		}
	}
	return tw.Flush()
}

func publishAdd(a *app, args []string) error {
	s := spec{name: "juist publish add", args: "NAME HOST:PORT | DEVICE NAME [PORT]", min: 2, max: 3, about: `
Publish NAME.DOMAIN, or DOMAIN itself. Given HOST:PORT, such as
127.0.0.1:2283, it is published on this device, where juist ends TLS with a
certificate of its own and sends the connection on to HOST:PORT. Given
DEVICE, on DEVICE's PORT, 443 unless given, where the service ends TLS once
DEVICE's operator agrees.`}
	fs := newFlags(s.name)
	proxy := fs.Bool("proxy", false, "send the client's address in a PROXY protocol v2 header")
	http2 := fs.Bool("http2", false, "offer clients HTTP/2; the service at HOST:PORT takes it without TLS (h2c)")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	if last := pos[len(pos)-1]; strings.Contains(last, ":") {
		if *http2 {
			pos[len(pos)-1] = ipc.HTTP2To(last)
		}
		return a.publishHere(pos, *proxy)
	}
	if *http2 {
		return fmt.Errorf("--http2 is for a service whose TLS juist ends, given as HOST:PORT\n%s", s.usage(fs))
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	target, err := resolveDevice(state, pos[0])
	if err != nil {
		return err
	}
	label, err := publishableLabel(state, pos[1])
	if err != nil {
		return err
	}
	port := uint16(443)
	if len(pos) > 2 {
		n, err := strconv.ParseUint(pos[2], 10, 16)
		if err != nil || n == 0 {
			return fmt.Errorf("%q is no port", pos[2])
		}
		port = uint16(n)
	}
	next, err := publishedWith(state, target, types.PublishedName{Label: label, Port: port, Proxy: *proxy})
	if err != nil {
		return err
	}
	applied, err := a.submitPublished(auth, target, next)
	if err != nil || !applied {
		return err
	}
	a.domainItselfHint(label, state.Domain())
	return a.servePublishedNext(target)
}

// domainItselfHint says what publishing the domain itself, label "", needs
// besides: its own addresses at its DNS, which *.DOMAIN does not cover.
func (a *app) domainItselfHint(label, domain string) {
	if label == "" {
		a.hint("%s needs A and AAAA records of its own, the ingress's; *.%s does not cover it", domain, domain)
	}
}

// publishHere is "juist publish add [DEVICE] NAME HOST:PORT", DEVICE this
// one: NAME published here, on the port it is already or 443, and its TLS
// ended here and sent on.
func (a *app) publishHere(pos []string, proxy bool) error {
	st, err := a.daemonStatus()
	if err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	self, ok := state.Node(st.Self)
	if !ok {
		return errors.New("this device is no member of the network")
	}
	if len(pos) == 3 {
		target, err := resolveDevice(state, pos[0])
		if err != nil {
			return err
		}
		if target.Identity != self.Identity {
			return fmt.Errorf("juist ends TLS on the device it runs on\nhint: on %s, juist publish add %s %s",
				displayMember(target), pos[1], pos[2])
		}
		pos = pos[1:]
	}
	switch {
	case a.host.serveScript == "":
		return errors.New("juist ends TLS on Linux and FreeBSD alone")
	case st.Instance != 0:
		return errors.New("juist ends TLS for the default network's instance alone, for now")
	}
	label, err := publishableLabel(state, pos[0])
	if err != nil {
		return err
	}
	t := ipc.ServeTo{Label: label, To: pos[1]}
	if !t.Valid() {
		addr, _ := ipc.HTTP2Of(pos[1])
		return fmt.Errorf("%q is no HOST:PORT, such as 127.0.0.1:2283", addr)
	}
	p := types.PublishedName{Label: label, Port: 443, Proxy: proxy}
	i := slices.IndexFunc(self.Published, func(q types.PublishedName) bool { return q.Label == label })
	if i >= 0 {
		p.Port = self.Published[i].Port
	}
	next, err := publishedWith(state, self, p)
	if err != nil {
		return err
	}
	published, changed := i >= 0, !slices.Equal(next, self.Published)
	canPublish := !changed || a.adminKeyHere(state)
	if changed && canPublish {
		applied, err := a.submitPublished(auth, self, next)
		if err != nil {
			return err
		}
		published = published || applied
		if applied {
			a.domainItselfHint(label, state.Domain())
		}
	}
	agreed := st.Publish != nil && st.Publish.Consent
	n, err := a.openNode()
	if err != nil {
		return err
	}
	on := true
	after, err := n.exit(ipc.Request{Command: ipc.CmdPublish, ServePublished: &on, ServeTo: []ipc.ServeTo{t}})
	if err != nil {
		return err
	}
	pub := cmp.Or(after.Publish, &ipc.Publish{})
	if err := a.startTerminator(); err != nil {
		return err
	}
	if !agreed && len(pub.Serving) > 0 {
		a.ok("serving %s", strings.Join(pub.Serving, ", "))
	}
	name := p.Under(state.Domain())
	switch {
	case slices.Contains(pub.Ending, name+" to "+t.To):
		a.ok("ending TLS for %s to %s", name, describeTo(t.To))
		a.showCAA(name)
		if label == "" {
			a.warn("a CAA record at %s holds for every name under it without one of its own: give each device's names theirs", name)
		}
	case !published:
		a.ok("%s goes to %s once published on this device", name, describeTo(t.To))
	default:
		a.ok("%s goes to %s once served", name, describeTo(t.To))
		if pub.NotServing != "" {
			a.warn("not served here: %s", pub.NotServing)
		}
	}
	if len(pub.Serving) > 0 {
		a.warnFirewalled(st, publishedPorts(next)...)
	}
	if !canPublish {
		how := name
		if p.Port != 443 || proxy {
			how += " " + strconv.Itoa(int(p.Port))
		}
		if proxy {
			how += " --proxy"
		}
		a.hint("an admin publishes it: juist publish add %s %s", displayMember(self), how)
	}
	if !agreed {
		a.warnServing()
	}
	return nil
}

func publishStatusPage(a *app, args []string) error {
	s := spec{name: "juist publish status-page", args: "NAME", min: 1, max: 1, about: `
Serve the network's status page as NAME.DOMAIN on this device, where juist
ends TLS: its devices, how this device reaches them, the published names
and the log's changes. Members see all of it; --public says what anyone
else sees: none, services, network (all but the changes) or all.`}
	fs := newFlags(s.name)
	public := fs.String("public", ipc.ShowServices.String(), "`WHAT` non-members see: none, services, network or all")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	vis, err := ipc.ParseVisibility(*public)
	if err != nil {
		return fmt.Errorf("--public: %v\n%s", err, s.usage(fs))
	}
	return a.publishHere([]string{pos[0], ipc.StatusPageTo(vis)}, false)
}

// describeTo says where a name whose TLS juist ends goes.
func describeTo(to string) string {
	if vis, ok := ipc.StatusPageOf(to); ok {
		return "the status page, public: " + vis.String()
	}
	if addr, ok := ipc.HTTP2Of(to); ok {
		return addr + " over HTTP/2"
	}
	return to
}

// nameUnder is label under domain, or label alone without one.
func nameUnder(label, domain string) string {
	if domain == "" {
		return cmp.Or(label, "the domain itself")
	}
	return types.PublishedName{Label: label}.Under(domain)
}

// publishableLabel reads arg as a name to publish in state's network.
func publishableLabel(state *log.State, arg string) (string, error) {
	if state.Schema() < types.SchemaPublish {
		return "", needsUpgrade("published names")
	}
	if state.Domain() == "" {
		return "", fmt.Errorf("the network has no domain to publish under\nhint: juist network domain pub.example.org")
	}
	return parseLabel(arg, state.Domain())
}

// publishedWith is what target publishes once it publishes p too, in
// place of a name of p's label; p must be published on no other device.
func publishedWith(state *log.State, target types.NodeRecord, p types.PublishedName) ([]types.PublishedName, error) {
	if err := labelFree(state, p.Label, target.Identity); err != nil {
		return nil, err
	}
	next := slices.DeleteFunc(slices.Clone(target.Published), func(q types.PublishedName) bool { return q.Label == p.Label })
	if len(next) >= types.MaxPublishedPerNode {
		return nil, fmt.Errorf("%s publishes %d names, the most a device may", displayMember(target), types.MaxPublishedPerNode)
	}
	next = append(next, p)
	slices.SortFunc(next, func(x, y types.PublishedName) int { return strings.Compare(x.Label, y.Label) })
	return next, nil
}

// labelFree says why label is no name to publish under the domain on a
// device other than except: another publishes it, holds it as its own name,
// or a name under it points at a member.
func labelFree(state *log.State, label string, except types.Identity) error {
	name := nameUnder(label, state.Domain())
	for _, n := range state.Nodes() {
		if n.Identity == except {
			continue
		}
		switch l, ok := n.ShareLabel(); {
		case slices.ContainsFunc(n.Published, func(q types.PublishedName) bool { return q.Label == label }):
			return fmt.Errorf("%s is published on %s already\nhint: juist publish remove %s %s",
				name, displayMember(n), displayMember(n), name)
		case ok && l == label && n.HasRole(types.RolePublish):
			return fmt.Errorf("%s is %s's own name, which it shares under", name, displayMember(n))
		case slices.Contains(n.Names, name):
			return fmt.Errorf("%s points at %s already\nhint: juist names remove %s %s", name, displayMember(n),
				displayMember(n), name)
		}
	}
	return nil
}

// adminKeyHere reports whether an admin key here may sign changes to state's
// network; where the keys cannot be read, submit says why.
func (a *app) adminKeyHere(state *log.State) bool {
	files, err := a.adminKeyFiles()
	if err != nil {
		return true
	}
	return slices.ContainsFunc(files, func(f adminKeyFile) bool {
		_, ok := state.Admin(f.priv.Public())
		return ok && (a.keyName == "" || f.name == a.keyName)
	})
}

// servePublishedNext follows a name published on target: on this device,
// for its operator, it is served at once; elsewhere a hint names what the
// target's operator runs, unless the target serves already.
func (a *app) servePublishedNext(target types.NodeRecord) error {
	var st *ipc.Status
	if a.node != nil {
		st = a.node.status()
	}
	switch {
	case st != nil && st.Self == target.Identity && st.CanOperate:
		if st.Publish != nil && st.Publish.Consent {
			return nil
		}
		return a.serveHere(displayMember(target))
	case st != nil && slices.ContainsFunc(st.Devices, func(d ipc.Device) bool { return d.Identity == target.Identity && d.Serving }):
		return nil
	case target.HasRole(types.RoleService):
		return nil // its juistd --serve agreed already
	}
	a.hint("on %s, juist publish serve", displayMember(target))
	return nil
}

func publishRemove(a *app, args []string) error {
	s := spec{name: "juist publish remove", args: "[DEVICE] NAME", min: 1, max: 2, about: `
Stop publishing NAME on DEVICE, this device unless given. On this device,
juist also stops ending TLS for NAME.`}
	pos, err := a.parse(s, newFlags(s.name), args)
	if err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	n, err := a.openNode()
	if err != nil {
		return err
	}
	st := n.status()
	var target types.NodeRecord
	if len(pos) == 2 {
		if target, err = resolveDevice(state, pos[0]); err != nil {
			return err
		}
	} else {
		if st, err = a.daemonStatus(); err != nil {
			return err
		}
		var ok bool
		if target, ok = state.Node(st.Self); !ok {
			return errors.New("this device is no member of the network")
		}
	}
	label, err := parseLabel(pos[len(pos)-1], state.Domain())
	if err != nil {
		return err
	}
	name := nameUnder(label, state.Domain())
	here := st != nil && st.Self == target.Identity && st.CanOperate
	var to string
	if here && st.Publish != nil {
		if i := slices.IndexFunc(st.Publish.To, func(t ipc.ServeTo) bool { return t.Label == label }); i >= 0 {
			to = st.Publish.To[i].To
		}
	}
	next := slices.DeleteFunc(slices.Clone(target.Published), func(p types.PublishedName) bool { return p.Label == label })
	published := len(next) < len(target.Published)
	if !published && to == "" {
		return fmt.Errorf("%s does not publish %s\nhint: juist publish", displayMember(target), name)
	}
	canPublish := !here || to == "" || a.adminKeyHere(state)
	if published && canPublish {
		if _, err := a.submitPublished(auth, target, next); err != nil {
			return err
		}
	}
	if to != "" {
		after, err := n.exit(ipc.Request{Command: ipc.CmdPublish, Unserve: []string{label}})
		if err != nil {
			return err
		}
		a.ok("%s no longer goes to %s", name, describeTo(to))
		if st.Publish.Consent && (after.Publish == nil || len(after.Publish.To) == 0) {
			if err := a.stopTerminator(); err != nil {
				return err
			}
		}
	}
	if published && !canPublish {
		a.hint("an admin stops publishing it: juist publish remove %s %s", displayMember(target), name)
	}
	return nil
}

func publishServe(a *app, args []string) error {
	s := spec{name: "juist publish serve", about: `
Serve the names the network publishes on this device: the ingresses then
pass connections for them to this device's ports, where the service ends
TLS, or juist where told to (juist publish add NAME HOST:PORT). --stop undoes
it, and keeps where names go.`}
	fs := newFlags(s.name)
	stop := fs.Bool("stop", false, "stop serving")
	if _, err := a.parse(s, fs, args); err != nil {
		if name, addr, ok := cutServeTo(args); ok {
			return fmt.Errorf("unexpected argument %q\nhint: juist publish add %s %s", name+"="+addr, name, addr)
		}
		return err
	}
	st, err := a.daemonStatus()
	if err != nil {
		return err
	}
	if err := a.requireOperator(); err != nil {
		return err
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	pub := cmp.Or(st.Publish, &ipc.Publish{})
	if *stop {
		// A terminator a share left running stops here too.
		running := st.Terminator != nil && st.Terminator.Running && st.Share == nil
		if !pub.Consent && !running {
			a.ok("unchanged: not serving")
			return nil
		}
		if pub.Consent {
			if _, err := n.exit(ipc.Request{Command: ipc.CmdPublish, ServePublished: new(bool)}); err != nil {
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
	return a.serveHere(cmp.Or(st.SelfName, st.Self.ShortString()))
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
// device, named self.
func (a *app) serveHere(self string) error {
	n, err := a.openNode()
	if err != nil {
		return err
	}
	on := true
	after, err := n.exit(ipc.Request{Command: ipc.CmdPublish, ServePublished: &on})
	if err != nil {
		return err
	}
	pub := cmp.Or(after.Publish, &ipc.Publish{})
	// Started once told where names go, so that it is there when they are
	// published or the view is fresh again.
	if len(pub.To) > 0 {
		if err := a.startTerminator(); err != nil {
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
	a.showCAA(names...)
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
// for it to answer where the first name it serves is listened for.
func (a *app) startTerminator() error {
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
	if st := n.status(); st != nil && st.Instance != 0 {
		return errors.New("juist ends TLS for the default network's instance alone, for now")
	}
	resp, err := ipc.Call(n.socket(), ipc.Request{Command: ipc.CmdServing})
	if err != nil || resp.Serving == nil || len(resp.Serving.Names) == 0 || a.host.answersTLS == nil {
		return err
	}
	t := resp.Serving.Names[0]
	if len(t.Addrs) == 0 {
		return nil
	}
	at := netip.AddrPortFrom(t.Addrs[0], t.Port).String()
	// The terminator says where it listens; what answers there may be
	// another program's.
	for deadline := time.Now().Add(a.host.terminatorWait); a.host.terminatorWait > 0; {
		var said *ipc.Terminator
		if st, _ := n.restatus(); st != nil {
			said = st.Terminator
		}
		listening, err := terminatorAt(said, at)
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
	if err := a.host.answersTLS(a.ctx, at); err != nil {
		return fmt.Errorf("the terminator does not answer on %s: %v\nhint: %s", at, err, helperLog("juist-serve"))
	}
	return nil
}

// terminatorAt reports whether the terminator, as it last said, listens at
// at, and why it cannot where another program holds the port.
func terminatorAt(t *ipc.Terminator, at string) (bool, error) {
	switch {
	case t == nil || !t.Running:
		return false, nil
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
		if st := n.status(); st != nil && st.Share != nil {
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
	for {
		st, err := a.daemonStatus()
		var records []string
		if err == nil && st.Publish != nil {
			records = slices.DeleteFunc(slices.Clone(st.Publish.CAA), func(r string) bool {
				return !slices.Contains(names, strings.TrimSuffix(strings.Fields(r)[0], "."))
			})
		}
		if len(records) > 0 {
			for _, r := range records {
				a.printf("%s\n", r)
			}
			a.hint("at the domain's DNS, these records keep the names' certificates to this device")
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
	}
}

// notPublishedHere is juistd's word for a device the network publishes
// nothing on.
const notPublishedHere = "the network publishes nothing on this device"

// publishSummary is the status line of what this device serves of what is
// published on it; paint colours what it does not.
func publishSummary(pub *ipc.Publish, paint func(code, s string) string) string {
	switch {
	case pub == nil:
		return ""
	case len(pub.Serving) > 0 && pub.TerminatorSilent:
		return paint("33", "this device serves "+strings.Join(pub.Serving, ", ")+
			", but ends TLS for none: the terminator does not run (juist publish serve)")
	case len(pub.Serving) > 0:
		return "this device serves " + strings.Join(pub.Serving, ", ")
	case !pub.Consent && pub.NotServing == "":
		return paint("33", "not served here: not agreed to on this device (juist publish serve)")
	}
	return paint("33", "not served here: "+pub.NotServing)
}

// parseLabel reads arg as a name to publish under domain: one label, or one
// label of domain.
func parseLabel(arg, domain string) (string, error) {
	label := strings.ToLower(strings.TrimSuffix(arg, "."))
	if domain != "" && label == domain {
		return "", nil // the domain itself
	}
	if domain != "" {
		label = strings.TrimSuffix(label, "."+domain)
	}
	if strings.Contains(label, ".") {
		return "", fmt.Errorf("%q is no name under %s; a published name is one label, such as immich", arg,
			cmp.Or(domain, "the domain"))
	}
	if err := types.ValidateLabel(label); err != nil {
		return "", fmt.Errorf("%q is no name to publish: letters, digits and inner hyphens alone", arg)
	}
	return label, nil
}

// submitPublished proposes target's published names as next, and reports
// whether the change applied.
func (a *app) submitPublished(auth *log.Authority, target types.NodeRecord, next []types.PublishedName) (bool, error) {
	name := displayMember(target)
	if slices.Equal(next, target.Published) {
		a.ok("%s: unchanged", name)
		return false, nil
	}
	aum, err := auth.Builder().SetPublished(target.Identity, next)
	if err != nil {
		return false, err
	}
	done := name + ": publishes nothing"
	if len(next) > 0 {
		done = name + ": publishes " + publishedList(next, auth.State().Domain())
	}
	return a.submit(auth, &change{aum: aum, file: "publish-" + fileSafe(name) + ".rec", done: done})
}

// publishedList is ps under domain, as "NAME:PORT".
func publishedList(ps []types.PublishedName, domain string) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = fmt.Sprintf("%s:%d", p.Under(domain), p.Port)
	}
	return strings.Join(out, ", ")
}
