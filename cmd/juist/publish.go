package main

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"net"
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

const publishAbout = `
Publish services on the internet through an ingress, or list them.

  juist publish                           list the published names
  juist publish NAME PORT|HOST:PORT       publish NAME here; juist ends TLS
  juist publish NAME status-page          publish the network's status page
  juist publish NAME [PORT] --on DEVICE   publish NAME on DEVICE, whose
                                          service on PORT (443) ends TLS
  juist publish NAME                      serve what is published here
  juist publish PORT                      publish PORT under this device's name
  juist publish --stop [NAME|PORT]        stop publishing; alone, stop serving

NAME is a name under the network's domain, such as docs, the domain itself,
or a full name whose DNS points at the ingresses, such as photos.example.org.
Publishing a name takes an admin key; without one, juist prints the admin's
command. PORT needs the publish role and lasts until Ctrl-C, --for or --stop.`

func cmdPublish(a *app, args []string) error {
	s := spec{name: "juist publish", args: "[NAME] [PORT|HOST:PORT|status-page]", max: -1, about: publishAbout}
	fs := newFlags(s.name)
	on := fs.String("on", "", "publish on `DEVICE`, whose service ends TLS")
	stop := fs.Bool("stop", false, "stop publishing NAME or PORT; alone, stop serving")
	proxy := fs.Bool("proxy", false, "send the client address in a PROXY protocol v2 header")
	http2 := fs.Bool("http2", false, "offer HTTP/2; the service speaks it without TLS (h2c)")
	http3 := fs.Bool("http3", false, "offer HTTP/3 too")
	tcp := &tcpFlag{}
	fs.Var(tcp, "tcp", "publish by TCP on PORT of every ingress, default the device's port")
	membersOn := fs.Bool("members", false, "for members only, not the internet; =false makes it public")
	public := fs.String("public", ipc.ShowServices.String(), "`WHAT` non-members see of the status page: none, services, network or all")
	var dur longDuration
	fs.Var(&dur, "for", "publish PORT for `DURATION`, like 2h or 7d")
	bg := fs.Bool("background", false, "publish PORT in the background")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	// refuse says which of opts, given, the form does not take.
	refuse := func(form string, opts ...string) error {
		for _, o := range opts {
			if given[o] {
				return a.usageErr("--%s cannot be used with %s", o, form)
			}
		}
		return nil
	}
	if len(pos) > 2 {
		if tcp.on && tcp.port == 0 && isPort(pos[2]) {
			return a.usageErr("unexpected argument %q: the public port goes in --tcp=%s", pos[2], pos[2])
		}
		return fmt.Errorf("unexpected argument %q\n%s", pos[2], s.usage(fs))
	}
	nameOpts := []string{"on", "proxy", "http2", "http3", "tcp", "members", "public"}
	switch {
	case *stop:
		if err := refuse("--stop", slices.Concat(nameOpts[1:], []string{"for", "background"})...); err != nil {
			return err
		}
		return a.publishStop(pos, *on)
	case len(pos) == 0:
		if err := refuse("juist publish alone", slices.Concat(nameOpts, []string{"for", "background"})...); err != nil {
			return err
		}
		if listed, err := a.forEachNetwork(a.listPublished); listed {
			return err
		}
		return a.listPublished()
	case len(pos) == 1 && strings.Trim(pos[0], "0123456789") == "" && *on == "":
		if err := refuse("juist publish PORT", nameOpts...); err != nil {
			return err
		}
		return a.publishPort(pos[0], time.Duration(dur), *bg)
	}
	if err := refuse("juist publish NAME", "for", "background"); err != nil {
		return err
	}
	if pos[0] == statusPageWord {
		return fmt.Errorf("missing NAME\nusage: juist publish NAME status-page [--public WHAT]")
	}
	if given["public"] && (len(pos) < 2 || pos[1] != statusPageWord) {
		return a.usageErr("--public only works with status-page")
	}
	httpFlag := "--http2"
	if *http3 {
		httpFlag = "--http3"
	}
	if (*http2 || *http3) && tcp.on {
		return a.usageErr("%s cannot be used with --tcp", httpFlag)
	}
	// Kept where not given, so that a name for members alone is not made
	// public by a command that leaves it out.
	var members *bool
	if given["members"] {
		members = membersOn
	}
	if *membersOn && (tcp.on || *proxy) {
		return a.usageErr("--members cannot be used with --tcp or --proxy")
	}
	var target string
	if len(pos) == 2 {
		target = pos[1]
	}
	switch {
	case target == statusPageWord:
		if err := refuse("status-page", "proxy", "http2", "http3", "tcp", "members"); err != nil {
			return err
		}
		vis, err := ipc.ParseVisibility(*public)
		if err != nil {
			return a.usageErr("--public: %v", err)
		}
		return a.publishHere(withDevice(*on, pos[0], ipc.StatusPageTo(vis)), false, nil, &tcpFlag{})
	case strings.Contains(target, ":"):
		if *http2 {
			target = ipc.HTTP2To(target)
		}
		if *http3 {
			target = ipc.HTTP3To(target)
		}
		return a.publishHere(withDevice(*on, pos[0], target), *proxy, members, tcp)
	case *on != "":
		if *http2 || *http3 {
			return a.usageErr("%s cannot be used with --on: the service there ends TLS itself", httpFlag)
		}
		return a.publishOn(*on, pos[0], target, *proxy, members, tcp)
	case target != "":
		if !isPort(target) {
			return a.usageErr("%q is not a port, HOST:PORT or status-page", target)
		}
		to := localService(a, target)
		if *http2 {
			to = ipc.HTTP2To(to)
		}
		if *http3 {
			to = ipc.HTTP3To(to)
		}
		return a.publishHere([]string{pos[0], to}, *proxy, members, tcp)
	}
	if err := refuse("juist publish NAME without PORT", nameOpts...); err != nil {
		return err
	}
	return a.serveName(pos[0])
}

// hintLabelOfDigits says, after juist publish --stop PORT, how to name a
// published name of that label on this device instead.
func (a *app) hintLabelOfDigits(port string) {
	if name, arg, ok := a.labelPublishedHere(port); ok {
		a.hint("to stop the name %s: juist publish --stop %s", name, arg)
	}
}

// labelPublishedHere reports whether this device publishes label, and its
// name and how a command names it.
func (a *app) labelPublishedHere(label string) (name, arg string, ok bool) {
	n, err := a.openNode()
	if err != nil {
		return "", "", false
	}
	// A hint: nothing asked, no operator made for it.
	if d := daemonOf(n); d != nil && !d.st.CanOperate {
		return "", "", false
	}
	st := liveStatus(n)
	auth, err := n.log()
	if st == nil || err != nil {
		return "", "", false
	}
	state := auth.State()
	self, found := state.Node(st.Self)
	if !found || !slices.ContainsFunc(self.Published, func(p types.PublishedName) bool { return p.Label == label }) {
		return "", "", false
	}
	return nameUnder(label, state.Domain()), labelArg(label, state.Domain()), true
}

// statusPageWord is the target that publishes the network's status page.
const statusPageWord = "status-page"

// isPort reports whether arg is a port's number.
func isPort(arg string) bool {
	n, err := strconv.ParseUint(arg, 10, 16)
	return err == nil && n > 0
}

// withDevice is publishHere's arguments: name and target, after device where
// one is given.
func withDevice(device, name, target string) []string {
	if device == "" {
		return []string{name, target}
	}
	return []string{device, name, target}
}

// localService is the address of this host's port, at IPv4's loopback, or
// IPv6's where only it answers, as a server bound to localhost may be; it
// warns where neither answers yet.
func localService(a *app, port string) string {
	for _, host := range []string{"127.0.0.1", "::1"} {
		if c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), time.Second); err == nil {
			c.Close()
			return net.JoinHostPort(host, port)
		}
	}
	to := net.JoinHostPort("127.0.0.1", port)
	a.warn("nothing answers on %s yet", to)
	return to
}

// listPublished is "juist publish" for one network: the domain's names
// under it by their labels, then names of their own.
func (a *app) listPublished() error {
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	domain := state.Domain()
	node, err := a.openNode()
	if err != nil {
		return err
	}
	var self types.NodeRecord
	var to []ipc.ServeTo
	st := liveStatus(node)
	if st != nil {
		self, _ = state.Node(st.Self)
		if st.Publish != nil {
			to = st.Publish.To
		}
	}
	type row struct {
		label, device, port, to, state string
	}
	var rows []row
	for _, n := range state.Nodes() {
		for _, p := range n.Published {
			r := row{label: p.Label, device: displayMember(n), port: portShown(p)}
			if p.Public != 0 {
				r.port = fmt.Sprintf("%d/tcp", p.Public)
				r.to = fmt.Sprintf("%s:%d", r.device, p.Port)
			}
			if p.Proxy {
				r.port += " (proxy protocol)"
			}
			if p.Members {
				r.port += " (members)"
			}
			if st != nil && n.Identity == st.Self {
				if i := slices.IndexFunc(to, func(t ipc.ServeTo) bool { return t.Label == p.Label }); i >= 0 && p.Public == 0 {
					r.to = describeTo(to[i].To)
					if to[i].Members && !p.Members {
						r.to += " (members)"
					}
				}
			}
			if st != nil {
				r.state = publishedState(st, n, p, domain)
			}
			rows = append(rows, r)
		}
	}
	for _, t := range to {
		if !slices.ContainsFunc(self.Published, func(p types.PublishedName) bool { return p.Label == t.Label }) {
			r := row{label: t.Label, device: displayMember(self), port: "-", to: describeTo(t.To), state: stateUnpublished}
			if t.Members {
				r.to += " (members)"
			}
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		a.ok("no published names")
		if domain == "" {
			a.hint("an admin sets the domain first: juist network domain pub.example.org")
		} else {
			a.hint("publish one: juist publish NAME PORT")
		}
		return nil
	}
	// The domain itself heads its labels; names of their own follow.
	rank := func(r row) int {
		switch {
		case r.label == "":
			return 0
		case types.OwnName(r.label):
			return 2
		}
		return 1
	}
	slices.SortStableFunc(rows, func(x, y row) int {
		return cmp.Or(cmp.Compare(rank(x), rank(y)), strings.Compare(x.label, y.label))
	})
	if domain != "" && rank(rows[0]) == 1 {
		rows = slices.Insert(rows, 0, row{})
	}
	showTo := slices.ContainsFunc(rows, func(r row) bool { return r.to != "" })
	var table strings.Builder
	tw := tabwriter.NewWriter(&table, 0, 0, 2, ' ', 0)
	head := []string{"NAME", "DEVICE", "PORT"}
	if showTo {
		head = append(head, "TO")
	}
	if st != nil {
		head = append(head, "STATE")
	}
	fmt.Fprintln(tw, strings.Join(head, "\t"))
	for _, r := range rows {
		name := r.label
		switch rank(r) {
		case 0:
			name = domain
		case 1:
			name = "  " + r.label
		}
		cells := []string{name, r.device, r.port}
		if showTo {
			cells = append(cells, r.to)
		}
		switch {
		case st == nil:
		case r.device == "": // the domain, heading its labels alone
			cells = append(cells, "")
		default:
			cells = append(cells, a.paintState(r.state))
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	// Every row keeps its cells, so that one column block aligns them all.
	for _, l := range strings.SplitAfter(table.String(), "\n") {
		a.printf("%s", strings.TrimRight(l, " \n")+strings.Repeat("\n", strings.Count(l, "\n")))
	}
	return nil
}

// The states juist publish lists a name in.
const (
	stateServing     = "serving"
	stateUnserved    = "unserved"
	stateUnpublished = "unpublished"
	stateFailing     = "failing"
	stateOffline     = "offline"
)

// publishedState is p's state, published on n, as st has it: this device's
// own names as it serves them, another's as its announcement and reach say.
func publishedState(st *ipc.Status, n types.NodeRecord, p types.PublishedName, domain string) string {
	name := p.Under(domain)
	if n.Identity != st.Self {
		if i := slices.IndexFunc(st.Reach, func(r ipc.PeerReach) bool { return r.Identity == n.Identity }); i >= 0 &&
			!st.Reach[i].Live && st.Reach[i].Absent || i < 0 && slices.Contains(st.Silent, n.Name) {
			return stateOffline
		}
		i := slices.IndexFunc(st.Devices, func(d ipc.Device) bool { return d.Identity == n.Identity })
		switch {
		case i < 0:
			return ""
		case st.Devices[i].Serving:
			return stateServing
		}
		return stateUnserved
	}
	pub := st.Publish
	passedOn := func(e string) bool { return strings.HasPrefix(e, name+" to ") }
	switch {
	case pub == nil || !slices.Contains(pub.Serving, name),
		slices.Contains(pub.Withheld, name),
		slices.ContainsFunc(pub.Shared, func(s string) bool { return strings.HasPrefix(s, name+" with ") }),
		pub.TerminatorSilent && (slices.ContainsFunc(pub.Ending, passedOn) || slices.ContainsFunc(pub.Passing, passedOn)):
		return stateUnserved
	}
	if t := st.Terminator; t != nil {
		held := func(u string) bool {
			ap, err := netip.ParseAddrPort(u)
			return err == nil && ap.Port() == p.Port
		}
		if slices.ContainsFunc(t.NoCert, func(c ipc.NoCert) bool { return c.Name == name }) || slices.ContainsFunc(t.Unbound, held) {
			return stateFailing
		}
	}
	return stateServing
}

// paintState colours a state as juist publish lists it.
func (a *app) paintState(state string) string {
	switch state {
	case "":
		return "-"
	case stateServing:
		return a.paint("32", state)
	case stateOffline:
		return a.dim(state)
	}
	return a.paint("33", state)
}

// publishOn is "juist publish NAME [PORT] --on DEVICE": NAME published on
// DEVICE's PORT, 443 unless given, where its service ends TLS, or passed
// there by TCP.
func (a *app) publishOn(device, name, portArg string, proxy bool, members *bool, tcp *tcpFlag) error {
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	target, err := resolveDevice(state, device)
	if err != nil {
		return err
	}
	label, err := a.publishableLabel(state, name)
	if err != nil {
		return err
	}
	if err := newLabel(state, label); err != nil {
		return err
	}
	port := uint16(443)
	switch {
	case portArg != "":
		n, err := strconv.ParseUint(portArg, 10, 16)
		if err != nil || n == 0 {
			return a.usageErr("%q is not a port", portArg)
		}
		port = uint16(n)
	case tcp.on:
		return a.usageErr("--tcp with --on needs PORT")
	}
	p := types.PublishedName{Label: label, Port: port, Proxy: proxy, Members: keptMembers(target, label, members)}
	if p.Public, err = tcp.public(state, target, label, port, ""); err != nil {
		return err
	}
	if err := membersAllowed(state, p); err != nil {
		return err
	}
	next, err := publishedWith(state, target, p, a.now().Unix())
	if err != nil {
		return err
	}
	applied, err := a.submitPublished(auth, target, next)
	if err != nil || !applied {
		return err
	}
	a.domainItselfHint(label, state.Domain())
	return a.servePublishedNext(target, label, state.Domain())
}

// serveName is "juist publish NAME" on the device NAME is published on:
// served as it is.
func (a *app) serveName(name string) error {
	d, err := a.daemon()
	if err != nil {
		return err
	}
	if err := a.requireOperator(); err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	self, ok := state.Node(d.st.Self)
	if !ok {
		return errors.New("this device is not a member of the network")
	}
	label, err := a.publishableLabel(state, name)
	if err != nil {
		return err
	}
	published := slices.ContainsFunc(self.Published, func(q types.PublishedName) bool { return q.Label == label })
	if d.st.Publish != nil && !published {
		// How it was meant, by TCP or with PROXY, juist does not keep: the
		// operator's own command said it, and says it again.
		if i := slices.IndexFunc(d.st.Publish.To, func(t ipc.ServeTo) bool { return t.Label == label }); i >= 0 {
			t := d.st.Publish.To[i]
			err := fmt.Sprintf("%s goes to %s but is not published", nameUnder(label, state.Domain()), describeTo(t.To))
			if hint := unpublishedHint(t, state.Domain(), displayMember(self)); hint != "" {
				err += "\nhint: " + hint
			}
			return errors.New(err)
		}
	}
	if !published {
		if onlyDigits(label) {
			return fmt.Errorf("%s is not published on this device", nameUnder(label, state.Domain()))
		}
		return fmt.Errorf("%s is not published on this device\nhint: juist publish %s PORT", nameUnder(label, state.Domain()), name)
	}
	return a.serveHere(d, displayMember(self), d.st.Publish != nil && d.st.Publish.Consent)
}

// domainItselfHint says what publishing the domain itself, label "", or a
// name of its own needs besides: its own addresses at its DNS, which
// *.DOMAIN does not cover.
func (a *app) domainItselfHint(label, domain string) {
	switch {
	case label == "":
		a.hint("point A and AAAA records of %s at the ingress; *.%s does not cover it", domain, domain)
	case types.OwnName(label):
		a.hint("point A and AAAA records of %s at the ingress", label)
	}
}

// publishHere is "juist publish NAME HOST:PORT [--on DEVICE]", DEVICE this
// one: NAME published here, on the port it is already or 443, and its TLS
// ended here and sent on; by TCP, on the public port, and passed on as it
// is.
func (a *app) publishHere(pos []string, proxy bool, members *bool, tcp *tcpFlag) error {
	d, err := a.daemon()
	if err != nil {
		return err
	}
	st := d.st
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	self, ok := state.Node(st.Self)
	if !ok {
		return errors.New("this device is not a member of the network")
	}
	ends, flags := "ends TLS", ""
	if tcp.on {
		ends, flags = "passes TCP on", " --tcp"
		if tcp.port != 0 {
			flags += "=" + strconv.Itoa(int(tcp.port))
		}
	}
	if proxy {
		flags += " --proxy"
	}
	if members != nil && *members {
		flags += " --members"
	}
	hostPort, h2c := ipc.HTTP2Of(pos[len(pos)-1])
	if h2c {
		flags += " --http2"
	}
	if _, h3 := ipc.HTTP3Of(pos[len(pos)-1]); h3 {
		flags += " --http3"
	}
	if vis, ok := ipc.StatusPageOf(pos[len(pos)-1]); ok {
		hostPort, flags = statusPageWord, " --public "+vis.String()
	}
	if len(pos) == 3 {
		target, err := resolveDevice(state, pos[0])
		if err != nil {
			return err
		}
		if target.Identity != self.Identity {
			what := "HOST:PORT"
			if hostPort == statusPageWord {
				what = statusPageWord
			}
			return fmt.Errorf("%s only works on this device\nhint: on %s, juist publish %s %s%s",
				what, displayMember(target), pos[1], hostPort, flags)
		}
		pos = pos[1:]
	}
	switch {
	case a.host.serveScript == "":
		return fmt.Errorf("juist %s only on Linux and FreeBSD", ends)
	case st.Instance != 0:
		return fmt.Errorf("juist %s only in the default instance, for now", ends)
	}
	label, err := a.publishableLabel(state, pos[0])
	if err != nil {
		return err
	}
	if err := newLabel(state, label); err != nil {
		return err
	}
	t := ipc.ServeTo{Label: label, To: pos[1]}
	if !t.Valid() {
		addr, _ := ipc.HTTP2Of(pos[1])
		return a.usageErr("%q is not HOST:PORT", addr)
	}
	p := types.PublishedName{Label: label, Port: 443, Proxy: proxy, Members: keptMembers(self, label, members)}
	// Its service's mark is kept too, until --members=false; the log is
	// changed by the flag alone.
	marked := p.Members || members == nil && st.Publish != nil &&
		slices.ContainsFunc(st.Publish.To, func(s ipc.ServeTo) bool { return s.Label == label && s.Members })
	i := slices.IndexFunc(self.Published, func(q types.PublishedName) bool { return q.Label == label })
	if i >= 0 {
		p.Port = self.Published[i].Port
	}
	switch {
	case !tcp.on:
	case i >= 0 && self.Published[i].Public != 0 && (tcp.port == 0 || tcp.port == self.Published[i].Public):
		// On the ports it is published on already.
		p.Port = self.Published[i].Port
		tcp = &tcpFlag{on: true, port: self.Published[i].Public}
	default:
		_, port, _ := net.SplitHostPort(pos[1])
		n, _ := strconv.ParseUint(port, 10, 16)
		// The device takes the public port too, so that members reach it there.
		p.Port = cmp.Or(tcp.port, uint16(n))
	}
	again := "juist publish " + pos[0] + " " + hostPort + " --tcp"
	if proxy {
		again += " --proxy"
	}
	if p.Public, err = tcp.public(state, self, label, p.Port, again); err != nil {
		return err
	}
	if err := membersAllowed(state, p); err != nil {
		return err
	}
	next, err := publishedWith(state, self, p, a.now().Unix())
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
	// juistd holds a service meant for members alone from the name while the
	// log has it public.
	t.Members = marked
	agreed := st.Publish != nil && st.Publish.Consent
	on := true
	after, err := d.request(ipc.Request{Command: ipc.CmdPublish, ServePublished: &on, ServeTo: []ipc.ServeTo{t}})
	if err != nil {
		return err
	}
	pub := cmp.Or(after.Publish, &ipc.Publish{})
	if err := a.startTerminator(p.Under(state.Domain())); err != nil {
		return err
	}
	if !agreed && len(pub.Serving) > 0 {
		a.ok("serving %s", strings.Join(pub.Serving, ", "))
	}
	name := p.Under(state.Domain())
	switch {
	case slices.Contains(pub.Withheld, name):
		a.warn("%s", withheldWarning(name))
	case slices.Contains(pub.Passing, name+" to "+t.To):
		a.ok("passing %s to %s", name, t.To)
	case slices.Contains(pub.Ending, name+" to "+t.To):
		a.ok("ending TLS for %s to %s", name, describeTo(t.To))
		a.showCAA(name)
		a.showHTTPS(pub.Ending, name)
		if label == "" {
			a.warn("a CAA record at %s also covers every name under it without its own: give the names of other devices CAA records too", name)
		}
	case slices.ContainsFunc(pub.Shared, func(s string) bool { return strings.HasPrefix(s, name+" with ") }):
		i := slices.IndexFunc(pub.Shared, func(s string) bool { return strings.HasPrefix(s, name+" with ") })
		a.warn("%s", sharedWarning(pub.Shared[i]))
		a.hint("%s", sharedHint)
	case !published && t.Members:
		a.ok("%s goes to %s once published on this device for members only", name, describeTo(t.To))
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
	if withheld := slices.Contains(pub.Withheld, name); !canPublish || withheld {
		if p.Public != 0 && i >= 0 && self.Published[i].Public == 0 {
			a.warn("until an admin publishes it by TCP, juist ends TLS for %s", name)
		}
		asked := p
		asked.Members = asked.Members || withheld
		a.hint("an admin publishes it: %s", publishCommand(asked, state.Domain(), displayMember(self)))
	}
	if !agreed {
		a.warnServing()
	}
	return nil
}

// tcpFlag is --tcp, or --tcp=PORT: a name published by TCP, on the public
// port given or on the one the device takes.
type tcpFlag struct {
	on   bool
	port uint16
}

func (f *tcpFlag) String() string {
	switch {
	case f == nil || !f.on:
		return "false"
	case f.port == 0:
		return "true"
	}
	return strconv.Itoa(int(f.port))
}

func (f *tcpFlag) Set(v string) error {
	switch v {
	case "true":
		f.on, f.port = true, 0
		return nil
	case "false":
		f.on, f.port = false, 0
		return nil
	}
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil || n == 0 {
		return errors.New("not a port")
	}
	f.on, f.port = true, uint16(n)
	return nil
}

func (*tcpFlag) IsBoolFlag() bool    { return true }
func (*tcpFlag) Placeholder() string { return "[=PORT]" }

// public is the public port of label, published on target's port, by TCP
// where f says, zero otherwise: a name published by TCP stays so until
// removed, so that one left out of a command is not turned to TLS.
// The hint names again, or the admin's command where empty.
func (f *tcpFlag) public(state *log.State, target types.NodeRecord, label string, port uint16, again string) (uint16, error) {
	i := slices.IndexFunc(target.Published, func(q types.PublishedName) bool { return q.Label == label })
	if !f.on {
		if i >= 0 && target.Published[i].Public != 0 {
			p := target.Published[i]
			if again == "" {
				again = publishCommand(p, state.Domain(), displayMember(target))
			}
			return 0, fmt.Errorf("%s is published by TCP on port %d\nhint: %s, or juist publish --stop %s first",
				p.Under(state.Domain()), p.Public, again, labelArg(p.Label, state.Domain()))
		}
		return 0, nil
	}
	public := cmp.Or(f.port, port)
	if err := types.ValidatePublicPort(public); err != nil {
		return 0, fmt.Errorf("cannot publish by TCP on %v", err)
	}
	for _, n := range state.Nodes() {
		for _, q := range n.Published {
			if q.Public == public && (n.Identity != target.Identity || q.Label != label) {
				return 0, fmt.Errorf("%s is published on port %d already\nhint: use another port: --tcp=PORT",
					q.Under(state.Domain()), public)
			}
		}
	}
	return public, nil
}

// publishCommand is the admin's command that publishes p on device.
func publishCommand(p types.PublishedName, domain, device string) string {
	how := "juist publish " + labelArg(p.Label, domain)
	if p.Port != 443 || p.Proxy || p.Public != 0 {
		how += " " + strconv.Itoa(int(p.Port))
	}
	switch {
	case p.Public == p.Port:
		how += " --tcp"
	case p.Public != 0:
		how += " --tcp=" + strconv.Itoa(int(p.Public))
	}
	if p.Proxy {
		how += " --proxy"
	}
	if p.Members {
		how += " --members"
	}
	return how + " --on " + device
}

// labelArg is label as a command takes it: the domain itself spelled out.
func labelArg(label, domain string) string {
	if onlyDigits(label) && domain != "" {
		return label + "." + domain // alone, it would be taken for a port
	}
	return cmp.Or(label, domain)
}

// newLabel refuses as a name not yet published a label juist publish would
// take for a port.
func newLabel(state *log.State, label string) error {
	published := slices.ContainsFunc(state.Nodes(), func(n types.NodeRecord) bool {
		return slices.ContainsFunc(n.Published, func(p types.PublishedName) bool { return p.Label == label })
	})
	switch {
	case published || label == "":
	case onlyDigits(label):
		return fmt.Errorf("name cannot be only digits: %s", label)
	}
	return nil
}

// onlyDigits reports whether label is digits alone, which a new name may
// not be.
func onlyDigits(label string) bool {
	return label != "" && strings.Trim(label, "0123456789") == ""
}

// unpublishedHint is the admin's command that publishes t's name on device:
// for members alone where t's service is, else with what juist does not
// know of how it was meant.
func unpublishedHint(t ipc.ServeTo, domain, device string) string {
	if onlyDigits(t.Label) {
		return "" // no command publishes it anew
	}
	cmd := publishCommand(types.PublishedName{Label: t.Label, Port: 443, Members: t.Members}, domain, device)
	if _, page := ipc.StatusPageOf(t.To); page || t.Members {
		return "an admin publishes it: " + cmd
	}
	return "an admin publishes it: " + cmd + " (add PORT and --tcp or --proxy if the service needs them)"
}

// keptMembers is whether label, published on n, is for members alone: as
// given, or as it is already.
func keptMembers(n types.NodeRecord, label string, given *bool) bool {
	if given != nil {
		return *given
	}
	i := slices.IndexFunc(n.Published, func(q types.PublishedName) bool { return q.Label == label })
	return i >= 0 && n.Published[i].Members
}

// membersAllowed refuses a name for members alone the network cannot hold:
// before its schema, or on another port than 443, where members would reach
// it through the ingress, which passes it nobody.
func membersAllowed(state *log.State, p types.PublishedName) error {
	switch {
	case !p.Members:
		return nil
	case p.Proxy || p.Public != 0:
		return fmt.Errorf("%s is for members only: --proxy and --tcp cannot be used\nhint: make it public first: --members=false",
			p.Under(state.Domain()))
	case p.Port != 443:
		return errors.New("a name for members only must be on port 443")
	case types.OwnName(p.Label):
		return fmt.Errorf("%s cannot be for members only: it is not under %s", p.Label, state.Domain())
	}
	return nil
}

// portShown is where p is published, as a listing says it.
func portShown(p types.PublishedName) string {
	switch {
	case p.Public == 0:
		return strconv.Itoa(int(p.Port))
	case p.Public == p.Port:
		return strconv.Itoa(int(p.Public)) + "/tcp"
	}
	return fmt.Sprintf("%d/tcp to %d", p.Public, p.Port)
}

// describeTo says where a name whose TLS juist ends goes.
func describeTo(to string) string {
	if vis, ok := ipc.StatusPageOf(to); ok {
		return "the status page, public: " + vis.String()
	}
	_, h3 := ipc.HTTP3Of(to)
	addr, h2c := ipc.HTTP2Of(to)
	if h2c {
		addr += " over HTTP/2"
	}
	if h3 {
		addr += ", with HTTP/3"
	}
	return addr
}

// showHTTPS prints the DNS record that has browsers ask each of names over
// HTTP/3 from the first, which ending, "NAME to TO" each, offers it for.
func (a *app) showHTTPS(ending []string, names ...string) {
	said := false
	for _, e := range ending {
		name, to, _ := strings.Cut(e, " to ")
		if _, h3 := ipc.HTTP3Of(to); h3 && slices.Contains(names, name) {
			a.printf("%s. HTTPS 1 . alpn=\"h3,h2\"\n", name)
			said = true
		}
	}
	if said {
		a.hint("add this record at the domain's DNS so that browsers try HTTP/3 at once")
		a.hintOwnRecords()
	}
}

// hintOwnRecords says once that a name given records of its own, CAA or
// HTTPS, is given no address by a wildcard (RFC 4592).
func (a *app) hintOwnRecords() {
	if !a.ownRecordsSaid {
		a.ownRecordsSaid = true
		a.hint("a name with its own records gets no address from a wildcard: add A and AAAA records too")
	}
}

// nameUnder is label under domain, or label alone without one.
func nameUnder(label, domain string) string {
	if domain == "" {
		return cmp.Or(label, "the domain itself")
	}
	return types.PublishedName{Label: label}.Under(domain)
}

// publishableLabel reads arg as a name to publish in state's network.
func (a *app) publishableLabel(state *log.State, arg string) (string, error) {
	if state.Domain() == "" {
		return "", fmt.Errorf("the network has no domain to publish under\nhint: juist network domain pub.example.org")
	}
	label, err := parseLabel(arg, state.Domain())
	switch {
	case err != nil:
		return "", a.usageErr("%v", err)
	case types.OwnName(label) && state.Schema() < types.SchemaOwnNames:
		return "", needsUpgrade("names of their own")
	}
	return label, nil
}

// publishedWith is what target publishes once it publishes p too, in
// place of a name of p's label; p must be published on no other device.
func publishedWith(state *log.State, target types.NodeRecord, p types.PublishedName, now int64) ([]types.PublishedName, error) {
	if err := labelFree(state, p.Label, target.Identity, now); err != nil {
		return nil, err
	}
	next := slices.DeleteFunc(slices.Clone(target.Published), func(q types.PublishedName) bool { return q.Label == p.Label })
	if len(next) >= types.MaxPublishedPerNode {
		return nil, fmt.Errorf("%s already publishes %d names, the maximum", displayMember(target), types.MaxPublishedPerNode)
	}
	next = append(next, p)
	slices.SortFunc(next, func(x, y types.PublishedName) int { return strings.Compare(x.Label, y.Label) })
	return next, nil
}

// labelFree says why label is no name to publish under the domain on a
// device other than except at unix time now: another publishes it, holds it
// as its own name, or a name under it points at a member.
func labelFree(state *log.State, label string, except types.Identity, now int64) error {
	name := nameUnder(label, state.Domain())
	if relay, ok := ingressRelay(state, now); label == "relay" && ok {
		return fmt.Errorf("%s is taken by the relay on %s", name, displayMember(relay))
	}
	return labelClaimed(state, label, except)
}

// ingressRelay is an ingress that relays and has not expired at unix time
// now, whose relay takes relay.DOMAIN unless named otherwise, as
// daemon.IngressRelayName says.
func ingressRelay(state *log.State, now int64) (types.NodeRecord, bool) {
	for _, n := range state.Nodes() {
		if n.HasRole(types.RoleIngress) && n.HasRole(types.RoleRelayCapable) && !n.Expired(now) {
			return n, true
		}
	}
	return types.NodeRecord{}, false
}

// labelClaimed is [labelFree] but for the ingress's relay.
func labelClaimed(state *log.State, label string, except types.Identity) error {
	name := nameUnder(label, state.Domain())
	for _, n := range state.Nodes() {
		if n.Identity == except {
			continue
		}
		switch l, ok := n.ShareLabel(); {
		case slices.ContainsFunc(n.Published, func(q types.PublishedName) bool { return q.Label == label }):
			return fmt.Errorf("%s is published on %s already\nhint: juist publish --stop %s --on %s",
				name, displayMember(n), labelArg(label, state.Domain()), displayMember(n))
		case ok && l == label && n.HasRole(types.RolePublish):
			return fmt.Errorf("%s is taken: %s shares under it", name, displayMember(n))
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

// servePublishedNext follows label, published on target: on this device,
// for its operator, it is served at once; elsewhere a hint names what the
// target's operator runs, unless the target serves already.
func (a *app) servePublishedNext(target types.NodeRecord, label, domain string) error {
	st := liveStatus(a.node)
	switch {
	case st != nil && st.Self == target.Identity && st.CanOperate:
		if st.Publish != nil && st.Publish.Consent {
			return nil
		}
		return a.serveHere(daemonOf(a.node), displayMember(target), false)
	case st != nil && slices.ContainsFunc(st.Devices, func(d ipc.Device) bool { return d.Identity == target.Identity && d.Serving }):
		return nil
	case target.HasRole(types.RoleService):
		return nil // its juistd --serve agreed already
	}
	a.hint("on %s, juist publish %s", displayMember(target), labelArg(label, domain))
	return nil
}

// publishStop is "juist publish --stop [NAME|PORT] [--on DEVICE]": NAME no
// longer published on DEVICE, this device unless given, and its TLS no
// longer ended here; PORT's share ended; or, alone, nothing served here.
func (a *app) publishStop(pos []string, device string) error {
	switch {
	case len(pos) > 1:
		return fmt.Errorf("unexpected argument %q\nusage: juist publish --stop [NAME|PORT] [--on DEVICE]", pos[1])
	case len(pos) == 0 && device != "":
		return errors.New("missing NAME\nusage: juist publish --stop [NAME|PORT] [--on DEVICE]")
	case len(pos) == 0:
		return a.stopServing()
	case isPort(pos[0]) && device == "":
		if err := a.stopShare(pos[0]); err != nil {
			if name, arg, ok := a.labelPublishedHere(pos[0]); ok {
				first, _, _ := strings.Cut(err.Error(), "\n")
				return fmt.Errorf("%s\nhint: to stop the name %s: juist publish --stop %s", first, name, arg)
			}
			return err
		}
		a.hintLabelOfDigits(pos[0])
		return nil
	}
	if device != "" {
		pos = []string{device, pos[0]}
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
	d := daemonOf(n)
	st := liveStatus(n)
	var target types.NodeRecord
	if len(pos) == 2 {
		if target, err = resolveDevice(state, pos[0]); err != nil {
			return err
		}
	} else {
		if d, err = a.daemon(); err != nil {
			return err
		}
		st = d.st
		var ok bool
		if target, ok = state.Node(st.Self); !ok {
			return errors.New("this device is not a member of the network")
		}
	}
	label, err := parseLabel(pos[len(pos)-1], state.Domain())
	if err != nil {
		return a.usageErr("%v", err)
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
		return fmt.Errorf("%s does not publish %s\nhint: juist publish lists the published names", displayMember(target), name)
	}
	canPublish := !here || to == "" || a.adminKeyHere(state)
	if published && canPublish {
		if _, err := a.submitPublished(auth, target, next); err != nil {
			return err
		}
	}
	if to != "" {
		after, err := d.request(ipc.Request{Command: ipc.CmdPublish, Unserve: []string{label}})
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
		a.hint("an admin stops publishing it: juist publish --stop %s --on %s", labelArg(label, state.Domain()), displayMember(target))
	}
	return nil
}

// notPublishedHere is juistd's word for a device the network publishes
// nothing on.
const notPublishedHere = "the network publishes nothing on this device"

// sharedWarning says why a name for members alone, "NAME with OTHER", is
// not served.
func sharedWarning(shared string) string {
	name, other, _ := strings.Cut(shared, " with ")
	return fmt.Sprintf("not serving %s, which is for members only: %s reaches the same service, "+
		"whose clients could ask it for %s by Host", name, other, name)
}

const sharedHint = "give a name for members only its own service"

// withheldWarning says why name, its service meant for members alone, is
// not served.
func withheldWarning(name string) string {
	return fmt.Sprintf("not serving %s: its service is for members only, but the name is public", name)
}

// publishSummary is the status line of what this device serves of
// published, the names the log publishes on it; paint colours what it does
// not.
func publishSummary(pub *ipc.Publish, published []string, paint func(code, s string) string) string {
	switch {
	case pub == nil:
		return ""
	case len(pub.Serving) > 0 && pub.TerminatorSilent:
		return paint("33", "this device serves "+strings.Join(pub.Serving, ", ")+
			", but the terminator does not run (juist publish "+pub.Serving[0]+")")
	case len(pub.Serving) > 0:
		return "this device serves " + strings.Join(pub.Serving, ", ")
	case pub.NotServing == notPublishedHere && pub.Consent:
		return "none (ready to serve)"
	case pub.NotServing == notPublishedHere:
		return "none"
	case len(published) > 0:
		return paint("33", strings.Join(published, ", ")+" (not served)")
	}
	return paint("33", "not served")
}

// selfPublished are the names the log publishes on this device, as s lists
// its devices.
func selfPublished(s *ipc.Status) []string {
	i := slices.IndexFunc(s.Devices, func(d ipc.Device) bool { return d.Identity == s.Self })
	if i < 0 {
		return nil
	}
	return s.Devices[i].Published
}

// publishNotes say, for juist health, why published, the names the log
// publishes on this device, named self, are not served, which names the
// operator said where to send are not published under domain, and what
// serves or publishes them.
func publishNotes(pub *ipc.Publish, published []string, self, domain string) []line {
	if pub == nil {
		return nil
	}
	var out []line
	for _, t := range pub.To {
		name := nameUnder(t.Label, domain)
		if slices.ContainsFunc(published, func(p string) bool { n, _, _ := strings.Cut(p, ":"); return n == name }) {
			continue
		}
		out = append(out, line{kind: lineWarn, text: name + " goes to " + describeTo(t.To) + " but is not published"})
		if hint := unpublishedHint(t, domain, self); hint != "" {
			out = append(out, line{kind: lineHint, text: hint})
		}
	}
	what := cmp.Or(strings.Join(published, ", "), "what is published on this device")
	switch {
	case len(pub.Serving) > 0:
	case pub.NotServing == notPublishedHere:
	case !pub.Consent && pub.NotServing == "" && len(published) > 0:
		name, _, _ := strings.Cut(published[0], ":")
		if label, ok := strings.CutSuffix(name, "."+domain); ok && domain != "" {
			name = labelArg(label, domain)
		}
		out = append(out, line{kind: lineWarn, text: "not serving " + what + ": not agreed to on this device"},
			line{kind: lineHint, text: "juist publish " + name})
	case !pub.Consent && pub.NotServing == "":
		out = append(out, line{kind: lineWarn, text: "not serving " + what + ": not agreed to on this device"})
	default:
		out = append(out, line{kind: lineWarn, text: "not serving " + what + ": " + pub.NotServing})
	}
	return out
}

// parseLabel reads arg as a name to publish under domain: one label, or one
// label of domain.
func parseLabel(arg, domain string) (string, error) {
	label := strings.ToLower(strings.TrimSuffix(arg, "."))
	if domain != "" && label == domain {
		return "", nil // the domain itself
	}
	if under, ok := strings.CutSuffix(label, "."+domain); ok && domain != "" {
		if strings.Contains(under, ".") {
			return "", fmt.Errorf("name under %s cannot contain a dot: %q", domain, arg)
		}
		label = under
	}
	if types.OwnName(label) {
		if err := types.ValidateHostName(label); err != nil {
			return "", fmt.Errorf("%q is not a valid name: %w", arg, err)
		}
		return label, nil
	}
	if err := types.ValidateLabel(label); err != nil {
		return "", fmt.Errorf("name can only contain letters, digits and inner hyphens: %q", arg)
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

// publishedList is ps under domain, as "NAME:PORT", or "NAME:PORT/tcp" for
// a name published by TCP.
func publishedList(ps []types.PublishedName, domain string) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Under(domain) + ":" + portShown(p)
		if p.Members {
			out[i] += " (members)"
		}
	}
	return strings.Join(out, ", ")
}
