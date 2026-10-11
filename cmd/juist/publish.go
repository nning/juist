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

func publishFamily() family {
	return family{name: "juist publish", intro: "Publish devices' services on the internet, through an ingress.",
		subs: []subcommand{
			{name: "list", aliases: []string{"ls"}, run: publishList, forms: [][2]string{{"", "the published names, and where\nthis device sends them on"}}},
			{name: "add", run: publishAdd, forms: [][2]string{
				{"add NAME HOST:PORT", "publish NAME.DOMAIN on this device,\nending TLS and sending it on to HOST:PORT"},
				{"add DEVICE NAME [PORT]", "publish NAME.DOMAIN on DEVICE's PORT"},
				{"add DEVICE NAME PORT --tcp", "publish DEVICE's PORT on PORT of every\ningress, by TCP"},
			}},
			{name: "status-page", run: publishStatusPage, forms: [][2]string{{"status-page NAME [--public WHAT]",
				"serve the network's status page as\nNAME.DOMAIN on this device"}}},
			{name: "remove", aliases: []string{"rm"}, run: publishRemove, forms: [][2]string{{"remove [DEVICE] NAME", "stop publishing NAME"}}},
			{name: "serve", run: publishServe, forms: [][2]string{{"serve [--stop]", "serve what is published on this\ndevice to the ingresses"}}},
		}, footer: `A name is one label under the network's domain (juist network domain), or
the domain itself, spelled out, whose DNS points at the ingresses (juist
grant DEVICE ingress). The ingresses read the name a client asks for and
pass the connection to the device, where juist ends TLS (juist publish add
NAME HOST:PORT) or the service does; a name published by TCP (--tcp) has a
port of its own on every ingress instead. juist publish PORT publishes this
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
			r := row{name: p.Under(state.Domain()), device: displayMember(n), port: portShown(p)}
			if p.Proxy {
				r.port += " (proxy protocol)"
			}
			if p.Members {
				r.port += " (members)"
			}
			if i := slices.IndexFunc(to, func(t ipc.ServeTo) bool { return t.Label == p.Label }); i >= 0 && n.Identity == self.Identity {
				r.to = describeTo(to[i].To)
				if to[i].Members {
					r.to += " (members)"
				}
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
DEVICE's operator agrees. With --tcp, every ingress passes TCP on a port of
its own to the device instead, for a service that speaks no TLS. With
--members, the internet does not reach it: members do, at the device, as
the access policy names it for them.`}
	fs := newFlags(s.name)
	proxy := fs.Bool("proxy", false, "send the client's address in a PROXY protocol v2 header")
	http2 := fs.Bool("http2", false, "offer clients HTTP/2; the service at HOST:PORT takes it without TLS (h2c)")
	http3 := fs.Bool("http3", false, "offer clients HTTP/3 too; juist proxies the HTTP of the service at HOST:PORT")
	tcp := &tcpFlag{}
	fs.Var(tcp, "tcp", "publish by TCP on PORT of every ingress, the device's port unless given, not by TLS on 443")
	membersOn := fs.Bool("members", false, "for members alone, whom the access policy names: not for the internet; =false makes it public")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		first, _, _ := strings.Cut(err.Error(), "\n")
		var extra string
		if _, scanErr := fmt.Sscanf(first, "unexpected argument %q", &extra); scanErr == nil && tcp.on && tcp.port == 0 {
			if _, perr := strconv.ParseUint(extra, 10, 16); perr == nil {
				return fmt.Errorf("%s\nhint: a public port goes with the option: --tcp=%s", first, extra)
			}
		}
		return err
	}
	httpFlag := "--http2"
	if *http3 {
		httpFlag = "--http3"
	}
	if (*http2 || *http3) && tcp.on {
		return fmt.Errorf("%s is for a name whose TLS juist ends, not one published by TCP\n%s", httpFlag, s.usage(fs))
	}
	// Kept where not given, so that a name for members alone is not made
	// public by a command that leaves it out.
	var members *bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "members" {
			members = membersOn
		}
	})
	if *membersOn && (tcp.on || *proxy) {
		return fmt.Errorf("--members is for a name by TLS on 443, which members reach at its device\n%s", s.usage(fs))
	}
	if _, err := strconv.ParseUint(pos[len(pos)-1], 10, 16); err == nil && len(pos) == 3 && strings.Contains(pos[1], ":") &&
		tcp.on && tcp.port == 0 {
		return fmt.Errorf("unexpected argument %q\nhint: a public port goes with the option: --tcp=%s", pos[2], pos[2])
	}
	if last := pos[len(pos)-1]; strings.Contains(last, ":") {
		if *http2 {
			pos[len(pos)-1] = ipc.HTTP2To(last)
		}
		if *http3 {
			pos[len(pos)-1] = ipc.HTTP3To(pos[len(pos)-1])
		}
		return a.publishHere(pos, *proxy, members, tcp)
	}
	if *http2 || *http3 {
		return fmt.Errorf("%s is for a service whose TLS juist ends, given as HOST:PORT\n%s", httpFlag, s.usage(fs))
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
	} else if tcp.on {
		return fmt.Errorf("a name published by TCP needs the device's port\nhint: juist publish add %s %s PORT --tcp",
			pos[0], pos[1])
	}
	p := types.PublishedName{Label: label, Port: port, Proxy: *proxy, Members: keptMembers(target, label, members)}
	if p.Public, err = tcp.public(state, target, label, port, ""); err != nil {
		return err
	}
	if err := membersAllowed(state, p); err != nil {
		return err
	}
	next, err := publishedWith(state, target, p)
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
// ended here and sent on; by TCP, on the public port, and passed on as it
// is.
func (a *app) publishHere(pos []string, proxy bool, members *bool, tcp *tcpFlag) error {
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
	if len(pos) == 3 {
		target, err := resolveDevice(state, pos[0])
		if err != nil {
			return err
		}
		if target.Identity != self.Identity {
			return fmt.Errorf("juist %s on the device it runs on\nhint: on %s, juist publish add %s %s%s",
				ends, displayMember(target), pos[1], hostPort, flags)
		}
		pos = pos[1:]
	}
	switch {
	case a.host.serveScript == "":
		return fmt.Errorf("juist %s on Linux and FreeBSD alone", ends)
	case st.Instance != 0:
		return fmt.Errorf("juist %s for the default network's instance alone, for now", ends)
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
	again := "juist publish add " + pos[0] + " " + hostPort + " --tcp"
	if proxy {
		again += " --proxy"
	}
	if p.Public, err = tcp.public(state, self, label, p.Port, again); err != nil {
		return err
	}
	if err := membersAllowed(state, p); err != nil {
		return err
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
	// juistd holds a service meant for members alone from the name while the
	// log has it public.
	t.Members = marked
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
			a.warn("a CAA record at %s holds for every name under it without one of its own: give each device's names theirs", name)
		}
	case slices.ContainsFunc(pub.Shared, func(s string) bool { return strings.HasPrefix(s, name+" with ") }):
		i := slices.IndexFunc(pub.Shared, func(s string) bool { return strings.HasPrefix(s, name+" with ") })
		a.warn("%s", sharedWarning(pub.Shared[i]))
		a.hint("%s", sharedHint)
	case !published && t.Members:
		a.ok("%s goes to %s once published on this device for members alone", name, describeTo(t.To))
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
		a.hint("an admin publishes it: juist publish add %s %s", displayMember(self), publishArgs(asked, state.Domain()))
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
	return a.publishHere([]string{pos[0], ipc.StatusPageTo(vis)}, false, nil, &tcpFlag{})
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
		return errors.New("want a port, as --tcp=25565")
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
				again = "juist publish add " + displayMember(target) + " " + publishArgs(p, state.Domain())
			}
			return 0, fmt.Errorf("%s is published by TCP on port %d\nhint: %s, or juist publish remove first",
				p.Under(state.Domain()), p.Public, again)
		}
		return 0, nil
	}
	if state.Schema() < types.SchemaTCP {
		return 0, needsUpgrade("names published by TCP")
	}
	public := cmp.Or(f.port, port)
	if err := types.ValidatePublicPort(public); err != nil {
		return 0, fmt.Errorf("a name is not published by TCP on %v", err)
	}
	for _, n := range state.Nodes() {
		for _, q := range n.Published {
			if q.Public == public && (n.Identity != target.Identity || q.Label != label) {
				return 0, fmt.Errorf("%s is published on port %d already\nhint: another port, as --tcp=PORT",
					q.Under(state.Domain()), public)
			}
		}
	}
	return public, nil
}

// publishArgs is what follows DEVICE in "juist publish add" to publish p.
func publishArgs(p types.PublishedName, domain string) string {
	how := p.Under(domain)
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
	return how
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
	case state.Schema() < types.SchemaMembers:
		return needsUpgrade("names for members alone")
	case p.Proxy || p.Public != 0:
		return fmt.Errorf("%s is for members alone, which takes neither --proxy nor --tcp\nhint: --members=false makes it public first",
			p.Under(state.Domain()))
	case p.Port != 443:
		return fmt.Errorf("a name for members alone is on port 443, where members reach it at its device")
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
		a.hint("at the domain's DNS, this record has browsers try HTTP/3 at once, not from their second request")
		a.hintOwnRecords()
	}
}

// hintOwnRecords says once that a name given records of its own, CAA or
// HTTPS, is given no address by a wildcard (RFC 4592).
func (a *app) hintOwnRecords() {
	if !a.ownRecordsSaid {
		a.ownRecordsSaid = true
		a.hint("a name with records of its own gets no address from a wildcard: give it A and AAAA records too")
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
		running := st.Terminator != nil && st.Terminator.Running && len(st.Shares) == 0
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
	st := n.status()
	if st != nil && st.Instance != 0 {
		return errors.New("juist ends TLS for the default network's instance alone, for now")
	}
	self := "DEVICE"
	if st != nil {
		self = cmp.Or(st.SelfName, st.Self.ShortString())
	}
	resp, err := ipc.Call(n.socket(), ipc.Request{Command: ipc.CmdServing})
	if err != nil || resp.Serving == nil || a.host.answersTLS == nil {
		return err
	}
	t := servedAs(resp.Serving, name)
	if len(t.Addrs) == 0 {
		return nil
	}
	at := netip.AddrPortFrom(t.Addrs[0], t.Port).String()
	// The terminator says where it listens; what answers there may be
	// another program's.
	for deadline := time.Now().Add(a.host.terminatorWait); a.host.terminatorWait > 0; {
		var said *ipc.Terminator
		if now, _ := n.restatus(); now != nil {
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
		if st := n.status(); st != nil && len(st.Shares) > 0 {
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
	}
}

// notPublishedHere is juistd's word for a device the network publishes
// nothing on.
const notPublishedHere = "the network publishes nothing on this device"

// publishSummary is the status line of what this device serves of what is
// published on it; paint colours what it does not.
// sharedWarning says why a name for members alone, "NAME with OTHER", is
// not served.
func sharedWarning(shared string) string {
	name, other, _ := strings.Cut(shared, " with ")
	return fmt.Sprintf("not serving %s, which is for members alone: %s reaches its service as it is, "+
		"whose clients could ask it for %s by Host", name, other, name)
}

const sharedHint = "give a name for members alone a service of its own"

// withheldWarning says why name, its service meant for members alone, is
// not served.
func withheldWarning(name string) string {
	return fmt.Sprintf("not serving %s, its service meant for members alone: the log has the name public", name)
}

func publishSummary(pub *ipc.Publish, paint func(code, s string) string) string {
	switch {
	case pub == nil:
		return ""
	case len(pub.Serving) > 0 && pub.TerminatorSilent && len(pub.Ending) == 0:
		return paint("33", "this device serves "+strings.Join(pub.Serving, ", ")+
			", but passes none on: the terminator does not run (juist publish serve)")
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
