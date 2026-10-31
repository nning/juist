package main

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/ipc"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

func cmdStatus(a *app, args []string) error {
	s := spec{name: "juist status", about: `
Show this device's network and how many devices it reaches, for every
network if the device is in several. Any local user may run it. juist health
says what needs attention; juist devices lists the devices.`}
	fs := newFlags(s.name)
	devices := fs.Bool("devices", false, "list the devices too, as juist devices does")
	verbose := fs.Bool("verbose", false, "name the relay that carries the traffic to each relayed device")
	if _, err := a.parse(s, fs, args); err != nil {
		return err
	}
	if err := a.showStatus(*verbose); err != nil || !*devices {
		return err
	}
	a.printf("\n")
	return cmdDevices(a, nil)
}

func (a *app) showStatus(verbose bool) error {
	if insts := a.statusInstances(); len(insts) > 1 || len(insts) == 1 && insts[0].st == nil {
		a.printHostStatus(insts, verbose)
		return nil
	}
	if i, ok := a.namedDown(); ok {
		a.printDown(i, a.inSeveralNetworks())
		return nil
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	st := liveStatus(n)
	if st == nil {
		return a.offlineStatus(n)
	}
	a.printStatusIn(st, "", verbose)
	a.healthHint(st, "", false)
	return nil
}

// healthHint points at juist health where it has warnings to print, and at
// juist approve where changes wait for this keystore's vote.
func (a *app) healthHint(st *ipc.Status, inst string, several bool) {
	warnings, votes := a.healthWarnings(st, inst, several)
	a.pointAtHealth(warnings, votes, inst, several)
}

// pointAtHealth points at juist health for warnings, and at juist approve for
// votes; several names the network inst.
func (a *app) pointAtHealth(warnings, votes int, inst string, several bool) {
	if warnings+votes == 0 {
		return
	}
	a.printf("\n")
	if votes > 0 {
		verb := "waits"
		if votes > 1 {
			verb = "wait"
		}
		a.hint("%s %s for your vote: juist approve", count(votes, "change"), verb)
	}
	if warnings > 0 {
		cmd := "juist health"
		if several {
			cmd += " " + inst
		}
		a.hint("%s: %s", count(warnings, "warning"), cmd)
	}
}

// adminNotes say what waits for an admin key in this keystore: changes for
// its vote, which it counts, and a network to upgrade; several names the
// network in the hint.
func (a *app) adminNotes(st *ipc.Status, several bool) (notes []line, votes int) {
	if !st.CanOperate {
		return nil, 0
	}
	if st.Waiting > 0 {
		notes, votes = a.waitingNote()
	}
	if st.InNetwork && !st.NotMember && st.SchemaAlarm == "" && st.Schema < types.CurrentSchema {
		notes = append(notes, a.upgradeNote(st, several)...)
	}
	return notes, votes
}

// offlineStatus reports what the log says when no daemon is there to ask.
func (a *app) offlineStatus(n node) error {
	auth, err := n.log()
	if err != nil {
		return err
	}
	state := auth.State()
	a.printf("%s · %s\n", a.bold(state.Network()), "juistd not running")
	k, err := a.home.optionalNodeKeys()
	if err != nil {
		return err
	}
	if k != nil {
		if self, ok := state.Node(k.Identity.Public()); ok {
			a.field("This device", "%s  %s", displayMember(self), addrList(state, self.Identity))
		} else {
			a.field("This device", "not a member")
		}
	}
	a.field("Devices", "%d", len(state.Nodes()))
	a.pointAtHealth(1, 0, "", false) // juistd not running
	return nil
}

// printStatusIn prints s, its head naming inst where the host is in several
// networks; verbose adds the relay of each relayed device.
func (a *app) printStatusIn(s *ipc.Status, inst string, verbose bool) {
	v := statusOfOn(s, a.now(), a.paint, a.instanceLabel, inst != "")
	if inst != "" && len(v.head) > 0 {
		v.head[0].text += " · " + a.dim(inst)
	}
	if verbose {
		v.head = withRelayed(v.head, s)
	}
	a.emit(v.head)
	// What stops the network is said here too; the rest, juist health says.
	alarms := slices.DeleteFunc(slices.Clone(v.notes), func(l line) bool { return l.kind != lineAlarm })
	if len(alarms) > 0 {
		a.printf("\n")
		a.emit(alarms)
	}
}

// withRelayed is head with a line per relayed device under its Relays
// field, naming the relay that carries the traffic to it.
func withRelayed(head []line, s *ipc.Status) []line {
	names := map[types.Identity]string{}
	for _, d := range s.Devices {
		names[d.Identity] = d.Name
	}
	var relayed []line
	for _, r := range s.Reach {
		if !r.Live || r.Direct {
			continue
		}
		via := cmp.Or(r.Relay, "a relay")
		who := cmp.Or(names[r.Identity], r.Identity.ShortString())
		if r.Identity == (types.Identity{}) {
			// A reader's status, which names no member.
			who = "a device"
		}
		relayed = append(relayed, line{kind: lineField, text: who + " via " + via})
	}
	slices.SortFunc(relayed, func(x, y line) int { return cmp.Compare(x.text, y.text) })
	at := slices.IndexFunc(head, func(l line) bool { return l.kind == lineField && l.label == "Relays" })
	if at < 0 {
		return append(head, relayed...)
	}
	return slices.Insert(head, at+1, relayed...)
}

// A line is one line of output, of a kind that says how it is printed.
type line struct {
	kind  lineKind
	label string // a field's
	text  string
}

type lineKind int

const (
	linePlain lineKind = iota
	lineField
	lineInfo // dimmed
	lineWarn
	lineHint
	lineAlarm
)

func (a *app) emit(lines []line) {
	for _, l := range lines {
		switch l.kind {
		case linePlain:
			a.printf("%s\n", l.text)
		case lineField:
			a.field(l.label, "%s", l.text)
		case lineInfo:
			a.printf("%s\n", a.dim(l.text))
		case lineWarn:
			a.warn("%s", l.text)
		case lineHint:
			a.hint("%s", l.text)
		case lineAlarm:
			a.alarm("%s", l.text)
		}
	}
}

// A statusView is "juist status" of a daemon's report: head, then the notes
// on what needs attention.
type statusView struct {
	head  []line
	notes []line
}

// dnsRefusedRecent is how long a refused name is worth a warning.
const dnsRefusedRecent = 10 * time.Minute

// refusedHint is what lets names refused for why through, "" for nothing.
func refusedHint(why string) string {
	switch {
	case strings.Contains(why, "tailscaled alone"):
		return asRoot("tailscale set --accept-dns=false") + " leaves the tailnet's names to this host's other resolvers"
	case strings.Contains(why, "DNS over TLS"):
		return "juist exit use DEVICE sends them through the tunnel"
	case strings.Contains(why, "knows no DNS server"):
		return "resolvectl status shows the servers systemd-resolved knows"
	}
	return ""
}

// checkStale is how old the last tunnel check may grow before its age is
// worth saying: juistd checks every 30 seconds.
const checkStale = 2 * time.Minute

// stale reports whether s's last tunnel check is older than [checkStale].
func stale(s *ipc.Status, now time.Time) bool {
	return s.ReachChecked > 0 && now.Sub(time.Unix(s.ReachChecked, 0)) > checkStale
}

// statusOfOn renders s as of now, painted by paint, on a host whose instances
// other names, for what one of them holds of this network's claims; several
// says the host is in more networks than s's.
func statusOfOn(s *ipc.Status, now time.Time, paint func(code, s string) string, other func(n int) string,
	several bool) statusView {
	r := &statusRender{s: s, now: now, paint: paint, other: other, several: several}
	if !r.connected() {
		return r.v
	}
	r.thisDevice()
	r.devices()
	r.relays()
	r.exit()
	r.served()
	r.renumbering()
	r.freshness()
	r.ports()
	r.hostConflict()
	r.v.notes = append(r.v.notes, statusNotes(s, several)...)
	if s.DNSRefused != "" && now.Sub(time.Unix(s.DNSRefusedAt, 0)) < dnsRefusedRecent {
		r.note(lineWarn, "names juistd forwards are refused: "+s.DNSRefused)
		if h := refusedHint(s.DNSRefused); h != "" {
			r.note(lineHint, h)
		}
	}
	return r.v
}

// A statusRender builds statusOfOn's view, a section at a time.
type statusRender struct {
	s       *ipc.Status
	now     time.Time
	paint   func(code, s string) string
	other   func(n int) string
	several bool
	v       statusView
}

func (r *statusRender) head(state string) {
	r.v.head = append(r.v.head, line{text: r.paint("1", r.s.NetworkName) + " · " + state})
}

func (r *statusRender) field(label, format string, args ...any) {
	r.v.head = append(r.v.head, line{kind: lineField, label: label, text: fmt.Sprintf(format, args...)})
}

func (r *statusRender) note(kind lineKind, text string) {
	r.v.notes = append(r.v.notes, line{kind: kind, text: text})
}

func (r *statusRender) since(unix int64) string { return ago(r.now.Sub(time.Unix(unix, 0))) }

// connected heads the view with the device's state, and reports whether it
// is in a network that runs, which the other sections describe.
func (r *statusRender) connected() bool {
	s, paint := r.s, r.paint
	if !s.InNetwork {
		name := cmp.Or(s.SelfName, s.Self.ShortString())
		if s.Joining {
			r.v.head = append(r.v.head, line{text: paint("1", name) + " · joining a network"})
			return false
		}
		r.v.head = append(r.v.head, line{text: paint("1", name) + " · no network"})
		if h := s.HTTPS; h != nil && h.Only {
			r.field("HTTPS", "only%s", proxied(h))
		}
		r.note(lineHint, "juist join CODE, or juist create")
		return false
	}
	if s.Disabled != "" {
		r.head(paint("1;31", "disabled"))
		r.note(lineWarn, "the network was ended with a break-glass secret")
		r.note(lineHint, "start over: "+resetCommand(s, r.several))
		return false
	}
	if c := s.HostConflict; c != nil && c.SameNetwork {
		r.head(paint("1;31", "not connected"))
		r.note(lineWarn, fmt.Sprintf("this network runs on this host already, "+
			"as %s; this juistd would be a second device in it", r.other(c.Instance)))
		r.note(lineHint, fmt.Sprintf("juist reset %s --force, which removes it", instance.Name(s.Instance)))
		return false
	}
	if s.StartError != "" {
		r.head(paint("1;31", "not connected"))
		r.note(lineWarn, "tunnels not up, retrying: "+s.StartError)
		r.note(lineHint, "without CAP_NET_ADMIN, run the packaged service")
		return false
	}
	if s.NotMember {
		r.head(paint("1;31", "removed"))
		r.note(lineWarn, "this device was removed from the network")
		r.note(lineHint, "rejoin with a new invite, or start over: "+resetCommand(s, r.several))
		return false
	}
	switch {
	case s.Alarm != "":
		r.head(paint("1;31", "disconnected"))
	case s.Refused:
		r.head(paint("1;31", "refused"))
	case s.Overtaken:
		r.head(paint("1;31", "behind"))
	case s.Stale:
		r.head(paint("33", "limited"))
	case s.Members > 1 && s.Peers == 0:
		r.head(paint("33", "waiting for peers"))
	case s.TunnelsChecked && s.Peers > 0 && s.TunnelsLive == 0:
		r.head(paint("33", "no tunnel up"))
	default:
		r.head(paint("32", "connected"))
	}
	return true
}

func (r *statusRender) thisDevice() {
	s := r.s
	var selfDev ipc.Device
	for _, d := range s.Devices {
		if d.Identity == s.Self {
			selfDev = d
		}
	}
	var v4, old, v6 []string
	for _, p := range s.Addrs {
		switch {
		case p.Addr().Is4() && p.Addr().String() == selfDev.Retiring:
			old = append(old, fmt.Sprintf("%v (until %s)", p.Addr(), deadline(uint64(selfDev.RetiringUntil))))
		case p.Addr().Is4():
			v4 = append(v4, p.Addr().String())
		default:
			v6 = append(v6, p.Addr().String())
		}
	}
	r.field("This device", "%s  %s", cmp.Or(s.SelfName, s.Self.ShortString()),
		strings.Join(append(append(v4, old...), v6...), "  "))
}

func (r *statusRender) devices() {
	s, paint := r.s, r.paint
	devices := "no others"
	if others := s.Members - 1 - s.Expired; others > 0 {
		devices = count(others, "other")
	}
	// Devices the access policy keeps apart are in neither, and need no tunnel.
	without := s.Unreachable + len(s.TunnelsDown)
	switch {
	case s.Peers > 0 && !s.TunnelsChecked:
		devices += ", " + paint("2", "not checked yet")
	case without > 0:
		devices += ", " + paint("33", fmt.Sprintf("%d without a tunnel", without))
	}
	if s.Peers > 0 && s.TunnelsChecked && stale(s, r.now) {
		devices += ", " + paint("33", "checked "+r.since(s.ReachChecked))
	}
	r.field("Devices", "%s", devices)
}

// relays says the relays and how this device reaches them over 443.
func (r *statusRender) relays() {
	s, paint := r.s, r.paint
	if s.RelayCapable > 0 || s.Relaying {
		relays := fmt.Sprintf("%d available", s.RelayCapable)
		switch {
		case s.Relaying:
			// Its own relay is its home; whom it serves says more.
		case s.HomeRelay != "":
			relays += ", via " + s.HomeRelay
		case s.Relays > 0 && s.TunnelsChecked:
			relays += ", " + paint("33", "no connection")
		}
		if s.Relaying {
			relays += "; this device relays"
			if s.RelayedFor > 0 {
				relays += " for " + count(s.RelayedFor, "device")
			}
		}
		r.field("Relays", "%s", relays)
	}
	if h := s.HTTPS; h != nil && h.Only {
		switch len(h.Relays) {
		case 0:
			r.field("HTTPS", "%s", paint("33", "only, and no relay on 443")+proxied(h))
		default:
			r.field("HTTPS", "only, by %s%s", strings.Join(h.Relays, ", "), proxied(h))
		}
	}
	if h := s.HTTPS; h != nil && h.Name != "" && s.Relaying {
		r.field("Relay name", "%s", relayNameSummary(h, s.CanOperate, paint))
	} else if h != nil && h.Name != "" {
		r.field("Relay name", "%s, %s", h.Name, paint("2", "not relaying"))
	}
}

func (r *statusRender) exit() {
	s, paint := r.s, r.paint
	ex := s.Exit
	if ex == nil {
		return
	}
	name := exitName(ex)
	if !ex.Node.IsZero() {
		name += isolation(ex.Isolated)
	}
	switch {
	case ex.Failed != "":
		r.field("Exit node", "%s", paint("1;31", name+", internet may leave directly: "+ex.Failed))
	case ex.Refused != "" && ex.Node.IsZero():
		r.field("Exit node", "%s", paint("1;31", "internet refused: "+ex.Refused))
	case ex.Refused != "":
		r.field("Exit node", "%s", paint("1;31", name+", internet refused: "+ex.Refused))
	case !ex.Node.IsZero() && exitReach(s, ex.Node) != "":
		r.field("Exit node", "%s", paint("33", name+", "+exitReach(s, ex.Node)))
	case !ex.Node.IsZero() && ex.Partly != "":
		text := name
		if ex.DNS {
			text += ", DNS too"
		}
		r.field("Exit node", "%s", text+"; "+paint("33", ex.Partly))
	case !ex.Node.IsZero() && ex.DNS:
		r.field("Exit node", "%s, DNS too", name)
	case !ex.Node.IsZero():
		r.field("Exit node", "%s", name)
	case ex.Serving:
		r.field("Exit node", "this device serves")
		if ex.DNSUnserved != "" {
			r.note(lineWarn, "members' DNS is not answered here: "+ex.DNSUnserved)
		}
	case ex.Consent:
		r.field("Exit node", "%s", paint("33", "this device does not serve: "+ex.NotServing))
	}
}

// served says the subnets, published names, ingress, shares and names.
func (r *statusRender) served() {
	s, paint := r.s, r.paint
	if t := subnetSummary(s.Subnets, paint); t != "" {
		r.field("Subnets", "%s", t)
	}
	published := selfPublished(s)
	if t := publishSummary(s.Publish, published, paint); t != "" {
		r.field("Published", "%s", t)
	}
	r.v.notes = append(r.v.notes, publishNotes(s.Publish, published, cmp.Or(s.SelfName, s.Self.ShortString()))...)
	if s.Publish != nil {
		for _, sh := range s.Publish.Shared {
			r.note(lineWarn, sharedWarning(sh))
		}
		if len(s.Publish.Shared) > 0 {
			r.note(lineHint, sharedHint)
		}
		for _, name := range s.Publish.Withheld {
			r.note(lineWarn, withheldWarning(name))
		}
	}
	if t := ingressSummary(s.Ingress, paint); t != "" {
		r.field("Ingress", "%s", t)
	}
	if t := shareSummary(s.Shares, paint); t != "" {
		r.field("Sharing", "%s", t)
	}
	if s.Names != nil {
		if text := namesLine(s.Names, s.SelfName, paint); text != "" {
			r.field("Names", "%s", text)
		}
		r.v.notes = append(r.v.notes, namesNotes(s.Names)...)
	}
	if m := s.Multicast; m != nil {
		switch {
		case m.Off:
			r.field("Multicast", "off")
		case len(m.Groups) > 0:
			r.field("Multicast", "on, routed: %s", strings.Join(m.Groups, ", "))
		default:
			r.field("Multicast", "on")
		}
	}
}

func (r *statusRender) renumbering() {
	s, paint := r.s, r.paint
	var until int64
	for _, d := range s.Devices {
		until = max(until, d.RetiringUntil)
	}
	switch {
	case until > 0:
		renumbering := "old addresses until " + deadline(uint64(until))
		if len(s.Unmoved) > 0 {
			renumbering += "; " + paint("33", "not told yet: "+strings.Join(s.Unmoved, ", "))
		} else {
			renumbering += "; all told"
		}
		r.field("Renumbering", "%s", renumbering)
	case len(s.Unmoved) > 0:
		// Retired already, so these reach a moved device over IPv6 alone.
		r.field("Renumbering", "%s", "old addresses held; "+paint("33", "not told yet: "+strings.Join(s.Unmoved, ", ")))
	}
}

func (r *statusRender) freshness() {
	s, paint := r.s, r.paint
	switch {
	case s.LeaseSigners == 0:
		r.field("Freshness", "%s", paint("2", "unchecked: no voucher"))
	case s.Stale && s.Vouchers > 1:
		r.field("Freshness", "%s", paint("33", fmt.Sprintf("expired (%d of %d vouchers); vouchers only",
			s.Vouching, s.Vouchers)))
	case s.Stale:
		r.field("Freshness", "%s", paint("33", "expired; vouchers only"))
	case s.FreshUntil > 0:
		by := ""
		if s.Vouchers > 1 {
			by = fmt.Sprintf(" by %d vouchers", s.Vouching)
		}
		r.field("Freshness", "vouched%s %s, valid %s", by, r.since(s.FreshSince),
			roughly(time.Unix(s.FreshUntil, 0).Sub(r.now)))
	}
}

// ports says the ports open from outside, the schema and the last update.
func (r *statusRender) ports() {
	s, paint := r.s, r.paint
	var open []string
	if s.HTTPS == nil || !s.HTTPS.Only {
		// On HTTPS alone nothing comes to the data plane's port.
		open = append(open, fmt.Sprintf("udp/%d", s.ListenPort))
	}
	if !s.SyncInTunnel {
		open = append(open, fmt.Sprintf("tcp/%d sync", s.GossipPort))
	}
	if s.Relaying && s.RelayPort != 0 {
		open = append(open, fmt.Sprintf("tcp/%d and udp/%d relay", s.RelayPort, s.RelayPort))
		if h := s.HTTPS; h != nil && len(h.Listening) > 0 && h.Listening[0] != ipc.HandedOn {
			open = append(open, "tcp/443 relay")
		}
	}
	r.field("Ports", "%s", cmp.Or(strings.Join(open, ", "), "none from outside"))
	if s.Schema != 0 {
		schema := strconv.Itoa(int(s.Schema))
		if s.Schema < types.CurrentSchema {
			schema += paint("33", fmt.Sprintf(" (%d)", types.CurrentSchema))
		}
		r.field("Schema", "%s", schema)
	}
	if s.LastReconcile > 0 {
		r.field("Updated", "%s", r.since(s.LastReconcile))
	}
}

// hostConflict notes another network on this host holding this one's IPv4.
func (r *statusRender) hostConflict() {
	s := r.s
	c := s.HostConflict
	if c == nil {
		return
	}
	if c.Unanswered {
		r.note(lineInfo, fmt.Sprintf("no IPv4 yet: %s holds a network "+
			"here and has not answered; IPv4 follows once it has, if the two do not overlap", r.other(c.Instance)))
		return
	}
	r.note(lineWarn, fmt.Sprintf("no IPv4 on this host: %s holds %s, which %q claims too (%v)",
		r.other(c.Instance), heldText(c.Held), s.NetworkName, c.Claim))
	if !slices.ContainsFunc(s.Addrs, func(p netip.Prefix) bool { return p.Addr().Is6() }) {
		r.note(lineWarn, "and IPv6 is off here, so this network has no address on this host at all")
	}
	r.note(lineHint, fmt.Sprintf("renumber one of the two networks: "+
		"juist network renumber %s PREFIX, or the other", instance.Name(s.Instance)))
}

// httpsNotes are what keeps this device's use of 443 from working.
func httpsNotes(s *ipc.Status) []line {
	h := s.HTTPS
	if h == nil || s.Alarm != "" {
		return nil
	}
	var notes []line
	note := func(kind lineKind, format string, args ...any) {
		notes = append(notes, line{kind: kind, text: fmt.Sprintf(format, args...)})
	}
	if h.Only && len(h.Relays) == 0 {
		note(lineWarn, "no relay on 443/tcp")
		note(lineHint, "a relay's operator names it there: juist set --relay-name NAME")
	}
	switch {
	case h.Name == "" || !s.Relaying:
	case h.NotAnnounced != "":
		note(lineWarn, "members are not told of %s: %s", h.Name, h.NotAnnounced)
	case h.ListenError != "":
		note(lineWarn, "the relay cannot take 443: %s", h.ListenError)
		switch {
		case !strings.Contains(h.ListenError, "permission denied") && !strings.Contains(h.ListenError, "not granted"):
			note(lineHint, "another program holds 443 here")
		case types.ValidateHostName(h.Name) == nil:
			note(lineHint, "sudo juist set --relay-name %s, which lets the packaged juistd bind 443", h.Name)
		}
	case h.NoCert != "":
		note(lineWarn, "no certificate for %s yet: %s", h.Name, h.NoCert)
		note(lineHint, "%s must point at this device in DNS, and %s let 443/tcp in", h.Name,
			map[bool]string{true: "the ingress", false: "every firewall in front of it"}[len(h.Listening) > 0 &&
				h.Listening[0] == ipc.HandedOn])
	}
	return notes
}

// proxied is what an HTTPS-only device goes through, if anything.
func proxied(h *ipc.HTTPS) string {
	if h.Proxy == "" {
		return ""
	}
	return " through " + h.Proxy
}

// relayNameSummary is the status line of this device's relay on 443; a
// caller who may not operate is not told how the relay holds it.
func relayNameSummary(h *ipc.HTTPS, operator bool, paint func(code, s string) string) string {
	switch {
	case !operator:
		return h.Name
	case h.NotAnnounced != "":
		return h.Name + ", " + paint("33", "not told to members")
	case h.NoCert != "":
		return h.Name + ", " + paint("33", "no certificate yet")
	case len(h.Listening) == 0:
		return h.Name + ", " + paint("33", "not on 443")
	case h.Listening[0] == ipc.HandedOn:
		return h.Name + ", on 443 through the ingress"
	}
	return h.Name + ", on 443"
}

// statusNotes are what needs attention on a connected device.
func statusNotes(s *ipc.Status, several bool) []line {
	var n notes
	deviceNotes(&n, s, several)
	terminatorNotes(&n, s)
	syncNotes(&n, s)
	reachNotes(&n, s)
	n = append(n, httpsNotes(s)...)
	voucherNotes(&n, s)
	relayNotes(&n, s)
	logNotes(&n, s)
	return n
}

// notes gathers the lines statusNotes says.
type notes []line

func (n *notes) note(kind lineKind, format string, args ...any) {
	*n = append(*n, line{kind: kind, text: fmt.Sprintf(format, args...)})
}

// deviceNotes are what keeps this device itself from working.
func deviceNotes(n *notes, s *ipc.Status, several bool) {
	if s.StaleKeys {
		n.note(lineWarn, "juistd runs on replaced keys; restart it")
	}
	if s.Refused {
		n.note(lineWarn, "the network's devices refuse this one: most likely it was removed")
		n.note(lineHint, "rejoin with a new invite, or start over: %s", resetCommand(s, several))
	} else if s.Overtaken {
		n.note(lineWarn, "this device's log is older than what the network's devices keep")
		n.note(lineHint, "rejoin with a new invite link")
	}
	if s.EpochError != "" {
		n.note(lineWarn, "cannot open the group secret, so no discovery or log updates: %s", s.EpochError)
	}
	if s.Alarm == "" && s.Firewalled != "" {
		if s.FirewallUnsure {
			n.note(lineWarn, "firewalld may block %s: its zone is not trusted, and juistd may not read its ports",
				s.Firewalled)
		} else {
			n.note(lineWarn, "firewalld blocks %s, so log sync in the tunnel fails", s.Firewalled)
		}
		if pastableIfName(s.Firewalled) {
			n.note(lineHint, "sudo firewall-cmd --permanent --zone=trusted --change-interface=%s && sudo firewall-cmd --reload",
				s.Firewalled)
		}
	}
	if s.Unguarded != "" {
		n.note(lineWarn, "other devices than the tunnel reach this device's overlay addresses: %s", s.Unguarded)
	}
	if s.DataPlaneError != "" {
		n.note(lineWarn, "data plane refused the device set: %s", s.DataPlaneError)
	}
	if s.DNSRoutingUnread != "" {
		n.note(lineWarn, "names the host's DNS routing sends elsewhere are refused, as it cannot be read: %s", s.DNSRoutingUnread)
	}
}

// terminatorNotes are what keeps the names served here from being served.
func terminatorNotes(n *notes, s *ipc.Status) {
	if t := s.Terminator; t != nil && t.Running {
		for _, c := range t.NoCert {
			n.note(lineWarn, "no certificate for %s: %s", c.Name, c.Why)
		}
		if on := t.HTTPHeldOn(); len(on) > 0 {
			n.note(lineWarn, "another program holds port 80 on %s, so http:// to a name served here reaches it, "+
				"not a redirect to https", strings.Join(on, ", "))
			n.note(lineHint, "have it listen on the addresses it serves alone, not on every one")
		}
		held := map[uint16][]string{}
		for _, u := range t.Unbound {
			if ap, err := netip.ParseAddrPort(u); err == nil && ap.Port() != 80 {
				held[ap.Port()] = append(held[ap.Port()], ap.Addr().String())
			}
		}
		for _, port := range slices.Sorted(maps.Keys(held)) {
			n.note(lineWarn, "another program holds port %d on %s, where juist would serve what is published here",
				port, strings.Join(held[port], ", "))
		}
		if len(held) > 0 {
			n.note(lineHint, "where the service listens on every address, publish its port: juist publish add DEVICE NAME PORT")
		}
	}
}

// syncNotes are who is not heard from, and whose log sync fails.
func syncNotes(n *notes, s *ipc.Status) {
	if s.Unreachable > 0 && s.Peers > 0 {
		what := count(s.Unreachable, "device")
		if len(s.Silent) > 0 {
			what = strings.Join(s.Silent, ", ")
		}
		n.note(lineInfo, "not heard from: %s", what)
	}
	dev := cmp.Or(s.Device, instance.Name(s.Instance))
	if len(s.SyncFailing) > 0 {
		// Which system the other end runs no announcement says: a phone has
		// no firewall to open.
		n.note(lineWarn, "log sync to %s fails in the tunnel: tcp/%d does not answer there",
			strings.Join(s.SyncFailing, ", "), s.GossipPort)
		if pastableIfName(dev) {
			n.note(lineHint, "where it runs Linux: sudo ufw allow in on %s, or add %s to firewalld's trusted zone", dev, dev)
		}
	}
	if len(s.SyncNewer) > 0 {
		n.note(lineWarn, "log sync fails: %s a newer juist", runs(s.SyncNewer))
		n.note(lineHint, "update juist on this device")
	}
	if len(s.SyncBroken) > 0 {
		n.note(lineWarn, "log sync to %s fails", strings.Join(s.SyncBroken, ", "))
		n.note(lineHint, "juistd's log says why")
	}
	if len(s.Outdated) > 0 {
		n.note(lineWarn, "%s an older juist, unreachable until updated", runs(s.Outdated))
	}
	if len(s.OlderBuild) > 0 {
		n.note(lineWarn, "%s an older juist, which applies no changes until updated", runs(s.OlderBuild))
	}
}

// reachNotes are who answers on no path, and who fell behind. A peer the
// relay says is not there is said so in its one line: a warning where it
// runs, as it then keeps no connection there, and nothing where it is
// offline.
func reachNotes(n *notes, s *ipc.Status) {
	httpsOnly := s.HTTPS != nil && s.HTTPS.Only
	notAt := func(name string) bool { return slices.Contains(s.NotAtRelay, name) }
	seeking := slices.DeleteFunc(slices.Clone(s.Seeking), notAt)
	gone := slices.DeleteFunc(slices.Clone(s.Seeking), func(name string) bool { return !notAt(name) })
	down := slices.DeleteFunc(s.Blocked(), notAt)
	away := slices.DeleteFunc(s.Blocked(), func(name string) bool { return !notAt(name) })
	itThem := func(names []string) string { return map[bool]string{true: "it", false: "them"}[len(names) == 1] }
	if len(seeking) > 0 && httpsOnly {
		n.note(lineInfo, "no answer from %s: offline, or at no relay on 443", strings.Join(seeking, ", "))
	} else if len(seeking) > 0 {
		n.note(lineInfo, "no answer from %s: offline, or udp/%d blocked", strings.Join(seeking, ", "), s.ListenPort)
	}
	if len(gone) > 0 {
		n.note(lineInfo, "no answer from %s: not at the relay on %s, the one this device reaches %s at",
			strings.Join(gone, ", "), s.HomeRelay, itThem(gone))
	}
	if len(down) > 0 && httpsOnly {
		n.note(lineWarn, "no tunnel traffic from %s through the relays on 443", strings.Join(down, ", "))
	} else if len(down) > 0 && s.Relays > 0 {
		n.note(lineWarn, "no tunnel traffic from %s, though it announces itself", strings.Join(down, ", "))
	} else if len(down) > 0 {
		n.note(lineWarn, "no tunnel traffic from %s: udp/%d blocked, or both behind NAT with no relay",
			strings.Join(down, ", "), s.ListenPort)
		n.note(lineHint, "on a device with a public address: %s", openPorts("juist", s.ListenPort, serviceDataPort,
			"udp"))
	}
	if len(away) > 0 {
		n.note(lineWarn, "%s not at the relay on %s, the one this device reaches %s at", strings.Join(away, ", "),
			s.HomeRelay, itThem(away))
	}
	if s.Conflicted > 0 {
		n.note(lineWarn, "%s announce a key another device uses; ignored", count(s.Conflicted, "device"))
	}
	if behind := s.Behind(); len(behind) > 0 {
		n.note(lineWarn, "%s fell too far behind to reach this device", strings.Join(behind, ", "))
		n.note(lineHint, "it catches up from a device that has been away as long, or joins again with a new invite")
	}
}

// voucherNotes are what bounds freshness.
func voucherNotes(n *notes, s *ipc.Status) {
	if s.LeaseSigners == 0 {
		var relays []string
		for _, d := range s.Devices {
			// An ingress or a service member may not vouch.
			if slices.Contains(d.Roles, types.RoleRelayCapable) &&
				!slices.Contains(d.Roles, types.RoleIngress) && !slices.Contains(d.Roles, types.RoleService) {
				relays = append(relays, d.Name)
			}
		}
		if len(relays) >= 2 {
			n.note(lineHint, "vouchers that are always on bound how long a removal takes to reach a device cut off: "+
				"juist grant %s voucher, juist grant %s voucher, juist admins vouchers 2", relays[0], relays[1])
		}
	}
	if left, ending := s.FreshnessEnding(time.Now().Unix()); ending {
		n.note(lineWarn, "freshness ends in %s unless %s", roughly(left), s.VouchAgain())
		n.note(lineHint, "a voucher vouches while juistd runs on it and reaches this device")
	}
}

// relayNotes are what keeps devices from relaying.
func relayNotes(n *notes, s *ipc.Status) {
	if s.RelayUnreached && s.Alarm == "" {
		n.note(lineWarn, "no device reaches this relay: tcp/%d or udp/%d is likely closed", s.RelayPort, s.RelayPort)
		n.note(lineHint, "%s; and any firewall in front of this host",
			openPorts("juist-relay", s.RelayPort, serviceRelayPort, "tcp", "udp"))
	}
	// Two devices behind strict NATs need a third, reachable, to relay.
	if s.RelayCapable == 0 && s.Members > 2 && s.Alarm == "" {
		n.note(lineWarn, "no device may relay; devices behind strict NATs need one")
		n.note(lineHint, "juist grant DEVICE relay, on a device with a public address")
	}
}

// logNotes are what the log lost or refuses.
func logNotes(n *notes, s *ipc.Status) {
	for _, l := range s.Lost {
		n.note(lineWarn, "%s lost to a concurrent change", l)
		n.note(lineHint, "redo it if still wanted; juist log lists what was lost")
	}
	for _, u := range s.Unrevoked {
		n.note(lineWarn, "%s lost to a concurrent change and is not in effect", u)
		n.note(lineHint, "an admin redoes it")
	}
	if s.SchemaAlarm != "" {
		n.note(lineAlarm, "%s; no changes, removals included, apply until juist is updated", s.SchemaAlarm)
	}
	if s.Alarm != "" {
		n.note(lineAlarm, "%s; tunnels down until resolved", s.Alarm)
	}
}

// resetCommand is how a device that left s's network starts over: the
// default instance stays, in no network; another goes with its reset.
func resetCommand(s *ipc.Status, several bool) string {
	if s.Instance == 0 && !several {
		return "juist reset"
	}
	return "juist reset " + instance.Name(s.Instance)
}

// heldText is an address, or a prefix where it is more than one.
func heldText(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// The ports the package's firewalld and ufw services name: juistd's
// defaults, which the default instance listens on (packaging/firewalld).
const (
	serviceDataPort  = 41643
	serviceRelayPort = 41645
)

// openPorts says how to let port in through ufw or firewalld: by the
// package's service where it is the default port, by number where an
// instance's is another.
func openPorts(service string, port, def uint16, protos ...string) string {
	if port == 0 || port == def {
		return fmt.Sprintf("sudo ufw allow %s, or firewall-cmd --add-service=%s", service, service)
	}
	var ufw, fwd []string
	for _, p := range protos {
		ufw = append(ufw, fmt.Sprintf("sudo ufw allow %d/%s", port, p))
		fwd = append(fwd, fmt.Sprintf("--add-port=%d/%s", port, p))
	}
	return strings.Join(ufw, " && ") + ", or firewall-cmd " + strings.Join(fwd, " ")
}

// startWarning reports a daemon that holds the network but could not start
// its tunnels.
func (a *app) startWarning() {
	if st := liveStatus(a.node); st != nil && st.StartError != "" {
		a.warn("tunnels not up yet, retrying: %s", st.StartError)
	}
}

// ago and roughly render a duration the way a person reads one.
func ago(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	return roughly(d) + " ago"
}

func roughly(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d.Round(time.Hour) <= 72*time.Hour:
		// In hours up to three days, so the 48-hour TTL reads the same
		// whether a little more or a little less of it is left.
		return fmt.Sprintf("%dh", int(d.Round(time.Hour).Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// deadline renders a Unix time in seconds as local time, with the year only
// where it is not this one.
func deadline(unix uint64) string {
	t := time.Unix(int64(min(unix, 1<<62)), 0).Local()
	if t.Year() != time.Now().Year() {
		return t.Format("2 Jan 2006 15:04")
	}
	return t.Format("Mon 2 Jan 15:04")
}

// addrList renders a member's overlay addresses: IPv4 first, its own before
// one it is retiring.
func addrList(state *log.State, id types.Identity) string {
	n, ok := state.Node(id)
	if !ok {
		return ""
	}
	var out []string
	if n.V4 != nil {
		out = append(out, n.V4.String())
	}
	if r := n.Retiring; r.Live(time.Now().Unix()) {
		out = append(out, fmt.Sprintf("%v (until %s)", r.Addr, deadline(r.Until)))
	}
	return strings.Join(append(out, state.Addr6(id).String()), "  ")
}

// describeCallFailure turns "the socket did not answer" into what it means.
func describeCallFailure(sock string, err error) error {
	if errors.Is(err, fs.ErrPermission) {
		msg := fmt.Sprintf("%s: permission denied", sock)
		if owner := stateDirOwner(filepath.Dir(sock)); owner != "" {
			msg += fmt.Sprintf("\nhint: sudo -u %s juist --socket %s status", owner, sock)
		}
		return errors.New(msg)
	}
	return fmt.Errorf("%s: %w", sock, err)
}

// stateDirOwner names the account a daemon on this home directory runs as,
// read from the directory, since the socket is what the caller was refused.
func stateDirOwner(dir string) string {
	info, err := os.Stat(dir)
	if err != nil {
		return ""
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	uid := strconv.FormatUint(uint64(st.Uid), 10)
	if u, err := user.LookupId(uid); err == nil {
		return u.Username
	}
	return uid
}

// noDaemon reports whether a failed call means nothing is listening: no socket
// file, or one nobody is bound to, which is what a crashed daemon leaves.
func noDaemon(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
}

// relayGranted reports whether relay.sh's grant of 443 to the host's
// juistd is in place, and the juistd asked is that one.
func (a *app) relayGranted() bool {
	return a.host.relayGrant != "" && fileExists(a.host.relayGrant) &&
		(!a.socketExplicit || a.socket == a.host.socket(0))
}

// runs is "a runs", or "a, b run".
func runs(names []string) string {
	if len(names) == 1 {
		return names[0] + " runs"
	}
	return strings.Join(names, ", ") + " run"
}
