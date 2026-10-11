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
Show this device's network, how many devices it reaches, and what needs
attention; every network, where it is in several. Any local user may run it.
juist devices lists the devices.`}
	if _, err := a.parse(s, newFlags(s.name), args); err != nil {
		return err
	}
	if insts := a.statusInstances(); len(insts) > 1 || len(insts) == 1 && insts[0].st == nil {
		a.printHostStatus(insts)
		return nil
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	st := n.status()
	if st == nil {
		return a.offlineStatus(n)
	}
	a.printStatus(st)
	a.adminNotes(st, false)
	return nil
}

// adminNotes says what waits for an admin key in this keystore: changes for
// its vote, and a network to upgrade; several names the network in the hint.
func (a *app) adminNotes(st *ipc.Status, several bool) {
	if !st.CanOperate {
		return
	}
	if st.Waiting > 0 {
		a.waitingNote()
	}
	if st.InNetwork && !st.NotMember && st.SchemaAlarm == "" && st.Schema < types.CurrentSchema {
		a.upgradeNote(several)
	}
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
	a.startHint()
	return nil
}

func (a *app) printStatus(s *ipc.Status) { a.printStatusIn(s, "") }

// printStatusIn is printStatus with the head naming the instance, on a host
// in several networks.
func (a *app) printStatusIn(s *ipc.Status, inst string) {
	v := statusOfOn(s, a.now(), a.paint, a.instanceLabel, inst != "")
	if inst != "" && len(v.head) > 0 {
		v.head[0].text += " · " + a.dim(inst)
	}
	a.emit(v.head)
	if len(v.notes) > 0 {
		a.printf("\n")
		a.emit(v.notes)
	}
	if s.Instance == 0 && (s.HTTPS == nil || s.HTTPS.Name == "") && a.relayGranted() {
		a.warn("juistd may bind any port below 1024, which no relay on 443 here needs")
		a.hint("%s", asRoot(a.host.relayScript+" off"))
	}
	if ex := s.Exit; ex != nil && !ex.Node.IsZero() && ex.Refused == "" && ex.Failed == "" {
		a.warnDNS(ex, dnsOverlay(s, nil))
		a.warnStrictRP(ex)
	}
	if !s.CanOperate {
		network := ""
		if inst != "" {
			network = inst + " "
		}
		a.hint("read-only; to manage this device: %s", asRoot("juist set "+network+"--operator="+currentUser()))
	}
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

// checkStale is how old the last tunnel check may grow before its age is
// worth saying: juistd checks every 30 seconds.
const checkStale = 2 * time.Minute

// stale reports whether s's last tunnel check is older than [checkStale].
func stale(s *ipc.Status, now time.Time) bool {
	return s.ReachChecked > 0 && now.Sub(time.Unix(s.ReachChecked, 0)) > checkStale
}

// statusOf renders s as of now; paint colours text.
func statusOf(s *ipc.Status, now time.Time, paint func(code, s string) string) statusView {
	return statusOfOn(s, now, paint, instance.Name, false)
}

// statusOfOn is statusOf on a host whose instances other names, for what
// one of them holds of this network's claims; several says the host is in
// more networks than s's.
func statusOfOn(s *ipc.Status, now time.Time, paint func(code, s string) string, other func(n int) string,
	several bool) statusView {
	var v statusView
	head := func(state string) { v.head = append(v.head, line{text: paint("1", s.NetworkName) + " · " + state}) }
	field := func(label, format string, args ...any) {
		v.head = append(v.head, line{kind: lineField, label: label, text: fmt.Sprintf(format, args...)})
	}
	since := func(unix int64) string { return ago(now.Sub(time.Unix(unix, 0))) }

	if !s.InNetwork {
		name := cmp.Or(s.SelfName, s.Self.ShortString())
		if s.Joining {
			v.head = append(v.head, line{text: paint("1", name) + " · joining a network"})
			return v
		}
		v.head = append(v.head, line{text: paint("1", name) + " · no network"})
		if h := s.HTTPS; h != nil && h.Only {
			field("HTTPS", "only%s", proxied(h))
		}
		v.head = append(v.head, line{kind: lineHint, text: "juist join CODE, or juist create"})
		return v
	}
	if s.Disabled != "" {
		head(paint("1;31", "disabled"))
		v.head = append(v.head, line{kind: lineWarn, text: "the network was ended with a break-glass secret"},
			line{kind: lineHint, text: "start over: " + resetCommand(s, several)})
		return v
	}
	if c := s.HostConflict; c != nil && c.SameNetwork {
		head(paint("1;31", "not connected"))
		v.head = append(v.head, line{kind: lineWarn, text: fmt.Sprintf("this network runs on this host already, "+
			"as %s; this juistd would be a second device in it", other(c.Instance))},
			line{kind: lineHint, text: fmt.Sprintf("juist reset %s --force, which removes it",
				instance.Name(s.Instance))})
		return v
	}
	if s.StartError != "" {
		head(paint("1;31", "not connected"))
		v.head = append(v.head, line{kind: lineWarn, text: "tunnels not up, retrying: " + s.StartError},
			line{kind: lineHint, text: "without CAP_NET_ADMIN, run the packaged service"})
		return v
	}
	if s.NotMember {
		head(paint("1;31", "removed"))
		v.head = append(v.head, line{kind: lineHint, text: "rejoin with a new invite, or start over: " +
			resetCommand(s, several)})
		return v
	}
	switch {
	case s.Alarm != "":
		head(paint("1;31", "disconnected"))
	case s.Refused:
		head(paint("1;31", "refused"))
	case s.Stale:
		head(paint("33", "limited"))
	case s.Members > 1 && s.Peers == 0:
		head(paint("33", "waiting for peers"))
	case s.TunnelsChecked && s.Peers > 0 && s.TunnelsLive == 0:
		head(paint("33", "no tunnel up"))
	default:
		head(paint("32", "connected"))
	}

	var selfDev ipc.Device
	var until int64
	for _, d := range s.Devices {
		if d.Identity == s.Self {
			selfDev = d
		}
		until = max(until, d.RetiringUntil)
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
	field("This device", "%s  %s", cmp.Or(s.SelfName, s.Self.ShortString()),
		strings.Join(append(append(v4, old...), v6...), "  "))
	// An offline device's announcement is held, but it has said nothing
	// since it went quiet.
	heard := s.Peers - len(s.Absent)
	switch others := s.Members - 1 - s.Expired; {
	case others == 1 && heard == 1:
		field("Devices", "1 other, heard from")
	case others == 1 && len(s.Absent) == 1:
		field("Devices", "1 other, offline")
	case others == 1:
		field("Devices", "1 other, not heard from yet")
	case others > 1 && heard == others:
		field("Devices", "%d others, all heard from", others)
	case others > 1:
		field("Devices", "%d others, %d of them heard from", others, heard)
	default:
		field("Devices", "no others")
	}
	switch {
	case s.TunnelsChecked && s.Peers > 0:
		live := fmt.Sprintf("%d of %d live", s.TunnelsLive, s.TunnelsLive+len(s.TunnelsDown))
		if len(s.TunnelsDown) > 0 {
			live = paint("33", live)
		}
		if stale(s, now) {
			live += ", " + paint("33", "checked "+since(s.ReachChecked))
		}
		field("Tunnels", "%s", live)
	case s.Peers > 0:
		field("Tunnels", "%s", paint("2", "not checked yet"))
	}
	if t := pqSummary(s, paint); t != "" {
		field("Post-quantum", "%s", t)
	}
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
		field("Relays", "%s", relays)
	}
	if h := s.HTTPS; h != nil && h.Only {
		switch len(h.Relays) {
		case 0:
			field("HTTPS", "%s", paint("33", "only, and no relay on 443")+proxied(h))
		default:
			field("HTTPS", "only, by %s%s", strings.Join(h.Relays, ", "), proxied(h))
		}
	}
	if h := s.HTTPS; h != nil && h.Name != "" && s.Relaying {
		field("Relay name", "%s", relayNameSummary(h, s.CanOperate, paint))
	} else if h != nil && h.Name != "" {
		field("Relay name", "%s, %s", h.Name, paint("2", "not relaying"))
	}
	if ex := s.Exit; ex != nil {
		name := exitName(ex)
		if !ex.Node.IsZero() {
			name += isolation(ex.Isolated)
		}
		switch {
		case ex.Failed != "":
			field("Exit node", "%s", paint("1;31", name+", internet may leave directly: "+ex.Failed))
		case ex.Refused != "" && ex.Node.IsZero():
			field("Exit node", "%s", paint("1;31", "internet refused: "+ex.Refused))
		case ex.Refused != "":
			field("Exit node", "%s", paint("1;31", name+", internet refused: "+ex.Refused))
		case !ex.Node.IsZero() && exitReach(s, ex.Node) != "":
			field("Exit node", "%s", paint("33", name+", "+exitReach(s, ex.Node)))
		case !ex.Node.IsZero() && ex.Partly != "":
			text := name
			if ex.DNS {
				text += ", DNS too"
			}
			field("Exit node", "%s", text+"; "+paint("33", ex.Partly))
		case !ex.Node.IsZero() && ex.DNS:
			field("Exit node", "%s, DNS too", name)
		case !ex.Node.IsZero():
			field("Exit node", "%s", name)
		case ex.Serving:
			field("Exit node", "this device serves")
		case ex.Consent:
			field("Exit node", "%s", paint("33", "this device does not serve: "+ex.NotServing))
		}
	}
	if t := subnetSummary(s.Subnets, paint); t != "" {
		field("Subnets", "%s", t)
	}
	if t := publishSummary(s.Publish, paint); t != "" {
		field("Published", "%s", t)
	}
	if t := ingressSummary(s.Ingress, paint); t != "" {
		field("Ingress", "%s", t)
	}
	if t := shareSummary(s.Shares, paint); t != "" {
		field("Sharing", "%s", t)
	}
	if s.Names != nil {
		text, hint := namesSummary(s.Names, paint)
		field("Names", "%s", text)
		if hint != "" {
			v.head = append(v.head, line{kind: lineHint, text: hint})
		}
	}
	switch {
	case until > 0:
		renumbering := "old addresses until " + deadline(uint64(until))
		if len(s.Unmoved) > 0 {
			renumbering += "; " + paint("33", "not told yet: "+strings.Join(s.Unmoved, ", "))
		} else {
			renumbering += "; all told"
		}
		field("Renumbering", "%s", renumbering)
	case len(s.Unmoved) > 0:
		// Retired already, so these reach a moved device over IPv6 alone.
		field("Renumbering", "%s", "old addresses held; "+paint("33", "not told yet: "+strings.Join(s.Unmoved, ", ")))
	}
	switch {
	case s.LeaseSigners == 0:
		field("Freshness", "%s", paint("2", "unchecked: no voucher"))
	case s.Stale && s.Vouchers > 1:
		field("Freshness", "%s", paint("33", fmt.Sprintf("expired (%d of %d vouchers); vouchers only",
			s.Vouching, s.Vouchers)))
	case s.Stale:
		field("Freshness", "%s", paint("33", "expired; vouchers only"))
	case s.FreshUntil > 0:
		by := ""
		if s.Vouchers > 1 {
			by = fmt.Sprintf(" by %d vouchers", s.Vouching)
		}
		field("Freshness", "vouched%s %s, valid %s", by, since(s.FreshSince),
			roughly(time.Unix(s.FreshUntil, 0).Sub(now)))
	}
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
	field("Ports", "%s", cmp.Or(strings.Join(open, ", "), "none from outside"))
	if s.LastReconcile > 0 {
		field("Updated", "%s", since(s.LastReconcile))
	}
	if c := s.HostConflict; c != nil && c.Unanswered {
		v.notes = append(v.notes, line{kind: lineInfo, text: fmt.Sprintf("no IPv4 yet: %s holds a network "+
			"here and has not answered; IPv4 follows once it has, if the two do not overlap", other(c.Instance))})
	} else if c != nil {
		v.notes = append(v.notes, line{kind: lineWarn, text: fmt.Sprintf(
			"no IPv4 on this host: %s holds %s, which %q claims too (%v)",
			other(c.Instance), heldText(c.Held), s.NetworkName, c.Claim)})
		if !slices.ContainsFunc(s.Addrs, func(p netip.Prefix) bool { return p.Addr().Is6() }) {
			v.notes = append(v.notes, line{kind: lineWarn,
				text: "and IPv6 is off here, so this network has no address on this host at all"})
		}
		v.notes = append(v.notes, line{kind: lineHint, text: fmt.Sprintf("renumber one of the two networks: "+
			"juist network renumber %s PREFIX, or the other", instance.Name(s.Instance))})
	}
	v.notes = append(v.notes, statusNotes(s, several)...)
	return v
}

// pqSummary says how many of the installed peers' tunnels are post-quantum,
// and by what key.
func pqSummary(s *ipc.Status, paint func(code, s string) string) string {
	if s.PQ == nil {
		return ""
	}
	pq := s.PQ.Pair + s.PQ.Group
	n := pq + len(s.PQ.None) + len(s.PQ.NoKey)
	switch {
	case n == 0:
		return ""
	case s.Schema < types.SchemaPQ:
		return paint("33", "no, the network predates it")
	}
	var by []string
	switch s.PQ.Pair {
	case 0:
	case 1:
		by = append(by, "1 by a pair key")
	default:
		by = append(by, fmt.Sprintf("%d by pair keys", s.PQ.Pair))
	}
	if s.PQ.Group > 0 {
		by = append(by, fmt.Sprintf("%d by the group key", s.PQ.Group))
	}
	text := fmt.Sprintf("%d of %d tunnels", pq, n)
	if pq == n {
		text = "every tunnel"
	}
	if len(by) > 0 {
		text += ": " + strings.Join(by, ", ")
	}
	if pq < n {
		return paint("33", text)
	}
	return text
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
		note(lineHint, "juist log upgrade")
	case h.ListenError != "":
		note(lineWarn, "the relay cannot take 443: %s", h.ListenError)
		if strings.Contains(h.ListenError, "permission denied") || strings.Contains(h.ListenError, "not granted") {
			note(lineHint, "sudo juist set --relay-name %s, which lets the packaged juistd bind 443", h.Name)
		} else {
			note(lineHint, "another program holds 443 here")
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
	var notes []line
	note := func(kind lineKind, format string, args ...any) {
		notes = append(notes, line{kind: kind, text: fmt.Sprintf(format, args...)})
	}
	if s.StaleKeys {
		note(lineWarn, "juistd runs on replaced keys; restart it")
	}
	if s.Refused {
		note(lineWarn, "the network's devices refuse this one: most likely it was removed")
		note(lineHint, "rejoin with a new invite, or start over: %s", resetCommand(s, several))
	}
	if s.EpochError != "" {
		note(lineWarn, "cannot open the group secret, so no discovery or log updates: %s", s.EpochError)
	}
	if s.Alarm == "" && s.Firewalled != "" {
		if s.FirewallUnsure {
			note(lineWarn, "firewalld may block %s: its zone is not trusted, and juistd may not read its ports",
				s.Firewalled)
		} else {
			note(lineWarn, "firewalld blocks %s, so log sync in the tunnel fails", s.Firewalled)
		}
		note(lineHint, "sudo firewall-cmd --permanent --zone=trusted --change-interface=%s && sudo firewall-cmd --reload",
			s.Firewalled)
	}
	if s.DataPlaneError != "" {
		note(lineWarn, "data plane refused the device set: %s", s.DataPlaneError)
	}
	if t := s.Terminator; t != nil && t.Running {
		for _, n := range t.NoCert {
			note(lineWarn, "no certificate for %s: %s", n.Name, n.Why)
		}
		if on := t.HTTPHeldOn(); len(on) > 0 {
			note(lineWarn, "another program holds port 80 on %s, so http:// to a name served here reaches it, "+
				"not a redirect to https", strings.Join(on, ", "))
			note(lineHint, "have it listen on the addresses it serves alone, not on every one")
		}
		held := map[uint16][]string{}
		for _, u := range t.Unbound {
			if ap, err := netip.ParseAddrPort(u); err == nil && ap.Port() != 80 {
				held[ap.Port()] = append(held[ap.Port()], ap.Addr().String())
			}
		}
		for _, port := range slices.Sorted(maps.Keys(held)) {
			note(lineWarn, "another program holds port %d on %s, where juist would serve what is published here",
				port, strings.Join(held[port], ", "))
		}
		if len(held) > 0 {
			note(lineHint, "where the service listens on every address, publish its port: juist publish add DEVICE NAME PORT")
		}
	}
	if s.Unreachable > 0 && s.Peers > 0 {
		what := count(s.Unreachable, "device")
		if len(s.Silent) > 0 {
			what = strings.Join(s.Silent, ", ")
		}
		note(lineInfo, "not heard from: %s", what)
	}
	dev := cmp.Or(s.Device, instance.Name(s.Instance))
	if len(s.SyncFailing) > 0 {
		note(lineWarn, "log sync to %s fails in the tunnel: a firewall drops tcp/%d on %s",
			strings.Join(s.SyncFailing, ", "), s.GossipPort, dev)
		note(lineHint, "on both devices: sudo ufw allow in on %s, or add %s to firewalld's trusted zone", dev, dev)
	}
	httpsOnly := s.HTTPS != nil && s.HTTPS.Only
	if len(s.Seeking) > 0 && httpsOnly {
		note(lineInfo, "no answer from %s: offline, or at no relay on 443", strings.Join(s.Seeking, ", "))
	} else if len(s.Seeking) > 0 {
		note(lineInfo, "no answer from %s: offline, or udp/%d blocked", strings.Join(s.Seeking, ", "), s.ListenPort)
	}
	// Only where the announcement held is known to be the device's newest is
	// the way to it to blame.
	if down := slices.DeleteFunc(slices.Clone(s.TunnelsDown), func(n string) bool {
		return slices.Contains(s.Seeking, n) || slices.Contains(s.Absent, n)
	}); len(down) > 0 && httpsOnly {
		note(lineWarn, "no tunnel traffic from %s through the relays on 443", strings.Join(down, ", "))
	} else if len(down) > 0 {
		note(lineWarn, "no tunnel traffic from %s: udp/%d blocked, or both behind NAT with no relay",
			strings.Join(down, ", "), s.ListenPort)
		note(lineHint, "on a device with a public address: %s", openPorts("juist", s.ListenPort, serviceDataPort,
			"udp"))
	}
	if s.Conflicted > 0 {
		note(lineWarn, "%s announce a key another device uses; ignored", count(s.Conflicted, "device"))
	}
	if s.PQ != nil && len(s.PQ.None) > 0 && s.Schema >= types.SchemaPQ {
		note(lineWarn, "not post-quantum, so juist's own traffic alone: %s, on an older build or behind the network",
			strings.Join(s.PQ.None, ", "))
	}
	if s.PQ != nil && len(s.PQ.NoKey) > 0 {
		note(lineWarn, "no preshared key in common with %s, behind by more changes than this device keeps",
			strings.Join(s.PQ.NoKey, ", "))
		note(lineHint, "it catches up from a device that has been away as long, or joins again with a new invite")
	}
	notes = append(notes, httpsNotes(s)...)
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
			note(lineHint, "vouchers that are always on bound how long a removal takes to reach a device cut off: "+
				"juist grant %s voucher, juist grant %s voucher, juist admins vouchers 2", relays[0], relays[1])
		}
	}
	if left, ending := s.FreshnessEnding(time.Now().Unix()); ending {
		note(lineWarn, "freshness ends in %s unless %s", roughly(left), s.VouchAgain())
		note(lineHint, "a voucher vouches while juistd runs on it and reaches this device")
	}
	if s.RelayUnreached && s.Alarm == "" {
		note(lineWarn, "no device reaches this relay: tcp/%d or udp/%d is likely closed", s.RelayPort, s.RelayPort)
		note(lineHint, "%s; and any firewall in front of this host",
			openPorts("juist-relay", s.RelayPort, serviceRelayPort, "tcp", "udp"))
	}
	// Two devices behind strict NATs need a third, reachable, to relay.
	if s.RelayCapable == 0 && s.Members > 2 && s.Alarm == "" {
		note(lineWarn, "no device may relay; devices behind strict NATs need one")
		note(lineHint, "juist grant DEVICE relay, on a device with a public address")
	}
	for _, l := range s.Lost {
		note(lineWarn, "%s lost to a concurrent change", l)
		note(lineHint, "redo it if still wanted; juist log lists what was lost")
	}
	for _, u := range s.Unrevoked {
		note(lineWarn, "%s lost to a concurrent change and is not in effect", u)
		note(lineHint, "an admin redoes it")
	}
	if s.SchemaAlarm != "" {
		note(lineAlarm, "%s; no changes, removals included, apply until juist is updated", s.SchemaAlarm)
	}
	if s.Alarm != "" {
		note(lineAlarm, "%s; tunnels down until resolved", s.Alarm)
	}
	return notes
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
// its tunnels, and whether it did.
func (a *app) startWarning() bool {
	st := a.node.status()
	if st == nil || st.StartError == "" {
		return false
	}
	a.warn("tunnels not up yet, retrying: %s", st.StartError)
	return true
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
