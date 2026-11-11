package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/nning/juist/ipc"
)

func cmdHealth(a *app, args []string) error {
	s := spec{name: "juist health", about: `
Say what needs attention on this device, and which devices it does not
reach, for every network if the device is in several.`}
	if _, err := a.parse(s, newFlags(s.name), args); err != nil {
		return err
	}
	if insts := a.statusInstances(); len(insts) > 1 || len(insts) == 1 && insts[0].st == nil {
		a.printHostHealth(insts)
		return nil
	}
	if i, ok := a.namedDown(); ok {
		a.warn("juistd not running")
		a.hint("%s", startCmd(i.n))
		return nil
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	st := liveStatus(n)
	if st == nil {
		a.warn("juistd not running")
		a.startHint()
		return nil
	}
	if said := a.health(st, "", false); !said {
		a.ok("nothing needs attention")
	}
	return nil
}

// namedDown is the host's instance the command names, where its juistd does
// not answer.
func (a *app) namedDown() (hostInstance, bool) {
	if a.network == "" || !a.hostScope() {
		return hostInstance{}, false
	}
	var named []hostInstance
	for _, i := range a.hostInstances() {
		if i.named(a.network) {
			named = append(named, i)
		}
	}
	if len(named) != 1 || named[0].st != nil {
		return hostInstance{}, false
	}
	return named[0], true
}

// health prints what needs attention in s's network, the network inst on a
// host in several, and reports whether it printed anything.
func (a *app) health(s *ipc.Status, inst string, several bool) (said bool) {
	notes, _ := a.healthLines(s, inst, several)
	a.emitIssues(notes)
	return len(notes) > 0
}

// emitIssues is emit with a blank line between issues, on stderr, so that
// stdout keeps a line per outcome.
func (a *app) emitIssues(lines []line) {
	for k, l := range lines {
		if k > 0 && l.startsIssue() {
			fmt.Fprintln(a.errOut)
		}
		a.emit(lines[k : k+1])
	}
}

// healthLines is what [app.health] prints, and how many changes wait for
// this keystore's vote.
func (a *app) healthLines(s *ipc.Status, inst string, several bool) ([]line, int) {
	notes := a.healthNotes(s, inst)
	if several {
		defer a.within(inst)()
	}
	admin, votes := a.adminNotes(s, several)
	return append(notes, admin...), votes
}

// healthNotes are what needs attention as s says it, admin keys aside.
func (a *app) healthNotes(s *ipc.Status, inst string) []line {
	notes := statusOfOn(s, a.now(), a.paint, a.instanceLabel, inst != "").notes
	if s.Instance == 0 && (s.HTTPS == nil || s.HTTPS.Name == "") && a.relayGranted() {
		notes = append(notes, line{kind: lineWarn, text: "juistd may bind ports below 1024, but no relay here uses 443"},
			line{kind: lineHint, text: asRoot(a.host.relayScript + " off")})
	}
	if ex := s.Exit; ex != nil && !ex.Node.IsZero() && ex.Refused == "" && ex.Failed == "" {
		notes = append(notes, a.dnsNotes(ex, dnsOverlay(s, nil))...)
		notes = append(notes, a.strictRPNotes(ex)...)
	}
	if m := s.Multicast; m != nil && !m.Off && s.Device != "" {
		notes = append(notes, avahiNotes(a.system, s.Device)...)
	}
	if u := s.Underlay; u != nil && u.Mapped != "" && s.ListenPort != 0 && a.host.udpBlocked != nil {
		if zone, service, unsure := a.host.udpBlocked(a.ctx, s.ListenPort); unsure {
			// A hint, not a warning: without the right to read the zone, the
			// user could never clear it.
			notes = append(notes, line{kind: lineHint, apart: true, text: fmt.Sprintf("firewalld may block udp/%d, which the router maps to this device: juist cannot read the ports of zone %s; to check: %s",
				s.ListenPort, zone, asRoot("juist health"))})
		} else if zone != "" {
			open := fmt.Sprintf("--add-port=%d/udp", s.ListenPort)
			if service {
				open = "--add-service=juist"
			}
			notes = append(notes, line{kind: lineWarn, text: fmt.Sprintf("firewalld blocks udp/%d, which the router maps to this device", s.ListenPort)})
			if pastableZone(zone) {
				notes = append(notes, line{kind: lineHint,
					text: "sudo firewall-cmd --permanent --zone=" + zone + " " + open + " && sudo firewall-cmd --reload"})
			}
		}
	}
	if !s.CanOperate {
		network := ""
		if inst != "" {
			network = inst + " "
		}
		notes = append(notes, line{kind: lineHint, apart: true,
			text: "read-only; to manage this device: " + asRoot("juist set "+network+"--operator="+currentUser())})
	}
	return notes
}

// healthWarnings is how many warnings [app.health] would print, alarms
// aside, and changes for this keystore's vote, printing nothing.
func (a *app) healthWarnings(s *ipc.Status, inst string, several bool) (n, votes int) {
	notes, votes := a.healthLines(s, inst, several)
	return warnings(notes), votes
}

// warnings counts the warnings among lines, alarms aside.
func warnings(lines []line) int {
	n := 0
	for _, l := range lines {
		if l.kind == lineWarn {
			n++
		}
	}
	return n
}

// printHostHealth is "juist health" on a host in several networks.
func (a *app) printHostHealth(insts []hostInstance) {
	for k, i := range insts {
		if k > 0 {
			a.printf("\n")
		}
		a.printf("%s\n", a.bold(i.name()))
		if i.st == nil {
			a.warn("juistd not running")
			a.hint("%s", startCmd(i.n))
			continue
		}
		if said := a.health(i.st, i.name(), true); !said {
			a.ok("nothing needs attention")
		}
	}
}

// avahi's configuration and pid file, on Linux and FreeBSD.
var avahiFiles = [][2]string{
	{"/etc/avahi/avahi-daemon.conf", "/run/avahi-daemon/pid"},
	{"/usr/local/etc/avahi/avahi-daemon.conf", "/var/run/avahi-daemon/pid"},
}

// avahiNotes warn where avahi runs and leaves dev out, as it does a
// point-to-point device unless told otherwise.
func avahiNotes(read func(string) ([]byte, error), dev string) []line {
	for _, f := range avahiFiles {
		if _, err := read(f[1]); err != nil {
			continue
		}
		conf, _ := read(f[0])
		server := iniSection(string(conf), "server")
		list := func(key string) []string {
			var out []string
			for _, v := range strings.Split(server[key], ",") {
				if v = strings.TrimSpace(v); v != "" {
					out = append(out, v)
				}
			}
			return out
		}
		allow, deny := list("allow-interfaces"), list("deny-interfaces")
		switch {
		case slices.Contains(deny, dev) || len(allow) > 0 && !slices.Contains(allow, dev):
			return []line{{kind: lineWarn, text: "avahi skips " + dev + ": allow-interfaces or deny-interfaces leave it out"},
				{kind: lineHint, text: "name " + dev + " in allow-interfaces in " + f[0] + ", then restart avahi-daemon"}}
		case !avahiYes(server["allow-point-to-point"]):
			return []line{{kind: lineWarn, text: "avahi skips " + dev + ", a point-to-point device, so mDNS finds no members"},
				{kind: lineHint, text: "set allow-point-to-point=yes under [server] in " + f[0] + ", then restart avahi-daemon"}}
		}
		return nil
	}
	return nil
}

// avahiYes reads a boolean as avahi does: by its first letter.
func avahiYes(v string) bool { return v != "" && strings.ContainsRune("yYtT1", rune(v[0])) }

// iniSection is the keys of an INI file's section, as avahi reads them.
func iniSection(text, section string) map[string]string {
	out := map[string]string{}
	in := false
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "" || l[0] == '#' || l[0] == ';':
		case l[0] == '[':
			in = strings.TrimSpace(strings.Trim(l, "[]")) == section
		case in:
			if k, v, ok := strings.Cut(l, "="); ok {
				out[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	return out
}
