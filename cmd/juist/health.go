package main

import "github.com/nning/juist/ipc"

func cmdHealth(a *app, args []string) error {
	s := spec{name: "juist health", about: `
Say what needs attention on this device, each with a hint to fix it, and
which devices it does not reach; every network, where it is in several.
juist status shows how things stand.`}
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
	a.emit(notes)
	return len(notes) > 0
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
		notes = append(notes, line{kind: lineWarn, text: "juistd may bind any port below 1024, which no relay on 443 here needs"},
			line{kind: lineHint, text: asRoot(a.host.relayScript + " off")})
	}
	if ex := s.Exit; ex != nil && !ex.Node.IsZero() && ex.Refused == "" && ex.Failed == "" {
		notes = append(notes, a.dnsNotes(ex, dnsOverlay(s, nil))...)
		notes = append(notes, a.strictRPNotes(ex)...)
	}
	if !s.CanOperate {
		network := ""
		if inst != "" {
			network = inst + " "
		}
		notes = append(notes, line{kind: lineHint,
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
