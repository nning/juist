package main

import (
	"bytes"
	"io"

	"github.com/nning/juist/ipc"
)

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
	n, err := a.openNode()
	if err != nil {
		return err
	}
	st := n.status()
	if st == nil {
		a.warn("juistd not running")
		a.startHint()
		return nil
	}
	if _, _, said := a.health(st, "", false); !said {
		a.ok("nothing needs attention")
	}
	return nil
}

// health prints what needs attention in s's network, the network inst on a
// host in several, and reports how many warnings it printed, alarms among
// them, how many changes wait for this keystore's vote, and whether it
// printed anything.
func (a *app) health(s *ipc.Status, inst string, several bool) (warnings, votes int, said bool) {
	out, errOut := &lineCounter{w: a.out}, &lineCounter{w: a.errOut}
	a.out, a.errOut = out, errOut
	defer func() { a.out, a.errOut = out.w, errOut.w }()
	a.healthNotes(s, inst)
	if several {
		a.network, a.node, a.instance = inst, nil, nil
		defer func() { a.network, a.node, a.instance = "", nil, nil }()
	}
	votes = a.adminNotes(s, several)
	return errOut.warnings, votes, out.lines+errOut.lines > 0
}

// healthNotes prints what needs attention as s says it, admin keys aside.
func (a *app) healthNotes(s *ipc.Status, inst string) {
	v := statusOfOn(s, a.now(), a.paint, a.instanceLabel, inst != "")
	a.emit(v.notes)
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

// healthWarnings is how many warnings [app.health] would print, alarms
// aside, and changes for this keystore's vote, printing nothing.
func (a *app) healthWarnings(s *ipc.Status, inst string, several bool) (n, votes int) {
	out, errOut, color := a.out, a.errOut, a.color
	a.out, a.errOut, a.color = io.Discard, io.Discard, false
	defer func() { a.out, a.errOut, a.color = out, errOut, color }()
	n, votes, _ = a.health(s, inst, several)
	for _, l := range statusOfOn(s, a.now(), a.paint, a.instanceLabel, inst != "").notes {
		if l.kind == lineAlarm {
			n--
		}
	}
	return n, votes
}

// printHostHealth is "juist health" on a host in several networks.
func (a *app) printHostHealth(insts []hostInstance) {
	for k, i := range insts {
		if k > 0 {
			a.printf("\n")
		}
		if i.st == nil {
			a.printf("%s · %s\n", a.bold(i.name()), a.paint("1;31", "not running"))
			a.hint("%s", startCmd(i.n))
			continue
		}
		a.printf("%s\n", a.bold(i.name()))
		if _, _, said := a.health(i.st, i.name(), true); !said {
			a.ok("nothing needs attention")
		}
	}
}

// A lineCounter passes lines on and counts them, and the warnings among them.
type lineCounter struct {
	w               io.Writer
	lines, warnings int
}

func (c *lineCounter) Write(p []byte) (int, error) {
	for _, l := range bytes.SplitAfter(p, []byte("\n")) {
		if len(l) == 0 {
			continue
		}
		c.lines++
		if bytes.HasPrefix(stripANSI(l), []byte("warning:")) {
			c.warnings++
		}
	}
	return c.w.Write(p)
}

// stripANSI drops the colour codes paint adds.
func stripANSI(b []byte) []byte {
	var out []byte
	for i := 0; i < len(b); i++ {
		if b[i] == 0x1b {
			for i < len(b) && b[i] != 'm' {
				i++
			}
			continue
		}
		out = append(out, b[i])
	}
	return out
}
