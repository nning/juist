package main

import (
	"strings"
	"testing"
)

// juist(1) has every command and subcommand, from its own help, and nothing
// but the requests a man page may use.
func TestTheManPageHasEveryCommand(t *testing.T) {
	t.Parallel()
	var out syncBuffer
	a := newCLI(t).app(&out, "")
	if err := a.main([]string{"__manpage"}); err != nil {
		t.Fatal(err)
	}
	page := out.String()
	for _, c := range commands {
		if c.family == nil {
			if !strings.Contains(page, `.B "juist `+c.name+`"`) {
				t.Errorf("the page lacks juist %s", c.name)
			}
			continue
		}
		for _, sub := range c.family().subs[1:] {
			if !strings.Contains(page, `.B "juist `+c.name+" "+sub.name+`"`) {
				t.Errorf("the page lacks juist %s %s", c.name, sub.name)
			}
		}
	}
	mustContain(t, page, ".TH JUIST 1", `\-\-network NAME`, "JUIST_NETWORK", "SEVERAL NETWORKS", ".BR juistd (8)")
	if strings.Contains(page, `"juist init"`) {
		t.Error("the page lists init, which is create")
	}
	allowed := map[string]bool{"TH": true, "SH": true, "SS": true, "TP": true, "PP": true, "IP": true, "RS": true,
		"RE": true, "B": true, "I": true, "RI": true, "BR": true, "nf": true, "fi": true}
	open := 0
	for n, l := range strings.Split(page, "\n") {
		if strings.HasPrefix(l, "'") {
			t.Errorf("line %d starts with a quote, which roff reads as a request: %q", n+1, l)
		}
		if !strings.HasPrefix(l, ".") {
			continue
		}
		req, _, _ := strings.Cut(l[1:], " ")
		if !allowed[req] {
			t.Errorf("line %d: request %q", n+1, l)
		}
		switch req {
		case "nf":
			open++
		case "fi":
			open--
		}
	}
	if open != 0 {
		t.Errorf("%d fill blocks left open", open)
	}
}
