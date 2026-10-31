package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nning/juist/ipc"
)

// manpage writes juist(1) in roff, from the command table and each command's
// own help, so that it cannot drift from them.
func (a *app) manpage(w io.Writer) error {
	// Capturing a command opens a keystore; a throwaway one, so building
	// the page touches nobody's.
	tmp, err := os.MkdirTemp("", "juist-man")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	g := globals{home: tmp}
	m := &roff{w: w}
	m.line(`.TH JUIST 1 "" "juist %s" "juist manual"`, roffText(version()))
	m.section("NAME")
	m.line(`juist \- peer-to-peer mesh VPN with no coordination server`)
	m.section("SYNOPSIS")
	m.line(`.B juist`)
	m.line(`.I command`)
	m.line(`.RI [ network ]`)
	m.line(`.RI [ arguments ]`)
	m.line(`.RI [ options ]`)
	m.section("DESCRIPTION")
	m.text(`juist creates and runs a juist network: a WireGuard mesh whose membership is a
log signed by its admins, checked by every device, with nothing in the middle.
juist holds the admin keys, in the keystore, and never hands them to the
daemon; juistd(8), the daemon, holds the device and carries the traffic.
Any local user may run juist status; everything else is for root and the
device's operator, one local user named with juist set --operator.`)
	m.section("COMMANDS")
	group := ""
	for i := range commands {
		c := &commands[i]
		if c.group != group {
			group = c.group
			m.line(".SS %s", roffText(group))
		}
		if c.family == nil {
			if err := m.command(a, g, c, nil); err != nil {
				return err
			}
			continue
		}
		f := c.family()
		for k, sub := range f.subs {
			args := []string{sub.name}
			if k == 0 {
				args = nil
			}
			if err := m.command(a, g, c, args); err != nil {
				return err
			}
		}
	}
	m.section("SEVERAL NETWORKS")
	m.text(`A device may be in several networks, each run by a juistd of its own:
juistd.service for the first, juistd@juist1.service and on for the others.
A command about one network takes it first, by the network's name or its
juistd's (juist1), and may leave it out where the device is in one network:
juist devices home, juist network renumber juist1 10.7.0.0/24. Listings
(status, devices, network, admins) show every network where none is named;
any other command stops and names the networks. No command asks which.`)
	m.section("OPTIONS")
	m.text("These go before or after the command, and are taken by every one.")
	for _, o := range [][2]string{
		{"-H, --home DIR", "The keystore: admin keys, and each network's anchor. Default $JUIST_HOME, or ~/.config/juist."},
		{"-s, --socket PATH", "The juistd to talk to. Default $JUIST_SOCKET, or the packaged service's."},
		{"--network NAME", "The network, as NETWORK first does. Default $JUIST_NETWORK."},
		{"-h, --help", "Show a command's help."},
	} {
		m.option(o[0], o[1])
	}
	m.section("ENVIRONMENT")
	for _, e := range [][2]string{
		{"JUIST_HOME", "The keystore, as --home."},
		{"JUIST_SOCKET", "juistd's socket, as --socket."},
		{"JUIST_NETWORK", "The network, as --network; juist create, juist join and juist admins new do not follow it."},
		{"NO_COLOR", "Plain output."},
	} {
		m.option(e[0], e[1])
	}
	m.section("FILES")
	for _, f := range [][2]string{
		{"~/.config/juist", "The keystore: admins/ holds admin keys, NAME@NETWORK.key for one network's, networks/ what the keystore last verified of each network, founded-NETWORK each network founded from it."},
		{systemHome, "The packaged juistd's state: the device's keys and the network's log; " + systemHome + "N for the others, each its own user's."},
		{ipc.SystemSocket, "The packaged juistd's control socket; " + filepath.Dir(ipc.SystemSocket) + "N/juistd.sock for the others."},
	} {
		m.option(f[0], f[1])
	}
	m.section("EXIT STATUS")
	m.text("0 where the command did what it was asked, 1 otherwise, with the reason on standard error and, where there is one, a hint of what to do.")
	m.section("EXAMPLES")
	m.pre(`juist create                 # a new network, with this device in it
juist invite                 # prints a code and a link for the next device
sudo juist join 'juist:…'    # on that device
juist status                 # this device's networks, and what needs attention
juist remove phone           # out of the network, on every device
juist grant vps relay        # a device with a public address relays for others`)
	m.section("SEE ALSO")
	m.line(`.BR juistd (8)`)
	m.line(`.PP`)
	m.line(`https://github.com/nning/juist`)
	return m.err
}

// command writes one command's entry: its synopsis, what it does, and its
// options, as its help has them.
func (m *roff) command(a *app, g globals, c *command, args []string) error {
	got, ok := a.captureCommand(g, c, args)
	if !ok {
		return fmt.Errorf("juist __manpage: %s %s gave no help to take", c.name, strings.Join(args, " "))
	}
	s := got.spec
	m.line(".TP")
	syn := `.B "` + roffText(s.name) + `"`
	if args := s.synopsis(); args != "" && !strings.Contains(args, "SUBCOMMAND") {
		syn += " " + roffText(args)
	}
	m.line("%s", syn)
	about := strings.TrimSpace(s.about)
	if c.family != nil && len(args) == 0 {
		// A family's first subcommand carries the family's help: its intro,
		// every form, and its footer.
		f := c.family()
		about = strings.TrimSpace(f.about())
	}
	m.body(about)
	rows := optionRows(got.fs)
	if len(rows) == 0 {
		return nil
	}
	m.line(".RS")
	for _, o := range rows {
		m.option(o[0], o[1])
	}
	m.line(".RE")
	return nil
}

// roff writes a man page, keeping the first error.
type roff struct {
	w   io.Writer
	err error
}

func (m *roff) line(format string, args ...any) {
	if m.err == nil {
		_, m.err = fmt.Fprintf(m.w, format+"\n", args...)
	}
}

func (m *roff) section(name string) { m.line(".SH %s", name) }

// text writes a paragraph of prose.
func (m *roff) text(s string) {
	m.line(".PP")
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		m.line("%s", roffLine(strings.TrimSpace(l)))
	}
}

// body writes a command's help text: paragraphs as prose, and indented lines,
// such as a family's list of forms, as they are.
func (m *roff) body(s string) {
	paras := strings.Split(s, "\n\n")
	for k, p := range paras {
		if k > 0 {
			m.line(".IP")
		}
		lines := strings.Split(p, "\n")
		if strings.HasPrefix(lines[0], "  ") {
			m.pre(p)
			continue
		}
		for _, l := range lines {
			m.line("%s", roffLine(strings.TrimSpace(l)))
		}
	}
}

// pre writes lines as they are, in a fixed-width block.
func (m *roff) pre(s string) {
	m.line(".nf")
	m.line(".RS 2")
	for _, l := range strings.Split(s, "\n") {
		m.line("%s", roffLine(l))
	}
	m.line(".RE")
	m.line(".fi")
}

// option writes a tagged paragraph: an option, a variable, a file.
func (m *roff) option(tag, text string) {
	m.line(".TP")
	m.line(`.B "%s"`, strings.ReplaceAll(roffText(tag), "-", `\-`))
	m.line("%s", roffLine(text))
}

// roffText escapes what roff would take for its own in running text.
func roffText(s string) string { return strings.ReplaceAll(s, `\`, `\e`) }

// roffLine is roffText for a line of its own, which roff would take for a
// request where it starts with a dot or a quote.
func roffLine(s string) string {
	s = roffText(s)
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "'") {
		s = `\&` + s
	}
	return s
}
