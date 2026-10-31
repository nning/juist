package main

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/nning/juist/cmd/internal/defaults"
	"github.com/nning/juist/internal/cliflag"
	"github.com/nning/juist/ipc"
)

// manpage writes juistd(8) in roff, its options taken from fs as --help
// takes them, so the page cannot drift from the daemon. "juistd __manpage"
// runs it; `make man` and the packages build it.
func manpage(w io.Writer, fs *flag.FlagSet) error {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	text := func(s string) {
		line(".PP")
		for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
			line("%s", roffLine(strings.TrimSpace(l)))
		}
	}
	tagged := func(tag, s string) {
		line(".TP")
		line(`.B "%s"`, strings.ReplaceAll(roffLine(tag), "-", `\-`))
		line("%s", roffLine(s))
	}
	version := "(devel)"
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		version = bi.Main.Version
	}
	line(`.TH JUISTD 8 "" "juist %s" "juist manual"`, roffLine(version))
	line(".SH NAME")
	line(`juistd \- the juist node daemon`)
	line(".SH SYNOPSIS")
	line(".B juistd")
	line(".RI [ options ]")
	line(".SH DESCRIPTION")
	text(`juistd runs a juist node: it holds the membership log this device is in,
keeps a WireGuard peer for every member the log authorizes and nobody else,
finds them on the LAN, through each other and through the public DHT, and
keeps its log in step with theirs. There is no coordination server to
configure. It holds no admin key, so a juistd taken over is one member taken
over, not the network. juist(1) talks to it over its control socket.`)
	text(privilegeText)
	line(".SH OPTIONS")
	for _, o := range optionOrder {
		f := fs.Lookup(o.long)
		label, _ := cliflag.Label(fs, f)
		desc, def := f.Usage, f.DefValue
		if d, err := time.ParseDuration(def); err == nil {
			def = shortDuration(d)
		}
		if def != "" && def != "false" {
			desc += " (default " + def + ")"
		}
		tagged(strings.TrimSpace(label+" "+o.arg), desc+".")
	}
	tagged("-h, --help", "Show the options.")
	text(`Default ports another program holds become ones the OS chooses; ports
given here do not. Each node announces the ports it listens on.`)
	line(".SH INSTANCES")
	text(`A host in several networks runs one juistd per network. The default is
juistd.service; juistd@juist1.service to juistd@juist9.service run with
--instance juist1 to juist9 beside it. The instance takes the default ports
plus ten times its number, a TUN device and routing table of its own, and
policy rules of its own, so that stopping one leaves the others' routes as
they are. Where two networks claim one IPv4 address, the lower instance's
routes win, and the higher runs without IPv4 until one of them renumbers.`)
	line(".SH FILES")
	for _, f := range [][2]string{
		{defaults.SystemHome, "The packaged juistd's state: node.keys, the log, the peer cache and leases; " + defaults.SystemHome + "N for an instance, which runs as the user juistN."},
		{ipc.SystemSocket, "The control socket; " + filepath.Dir(ipc.SystemSocket) + "N/juistd.sock for an instance."},
		serviceFiles,
	} {
		tagged(f[0], f[1])
	}
	line(".SH SEE ALSO")
	line(".BR juist (1)")
	_, err := io.WriteString(w, b.String())
	return err
}

// roffLine escapes a line of text for roff: backslashes, and a leading dot
// or quote that roff would take for a request.
func roffLine(s string) string {
	s = strings.ReplaceAll(s, `\`, `\e`)
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "'") {
		s = `\&` + s
	}
	return s
}
