// Command juistd runs a juist node: it holds the membership log this device
// is in, keeps a WireGuard peer for every member the log authorizes and
// nobody else, finds them with blinded LAN discovery, and keeps its log in
// step by gossip. There is no coordination server to configure.
//
// It creates a real TUN device and programs the host's routes, which needs
// /dev/net/tun and CAP_NET_ADMIN; pass --tun "" to run without one. It holds no
// admin signing keys and cannot authorize a membership change, so an attacker
// who owns this process owns one member rather than the network.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nning/juist/cmd/internal/defaults"
	"github.com/nning/juist/daemon"
	"github.com/nning/juist/internal/cliflag"
	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/internal/rendezvous"
	"github.com/nning/juist/ipc"
)

const synopsis = "usage: juistd [options]"

// errHelp is help asked for and given.
var errHelp = errors.New("help")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "juistd: %v\n", err)
		os.Exit(1)
	}
}

// run runs the node args describe until ctx ends; help goes to out.
func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	opts, err := parse(args, out)
	if errors.Is(err, errHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if opts.verbose {
		logf := func(format string, a ...any) { fmt.Fprintf(errOut, format+"\n", a...) }
		opts.service.Logf, opts.service.Mesh.Logf = logf, logf
	}
	s, err := daemon.NewService(opts.service)
	if err != nil {
		return err
	}
	// The deferred Close removes the control socket.
	defer s.Close()
	if err := s.Start(ctx); err != nil {
		return err
	}
	report(out, errOut, s.Status(), opts.service.Mesh.TunName)
	<-ctx.Done()
	return ctx.Err()
}

type options struct {
	service daemon.ServiceOptions
	verbose bool
}

// parse reads juistd's options, printing help to out where asked.
func parse(args []string, out io.Writer) (options, error) {
	fs := flag.NewFlagSet("juistd", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	inst := fs.String("instance", "", "run as instance NAME, juist1 to juist9: another network beside the default's")
	home := fs.String("home", "", "state directory (default $JUIST_HOME, or ~/.config/juist, and NAME in it)")
	socket := fs.String("socket", "", "control socket (default daemon.sock in the state directory)")
	port := fs.Uint("port", daemon.DefaultListenPort, "UDP port for the data plane")
	gossipPort := fs.Uint("gossip-port", daemon.DefaultGossipPort, "TCP port for log sync")
	relayPort := fs.Uint("relay-port", daemon.DefaultRelayPort, "TCP and UDP port for relaying, where the log grants it")
	tun := fs.String("tun", "juist0", `TUN device to create, "" for none; needs CAP_NET_ADMIN`)
	noRelay := fs.Bool("no-relay", false, "do not relay for other members, whatever the log grants")
	noDiscovery := fs.Bool("no-discovery", false, "do not announce or look for members on the LAN")
	noDHT := fs.Bool("no-dht", false, "do not use the public DHT, for members or invites")
	stunList := fs.String("stun", strings.Join(rendezvous.DefaultSTUN, ","), "public STUN servers, comma-separated")
	noSTUN := fs.Bool("no-stun", false, "ask no STUN server outside the network")
	ttl := fs.Duration("freshness-ttl", daemon.DefaultFreshnessTTL, "how long to trust the network's state unvouched")
	verbose := fs.Bool("verbose", false, "log what the daemon is doing")
	for _, o := range optionOrder {
		cliflag.Short(fs, o.short, o.long)
	}
	if len(args) == 1 && args[0] == "__manpage" {
		if err := manpage(out, fs); err != nil {
			return options{}, err
		}
		return options{}, errHelp
	}
	err := cliflag.Check(fs, args)
	if err == nil {
		err = cliflag.TidyIn(fs, fs.Parse(args))
	}
	switch {
	case errors.Is(err, flag.ErrHelp):
		fmt.Fprint(out, help(fs))
		return options{}, errHelp
	case err != nil:
		return options{}, fmt.Errorf("%v\n%s", err, synopsis)
	case fs.NArg() > 0:
		return options{}, fmt.Errorf("unexpected argument %q\n%s", fs.Arg(0), synopsis)
	}
	if *port > 0xffff || *gossipPort > 0xffff || *relayPort > 0xffff {
		return options{}, errors.New("a port must be below 65536")
	}
	n := 0
	if cliflag.IsSet(fs, "instance") {
		if n, err = instance.Parse(*inst); err != nil {
			return options{}, fmt.Errorf("--instance: %w", err)
		}
		// Everything two instances must not share follows from the number,
		// unless given.
		if !cliflag.IsSet(fs, "tun") {
			*tun = *inst
		}
		for _, p := range []struct {
			name string
			v    *uint
		}{{"port", port}, {"gossip-port", gossipPort}, {"relay-port", relayPort}} {
			if !cliflag.IsSet(fs, p.name) {
				*p.v = uint(instance.Port(uint16(*p.v), n))
			}
		}
	}
	// Vouchers vouch every lease interval; a TTL below two of them has nodes
	// go stale between leases and drop tunnels every time.
	if minTTL := 2 * daemon.DefaultLeaseInterval; *ttl < minTTL {
		return options{}, fmt.Errorf("--freshness-ttl must be at least %s, twice how often vouchers vouch",
			shortDuration(minTTL))
	}
	var stun []string
	if !*noSTUN {
		for _, s := range strings.Split(*stunList, ",") {
			if s = strings.TrimSpace(s); s != "" {
				stun = append(stun, s)
			}
		}
	}
	if *home == "" {
		*home = defaults.Home()
		if n > 0 {
			*home = filepath.Join(*home, *inst)
		}
	}
	nop := func(string, ...any) {}
	return options{verbose: *verbose, service: daemon.ServiceOptions{
		Home:   *home,
		Socket: *socket,
		Mesh: daemon.Options{
			ListenPort:   uint16(*port),
			TunName:      *tun,
			Instance:     n,
			GossipPort:   uint16(*gossipPort),
			RelayPort:    uint16(*relayPort),
			DisableRelay: *noRelay,
			// Ports the operator named are held to; defaults give way.
			PortFallback:     !cliflag.IsSet(fs, "port") && !cliflag.IsSet(fs, "gossip-port") && !cliflag.IsSet(fs, "relay-port"),
			DisableDiscovery: *noDiscovery,
			DisableDHT:       *noDHT,
			STUN:             stun,
			FreshnessTTL:     *ttl,
			Logf:             nop,
		},
		Logf: nop,
	}}, nil
}

// optionOrder is every option's one-letter spelling, in the order help lists
// them, with what its value is.
var optionOrder = []struct {
	short byte
	long  string
	arg   string
}{
	{'i', "instance", "NAME"}, {'H', "home", "DIR"}, {'s', "socket", "PATH"}, {'p', "port", "N"}, {'g', "gossip-port", "N"},
	{'r', "relay-port", "N"}, {'t', "tun", "NAME"}, {'R', "no-relay", ""}, {'l', "no-discovery", ""},
	{'d', "no-dht", ""}, {'u', "stun", "LIST"}, {'U', "no-stun", ""}, {'f', "freshness-ttl", "D"},
	{'v', "verbose", ""},
}

// help lists the options of fs with their defaults.
func help(fs *flag.FlagSet) string {
	var b strings.Builder
	b.WriteString("Usage: juistd [options]\n\nRun a juist node: the membership log in, the WireGuard mesh out.\n\nOptions:\n")
	for _, o := range optionOrder {
		f := fs.Lookup(o.long)
		label, _ := cliflag.Label(fs, f)
		text, def := f.Usage, f.DefValue
		if d, err := time.ParseDuration(def); err == nil {
			def = shortDuration(d)
		}
		if def != "" && def != "false" {
			text += " (default " + def + ")"
		}
		fmt.Fprintf(&b, "  %-22s %s\n", strings.TrimSpace(label+" "+o.arg), text)
	}
	fmt.Fprintf(&b, "  %-22s %s\n", "-h, --help", "show this help")
	b.WriteString("\nDefault ports another program holds become OS-chosen ones; ports given here do not.\n")
	b.WriteString("An instance takes the default ports plus ten times its number, and its name for the device.\n")
	return b.String()
}

// shortDuration prints 48h rather than 48h0m0s.
func shortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// report says how the node started: its state on out, what needs attention
// on errOut.
func report(out, errOut io.Writer, st ipc.Status, tun string) {
	warn := func(format string, a ...any) { fmt.Fprintf(errOut, "warning: "+format+"\n", a...) }
	hint := func(format string, a ...any) { fmt.Fprintf(errOut, "hint: "+format+"\n", a...) }
	field := func(label, format string, a ...any) {
		fmt.Fprintf(out, "  %-11s %s\n", label, fmt.Sprintf(format, a...))
	}
	if !st.InNetwork {
		fmt.Fprintf(out, "juistd: %s (%v) in no network\n", st.SelfName, st.Self.ShortString())
		hint("juist create, or juist join CODE")
		return
	}
	fmt.Fprintf(out, "juistd: network %q (%v)\n", st.NetworkName, st.Network)
	field("this node", "%s (%v)", st.SelfName, st.Self.ShortString())
	if st.NotMember {
		warn("not a member: the log no longer lists this device")
		hint("rejoin with a new invite")
		return
	}
	for _, a := range st.Addrs {
		field("overlay", "%v", a.Addr())
	}
	field("device", "%s", map[bool]string{true: "none", false: tun}[tun == ""])
	field("data plane", "udp/%d", st.ListenPort)
	field("log sync", "tcp/%d", st.GossipPort)
	field("members", "%d", st.Members)
	if st.Relaying {
		field("relaying", "yes")
	}
	switch {
	case st.LeaseSigners == 0:
		field("freshness", "not checked: no voucher in the network")
	case st.Stale:
		field("freshness", "expired; tunnels only to vouchers until %d vouch again", max(st.Vouchers, 1))
	default:
		field("freshness", "good until %s", time.Unix(st.FreshUntil, 0).Format(time.DateTime))
	}
	for _, alarm := range []string{st.SchemaAlarm, st.Alarm} {
		if alarm != "" {
			warn("%s", alarm)
		}
	}
	if st.StartError != "" {
		warn("tunnels cannot start yet, retrying: %s", st.StartError)
		if tun != "" && strings.Contains(st.StartError, iofs.ErrPermission.Error()) {
			hint("creating %q needs CAP_NET_ADMIN: setcap cap_net_admin+ep on this binary, the packaged "+
				"service, or --tun \"\"", tun)
		}
	}
}
