// Command juistd runs a juist node: it holds the membership log this device
// is in, keeps a WireGuard peer for every member the log authorizes and
// nobody else, finds them with blinded LAN discovery, and keeps its log in
// step by gossip. There is no coordination server to configure.
//
// It creates a real TUN device and programs the host's routes, which needs
// CAP_NET_ADMIN on Linux and root on FreeBSD, where it keeps root for a
// helper alone; pass --tun "" to run without one. It holds no
// admin signing keys and cannot authorize a membership change, so an attacker
// who owns this process owns one member rather than the network.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	iofs "io/fs"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/nning/juist/cmd/internal/defaults"
	"github.com/nning/juist/daemon"
	"github.com/nning/juist/internal/cliflag"
	"github.com/nning/juist/internal/ingress"
	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/internal/rendezvous"
	"github.com/nning/juist/internal/terminator"
	"github.com/nning/juist/ipc"
)

const synopsis = "usage: juistd [options]"

// errHelp is help asked for and given.
var errHelp = errors.New("help")

func main() {
	if code, ok := split(os.Args[1:]); ok {
		os.Exit(code)
	}
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
	switch opts.helper {
	case "ingress":
		socket := cmp.Or(opts.service.Socket, ipc.SystemSocket)
		if os.Getuid() == 0 {
			// Root stays, to listen on the ports juistd says are
			// published, and the ingress drops.
			return runBinder(ctx, args, daemon.IngressUser, func(ctx context.Context, addr string) (*os.File, error) {
				return bindPublic(ctx, addr, func(ctx context.Context) (*ipc.Published, error) {
					return ipc.CallPublished(ctx, socket, nil)
				})
			}, errOut)
		}
		b, ctx, cancel, err := withBinder(ctx)
		if err != nil {
			return err
		}
		defer cancel()
		listen, listenQUIC := listenIngress, listenIngressQUIC
		if b != nil {
			listen = func(port uint16) (net.Listener, error) { return b.listen("tcp", fmt.Sprintf(":%d", port)) }
			listenQUIC = func() (*net.UDPConn, error) { return b.listenUDP(":443") }
		}
		return runIngress(ctx, socket, opts, listen, listenQUIC, errOut)
	case "tls":
		socket := cmp.Or(opts.service.Socket, ipc.SystemSocket)
		if os.Getuid() == 0 {
			// No capability binds a port alone everywhere: root stays,
			// to listen where juistd says, and the terminator drops.
			return runBinder(ctx, args, daemon.ServeUser, func(ctx context.Context, addr string) (*os.File, error) {
				return bindServed(ctx, addr, func(ctx context.Context) (*ipc.Published, error) {
					return ipc.CallServing(ctx, socket, nil)
				})
			}, errOut)
		}
		b, ctx, cancel, err := withBinder(ctx)
		if err != nil {
			return err
		}
		defer cancel()
		var listen func(network, addr string) (net.Listener, error)
		var listenPacket func(network, addr string) (net.PacketConn, error)
		if b != nil {
			listen = b.listen
			listenPacket = func(_, addr string) (net.PacketConn, error) { return b.listenUDP(addr) }
		}
		return runTerminator(ctx, opts, errOut, func(ctx context.Context, r *ipc.TerminatorReport) (*ipc.Published, error) {
			return ipc.CallServing(ctx, socket, r)
		}, func(ctx context.Context) (*ipc.StatusPage, error) {
			return ipc.CallStatusPage(ctx, socket)
		}, listen, listenPacket, httpPort)
	}
	if opts.verbose {
		logf := func(format string, a ...any) { fmt.Fprintf(errOut, format+"\n", a...) }
		opts.service.Logf, opts.service.Mesh.Logf = logf, logf
	}
	opts.service.Say = func(format string, a ...any) { fmt.Fprintf(out, "juistd: "+format+"\n", a...) }
	var helperGone <-chan struct{}
	if opts.service.Mesh.Plumber, helperGone, err = inheritedPlumber(); err != nil {
		return err
	}
	if h, ok := opts.service.Mesh.Plumber.(httpsBinder); ok {
		// The helper binds 443 for the relay, which no capability grants here.
		tun := opts.service.Mesh.TunName
		opts.service.Mesh.ListenHTTPS = func(a netip.Addr) (net.Listener, error) { return h.ListenHTTPS(tun, a) }
	}
	if helperGone != nil {
		var cancel context.CancelCauseFunc
		ctx, cancel = context.WithCancelCause(ctx)
		defer cancel(nil)
		go func() {
			select {
			case <-helperGone:
				cancel(errors.New("the helper is gone, and with it the device's plumbing"))
			case <-ctx.Done():
			}
		}()
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
	if opts.service.ServeTo != nil {
		// A service member ends TLS itself, on its network stack.
		go func() {
			err := runTerminator(ctx, opts, errOut, func(_ context.Context, r *ipc.TerminatorReport) (*ipc.Published, error) {
				if m := s.Mesh(); m != nil {
					return m.Serving(r), nil
				}
				return nil, errors.New("no network yet")
			}, func(context.Context) (*ipc.StatusPage, error) {
				return s.StatusPage()
			}, func(_, addr string) (net.Listener, error) {
				if m := s.Mesh(); m != nil {
					return m.ListenOverlay(addr)
				}
				return nil, errors.New("no network yet")
			}, func(_, addr string) (net.PacketConn, error) {
				if m := s.Mesh(); m != nil {
					return m.ListenOverlayUDP(addr)
				}
				return nil, errors.New("no network yet")
			}, 0)
			if err != nil {
				fmt.Fprintf(errOut, "juistd: %v\n", err)
			}
		}()
	}
	<-ctx.Done()
	return context.Cause(ctx)
}

// httpsBinder binds 443 for the relay where juistd may not.
type httpsBinder interface {
	ListenHTTPS(dev string, a netip.Addr) (net.Listener, error)
}

type options struct {
	service daemon.ServiceOptions
	verbose bool

	// helper is "ingress" or "tls" for a helper of the juistd on the
	// socket, and acmeDirectory the CA a terminator asks, whose own
	// certificate a CA of one's own has trusted by SSL_CERT_FILE.
	helper        string
	acmeDirectory string

	// maxConns and maxPerSource bound a helper's or service member's
	// connections, zero for its default.
	maxConns, maxPerSource int
}

// httpPort is where a device's terminator redirects plain HTTP to https.
const httpPort = 80

// runTerminator ends TLS for what serving says, and serves the status page
// statusPage says, listening by listen and listenPacket, nil for the host's,
// and redirecting
// plain HTTP on redirect, 0 for none, with certificates its CA issues by
// TLS-ALPN-01, kept in the home's certs.
func runTerminator(ctx context.Context, opts options, errOut io.Writer,
	serving func(context.Context, *ipc.TerminatorReport) (*ipc.Published, error),
	statusPage func(context.Context) (*ipc.StatusPage, error), listen func(network, addr string) (net.Listener, error),
	listenPacket func(network, addr string) (net.PacketConn, error), redirect uint16) error {
	certs := filepath.Join(opts.service.Home, "certs")
	if err := os.MkdirAll(certs, 0o700); err != nil {
		return err
	}
	logf := func(format string, a ...any) { fmt.Fprintf(errOut, format+"\n", a...) }
	return terminator.Serve(ctx, terminator.Options{
		Serving: serving, StatusPage: statusPage, Listen: listen, ListenPacket: listenPacket, HTTPPort: redirect,
		ACME: &acme.Client{DirectoryURL: opts.acmeDirectory}, Cache: autocert.DirCache(certs),
		MaxConns: opts.maxConns, Logf: logf,
	})
}

// withBinder is the root parent this helper was started by, if any, and ctx
// ended once that parent is gone.
func withBinder(ctx context.Context) (*binder, context.Context, context.CancelFunc, error) {
	b, gone, err := inheritedBinder()
	if err != nil || b == nil {
		return nil, ctx, func() {}, err
	}
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-gone:
			cancel()
		case <-ctx.Done():
		}
	}()
	return b, ctx, cancel, nil
}

// listenIngress binds port for the ingress, saying why it cannot.
func listenIngress(port uint16) (net.Listener, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	switch {
	case errors.Is(err, syscall.EADDRINUSE):
		return nil, fmt.Errorf("%w\nhint: another program serves port %d here", err, port)
	case errors.Is(err, syscall.EACCES):
		return nil, fmt.Errorf("%w\nhint: an ingress binds 443, 80 and the ports names are published on by TCP, which takes CAP_NET_BIND_SERVICE", err)
	}
	return ln, err
}

// listenIngressQUIC binds 443/udp for the ingress's QUIC.
func listenIngressQUIC() (*net.UDPConn, error) {
	pc, err := net.ListenPacket("udp", ":443")
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// runIngress serves the network's published names as its ingress, on 443
// and 80, QUIC on 443/udp, and the ports names are published on by TCP,
// each bound by listen, asking the juistd at socket what they are.
func runIngress(ctx context.Context, socket string, opts options, listen func(uint16) (net.Listener, error),
	listenQUIC func() (*net.UDPConn, error), errOut io.Writer) error {
	tlsLn, err := listen(443)
	if err != nil {
		return err
	}
	defer tlsLn.Close()
	httpLn, err := listen(80)
	if err != nil {
		return err
	}
	defer httpLn.Close()
	o := ingressOptions(socket, errOut)
	o.MaxConns, o.MaxPerSource, o.Listen, o.ListenQUIC = opts.maxConns, opts.maxPerSource, listen, listenQUIC
	return ingress.Serve(ctx, tlsLn, httpLn, o)
}

// ingressOptions has the ingress ask the juistd on socket, and say on errOut
// when it stops answering, which is why names go down, and each connection.
func ingressOptions(socket string, errOut io.Writer) ingress.Options {
	return ingress.Options{
		Published: func(ctx context.Context, r *ipc.IngressReport) (*ipc.Published, error) {
			return ipc.CallPublished(ctx, socket, r)
		},
		Logf:   func(format string, a ...any) { fmt.Fprintf(errOut, format+"\n", a...) },
		Access: func(format string, a ...any) { fmt.Fprintf(errOut, format+"\n", a...) },
	}
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
	tun := fs.String("tun", "juist0", `TUN device to create, "" for none; needs `+defaults.TunPrivilege)
	noRelay := fs.Bool("no-relay", false, "do not relay for other members, whatever the log grants")
	noDiscovery := fs.Bool("no-discovery", false, "do not announce or look for members on the LAN")
	noDHT := fs.Bool("no-dht", false, "do not use the public DHT, for members or invites")
	stunList := fs.String("stun", strings.Join(rendezvous.DefaultSTUN, ","), "public STUN servers, comma-separated")
	noSTUN := fs.Bool("no-stun", false, "ask no STUN server outside the network")
	ttl := fs.Duration("freshness-ttl", daemon.DefaultFreshnessTTL, "how long to trust the network's state unvouched")
	verbose := fs.Bool("verbose", false, "log what the daemon is doing")
	helper := fs.String("helper", "", `run as a helper of the juistd on --socket: ingress, or tls for what is published here`)
	var serve serveFlag
	fs.Var(&serve, "serve", "be a service member, on no device, ending TLS for NAME, @ for the domain itself, and sending it to ADDR, or passing it by TCP where published so, or serving status-page[:WHAT]; repeatable")
	http3 := fs.Bool("http3", false, "with --serve, offer clients HTTP/3 too, proxying each service's HTTP")
	members := fs.Bool("members", false, "with --serve, each service is for members alone: never served under a name the log has public")
	acmeDir := fs.String("acme", autocert.DefaultACMEDirectory, "the ACME directory TLS certificates are taken from")
	join := fs.String("join", "", "join the network LINK invites to once started, unless in one (default $JUIST_JOIN)")
	maxConns := fs.Uint("max-conns", 0, fmt.Sprintf("connections served at once: %d by an ingress, %d ending TLS, unless given",
		ingress.DefaultMaxConns, terminator.DefaultMaxConns))
	maxPerSource := fs.Uint("max-per-source", ingress.DefaultMaxPerSource,
		"connections an ingress takes from one address at once, 4 times that from its /24 or /48")
	for _, o := range optionOrder {
		cliflag.Short(fs, o.short, o.long)
	}
	if len(args) == 1 && args[0] == "__manpage" {
		if err := manpage(out, fs); err != nil {
			return options{}, err
		}
		return options{}, errHelp
	}
	args, err := cliflag.Check(fs, args)
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
	// Read here rather than as the flag's default, which --help would show.
	switch {
	case *helper != "" && cliflag.IsSet(fs, "join"):
		return options{}, fmt.Errorf("a helper joins no network\n%s", synopsis)
	case *helper == "" && !cliflag.IsSet(fs, "join"):
		*join = os.Getenv("JUIST_JOIN")
	}
	nop := func(string, ...any) {}
	if *helper != "" && *helper != "ingress" && *helper != "tls" {
		return options{}, fmt.Errorf("--helper is ingress or tls, not %q\n%s", *helper, synopsis)
	}
	switch {
	case cliflag.IsSet(fs, "max-conns") && *helper == "" && serve == nil:
		return options{}, fmt.Errorf("--max-conns is for a helper or a service member\n%s", synopsis)
	case cliflag.IsSet(fs, "max-per-source") && *helper != "ingress":
		return options{}, fmt.Errorf("--max-per-source is for an ingress\n%s", synopsis)
	case *maxConns > 1<<20 || *maxPerSource > 1<<20 || cliflag.IsSet(fs, "max-per-source") && *maxPerSource == 0:
		return options{}, fmt.Errorf("--max-conns and --max-per-source take 1 to %d\n%s", 1<<20, synopsis)
	}
	if serve != nil {
		if cliflag.IsSet(fs, "tun") || *helper != "" {
			return options{}, fmt.Errorf("a service member runs on no device and is no helper\n%s", synopsis)
		}
		*tun = ""
	}
	if (*http3 || *members) && serve == nil {
		return options{}, fmt.Errorf("--http3 and --members are for a service member, beside --serve\n%s", synopsis)
	}
	var serveMembers map[string]bool
	for label, to := range serve {
		if _, page := ipc.StatusPageOf(to); *http3 && !page {
			serve[label] = ipc.HTTP3To(to)
		}
		if *members {
			if serveMembers == nil {
				serveMembers = map[string]bool{}
			}
			serveMembers[label] = true
		}
	}
	// systemd starts the terminator by this file (juist-serve.path), which
	// ends TLS for the default instance alone.
	wanted, ingressPorts := "", ""
	if runtime.GOOS == "linux" && n == 0 && serve == nil && *helper == "" {
		dir := filepath.Dir(cmp.Or(*socket, ipc.SocketPath(*home)))
		wanted = filepath.Join(dir, filepath.Base(ipc.TerminatorWanted))
		ingressPorts = filepath.Join(dir, filepath.Base(ipc.IngressPorts))
	}
	return options{verbose: *verbose, helper: *helper, acmeDirectory: *acmeDir,
		maxConns: int(*maxConns), maxPerSource: int(*maxPerSource),
		service: daemon.ServiceOptions{ServeTo: serve, ServeMembers: serveMembers, Join: *join,
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
				TerminatorWanted: wanted,
				IngressPorts:     ingressPorts,
				ACMEDirectory:    *acmeDir,
				Netstack:         serve != nil,
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
	{'v', "verbose", ""}, {'S', "serve", "NAME=ADDR"}, {'3', "http3", ""}, {'O', "members", ""}, {'j', "join", "LINK"}, {'I', "helper", "KIND"}, {'A', "acme", "URL"},
	{'M', "max-conns", "N"}, {'m', "max-per-source", "N"},
}

// help lists the options of fs with their defaults.
func help(fs *flag.FlagSet) string {
	var b strings.Builder
	b.WriteString("Usage: juistd [options]\n\nRun a juist node: the membership log in, the WireGuard mesh out.\n\nOptions:\n")
	for _, o := range optionOrder {
		f := fs.Lookup(o.long)
		label, _ := cliflag.Label(fs, f)
		text, def := f.Usage, f.DefValue
		if d, err := time.ParseDuration(def); err == nil && def != "0" {
			def = shortDuration(d)
		}
		if def != "" && def != "false" && def != "0" {
			text += " (default " + def + ")"
		}
		fmt.Fprintf(&b, "  %-22s %s\n", strings.TrimSpace(label+" "+o.arg), text)
	}
	fmt.Fprintf(&b, "  %-22s %s\n", "-h, --help", "show this help")
	b.WriteString("\nDefault ports in use become OS-chosen; an instance adds ten times its number to each, and names its device.\n")
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
	if h := st.HTTPS; h != nil && h.Only {
		field("https only", "by %s on 443", map[bool]string{true: "1 relay", false: fmt.Sprintf("%d relays", len(h.Relays))}[len(h.Relays) == 1])
	} else {
		field("data plane", "udp/%d", st.ListenPort)
	}
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
	if st.Disabled != "" {
		warn("the network was ended with a break-glass secret; tunnels are down for good")
	}
	if st.StartError != "" {
		warn("tunnels cannot start yet, retrying: %s", st.StartError)
		if tun != "" && strings.Contains(st.StartError, iofs.ErrPermission.Error()) {
			hint(permHint, tun)
		}
	}
}

// serveFlag is --serve, by label: where a service member sends each name,
// "@" naming the domain itself.
type serveFlag map[string]string

func (f *serveFlag) String() string { return "" }

func (f *serveFlag) Set(v string) error {
	name, addr, _ := strings.Cut(v, "=")
	label := name
	if name == "@" {
		label = ""
	}
	if t := (ipc.ServeTo{Label: label, To: addr}); name == "" || !t.Valid() {
		return fmt.Errorf("%q is no NAME=ADDR, such as immich=immich-server:2283", v)
	}
	name = label
	if *f == nil {
		*f = serveFlag{}
	}
	(*f)[name] = addr
	return nil
}

// onNoDevice reports whether args run juistd where it plumbs no device: as a
// helper, or as a service member, which then needs no helper of its own.
func onNoDevice(args []string) bool {
	for _, a := range args {
		name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if strings.HasPrefix(a, "-") && (name == "helper" || name == "I" || name == "serve" || name == "S") {
			return true
		}
	}
	return false
}
