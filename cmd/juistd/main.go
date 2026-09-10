// Command juistd runs a juist node: it holds the membership log this device
// was enrolled into, keeps a WireGuard peer for every member the log
// authorizes and nobody else, finds them with blinded LAN discovery, and keeps
// its log in step by gossip. There is no coordination server to configure.
//
// It creates a real TUN device and programs the host's routes, which needs
// /dev/net/tun and CAP_NET_ADMIN; pass -tun "" to run without one. It holds no
// admin signing keys and cannot authorize a membership change, so an attacker
// who owns this process owns one member rather than the network.
//
//	juistd [-home DIR] [-port N] [-gossip-port N] [-tun NAME] [-no-discovery]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	iofs "io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/nning/juist/daemon"
)

const usage = `juistd runs a juist node: log state in, WireGuard mesh out.

Usage:
  juistd [flags]

Flags:
  -home DIR        state directory (default $JUIST_HOME, or ~/.config/juist)
  -port N          UDP port for the data plane (default: chosen by the OS)
  -gossip-port N   TCP port for log sync (default: chosen by the OS)
  -tun NAME        OS TUN device to create (default "juist0"; "" for none).
                   Creating it needs /dev/net/tun and CAP_NET_ADMIN.
  -relay-port N    TCP and UDP port for this node's relay, used only where the
                   log grants it the relay-capable role (default: OS-chosen)
  -no-relay        do not relay for other members, whatever the log grants
  -no-discovery    do not announce or look for members on the LAN
  -no-dht          do not use the public DHT to find members that are on no
                   LAN this node can see and at no address it has cached
  -verbose         log what the daemon is doing

The device must already have been enrolled: juistd never creates a network and
never joins one on its own. Run "juist key -create" to generate this device's
keys, give them to an admin, and apply the record they send back.
`

func main() {
	err := run(os.Args[1:])
	switch {
	case err == nil, errors.Is(err, errHelp), errors.Is(err, context.Canceled):
		return
	case errors.Is(err, errSilent):
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "juistd: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("juistd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	home := fs.String("home", defaultHome(), "state directory")
	port := fs.Uint("port", 0, "UDP port for the data plane")
	gossipPort := fs.Uint("gossip-port", 0, "TCP port for log sync")
	tun := fs.String("tun", "juist0", `OS TUN device to create ("" for none)`)
	relayPort := fs.Uint("relay-port", 0, "TCP/UDP port for this node's relay, when the log grants it the role")
	noRelay := fs.Bool("no-relay", false, "do not relay for other members, whatever the log grants")
	noDiscovery := fs.Bool("no-discovery", false, "do not use LAN discovery")
	noDHT := fs.Bool("no-dht", false, "do not use the public DHT to find members off the LAN")
	verbose := fs.Bool("verbose", false, "log what the daemon is doing")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return errHelp
		}
		return errSilent
	}
	if *port > 0xffff || *gossipPort > 0xffff || *relayPort > 0xffff {
		return errors.New("a port must be below 65536")
	}

	logf := func(string, ...any) {}
	if *verbose {
		logf = func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }
	}

	node, err := openNode(*home)
	if err != nil {
		return err
	}

	d, err := daemon.New(daemon.Options{
		Authority:         node.authority,
		Storage:           node.storage,
		Identity:          node.identity,
		Recipient:         node.recipient,
		WireGuard:         node.wireguard,
		ListenPort:        uint16(*port),
		TunName:           *tun,
		GossipPort:        uint16(*gossipPort),
		RelayPort:         uint16(*relayPort),
		DisableRelay:      *noRelay,
		DisableDiscovery:  *noDiscovery,
		DisableDHT:        *noDHT,
		SocketPath:        daemon.SocketPath(*home),
		EndpointCachePath: daemon.EndpointCachePath(*home),
		Logf:              logf,
	})
	if err != nil {
		// Both ways out, because which one is right depends on whether this
		// is a deployment or someone trying the thing.
		if *tun != "" && errors.Is(err, iofs.ErrPermission) {
			return fmt.Errorf("%w\n\n"+
				"creating the %q device needs CAP_NET_ADMIN: grant it with "+
				"\"setcap cap_net_admin+ep\" on this binary, run it under "+
				"packaging/systemd/juistd.service, or pass -tun \"\" to run "+
				"without a device as M2 did", err, *tun)
		}
		return err
	}
	defer d.Close()

	// The banner prints before Run's first reconcile, so reconcile once here
	// or the summary shows a fresh daemon's empty state. Run's own first
	// reconcile is then a no-op.
	if err := d.Reconcile(); err != nil {
		logf("juistd: initial reconcile: %v", err)
	}

	st := d.Status()
	fmt.Printf("juistd: network %q (%v)\n", st.NetworkName, st.Network)
	fmt.Printf("  this node   %v\n", st.Self.ShortString())
	for _, a := range st.Addrs {
		fmt.Printf("  overlay     %v\n", a.Addr())
	}
	if *tun == "" {
		fmt.Printf("  device      none (overlay not plumbed into the host stack)\n")
	} else {
		fmt.Printf("  device      %s\n", *tun)
	}
	fmt.Printf("  data plane  udp/%d\n", st.ListenPort)
	fmt.Printf("  log sync    tcp/%d\n", st.GossipPort)
	fmt.Printf("  control     %s\n", daemon.SocketPath(*home))
	fmt.Printf("  members     %d\n", st.Members)
	if st.Relaying {
		fmt.Printf("  relaying    yes (this node's uplink carries traffic for members that cannot punch)\n")
	}
	if st.RelayCapable < 2 {
		fmt.Printf("  relays      %d granted; below two there is no fallback when one is offline\n",
			st.RelayCapable)
	}
	if st.SchemaAlarm != "" {
		fmt.Printf("  ALARM       %s\n", st.SchemaAlarm)
	}
	if st.Alarm != "" {
		fmt.Printf("  ALARM       %s\n", st.Alarm)
	}

	// SIGINT and SIGTERM stop the loop; everything the daemon owns is torn
	// down by the deferred Close, including the control socket.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return d.Run(ctx)
}

// errSilent reports a failure the flag package has already explained; errHelp
// reports that help was asked for and given, which is a success.
var (
	errSilent = silentError{}
	errHelp   = silentError{help: true}
)

type silentError struct{ help bool }

func (silentError) Error() string { return "" }

func defaultHome() string {
	if v := os.Getenv("JUIST_HOME"); v != "" {
		return v
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "juist")
	}
	return ".juist"
}
