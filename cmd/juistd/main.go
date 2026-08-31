// Command juistd runs a juist node.
//
// It holds the membership log this device was enrolled into, keeps a
// WireGuard peer for every member the log authorizes and nobody else, finds
// those members on the local network with blinded discovery, and keeps its log
// in step with theirs by gossip. There is no coordination server to configure
// and none to reach: everything it needs is the state directory and the LAN.
//
// M2 is a LAN milestone (docs/05-roadmap.md), so there is no NAT traversal
// beyond the local segment, no relays and no DHT cold start. Those arrive at
// M3 and none of them changes what this program trusts.
//
// # What it does not hold
//
// Admin signing keys. The daemon cannot authorize a membership change, only
// apply one that a quorum already signed — which is why handing it a record
// over its control socket is not a privileged operation, and why an attacker
// who owns this process owns one member rather than the network
// (docs/04-architecture.md, key custody).
//
//	juistd [-home DIR] [-port N] [-gossip-port N] [-no-discovery]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
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
  -no-discovery    do not announce or look for members on the LAN
  -verbose         log what the daemon is doing

The device must already have been enrolled: juistd never creates a network and
never joins one on its own. Run "juist key -create" to generate this device's
keys, give them to an admin, and apply the record they send back.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		if !errors.Is(err, context.Canceled) {
			fmt.Fprintf(os.Stderr, "juistd: %v\n", err)
			os.Exit(1)
		}
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("juistd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	home := fs.String("home", defaultHome(), "state directory")
	port := fs.Uint("port", 0, "UDP port for the data plane")
	gossipPort := fs.Uint("gossip-port", 0, "TCP port for log sync")
	noDiscovery := fs.Bool("no-discovery", false, "do not use LAN discovery")
	verbose := fs.Bool("verbose", false, "log what the daemon is doing")
	if err := fs.Parse(args); err != nil {
		return errSilent
	}
	if *port > 0xffff || *gossipPort > 0xffff {
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
		Authority:        node.authority,
		Storage:          node.storage,
		Identity:         node.identity,
		Recipient:        node.recipient,
		WireGuard:        node.wireguard,
		ListenPort:       uint16(*port),
		GossipPort:       uint16(*gossipPort),
		DisableDiscovery: *noDiscovery,
		SocketPath:       daemon.SocketPath(*home),
		Logf:             logf,
	})
	if err != nil {
		return err
	}
	defer d.Close()

	// The banner is the operator's first look at what this daemon holds, and
	// it is printed before Run's loop does its first reconcile. Reconcile
	// once here, so the summary counts the members the log carries rather
	// than showing the empty state a fresh daemon holds. Run reconciles
	// again as its first act; the second pass is a no-op.
	if err := d.Reconcile(); err != nil {
		logf("juistd: initial reconcile: %v", err)
	}

	st := d.Status()
	fmt.Printf("juistd: network %q (%v)\n", st.NetworkName, st.Network)
	fmt.Printf("  this node   %v\n", st.Self.ShortString())
	for _, a := range st.Addrs {
		fmt.Printf("  overlay     %v\n", a.Addr())
	}
	fmt.Printf("  data plane  udp/%d\n", st.ListenPort)
	fmt.Printf("  log sync    tcp/%d\n", st.GossipPort)
	fmt.Printf("  control     %s\n", daemon.SocketPath(*home))
	fmt.Printf("  members     %d\n", st.Members)
	if st.Alarm != "" {
		fmt.Printf("  ALARM       %s\n", st.Alarm)
	}

	// SIGINT and SIGTERM stop the loop; everything the daemon owns is torn
	// down by the deferred Close, including the control socket.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return d.Run(ctx)
}

var errSilent = silentError{}

type silentError struct{}

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
