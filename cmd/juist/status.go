package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"time"

	"github.com/nning/juist/daemon"
)

func cmdStatus(h *home, args []string) error {
	fs := flag.NewFlagSet("juist status", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: juist status

Asks the local daemon what state it is in: which network, where its chain is,
how many members the log carries, and how many of them it currently has a
WireGuard peer for.

The gap between those last two is the normal shape of a mesh coming up: a
member the log carries but that has not been heard from yet is counted as
unreachable, not as denied.
`)
	}
	if err := fs.Parse(args); err != nil {
		return errSilent
	}
	resp, err := daemon.Call(daemon.SocketPath(h.path), daemon.Request{Command: daemon.CmdStatus})
	if err != nil {
		return describeCallFailure(h, err)
	}
	printStatus(resp.Status)
	return nil
}

func printStatus(s *daemon.Status) {
	if s == nil {
		// A well-formed reply always carries one of Status or Err, and Err is
		// turned into an error before this is reached. A reply with neither is
		// a daemon that does not speak this protocol version.
		fmt.Fprintln(os.Stderr, "the daemon replied without a status; it may be a different version")
		return
	}
	fmt.Printf("network      %s (%v)\n", s.NetworkName, s.Network)
	fmt.Printf("this node    %v\n", s.Self.ShortString())
	for _, a := range s.Addrs {
		fmt.Printf("overlay      %v\n", a.Addr())
	}
	fmt.Printf("head         %v\n", s.Head)
	fmt.Printf("epoch        %d\n", s.Epoch)
	fmt.Printf("members      %d\n", s.Members)
	fmt.Printf("peers up     %d\n", s.Peers)
	if s.Unreachable > 0 {
		fmt.Printf("unreachable  %d (members this node has not heard from yet)\n", s.Unreachable)
	}
	if s.Conflicted > 0 {
		fmt.Printf("conflicted   %d (members announcing a NAT-traversal key another member claims)\n",
			s.Conflicted)
	}
	fmt.Printf("data plane   udp/%d\n", s.ListenPort)
	fmt.Printf("log sync     tcp/%d\n", s.GossipPort)
	if s.LastReconcile > 0 {
		fmt.Printf("reconciled   %s ago\n",
			time.Since(time.Unix(s.LastReconcile, 0)).Round(time.Second))
	}
	if s.NotMember {
		fmt.Printf("\nWARNING: this device is not in the member set (removed, or past its expiry).\n")
		fmt.Printf("Its tunnels are down. Rejoining takes an admin enrolling it again.\n")
	}
	if s.StaleKeys {
		fmt.Printf("\nWARNING: the log names different keys for this device than the daemon holds.\n")
		fmt.Printf("A key rotation was applied while it ran; restart juistd to pick up the promoted keys.\n")
	}
	if s.EpochError != "" {
		fmt.Printf("\nWARNING: this node cannot open the current group secret: %s\n", s.EpochError)
		fmt.Printf("It keeps its tunnels but is cut off from discovery and log sync.\n")
	}
	if s.Alarm != "" {
		fmt.Printf("\nALARM: %s\n", s.Alarm)
		fmt.Printf("No peers are configured while this is unresolved.\n")
	}
}

// describeCallFailure turns "the socket did not answer" into the two
// situations it actually is. They need different responses, and the syscall
// error distinguishes them but says so in a way that reads like a bug.
func describeCallFailure(h *home, err error) error {
	if noDaemon(err) {
		return fmt.Errorf("no daemon is running on %s (no control socket at %s)",
			h.path, daemon.SocketPath(h.path))
	}
	return fmt.Errorf("talking to the daemon at %s: %w", daemon.SocketPath(h.path), err)
}

// noDaemon reports whether a failed call means there is nothing listening, as
// opposed to something listening that did not answer.
//
// Only two errors mean absence: no socket file, and a socket file nobody is
// bound to — what a crashed daemon leaves behind. Everything else is a daemon
// that is present and did not reply.
func noDaemon(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
}

// daemonState reports whether a daemon owns this home directory's log.
//
// It answers by connecting, not by looking for the file: a socket left behind
// by a daemon that crashed is still a file, and treating it as a running
// daemon would send records into a void.
//
// The three-way answer matters because the caller is deciding who writes the
// log. "Present but silent" is not "absent": a daemon whose IPC slots are all
// held, or that is wedged past the deadline, fails this probe while still
// owning its in-memory authority — and writing the log underneath it is
// exactly the split brain the probe exists to prevent. So that case is an
// error rather than a licence to write.
func daemonState(h *home) (running bool, err error) {
	if _, err := daemon.Call(daemon.SocketPath(h.path), daemon.Request{Command: daemon.CmdStatus}); err != nil {
		if noDaemon(err) {
			return false, nil
		}
		return false, fmt.Errorf(
			"a daemon appears to be running on %s but did not answer: %w\n"+
				"Refusing to write the log underneath it, which would leave the two disagreeing "+
				"about the head. Stop juistd and retry, or wait for it to answer",
			h.path, err)
	}
	return true, nil
}
