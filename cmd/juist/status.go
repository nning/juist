package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"strconv"
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
		return parseResult(err)
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
	if s.Relays > 0 || s.Relaying || s.RelayCapable > 0 {
		line := fmt.Sprintf("relays       %d of %d granted", s.Relays, s.RelayCapable)
		if s.Relaying {
			line += ", including this node"
		}
		fmt.Println(line)
	}
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
	if s.DataPlaneError != "" {
		fmt.Printf("\nWARNING: the data plane did not take the peer set: %s\n", s.DataPlaneError)
	}
	// The floor docs/04-architecture.md sets. It is not a capacity model:
	// relay demand tracks the number of pairs that cannot be punched, which
	// nothing here measures. One relay is a network that loses its fallback
	// path whenever that member is off.
	if s.RelayCapable < 2 && !s.NotMember && s.Alarm == "" {
		fmt.Printf("\nNOTE: this network has %d relay-capable member(s).\n", s.RelayCapable)
		fmt.Printf("Two members that cannot punch through their NATs need a third to relay,\n")
		fmt.Printf("and below two there is no fallback when one is offline. Grant the role\n")
		fmt.Printf("with \"juist propose set-routes -identity nid:… -roles relay-capable\"\n")
		fmt.Printf("on a member with a public address.\n")
	}
	if s.SchemaAlarm != "" {
		fmt.Printf("\nALARM: %s\n", s.SchemaAlarm)
		fmt.Printf("This device still holds the state from before that record and still\n")
		fmt.Printf("carries traffic, but it will apply nothing further — including removals.\n")
	}
	if s.Alarm != "" {
		fmt.Printf("\nALARM: %s\n", s.Alarm)
		fmt.Printf("No peers are configured while this is unresolved.\n")
	}
}

// describeCallFailure turns "the socket did not answer" into the three
// situations it actually is. They need different responses, and the syscall
// error distinguishes them but says so in a way that reads like a bug.
func describeCallFailure(h *home, err error) error {
	sock := daemon.SocketPath(h.path)
	if noDaemon(err) {
		return fmt.Errorf("no daemon is running on %s (no control socket at %s)", h.path, sock)
	}
	if errors.Is(err, fs.ErrPermission) {
		msg := fmt.Sprintf("not permitted to reach the daemon at %s: it answers only the user it "+
			"runs as, which is not you", sock)
		if owner := stateDirOwner(h.path); owner != "" {
			msg += fmt.Sprintf(".\nRun: sudo -u %s juist -home %s status", owner, h.path)
		}
		return errors.New(msg)
	}
	return fmt.Errorf("talking to the daemon at %s: %w", sock, err)
}

// stateDirOwner names the account a daemon on this home directory runs as, or
// "" if that cannot be established. It reads the directory rather than the
// socket: the socket is what the caller was just refused.
func stateDirOwner(dir string) string {
	info, err := os.Stat(dir)
	if err != nil {
		return ""
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	uid := strconv.FormatUint(uint64(st.Uid), 10)
	if u, err := user.LookupId(uid); err == nil {
		return u.Username
	}
	return uid
}

// noDaemon reports whether a failed call means nothing is listening. Only two
// errors mean absence: no socket file, and a socket file nobody is bound to,
// which is what a crashed daemon leaves behind.
func noDaemon(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
}

// daemonState reports whether a daemon owns this home directory's log, by
// connecting rather than by looking for the file, since a crashed daemon
// leaves one behind. The answer is three-way because "present but silent" is
// not "absent": a wedged daemon still owns its in-memory authority, and
// writing the log underneath it is the split brain this prevents.
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
