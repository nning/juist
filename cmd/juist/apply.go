package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nning/juist/daemon"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

func cmdApply(h *home, args []string) error {
	fs := flag.NewFlagSet("juist apply", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: juist apply FILE...

Applies records to the local log, oldest first. Either the whole set applies or
none of it does, and a record is applied only if the log finds it authorized —
signing a record does not make it valid, and this tool has no way to make the
log accept one that is not.

Applied to a home directory with no network yet, a fully signed genesis record
creates the network: that is how a k-of-n genesis ceremony finishes, since the
record has to travel to the other admins to be signed at all.
`)
	}
	if err := fs.Parse(args); err != nil {
		return parseResult(err)
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return errSilent
	}
	st, auth, haveNetwork, err := h.openAuthorityAllowingNone()
	if err != nil {
		return err
	}
	records := make([]types.AUM, 0, fs.NArg())
	for _, path := range fs.Args() {
		aum, err := readRecordFile(path)
		if err != nil {
			return err
		}
		records = append(records, aum)
	}
	if !haveNetwork {
		return createFromGenesis(h, st, records)
	}
	// A running daemon owns the log: a second writer would leave the two
	// disagreeing about the head. Handing the records over also gets them
	// gossiped immediately.
	running, err := daemonState(h)
	if err != nil {
		return err
	}
	if running {
		return applyThroughDaemon(h, records)
	}
	before := auth.Head()
	if err := auth.Inform(records...); err != nil {
		return err
	}
	if err := h.promoteIfAdopted(auth); err != nil {
		return err
	}
	state := auth.State()
	fmt.Printf("applied %d record(s)\n", len(records))
	fmt.Printf("  head   %v (was %v)\n", state.Head(), before)
	fmt.Printf("  epoch  %d\n", state.Epoch())
	fmt.Printf("  members %d\n", len(state.Nodes()))
	if alarm := auth.Alarm(); alarm != nil {
		fmt.Printf("\nALARM: %v\n", alarm)
	}
	return nil
}

// applyThroughDaemon hands records to the running daemon, which applies them
// to the log it owns and pushes them to every member it can reach. Not a
// privileged call: the daemon cannot make an unauthorized record apply.
func applyThroughDaemon(h *home, records []types.AUM) error {
	bodies := make([][]byte, 0, len(records))
	for i := range records {
		b, err := records[i].Encode()
		if err != nil {
			return err
		}
		bodies = append(bodies, b)
	}
	resp, err := daemon.Call(daemon.SocketPath(h.path),
		daemon.Request{Command: daemon.CmdInform, Records: bodies})
	if err != nil {
		if resp.Err != "" {
			// The daemon answered and refused, so nothing was applied on
			// either side. Reporting it as a transport failure would send the
			// operator to the socket instead of to the record.
			return fmt.Errorf("the daemon refused the records: %s", resp.Err)
		}
		return describeCallFailure(h, err)
	}
	// Promotion is this tool's job either way: the daemon never reads staged
	// keys, so skipping it would leave the device holding old keys while the
	// log names new ones. The log is re-read rather than reused, since the
	// copy from before the call says the rotation never happened.
	_, auth, haveNetwork, err := h.openAuthorityAllowingNone()
	if err != nil {
		return err
	}
	fmt.Printf("handed %d record(s) to the daemon\n", len(records))
	printStatus(resp.Status)
	if haveNetwork {
		if err := h.promoteIfAdopted(auth); err != nil {
			return err
		}
	}
	return nil
}

// createFromGenesis completes a genesis ceremony whose record collected the
// rest of its quorum elsewhere. It is the only way a k-of-n network can be
// created: no single machine holds k keys.
func createFromGenesis(h *home, st *store.Dir, records []types.AUM) error {
	if len(records) != 1 || records[0].Kind != types.KindGenesis {
		return fmt.Errorf("%s holds no network; only a signed genesis record can create one. "+
			"Start a network with \"juist init\", or join one by being enrolled by an admin",
			h.join(logDir))
	}
	genesis := records[0]
	// Report a ceremony that is merely unfinished as such, rather than as a
	// broken record: the two look identical from an error string.
	status, err := log.GenesisStatus(&genesis)
	if err != nil {
		return err
	}
	if !status.Authorized() {
		return fmt.Errorf(
			"this genesis record carries %d of %d vote weight; it needs %d more before it creates a network. "+
				"Have the remaining admins run \"juist sign\" on it",
			status.Votes, status.Quorum, missing(status))
	}
	auth, err := log.Create(st, genesis)
	if err != nil {
		return err
	}
	state := auth.State()
	fmt.Printf("created network %q\n", state.Network())
	fmt.Printf("  genesis      %v\n", state.GenesisHash())
	fmt.Printf("  overlay      %v\n", state.ULA())
	fmt.Printf("  quorum       %d of %d votes\n", state.Quorum(), state.TotalVotes())
	for _, n := range state.Nodes() {
		fmt.Printf("  member       %s %v\n", n.Name, state.Addr6(n.Identity))
	}
	return nil
}

// promoteIfAdopted makes staged key material live, but only once the log names
// it. The decision is in [keys.MaybePromoteStaged], shared with juistd, which
// runs it at startup for rotations that arrive over gossip.
func (h *home) promoteIfAdopted(auth *log.Authority) error {
	promoted, err := keys.MaybePromoteStaged(h.path, auth.State().Node)
	if err != nil {
		return err
	}
	if promoted != nil {
		fmt.Printf("  promoted this device's staged keys; the log now names them\n")
	}
	return nil
}
