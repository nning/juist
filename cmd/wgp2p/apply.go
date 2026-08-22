package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nning/wg-p2p/trust/log"
	"github.com/nning/wg-p2p/trust/store"
	"github.com/nning/wg-p2p/types"
)

func cmdApply(h *home, args []string) error {
	fs := flag.NewFlagSet("wgp2p apply", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: wgp2p apply FILE...

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
		return errSilent
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

// createFromGenesis completes a genesis ceremony: the record left this machine
// unsigned or under-signed, collected the rest of its quorum elsewhere, and has
// come back.
//
// It is the only way a k-of-n network can be created at all. The whole point of
// the threshold is that no single machine holds k keys, so the record cannot be
// authorized where it is built.
func createFromGenesis(h *home, st *store.Dir, records []types.AUM) error {
	if len(records) != 1 || records[0].Kind != types.KindGenesis {
		return fmt.Errorf("%s holds no network; only a signed genesis record can create one. "+
			"Start a network with \"wgp2p init\", or join one by being enrolled by an admin",
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
				"Have the remaining admins run \"wgp2p sign\" on it",
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

// promoteIfAdopted makes staged key material live, but only once the log
// actually names it.
//
// The test is on the resulting state, not on which record kinds were in the
// batch. A rotation record can be authorized and still not be applied: it can
// lose fork choice to a sibling, in which case the log still names the old
// keys. Promoting on "the batch contained a rotation" would then leave the
// device holding keys nobody has agreed to — unable to handshake, unable to
// read the group secret, and with nothing to point at.
func (h *home) promoteIfAdopted(auth *log.Authority) error {
	staged, err := h.stagedNodeKeys()
	if keyFileMissing(err) {
		return nil // nothing staged
	}
	if err != nil {
		return err
	}
	member, ok := auth.State().Node(staged.identity.Public())
	if !ok {
		return nil
	}
	if member.WireGuard != staged.public.WireGuard ||
		member.X25519 != staged.public.X25519 ||
		member.MLKEM != staged.public.MLKEM {
		return nil
	}
	if err := h.promoteStagedNodeKeys(); err != nil {
		return err
	}
	fmt.Printf("  promoted this device's staged keys; the log now names them\n")
	return nil
}
