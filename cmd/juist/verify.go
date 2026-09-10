package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
)

func cmdVerify(h *home, args []string) error {
	fs := flag.NewFlagSet("juist verify", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: juist verify [FILE...]

With no arguments, re-verifies the stored log from the anchor: every record's
signatures, every rule, the fork analysis, and — if this device is a member —
that it can still open the current epoch's group secret.

With files, reports what each record still needs and whether it would apply,
without applying anything.
`)
	}
	if err := fs.Parse(args); err != nil {
		return parseResult(err)
	}

	st, auth, err := h.openAuthority()
	if err != nil {
		return err
	}
	state := auth.State()
	chain, err := auth.Chain()
	if err != nil {
		return err
	}
	floor, err := st.EpochFloor()
	if err != nil {
		return err
	}

	fmt.Printf("network      %s\n", state.Network())
	fmt.Printf("genesis      %v\n", state.GenesisHash())
	fmt.Printf("anchor       %v\n", auth.Anchor())
	fmt.Printf("head         %v\n", state.Head())
	fmt.Printf("chain        %d record(s) verified from the anchor\n", len(chain))
	fmt.Printf("epoch        %d (floor %d)\n", state.Epoch(), floor)
	fmt.Printf("quorum       %d of %d votes\n", state.Quorum(), state.TotalVotes())
	fmt.Printf("members      %d\n", len(state.Nodes()))
	unreachable, err := auth.Unreachable()
	if err != nil {
		return err
	}
	if unreachable > 0 {
		fmt.Printf("unreachable  %d stored record(s) the anchor cannot reach (removed by the next compaction)\n",
			unreachable)
	}
	for _, o := range auth.Orphans() {
		if o.Conflict == "" {
			fmt.Printf("orphan       branch at %v (%d record(s)) lost fork choice; reissue it against the head\n",
				o.Root, len(o.Records))
		}
	}
	if alarm := auth.Alarm(); alarm != nil {
		fmt.Printf("\nALARM: %v\n", alarm)
	} else {
		fmt.Printf("state        ok\n")
	}

	// Checking that this device can open the group secret is not a formality:
	// nothing in the log can prove a wrap was sealed to the right key, so the
	// only place that is discovered is here.
	if err := h.checkGroupSecret(state); err != nil {
		fmt.Printf("group secret UNREADABLE: %v\n", err)
	}

	for _, path := range fs.Args() {
		fmt.Println()
		aum, err := readRecordFile(path)
		if err != nil {
			return err
		}
		fmt.Printf("%s: %v record\n", path, aum.Kind)
		if aum.Prev != nil && *aum.Prev != state.Head() {
			fmt.Printf("  parent %v is not the current head; it would fork the chain\n", *aum.Prev)
		}
		reportStatus(path, &aum, auth)
		if _, err := log.NewBuilder(state).Dry(&aum); err != nil {
			fmt.Printf("  would not apply: %v\n", err)
		} else {
			fmt.Printf("  would apply cleanly to the current head\n")
		}
	}
	return nil
}

// checkGroupSecret opens this device's wrap of the current epoch secret, if
// this device is a member.
func (h *home) checkGroupSecret(state *log.State) error {
	k, err := h.nodeKeys()
	if keys.Missing(err) {
		return nil // not a member device; nothing to check
	}
	if err != nil {
		return fmt.Errorf("reading this device's keys: %w", err)
	}
	if !state.IsMember(k.Identity.Public()) {
		return nil
	}
	if _, err := secrets.Open(state.EpochRecord(), k.Identity.Public(), k.Recipient); err != nil {
		return err
	}
	fmt.Printf("group secret readable by this device\n")
	return nil
}
