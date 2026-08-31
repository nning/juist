package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nning/juist/types"
)

func cmdLog(h *home, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(os.Stderr, "Usage: juist log show [flags]\n")
		return errSilent
	}
	switch args[0] {
	case "show":
		return cmdLogShow(h, args[1:])
	default:
		return fmt.Errorf("unknown log subcommand %q", args[0])
	}
}

func cmdLogShow(h *home, args []string) error {
	fs := flag.NewFlagSet("juist log show", flag.ContinueOnError)
	records := fs.Bool("records", false, "list the chain's records instead of the state")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: juist log show [-records]

Prints the current membership state, or with -records the chain from the anchor
to the head.
`)
	}
	if err := fs.Parse(args); err != nil {
		return errSilent
	}
	st, auth, err := h.openAuthority()
	if err != nil {
		return err
	}
	state := auth.State()

	if *records {
		chain, err := auth.Chain()
		if err != nil {
			return err
		}
		for i, hash := range chain {
			aum, err := st.AUM(hash)
			if err != nil {
				return err
			}
			signers := make([]string, 0, len(aum.Signatures))
			for _, s := range aum.Signatures {
				signers = append(signers, s.KeyID.ShortString())
			}
			fmt.Printf("%4d  %-16v %v\n", i, aum.Kind, hash)
			fmt.Printf("      signed by %s\n", strings.Join(signers, ", "))
			if aum.Epoch != nil {
				fmt.Printf("      epoch %d, sealed to %d member(s)\n", aum.Epoch.Epoch, len(aum.Epoch.Wraps))
			}
			if aum.Subject != nil {
				fmt.Printf("      subject %v\n", *aum.Subject)
			}
		}
		return nil
	}

	fmt.Printf("network %s\n", state.Network())
	fmt.Printf("overlay %v\n", state.ULA())
	fmt.Printf("head    %v\n", state.Head())
	fmt.Printf("epoch   %d\n", state.Epoch())
	fmt.Printf("quorum  %d of %d votes\n", state.Quorum(), state.TotalVotes())

	fmt.Printf("\nadmin keys (%d)\n", len(state.Admins()))
	for _, a := range state.Admins() {
		name := a.Name
		if name == "" {
			name = "(unnamed)"
		}
		fmt.Printf("  %-20s %v  %d vote(s)\n", name, a.Public, a.Votes)
	}

	nodes := state.Nodes()
	fmt.Printf("\nmembers (%d)\n", len(nodes))
	for i := range nodes {
		n := &nodes[i]
		name := n.Name
		if name == "" {
			name = "(unnamed)"
		}
		fmt.Printf("  %-20s %v\n", name, n.Identity)
		for _, pfx := range state.Addrs(n.Identity) {
			fmt.Printf("    addr    %v\n", pfx)
		}
		if len(n.Roles) > 0 {
			fmt.Printf("    roles   %s\n", joinRoles(n.Roles))
		}
		for _, r := range n.Routes {
			fmt.Printf("    route   %v\n", r)
		}
		if n.Expiry != 0 {
			fmt.Printf("    expiry  %d\n", n.Expiry)
		}
	}

	if relays := state.NodesWithRole(types.RoleRelayCapable); len(relays) < 2 {
		// docs/02-threat-model.md, residual weakness 4: a network with no
		// relay-capable member and hard NAT on every side cannot form.
		fmt.Printf("\nwarning: %d relay-capable member(s); with fewer than two, "+
			"members behind hard NAT may be unable to connect\n", len(relays))
	}
	if alarm := auth.Alarm(); alarm != nil {
		fmt.Printf("\nALARM: %v\n", alarm)
	}
	for _, o := range auth.Orphans() {
		if o.Conflict == "" {
			fmt.Printf("\norphaned branch at %v (%d record(s)): lost fork choice, reissue against the head\n",
				o.Root, len(o.Records))
		}
	}
	return nil
}

func joinRoles(roles []types.Role) string {
	parts := make([]string, len(roles))
	for i, r := range roles {
		parts[i] = string(r)
	}
	return strings.Join(parts, ", ")
}
