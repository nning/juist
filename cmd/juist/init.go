package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

// numDisablementSecrets is how many break-glass preimages the genesis ceremony
// commits to. Tailnet lock commits about ten
// (docs/research/building-blocks.md); the number only has to be large enough
// that losing any one of them does not matter.
const numDisablementSecrets = 10

func cmdInit(h *home, args []string) error {
	fs := flag.NewFlagSet("juist init", flag.ContinueOnError)
	network := fs.String("network", "", "network name (required)")
	quorum := fs.Uint("quorum", 1, "vote weight a change requires (k)")
	adminName := fs.String("admin-name", "admin", "name for the admin key generated locally")
	var extraAdmins stringList
	fs.Var(&extraAdmins, "admin", "additional admin key as NAME=nid:KEY[:VOTES]; repeatable")
	adminVotes := fs.Uint("admin-votes", 1, "vote weight of the locally generated admin key")
	nodeName := fs.String("node-name", "", "enroll this device as a founding member under this name")
	wgKey := fs.String("wg", "", "this device's WireGuard public key; generated if omitted")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: juist init -network NAME [flags]

Creates a network. This is the genesis ceremony: it fixes the admin keys, the
vote threshold, and the break-glass commitments, none of which anything weaker
than the resulting quorum can change afterwards.

The break-glass secrets are written to `+disablementFile+` in the home
directory. Move them somewhere safe and offline: together with the admin keys
they are the only way to recover the network, and losing both makes it
unrecoverable by design.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return errSilent
	}
	if *network == "" {
		fs.Usage()
		return fmt.Errorf("-network is required")
	}
	if *quorum == 0 || *quorum > types.MaxVotes {
		return fmt.Errorf("-quorum must be between 1 and %d", types.MaxVotes)
	}

	// Everything that can be rejected from the arguments alone is rejected
	// before anything is written. The ceremony writes three files an operator
	// cannot simply re-run over — the admin key, the break-glass secrets, the
	// node keys — and a name the log will not accept used to fail after all
	// three were on disk, leaving a half-ceremony that refuses to be redone.
	if err := types.ValidateName(*network); err != nil {
		return fmt.Errorf("-network: %w", err)
	}
	if err := types.ValidateName(*adminName); err != nil {
		return fmt.Errorf("-admin-name: %w", err)
	}
	if *nodeName != "" {
		if err := types.ValidateName(*nodeName); err != nil {
			return fmt.Errorf("-node-name: %w", err)
		}
	}
	extra := make([]types.AdminKey, 0, len(extraAdmins))
	for _, spec := range extraAdmins {
		key, err := parseAdminSpec(spec)
		if err != nil {
			return err
		}
		extra = append(extra, key)
	}

	// Refuse before generating any keys if a network is already here, so a
	// mistyped command cannot leave half a ceremony behind.
	st, err := store.Open(h.join(logDir))
	if err != nil {
		return err
	}
	if _, ok, err := st.Anchor(); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("%s already holds a network; refusing to create another", h.join(logDir))
	}

	// A quorum nobody can reach would make the network unmanageable from the
	// moment it exists. Checked before the keys exist, for the same reason.
	total := uint32(*adminVotes)
	for _, a := range extra {
		total += a.Votes
	}
	if uint32(*quorum) > total {
		return fmt.Errorf("-quorum %d exceeds the total admin vote weight %d", *quorum, total)
	}

	localAdmin, err := h.createAdminKey(*adminName)
	if err != nil {
		return err
	}
	admins := append([]types.AdminKey{{
		Public: localAdmin.Public(), Votes: uint32(*adminVotes), Name: *adminName,
	}}, extra...)

	secretsList := make([][]byte, 0, numDisablementSecrets)
	commitments := make([]types.Hash, 0, numDisablementSecrets)
	for range numDisablementSecrets {
		s := make([]byte, types.DisablementSecretSize)
		if _, err := rand.Read(s); err != nil {
			return fmt.Errorf("drawing a break-glass secret: %w", err)
		}
		secretsList = append(secretsList, s)
		commitments = append(commitments, types.DisablementCommit(s))
	}
	lines := []string{
		"# juist break-glass secrets for network " + *network,
		"# Any one of these authorizes recovery if the admin quorum is lost.",
		"# Move this file offline. Losing these AND the admin keys makes the",
		"# network unrecoverable, which is the security property, not a bug.",
	}
	for _, s := range secretsList {
		lines = append(lines, b64.EncodeToString(s))
	}
	if err := h.writeSecret(disablementFile, lines); err != nil {
		return err
	}

	var nodes []types.NodeRecord
	if *nodeName != "" {
		rec, err := h.enrollLocalNode(*nodeName, *wgKey)
		if err != nil {
			return err
		}
		nodes = append(nodes, rec)
	}

	genesisPath := h.join(genesisFile)
	genesis, err := log.Genesis(*network, uint32(*quorum), admins, commitments, nodes, sealer())
	if err != nil {
		return err
	}
	if err := genesis.Sign(localAdmin); err != nil {
		return err
	}
	// A genesis the local key cannot authorize on its own is the normal
	// multi-admin case, not a failure: k-of-n means no machine holds k keys,
	// so the record has to leave this one to collect the rest. Write it out
	// rather than discarding it. Discarding was unrecoverable — the admin key
	// and the break-glass secrets are already on disk and a second init
	// refuses to overwrite them, so the ceremony could be neither finished
	// nor restarted.
	status, err := log.GenesisStatus(&genesis)
	if err != nil {
		return err
	}
	if !status.Authorized() {
		if err := writeRecordFile(genesisPath, &genesis); err != nil {
			return err
		}
		fmt.Printf("genesis ceremony started for network %q\n", *network)
		fmt.Printf("  record       %s\n", genesisPath)
		fmt.Printf("  signatures   %d of %d vote weight; needs %d more\n",
			status.Votes, status.Quorum, missing(status))
		fmt.Printf("  admin key    %v (%d vote(s))\n", localAdmin.Public(), *adminVotes)
		fmt.Printf("  break-glass  %s\n", h.join(disablementFile))
		fmt.Printf("\nThe remaining admins must sign it on the machines that hold their keys:\n")
		fmt.Printf("  juist sign %s\n", genesisPath)
		fmt.Printf("then bring it back here and create the network with:\n")
		fmt.Printf("  juist apply %s\n", genesisPath)
		return nil
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
	fmt.Printf("  admin key    %v (%d vote(s))\n", localAdmin.Public(), *adminVotes)
	fmt.Printf("  break-glass  %s\n", h.join(disablementFile))
	for _, n := range state.Nodes() {
		fmt.Printf("  member       %s %v\n", n.Name, state.Addr6(n.Identity))
	}
	return nil
}

// enrollLocalNode generates this device's keys and returns the record that
// would admit it. An explicit WireGuard key overrides the generated one, for a
// device whose data plane already holds a key. The name is persisted with the
// keys so "juist key" can reprint the enrollment command later.
func (h *home) enrollLocalNode(name, wgKeyText string) (types.NodeRecord, error) {
	k, err := h.createNodeKeys(name)
	if err != nil {
		return types.NodeRecord{}, err
	}
	wg := k.Public.WireGuard
	if wgKeyText != "" {
		// The operator says the data plane already holds this key. The record
		// names it; this keystore's own WireGuard key is then unused, which is
		// harmless and visible in `juist key`.
		if wg, err = types.ParseWGKey(wgKeyText); err != nil {
			return types.NodeRecord{}, err
		}
	}
	return types.NodeRecord{
		Identity:  k.Identity.Public(),
		Name:      name,
		WireGuard: wg,
		X25519:    k.Public.X25519,
		MLKEM:     k.Public.MLKEM,
	}, nil
}

// parseAdminSpec parses NAME=nid:KEY[:VOTES].
func parseAdminSpec(spec string) (types.AdminKey, error) {
	name, rest, ok := strings.Cut(spec, "=")
	if !ok {
		return types.AdminKey{}, fmt.Errorf("admin %q: expected NAME=nid:KEY[:VOTES]", spec)
	}
	votes := uint64(1)
	// The key's own text form contains a colon, so split votes off the end
	// rather than at the first separator.
	if i := strings.LastIndex(rest, ":"); i > 0 {
		if v, err := strconv.ParseUint(rest[i+1:], 10, 32); err == nil {
			votes = v
			rest = rest[:i]
		}
	}
	key, err := types.ParseIdentity(rest)
	if err != nil {
		return types.AdminKey{}, fmt.Errorf("admin %q: %w", name, err)
	}
	if votes == 0 || votes > types.MaxVotes {
		return types.AdminKey{}, fmt.Errorf("admin %q: votes must be between 1 and %d", name, types.MaxVotes)
	}
	if err := types.ValidateName(name); err != nil {
		return types.AdminKey{}, fmt.Errorf("admin %q: %w", name, err)
	}
	return types.AdminKey{Public: key, Votes: uint32(votes), Name: name}, nil
}

// sealer returns the epoch sealer, drawing a fresh group secret per epoch.
//
// The secret is not kept: every member — including this one, if it is a member
// — recovers it from the record's wrap addressed to it. Nothing needs the
// plaintext at the machine that signs.
func sealer() log.Sealer {
	return func(epoch uint64, members []types.NodeRecord) (*types.EpochRecord, error) {
		_, rec, err := secrets.NewEpoch(epoch, members)
		return rec, err
	}
}

// stringList collects a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}
