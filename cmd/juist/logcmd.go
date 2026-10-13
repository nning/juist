package main

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/changelog"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

func logFamily() family {
	return family{name: "juist log", intro: `Inspect the membership log: the signed, hash-chained record of every change,
held and verified by each device.`, subs: []subcommand{
		{name: "show", run: logShow, forms: [][2]string{{"", "list the changes"},
			{"show N|HASH", "what one change did, and who signed it; -1 is the last"}}},
		{name: "verify", run: logVerify, forms: [][2]string{{"verify [FILE]", "re-verify the log, or check a change file"}}},
		{name: "checkpoint", run: logCheckpoint, forms: [][2]string{{"checkpoint", "record the whole current state as one change"}}},
		{name: "upgrade", run: logUpgrade, forms: [][2]string{{"upgrade", "raise the network to this build's record schema"}}},
	}}
}

func cmdLog(a *app, args []string) error { return logFamily().run(a, args) }

func logShow(a *app, args []string) error {
	s := spec{name: "juist log", args: "[SUBCOMMAND] | show N|HASH", max: 1, backwards: true, about: logFamily().about()}
	pos, err := a.parse(s, newFlags(s.name), args)
	if err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	chain, err := a.node.chain()
	if err != nil {
		return err
	}
	entries := changelog.Of(chain, auth.State().Admins())
	if len(pos) == 1 {
		return a.showChange(chain, entries, pos[0])
	}
	for i, e := range entries {
		a.printf("%4d  %-44s %s\n", i, e.What, a.dim(e.Hash.String()[:12]))
		a.printf("      %s\n", a.dim("approved by "+strings.Join(e.Signers, ", ")))
	}
	a.printf("%s\n", a.dim(count(len(chain), "change")))
	a.reportLogHealth(auth)
	return nil
}

// showChange says what the change arg names did, to the state before it.
func (a *app) showChange(chain []types.AUM, entries []changelog.Entry, arg string) error {
	i, err := findChange(entries, arg)
	if err != nil {
		return err
	}
	var before *log.State
	if i > 0 {
		prior, err := log.FromRecords(log.NewMemStorage(), chain[:i])
		if err != nil {
			return err
		}
		before = prior.State()
	}
	e := entries[i]
	a.printf("%4d  %s\n", i, e.What)
	for _, line := range effect(&chain[i], before, a.now().Unix()) {
		a.printf("      %s\n", line)
	}
	if len(e.Signers) > 0 {
		keys := make([]string, len(chain[i].Signatures))
		for j, sig := range chain[i].Signatures {
			keys[j] = sig.KeyID.ShortString()
		}
		a.printf("      approved by %s, with %s\n", strings.Join(e.Signers, ", "), strings.Join(keys, ", "))
	}
	a.printf("      %s\n", a.dim("hash "+e.Hash.String()))
	return nil
}

// findChange is the index of the change arg names: its number as juist log
// lists it, -N counting back from the last, or the start of its hash.
func findChange(entries []changelog.Entry, arg string) (int, error) {
	if n, err := strconv.Atoi(arg); err == nil {
		i := n
		if strings.HasPrefix(arg, "-") {
			i += len(entries)
		}
		if i < 0 || i >= len(entries) {
			return 0, fmt.Errorf("no change %s: the log lists 0 to %d, or %d to -1", arg, len(entries)-1, -len(entries))
		}
		return i, nil
	}
	found := -1
	for i, e := range entries {
		if arg != "" && strings.HasPrefix(e.Hash.String(), strings.ToUpper(arg)) {
			if found >= 0 {
				return 0, fmt.Errorf("%s starts the hash of more than one change: give more of it", arg)
			}
			found = i
		}
	}
	if found < 0 {
		return 0, fmt.Errorf("no change %s in the log", arg)
	}
	return found, nil
}

func logVerify(a *app, args []string) error {
	s := spec{name: "juist log verify", args: "[FILE...]", max: -1, about: `
Re-verify the stored log from its start, and that this device can open the
group secret. With FILEs, say what each change needs and whether it applies.`}
	files, err := a.parse(s, newFlags(s.name), args)
	if err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	chain, err := auth.Chain()
	if err != nil {
		return err
	}
	a.field("Network", "%s", state.Network())
	a.field("Genesis", "%v", state.GenesisHash())
	a.field("Head", "%v", state.Head())
	a.field("Chain", "%s from %v", count(len(chain), "change"), auth.Anchor().String()[:12])
	a.field("Epoch", "%d", state.Epoch())
	a.field("Quorum", "%d of %s", state.Quorum(), count(state.TotalVotes(), "vote"))
	a.field("Schema", "%v", state.Schema())
	a.field("Devices", "%d", len(state.Nodes()))
	if n, err := auth.Unreachable(); err != nil {
		return err
	} else if n > 0 {
		a.field("Leftover", "%s off the chain (rejected forks)", count(n, "record"))
	}
	if st := a.node.status(); st != nil {
		// The daemon holds this device's keys and has already tried.
		if st.EpochError != "" {
			a.warn("cannot open the group secret: %s", st.EpochError)
		} else if st.InNetwork && !st.NotMember {
			a.ok("group secret: ok")
		}
		if st.Alarm != "" {
			a.alarm("%s", st.Alarm)
		}
	} else if err := a.home.checkGroupSecret(state); err != nil {
		a.warn("cannot open the group secret: %v", err)
	} else if k, _ := a.home.optionalNodeKeys(); k != nil && state.IsMember(k.Identity.Public()) {
		a.ok("group secret: ok")
	}
	if auth.Alarm() == nil {
		a.ok("log: ok")
	}
	a.reportLogHealth(auth)

	for _, path := range files {
		a.printf("\n")
		aum, err := readRecordFile(a.path(path))
		if err != nil {
			return err
		}
		a.printf("%s: %s\n", path, describeKind(aum.Kind))
		for _, line := range effect(&aum, state, a.now().Unix()) {
			a.printf("  %s\n", line)
		}
		if aum.Prev != nil && *aum.Prev != state.Head() {
			a.printf("  outdated: applying it forks the log\n")
		}
		sst := state.SignatureStatus(&aum)
		if sst.Authorized() {
			a.printf("  approved\n")
		} else {
			a.reportStatus(path, sst, state.Admins(), &aum)
		}
		// Missing votes are said above; what is asked here is whether the
		// change itself would apply once it has them.
		switch _, err := log.NewBuilder(state).Check(&aum); {
		case err != nil:
			a.printf("  does not apply: %s\n", strings.TrimPrefix(err.Error(), "log: "))
		case sst.Authorized():
			a.printf("  applies\n")
		default:
			a.printf("  applies once approved\n")
		}
	}
	return nil
}

func logUpgrade(a *app, args []string) error {
	s := spec{name: "juist log upgrade", about: `
Raise the network to this build's record schema:

  schema 1  juist admins vouchers; identity rotations signed by both keys
  schema 2  voucher revocations and raised thresholds win concurrent changes
  schema 3  several keys per admin (admins add, admins require); a raised
            quorum wins concurrent changes
  schema 4  new devices numbered from 198.18.0.0/15, not 100.64.0.0/10
  schema 5  juist network renumber
  schema 6  juist network rename
  schema 7  changes carried to the admin devices (admins receive)
  schema 8  public names pointed at devices (juist names add DEVICE NAME)
  schema 9  services published through an ingress (juist publish add)
  schema 10 devices renamed (juist rename)
  schema 11 services published on a TCP port of their own
            (juist publish add --tcp)
  schema 12 relays on 443 under a public name (juist set --relay-name)
  schema 13 an access policy (juist policy)
  schema 14 quantum-safe tunnels: a preshared key in every handshake
  schema 15 names for members alone, by name in the access policy
            (juist publish add --members, pass from … to name NAME)
  schema 16 discovery items that show no epoch and no size; devices on
            an older build shown as outdated
  schema 17 devices announce quantum-safe signing keys; a device's names
            take at most 2048 bytes
  schema 18 every change and message signed by ML-DSA: quantum-safe
            signatures. Run again at 17 once every device announces its
            key and every admin key has its own (admins receive)

Devices on older builds stop at the upgrade until updated: update them first.`}
	fs := newFlags(s.name)
	yes := fs.Bool("yes", false, "do not ask")
	if _, err := a.parse(s, fs, args); err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	cur := auth.State().Schema()
	switch {
	case cur >= types.CurrentSchema:
		a.ok("unchanged: at %v", cur)
		return nil
	case cur == types.SchemaSigning:
		return a.cutOver(auth, *yes)
	}
	// The cut-over to ML-DSA takes every device's key, which devices
	// announce from the schema before it.
	to := min(types.CurrentSchema, types.SchemaSigning)
	a.warn("raising %v to %v; devices on older builds stop until updated", cur, to)
	if err := a.proceed(*yes, "continue?"); err != nil {
		return err
	}
	aum, err := auth.Builder().SchemaUpgrade(to)
	if err != nil {
		return err
	}
	applied, err := a.submit(auth, &change{aum: aum, file: "schema-upgrade.rec",
		done: fmt.Sprintf("upgraded to %v", to)})
	if applied && cur < types.SchemaSealing {
		a.hint("for changes waiting for your vote to reach you: juist admins receive")
	}
	if applied && to == types.SchemaSigning {
		a.hint("once every device announces its signing key, for quantum-safe signatures: juist log upgrade")
	}
	return err
}

// cutOver authors the record that gives every member and admin key its
// signing key and cuts the network over to ML-DSA signatures.
func (a *app) cutOver(auth *log.Authority, yes bool) error {
	state := auth.State()
	var unregistered []string
	for _, p := range adminPeople(state.Admins()) {
		for _, k := range p.keys {
			if k.Signing == nil {
				unregistered = append(unregistered, cmp.Or(keyMachine(k), k.Public.ShortString())+" of "+p.name)
			}
		}
	}
	if len(unregistered) > 0 {
		return fmt.Errorf("no signing key registered yet by %s: %s\n"+
			"hint: on each, juist admins receive; or remove it: juist admins remove",
			count(len(unregistered), "admin key"), strings.Join(unregistered, ", "))
	}
	keys, missing := a.memberSigningKeys(state)
	if len(missing) > 0 {
		return fmt.Errorf("no signing key announced yet by %s: %s\n"+
			"hint: each needs this version of juist, online; or remove it: juist remove NAME",
			count(len(missing), "device"), strings.Join(missing, ", "))
	}
	// Two cut-overs from one head split the network for good: each device
	// keeps the one it adopted first.
	if changes, err := a.waitingChanges(auth); err == nil &&
		slices.ContainsFunc(changes, func(w waitingChange) bool { return w.aum.Kind == types.KindSetSigningKeys }) {
		return errors.New("a cut-over waits for votes already\nhint: juist approve")
	}
	a.warn("cutting %v over to ML-DSA signatures, for good", state.Network())
	if err := a.proceed(yes, "continue?"); err != nil {
		return err
	}
	aum, err := auth.Builder().SetSigningKeys(keys, sealer())
	if err != nil {
		return err
	}
	_, err = a.submit(auth, &change{aum: aum, file: "signing-keys.rec",
		done: fmt.Sprintf("upgraded to %v: signed by ML-DSA", types.SchemaMLDSA)})
	return err
}

// memberSigningKeys gathers every member's signing key as its announcement
// claims it, endorsed, and names the members whose announcement claims none.
func (a *app) memberSigningKeys(state *log.State) ([]types.MemberKey, []string) {
	claims := map[types.Identity]*gossip.SigningClaim{}
	if a.node != nil {
		eps, _ := a.node.hints()
		for _, b := range eps {
			if e, err := gossip.DecodeEndpoint(b); err == nil && e.Signing != nil {
				claims[e.Identity] = e.Signing
			}
		}
	}
	var keys []types.MemberKey
	var missing []string
	for _, n := range state.Nodes() {
		c, ok := claims[n.Identity]
		if !ok {
			missing = append(missing, n.Name)
			continue
		}
		keys = append(keys, types.MemberKey{Identity: n.Identity, Key: c.Key, Endorsement: c.Endorsement})
	}
	return keys, missing
}

// upgradeNote says the network's schema is below this build's, where a key
// in this keystore is one of its admins'.
func (a *app) upgradeNote(several bool) {
	auth, err := a.networkLog()
	if err != nil {
		return
	}
	state := auth.State()
	if state.Schema() >= types.CurrentSchema {
		return
	}
	files, err := a.home.adminKeyFiles()
	if err != nil || !slices.ContainsFunc(files, func(k adminKeyFile) bool {
		_, admin := state.Admin(k.priv.Public())
		return admin
	}) {
		return
	}
	cmd := "juist log upgrade"
	if several {
		cmd += " " + a.network
	}
	a.printf("\nthe network is at %v, this version at %v\n", state.Schema(), types.CurrentSchema)
	if state.Schema() == types.SchemaSigning {
		registered := 0
		for _, k := range state.Admins() {
			if k.Signing != nil {
				registered++
			}
		}
		mine := slices.ContainsFunc(files, func(f adminKeyFile) bool {
			k, ok := state.Admin(f.priv.Public())
			return ok && k.Signing == nil
		})
		switch total := len(state.Admins()); {
		case mine:
			a.hint("for quantum-safe signatures, first: juist admins receive")
			return
		case registered < total:
			a.hint("%d of %s have a signing key; once all do (juist admins receive): %s", registered,
				count(total, "admin key"), cmd)
			return
		}
		if _, missing := a.memberSigningKeys(state); len(missing) > 0 {
			a.hint("%s of %s announce a signing key; once all do: %s", strconv.Itoa(len(state.Nodes())-len(missing)),
				count(len(state.Nodes()), "device"), cmd)
			return
		}
		a.hint("every device announces a signing key: %s", cmd)
		return
	}
	a.hint("once every device runs this version: %s", cmd)
}

func logCheckpoint(a *app, args []string) error {
	s := spec{name: "juist log checkpoint", about: `
Record the whole current state as one change, which every device checks
against its own history.`}
	if _, err := a.parse(s, newFlags(s.name), args); err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	aum, err := auth.Builder().Checkpoint()
	if err != nil {
		return err
	}
	_, err = a.submit(auth, &change{aum: aum, file: "checkpoint.rec", done: "checkpoint recorded"})
	return err
}

func (a *app) reportLogHealth(auth *log.Authority) {
	for _, o := range auth.Orphans() {
		if len(o.Unrevoked) > 0 {
			a.warn("%s lost to a concurrent change, not in effect; an admin redoes it",
				count(len(o.Unrevoked), "revocation"))
		}
		if o.Conflict == "" && len(o.Records) > len(o.Unrevoked) {
			a.warn("%s lost to a concurrent change, not applied; redo if wanted",
				count(len(o.Records)-len(o.Unrevoked), "change"))
		}
	}
	if alarm := auth.Alarm(); alarm != nil {
		a.alarm("%v", alarm)
	}
	if d := auth.Disabled(); d != nil {
		a.alarm("the network was ended with a break-glass secret, in record %s", d.At.String()[:12])
	}
}

// checkGroupSecret opens this device's wrap of the current epoch secret. It is
// not a formality: nothing in the log can prove a wrap was sealed to the right
// key, so this is the only place that is found out.
func (h *home) checkGroupSecret(state *log.State) error {
	k, err := h.nodeKeys()
	if keys.Missing(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading this device's keys: %w", err)
	}
	if !state.IsMember(k.Identity.Public()) {
		return nil
	}
	_, err = secrets.Open(state.EpochRecord(), k.Identity.Public(), k.Recipient)
	return err
}
