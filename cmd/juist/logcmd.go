package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/nning/juist/internal/changelog"
	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

func logFamily() family {
	return family{name: "juist log", intro: `Inspect the membership log: the signed, hash-chained record of every change,
held and verified by each device.`, subs: []subcommand{
		{name: "show", run: logShow, forms: [][2]string{{"", "list the changes"}}},
		{name: "verify", run: logVerify, forms: [][2]string{{"verify [FILE]", "re-verify the log, or check a change file"}}},
		{name: "checkpoint", run: logCheckpoint, forms: [][2]string{{"checkpoint", "record the whole current state as one change"}}},
		{name: "upgrade", run: logUpgrade, forms: [][2]string{{"upgrade", "raise the network to this build's record schema"}}},
	}}
}

func cmdLog(a *app, args []string) error { return logFamily().run(a, args) }

func logShow(a *app, args []string) error {
	s := spec{name: "juist log", args: "[SUBCOMMAND]", about: logFamily().about()}
	if _, err := a.parse(s, newFlags(s.name), args); err != nil {
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
	for i, e := range changelog.Of(chain, auth.State().Admins()) {
		a.printf("%4d  %-44s %s\n", i, e.What, a.dim(e.Hash.String()[:12]))
		a.printf("      %s\n", a.dim("approved by "+strings.Join(e.Signers, ", ")))
	}
	a.printf("%s\n", a.dim(count(len(chain), "change")))
	a.reportLogHealth(auth)
	return nil
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
	if cur := auth.State().Schema(); cur >= types.CurrentSchema {
		a.ok("unchanged: at %v", cur)
		return nil
	}
	a.warn("raising %v to %v; devices on older builds stop until updated", auth.State().Schema(), types.CurrentSchema)
	if err := a.proceed(*yes, "continue?"); err != nil {
		return err
	}
	aum, err := auth.Builder().SchemaUpgrade(types.CurrentSchema)
	if err != nil {
		return err
	}
	applied, err := a.submit(auth, &change{aum: aum, file: "schema-upgrade.rec",
		done: fmt.Sprintf("upgraded to %v", types.CurrentSchema)})
	if applied && auth.State().Schema() < types.SchemaSealing {
		a.hint("for changes waiting for your vote to reach you: juist admins receive")
	}
	return err
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
