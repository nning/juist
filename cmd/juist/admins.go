package main

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/nning/juist/internal/cliflag"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

func adminsFamily() family {
	return family{name: "juist admins", intro: "Manage the admin keys that approve changes, and how many votes a change needs.",
		subs: []subcommand{
			{name: "list", aliases: []string{"ls"}, run: adminsList, forms: [][2]string{{"", "list admin keys and thresholds"}}},
			{name: "new", run: adminsNew, forms: [][2]string{{"new NAME", "create an admin key on this machine"}}},
			{name: "add", run: adminsAdd, forms: [][2]string{{"add NAME KEY", "give another admin's key a vote"}}},
			{name: "remove", aliases: []string{"rm"}, run: adminsRemove,
				forms: [][2]string{{"remove NAME|KEY", "take an admin key's vote away"}}},
			{name: "quorum", run: adminsQuorum, forms: [][2]string{{"quorum K", "require K votes for every change"}}},
			{name: "require", run: adminsRequire,
				forms: [][2]string{{"require NAME N", "count NAME's votes only when N of their keys sign"}}},
			{name: "vouchers", run: adminsVouchers,
				forms: [][2]string{{"vouchers M", "require M vouchers to confirm a device's view"}}},
			{name: "receive", run: adminsReceive,
				forms: [][2]string{{"receive", "let changes waiting for your vote reach your keys here"}}},
			{name: "export", run: adminsExport,
				forms: [][2]string{{"export NAME", "print an admin key here as one line, for a password manager"}}},
			{name: "import", run: adminsImport, forms: [][2]string{{"import NAME", "read that line from stdin into the key NAME"}}},
		},
		footer: "Admin keys leave their machine only as export's line, and it needs no network of its own."}
}

func cmdAdmins(a *app, args []string) error { return adminsFamily().run(a, args) }

func adminsList(a *app, args []string) error {
	s := spec{name: "juist admins", args: "[SUBCOMMAND]", about: adminsFamily().about()}
	if _, err := a.parse(s, newFlags(s.name), args); err != nil {
		return err
	}
	governs := map[types.Identity][]string{}
	list := func() error { return a.listAdmins(governs) }
	listed, err := a.forEachNetwork(list)
	if !listed {
		err = list()
	}
	if err != nil {
		return err
	}
	return a.listKeysHere(governs)
}

// listAdmins is "juist admins" for one network, noting in governs the
// networks each key governs.
func (a *app) listAdmins(governs map[types.Identity][]string) error {
	local, err := a.home.adminKeys()
	if err != nil {
		return err
	}
	here := map[types.Identity]bool{}
	for _, k := range local {
		here[k.Public()] = true
	}
	auth, err := a.optionalLog()
	if err != nil {
		return err
	}
	if auth == nil {
		if len(local) == 0 {
			return errors.New("no network and no admin key here\nhint: juist admins new NAME")
		}
		a.printf("no network here\n")
		return nil
	}
	state := auth.State()
	for _, k := range state.Admins() {
		if here[k.Public] {
			governs[k.Public] = append(governs[k.Public], state.Network())
		}
	}
	tw := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ADMIN\tVOTES\tSIGNS WITH\tON\tKEY")
	for _, p := range adminPeople(state.Admins()) {
		for i, k := range p.keys {
			key := k.Public.String()
			if here[k.Public] {
				key += " (here)"
			}
			on := orDash(keyMachine(k))
			if i > 0 {
				fmt.Fprintf(tw, "\t\t\t%s\t%s\n", on, key)
				continue
			}
			signs := fmt.Sprintf("%d of %d keys", k.NeededKeys(), len(p.keys))
			if len(p.keys) == 1 {
				signs = "its key"
			}
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", p.name, k.Votes, signs, on, key)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	a.printf("\n")
	a.field("Quorum", "%d of %s", state.Quorum(), count(state.TotalVotes(), "vote"))
	if devices := len(state.NodesWithRole(types.RoleAdmin)); devices > 0 {
		a.field("Vouchers", "%d of %d", max(state.Vouchers(), 1), devices)
	}
	if slices.ContainsFunc(state.Admins(), func(k types.AdminKey) bool {
		return here[k.Public] && k.Recipient == nil
	}) {
		a.hint("for changes waiting for your vote to reach you: juist admins receive")
	}
	return nil
}

func adminsNew(a *app, args []string) error {
	s := spec{name: "juist admins new", args: "NAME", min: 1, max: 1, anyNetwork: true, about: `
Create an admin key on this machine and print the command that adds it.
--network names the network it is for; without, the first network whose
log names it here files it under that network.`}
	fs := newFlags(s.name)
	on := fs.String("on", "", "`MACHINE` the key is kept on (default: this device's name, or the hostname)")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	if *on == "" {
		*on = a.machineName()
	}
	if err := checkName("--on", *on); err != nil {
		return err
	}
	if err := checkName("admin key name", pos[0]); err != nil {
		return err
	}
	if u := a.sudoUser(); u != "" {
		return fmt.Errorf("run as %s, without sudo: the key belongs in your keystore", u)
	}
	network := ""
	if a.network != "" && !a.networkFromEnv {
		if err := checkName("--network", a.network); err != nil {
			return err
		}
		network = a.network
	}
	name := adminKeyName(pos[0], network)
	priv, err := a.home.createAdminKey(name, network == "")
	if err != nil {
		return err
	}
	a.ok("created admin key %q; an admin of the network runs:", name)
	text, err := types.AdminKeyText(priv)
	if err != nil {
		return err
	}
	a.command("juist admins add %s %s --on %s", pos[0], text, *on)
	a.hint("an admin already? add it under your admin name, or it gets a vote of its own")
	return nil
}

func adminsAdd(a *app, args []string) error {
	s := spec{name: "juist admins add", args: "NAME KEY", min: 2, max: 2, about: `
Give KEY, as "juist admins new" printed it, a vote held by the person NAME.
Keys added under one name cast that person's votes once between them. --on is
an unverified label.`}
	fs := newFlags(s.name)
	votes := fs.Uint("votes", 1, "votes the key carries")
	on := fs.String("on", "", "`MACHINE` the key is kept on (default: this one, if it holds the key)")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	key, signing, endorsement, err := types.ParseAdminKey(pos[1])
	if err != nil {
		return fmt.Errorf("bad key %q; want the nid:… \"juist admins new\" printed", pos[1])
	}
	if err := checkName("NAME", pos[0]); err != nil {
		return err
	}
	if *votes == 0 || *votes > types.MaxVotes {
		return fmt.Errorf("--votes must be between 1 and %d", types.MaxVotes)
	}
	onGiven := *on != ""
	if onGiven {
		if err := checkName("--on", *on); err != nil {
			return err
		}
	} else if a.holdsAdminKey(key) {
		*on = a.machineName()
	}
	votesSet := cliflag.IsSet(fs, "votes")
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	for _, k := range state.Admins() {
		switch {
		case k.Public == key:
			a.ok("unchanged: key has %s, as %s", count(k.Votes, "vote"), orDash(cmp.Or(k.Holder, k.Name)))
			return nil
		// A key without a holder is shown and removed by its name; two alike
		// would make both ambiguous.
		case k.Holder == "" && foldName(k.Name) == foldName(pos[0]):
			return fmt.Errorf("admin key %q exists; pick another name", k.Name)
		}
	}
	if signing == nil {
		return errors.New("the key names no signing key, which the network needs; it is from an older juist\n" +
			"hint: juist admins new prints it whole")
	}
	add := types.AdminKey{Public: key, Votes: uint32(*votes), Name: pos[0], Signing: signing, Endorsement: endorsement}
	done := fmt.Sprintf("added %s's key, %s", pos[0], count(*votes, "vote"))
	// With a holder naming the person, the key's own name is its machine.
	add.Holder, add.Name = pos[0], *on
	if same := holderKeys(state, pos[0]); len(same) > 0 {
		p := same[0]
		if votesSet && uint32(*votes) != p.Votes {
			return fmt.Errorf("--votes: %s's keys all cast %s", p.Holder, count(p.Votes, "vote"))
		}
		add.Holder, add.Votes, add.Needed = p.Holder, p.Votes, p.Needed
		done = fmt.Sprintf("added a key of %s's; %s, %d signing", p.Holder, count(len(same)+1, "key"),
			p.NeededKeys())
	}
	if add.Needed == 0 && len(holderKeys(state, pos[0])) == 0 {
		// A new person gets a vote of their own; a device of an admin's
		// added under another name would give that admin a second one.
		var others []string
		for _, p := range adminPeople(state.Admins()) {
			others = append(others, p.name)
		}
		a.printf("%s is a new admin besides %s\n", pos[0], strings.Join(others, ", "))
		a.hint("a key of an existing admin goes under their name")
	}
	aum, err := auth.Builder().AddAdminKey(add)
	if err != nil {
		return err
	}
	_, err = a.submit(auth, &change{aum: aum, file: "admin-add-" + fileSafe(pos[0]) + ".rec", done: done})
	return err
}

func adminsReceive(a *app, args []string) error {
	s := spec{name: "juist admins receive", about: `
Give this keystore's admin keys the encryption keys that changes waiting for
their votes are sealed to, so that they reach you on the admin devices. It
is a change like any other, which each key signs for itself.`}
	if _, err := a.parse(s, newFlags(s.name), args); err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	files, err := a.adminKeyFiles()
	if err != nil {
		return err
	}
	type step struct {
		build      func(*log.Builder) (types.AUM, error)
		file, done string
	}
	var steps []step
	governs := false
	for _, f := range files {
		k, ok := auth.State().Admin(f.priv.Public())
		if !ok {
			continue
		}
		governs = true
		name := cmp.Or(keyPerson(k), k.Public.ShortString())
		r, err := adminRecipient(f.priv)
		if err != nil {
			return err
		}
		if k.Recipient == nil || *k.Recipient != r {
			steps = append(steps, step{
				build: func(b *log.Builder) (types.AUM, error) { return b.SetAdminRecipient(k.Public, r) },
				file:  "admin-receive-" + fileSafe(f.name) + ".rec",
				done:  fmt.Sprintf("changes waiting for %s reach key %s", name, f.name)})
		}
	}
	if !governs {
		return errors.New("no admin key of this network here\nhint: run it where an admin's key is")
	}
	if len(steps) == 0 {
		a.ok("unchanged: changes waiting for your vote reach your keys here")
		return nil
	}
	for i, st := range steps {
		aum, err := st.build(auth.Builder())
		if err != nil {
			return err
		}
		applied, err := a.submit(auth, &change{aum: aum, file: st.file, done: st.done})
		if err != nil || !applied {
			// Another from this head would fork the one pending.
			if err == nil && i < len(steps)-1 {
				a.hint("once that is applied, run it again for the rest")
			}
			return err
		}
		if auth, err = a.freshLog(); err != nil {
			return err
		}
	}
	return nil
}

func adminsRequire(a *app, args []string) error {
	s := spec{name: "juist admins require", args: "NAME N", min: 2, max: 2, about: `
Count NAME's votes only when N of their keys sign. Hold N+1 keys: with
exactly N, losing one device may lock the network.`}
	fs := newFlags(s.name)
	yes := fs.Bool("yes", false, "do not ask")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	n, err := strconv.ParseUint(pos[1], 10, 32)
	if err != nil || n == 0 {
		return fmt.Errorf("bad N %q: want a number >= 1", pos[1])
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	keys := holderKeys(state, pos[0])
	if len(keys) == 0 {
		return fmt.Errorf("no admin %q\nhint: juist admins", pos[0])
	}
	p := keys[0]
	switch {
	case uint32(n) == p.NeededKeys():
		a.ok("unchanged: %s needs %s", p.Holder, count(n, "key"))
		return nil
	case n > uint64(len(keys)):
		return fmt.Errorf("%s holds only %s\nhint: juist admins add %s KEY", p.Holder, count(len(keys), "key"), p.Holder)
	case n == uint64(len(keys)) && n > 1:
		if state.TotalVotes()-p.Votes >= state.Quorum() {
			a.warn("%s needs every key they hold; losing one device loses their vote", p.Holder)
			break
		}
		a.warn("%s needs every key they hold; losing one device locks the network", p.Holder)
		if err := a.proceed(*yes, "continue?"); err != nil {
			return err
		}
	}
	aum, err := auth.Builder().SetHolder(types.HolderPolicy{Name: p.Holder, Votes: p.Votes, Needed: uint32(n)})
	if err != nil {
		return err
	}
	_, err = a.submit(auth, &change{aum: aum, file: "admin-require-" + fileSafe(p.Holder) + ".rec",
		done: fmt.Sprintf("%s: %d of %s must sign", p.Holder, n, count(len(keys), "key"))})
	return err
}

func adminsRemove(a *app, args []string) error {
	s := spec{name: "juist admins remove", args: "NAME|KEY", min: 1, max: 1, about: `
Take an admin key's vote away; refused if the rest cannot reach the quorum.`}
	pos, err := a.parse(s, newFlags(s.name), args)
	if err != nil {
		return err
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	key, err := resolveAdmin(auth.State(), pos[0])
	if err != nil {
		return err
	}
	state := auth.State()
	// What the admins could cast without the key: a person's votes stay
	// while they hold enough other keys.
	var rest []types.AdminKey
	for _, k := range state.Admins() {
		if k.Public != key.Public {
			rest = append(rest, k)
		}
	}
	if left := types.AchievableVotes(rest); left < state.Quorum() {
		if key.Holder != "" {
			if others := len(holderKeys(state, key.Holder)) - 1; others > 0 && uint32(others) < key.NeededKeys() {
				return fmt.Errorf("%s would hold %d keys but need %d; quorum unreachable\n"+
					"hint: juist admins require %s %d", key.Holder, others, key.NeededKeys(), key.Holder, others)
			}
		}
		return fmt.Errorf("%s left for a quorum of %d\nhint: juist admins add NAME KEY", count(left, "vote"),
			state.Quorum())
	}
	aum, err := auth.Builder().RemoveAdminKey(key.Public)
	if err != nil {
		return err
	}
	name := cmp.Or(keyPerson(key), key.Public.ShortString())
	_, err = a.submit(auth, &change{aum: aum, file: "admin-remove-" + fileSafe(name) + ".rec",
		done: removedKeyText(state, key, name)})
	return err
}

// removedKeyText says what taking key away leaves: a person with other keys
// keeps their vote.
func removedKeyText(state *log.State, key types.AdminKey, name string) string {
	if key.Holder != "" {
		if others := len(holderKeys(state, key.Holder)) - 1; others > 0 {
			return fmt.Sprintf("removed a key of %s's; %s left", key.Holder, count(others, "key"))
		}
	}
	return fmt.Sprintf("removed %s's key", name)
}

func adminsQuorum(a *app, args []string) error {
	s := spec{name: "juist admins quorum", args: "K", min: 1, max: 1, about: `
Require K admin votes for every later change.`}
	fs := newFlags(s.name)
	yes := fs.Bool("yes", false, "do not ask")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	k, err := strconv.ParseUint(pos[0], 10, 32)
	if err != nil || k == 0 {
		return fmt.Errorf("bad K %q: want a number >= 1", pos[0])
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	switch total := uint64(auth.State().TotalVotes()); {
	case k > total:
		return fmt.Errorf("the admins cast only %s\nhint: juist admins add NAME KEY", count(total, "vote"))
	case k == total && total > 1:
		var names []string
		for _, p := range adminPeople(auth.State().Admins()) {
			names = append(names, p.name)
		}
		a.warn("every change needs every admin (%s); losing one admin's keys locks the network",
			strings.Join(names, ", "))
		if err := a.proceed(*yes, "continue?"); err != nil {
			return err
		}
	}
	aum, err := auth.Builder().SetQuorum(uint32(k))
	if err != nil {
		return err
	}
	applied, err := a.submit(auth, &change{aum: aum, file: "quorum.rec",
		done: fmt.Sprintf("quorum %d", k)})
	if err == nil && applied {
		a.hintVoucherCarries(uint32(k), auth.State().NodesWithRole(types.RoleAdmin))
	}
	return err
}

func adminsVouchers(a *app, args []string) error {
	s := spec{name: "juist admins vouchers", args: "M", min: 1, max: 1, about: `
Require M vouchers to have vouched within the freshness TTL before a device
trusts its view. With M, a lying voucher needs M-1 accomplices; M vouchers
must be online.`}
	pos, err := a.parse(s, newFlags(s.name), args)
	if err != nil {
		return err
	}
	m, err := strconv.ParseUint(pos[0], 10, 32)
	if err != nil || m == 0 {
		return fmt.Errorf("bad M %q: want a number >= 1", pos[0])
	}
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	if devices := len(auth.State().NodesWithRole(types.RoleAdmin)); m > uint64(devices) {
		return fmt.Errorf("only %s\nhint: juist grant DEVICE voucher", count(devices, "voucher"))
	}
	aum, err := auth.Builder().SetVouchers(uint32(m))
	if err != nil {
		return err
	}
	applied, err := a.submit(auth, &change{aum: aum, file: "vouchers.rec",
		done: fmt.Sprintf("vouchers %d", m)})
	if err == nil && applied {
		a.warnVouchers(auth.State().NodesWithRole(types.RoleAdmin), int(m))
	}
	return err
}

// listKeysHere lists the keystore's admin keys by the names --admin-key and
// --key take, with the networks each governs: a key governing several is
// shared.
func (a *app) listKeysHere(governs map[types.Identity][]string) error {
	files, err := a.home.adminKeyFiles()
	if err != nil || len(files) == 0 {
		return err
	}
	a.printf("\n")
	tw := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "KEY HERE\tGOVERNS\tPUBLIC")
	for _, k := range files {
		networks := strings.Join(governs[k.priv.Public()], ", ")
		fmt.Fprintf(tw, "%s\t%s\t%v\n", k.name, orDash(networks), k.priv.Public())
	}
	return tw.Flush()
}

// keyPerson is the admin a key belongs to: its holder, or before holders its
// own name.
func keyPerson(k types.AdminKey) string { return cmp.Or(k.Holder, k.Name) }

// keyMachine is the machine a key is kept on, as its holder named it. Before
// holders, and for keys added before machines were named, the name is the
// person's.
func keyMachine(k types.AdminKey) string {
	if k.Holder == "" || k.Name == k.Holder {
		return ""
	}
	return k.Name
}

// machineName names this machine for the admin keys kept on it: its name in
// the network where it is a member, else its host name.
func (a *app) machineName() string {
	if n, err := a.openNode(); err == nil {
		if auth, err := n.log(); err == nil {
			if id, ok, err := a.selfID(); err == nil && ok {
				if rec, ok := auth.State().Node(id); ok && checkName("name", rec.Name) == nil {
					return rec.Name
				}
			}
		}
	}
	host, _ := os.Hostname()
	host, _, _ = strings.Cut(host, ".")
	return memberName(host)
}

// holdsAdminKey reports whether this keystore holds the admin key id.
func (a *app) holdsAdminKey(id types.Identity) bool {
	keys, err := a.home.adminKeys()
	return err == nil && slices.ContainsFunc(keys, func(k types.PrivateIdentity) bool { return k.Public() == id })
}

// localAdminName is the admin whose key this keystore holds, if one does.
func (a *app) localAdminName(state *log.State) string {
	keys, err := a.home.adminKeys()
	if err != nil {
		return ""
	}
	for _, k := range keys {
		if admin, ok := state.Admin(k.Public()); ok {
			return cmp.Or(admin.Holder, admin.Name)
		}
	}
	return ""
}

// An adminPerson is the keys one admin holds: those of one holder, or a key
// that belongs to none.
type adminPerson struct {
	name string
	keys []types.AdminKey
}

// adminPeople groups admin keys by holder, in name order.
func adminPeople(keys []types.AdminKey) []adminPerson {
	var out []adminPerson
	at := map[string]int{}
	for _, k := range keys {
		name, id := k.Holder, "holder:"+k.Holder
		if k.Holder == "" {
			name, id = orDash(k.Name), "key:"+k.Public.String()
		}
		if i, ok := at[id]; ok {
			out[i].keys = append(out[i].keys, k)
			continue
		}
		at[id] = len(out)
		out = append(out, adminPerson{name: name, keys: []types.AdminKey{k}})
	}
	slices.SortStableFunc(out, func(a, b adminPerson) int { return strings.Compare(foldName(a.name), foldName(b.name)) })
	return out
}

// holderKeys returns the keys the holder named name holds, matched as
// names are.
func holderKeys(state *log.State, name string) []types.AdminKey {
	var out []types.AdminKey
	for _, k := range state.Admins() {
		if k.Holder != "" && foldName(k.Holder) == foldName(name) {
			out = append(out, k)
		}
	}
	return out
}

func resolveAdmin(state *log.State, arg string) (types.AdminKey, error) {
	// A key as juist admins new printed it names its identity first.
	if id, _, _, err := types.ParseAdminKey(arg); err == nil {
		arg = id.String()
	}
	var matches []types.AdminKey
	for _, k := range state.Admins() {
		if strings.EqualFold(k.Name, arg) || k.Holder != "" && strings.EqualFold(k.Holder, arg) || k.Public.String() == arg ||
			(len(arg) >= 8 && strings.HasPrefix(k.Public.String(), arg)) {
			matches = append(matches, k)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return types.AdminKey{}, fmt.Errorf("no admin key %q\nhint: juist admins", arg)
	default:
		keys := make([]string, len(matches))
		for i, k := range matches {
			keys[i] = k.Public.String()
		}
		return types.AdminKey{}, fmt.Errorf("%q matches %d admin keys; use one of:\n  %s",
			arg, len(matches), strings.Join(keys, "\n  "))
	}
}
