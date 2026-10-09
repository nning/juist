package main

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nning/juist/internal/waiting"
	"github.com/nning/juist/ipc"

	"go4.org/netipx"

	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// A change is a record this device built, on its way into the log.
type change struct {
	aum types.AUM

	// file is the name a record still collecting approvals is written under,
	// and written the path submit wrote it to, if it did.
	file, written string

	// done describes the change once applied, as a sentence.
	done string

	// wait is how long the change waits for more votes on the admin devices,
	// zero for as long as a change may.
	wait time.Duration
}

// needsUpgrade refuses what the network's schema predates.
func needsUpgrade(what string) error {
	return fmt.Errorf("the network predates %s\nhint: once every device runs this version: juist log upgrade", what)
}

// errNotSubmitted marks a failure before the change could reach any log: the
// one case in which whatever was prepared for it can be thrown away.
type errNotSubmitted struct{ err error }

func (e errNotSubmitted) Error() string { return e.err.Error() }
func (e errNotSubmitted) Unwrap() error { return e.err }

// submit signs a change with every local key that has a part in it, and
// applies it if that authorizes it. Otherwise it writes the record out for the
// other admins, which is an outcome rather than a failure: a quorum of more
// than one admin means no single machine can finish the change.
func (a *app) submit(auth *log.Authority, c *change) (applied bool, err error) {
	if _, err := a.signLocally(&c.aum, auth); err != nil {
		return false, errNotSubmitted{err}
	}
	// A record nobody here could sign is no change, only a proposal, and one
	// the next admin could as well start themselves. A device's own rotation
	// is signed by the device, and is what an admin approves.
	if len(c.aum.Signatures) == 0 {
		return false, errNotSubmitted{fmt.Errorf("no admin key of this network in %s\nhint: run it where "+
			"an admin's key is", a.home.path)}
	}
	st := auth.State().SignatureStatus(&c.aum)
	if st.Authorized() {
		if err := a.applyRecords([]types.AUM{c.aum}, false); err != nil {
			return false, err
		}
		a.ok("%s", c.done)
		return true, nil
	}
	path, err := a.writePending(c.file, &c.aum)
	if err != nil {
		return false, errNotSubmitted{err}
	}
	c.written = path
	carried, unread, err := a.carry(auth, &c.aum, cmp.Or(c.wait, waiting.MaxLifetime), types.Identity{})
	if err != nil {
		a.warn("%v", err)
	}
	needs := approvalsNeeded(st, auth.State().Admins(), &c.aum)
	if carried {
		a.printf("pending %s: needs %s; another admin runs, on an admin device or with the file:\n", path, needs)
		a.commands("juist approve", "juist approve "+filepath.Base(path))
	} else {
		a.printf("pending %s: needs %s; another admin runs:\n", path, needs)
		a.command("juist approve %s", filepath.Base(path))
	}
	if len(unread) > 0 && auth.State().Schema() >= types.SchemaSealing && a.node != nil && a.node.status() != nil {
		a.hint("%s cannot read it on an admin device yet; send them the file", strings.Join(unread, " or "))
	}
	return false, nil
}

// approvalsNeeded says what a record still needs, by admin: whose vote it
// lacks, and whose further keys, where an admin needs several to sign. keys
// are the admin keys that vote on it, and aum the record as signed so far.
func approvalsNeeded(st log.SignatureStatus, keys []types.AdminKey, aum *types.AUM) string {
	votes := count(missing(st), "more vote")
	var from []string
	for _, p := range adminPeople(keys) {
		signed := 0
		var on []string
		for _, k := range p.keys {
			if aum.VerifySignature(k.Public) {
				signed++
			} else if m := keyMachine(k); m != "" {
				on = append(on, m)
			}
		}
		where := ""
		if len(on) > 0 {
			where = " on " + strings.Join(on, " or ")
		}
		switch need := int(p.keys[0].NeededKeys()); {
		case signed >= need:
		case signed > 0:
			from = append(from, fmt.Sprintf("%s more of %s's keys%s (%d of %d signed)", fmt.Sprint(need-signed),
				p.name, where, signed, need))
		default:
			from = append(from, p.name+where)
		}
	}
	if len(from) > 0 && missing(st) > 0 {
		votes += ", from " + strings.Join(from, " or ")
	}
	switch n := missing(st); {
	case n == 0 && len(st.Unsigned) > 0:
		return "the device's own signature"
	case len(st.Unsigned) > 0:
		return votes + ", and the device's own signature"
	default:
		return votes
	}
}

func missing(st log.SignatureStatus) uint32 {
	if st.Votes >= st.Quorum {
		return 0
	}
	return st.Quorum - st.Votes
}

// writePending writes a record to the working directory under name, or a
// variant of it if that is taken: a file there may be another change still
// collecting approvals. It returns the name it wrote.
func (a *app) writePending(name string, aum *types.AUM) (string, error) {
	base := strings.TrimSuffix(name, ".rec")
	for i := 1; i < 100; i++ {
		path := base + ".rec"
		if i > 1 {
			path = base + "-" + strconv.Itoa(i) + ".rec"
		}
		err := writeNewRecordFile(a.path(path), aum)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return path, err
	}
	return "", fmt.Errorf("%s.rec and 98 variants of it exist already", base)
}

// signLocally adds every admin signature this keystore can usefully give. An
// untrusted signature spoils a record rather than failing to count, so a key
// signs only where the network trusts it — or, with no log to ask, where it
// may be the air-gapped key the record is waiting for. A device's own
// signature, which rotations need, is added where its keys are.
func (a *app) signLocally(aum *types.AUM, auth *log.Authority) ([]types.Identity, error) {
	if auth != nil && auth.Disabled() != nil {
		return nil, fmt.Errorf("%q is disabled; nothing changes it any more", auth.State().Network())
	}
	admins, err := a.signingKeys(aum, auth)
	if err != nil {
		return nil, err
	}
	var added []types.Identity
	for _, key := range admins {
		id := key.Public()
		if aum.VerifySignature(id) || !wanted(aum, id, auth) {
			continue
		}
		if aum.Sign(key) == nil {
			added = append(added, id)
		}
	}
	if aum.Kind == types.KindGenesis && aum.State != nil && len(added) > 0 && a.sudoUser() == "" {
		a.home.fileAdminKeys(aum.State.Network, func(id types.Identity) bool { return slices.Contains(added, id) })
	}
	return added, nil
}

// signingKeys are the admin keys here that may sign aum: the one --key
// names, or every one. Without a log to ask, keys filed under different
// networks are refused together, since each spoils the other's records.
func (a *app) signingKeys(aum *types.AUM, auth *log.Authority) ([]types.PrivateIdentity, error) {
	files, err := a.adminKeyFiles()
	if err != nil {
		return nil, err
	}
	if a.keyName != "" {
		for _, k := range files {
			if k.name == a.keyName {
				return []types.PrivateIdentity{k.priv}, nil
			}
		}
		return nil, fmt.Errorf("--key: no admin key %q here\nhint: juist admins", a.keyName)
	}
	// Keys filed under one network are that network's; any other two may be
	// two networks'.
	if auth == nil && aum.Kind != types.KindGenesis && len(files) > 1 {
		var names []string
		one := files[0].network() != ""
		for _, k := range files {
			names = append(names, k.name)
			one = one && k.network() == files[0].network()
		}
		if !one {
			return nil, fmt.Errorf("no log here to say which admin key is this network's: %s\n"+
				"hint: juist approve --key NAME FILE", strings.Join(names, ", "))
		}
	}
	return privateKeys(files), nil
}

// partIn reports whether any admin key here may sign aum, and whether every
// such key already has.
func (a *app) partIn(aum *types.AUM, auth *log.Authority) (part, signed bool, err error) {
	admins, err := a.signingKeys(aum, auth)
	if err != nil {
		return false, false, err
	}
	signed = true
	for _, key := range admins {
		if id := key.Public(); wanted(aum, id, auth) {
			part = true
			signed = signed && (aum.VerifySignature(id) || auth != nil && votedAlready(auth.State(), aum, id))
		}
	}
	return part, part && signed, nil
}

// votedAlready reports whether the admin holding id has cast their vote on
// aum with other keys: another signature by this key would add nothing.
func votedAlready(state *log.State, aum *types.AUM, id types.Identity) bool {
	k, ok := state.Admin(id)
	if !ok || k.Holder == "" {
		return false
	}
	signed := 0
	for _, other := range holderKeys(state, k.Holder) {
		if aum.VerifySignature(other.Public) {
			signed++
		}
	}
	return uint32(signed) >= k.NeededKeys()
}

// adminName is how an admin key is shown: by the person it belongs to, and
// the machine it is kept on, where the log names them.
func (a *app) adminName(auth *log.Authority, id types.Identity) string {
	if auth != nil {
		if k, ok := auth.State().Admin(id); ok && keyPerson(k) != "" {
			if m := keyMachine(k); m != "" {
				return keyPerson(k) + "'s key on " + m
			}
			return keyPerson(k)
		}
	}
	return id.ShortString()
}

// count is n with word, in the plural where n is not one.
func count[N ~int | ~uint | ~uint32 | ~uint64](n N, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// errInLog is checkApplicable's answer for a change the log already has.
var errInLog = errors.New("in the log already")

// checkApplicable refuses a record that cannot apply to the log as this
// device holds it, before anyone signs it: a signature cannot be taken back,
// and one on a record built before the latest change would, if the record
// then won fork choice over that change, undo it and everything after.
func (a *app) checkApplicable(path string, auth *log.Authority, aum *types.AUM) error {
	chain, err := a.node.chain()
	if err != nil {
		return err
	}
	parent := -1
	for i := range chain {
		if chain[i].SigHash() == aum.SigHash() {
			return errInLog
		}
		if chain[i].Hash() == *aum.Prev {
			parent = i
		}
	}
	if parent < 0 {
		return fmt.Errorf("%s: another network's, or follows changes not received here yet\nhint: let this "+
			"device catch up, or approve where the admin key is", path)
	}
	// Refused whatever it is. It forks the log where it was started, and a
	// revocation there would win and undo every change since, a removal of
	// its own signers' keys included; anything else would win or lose on
	// its hash. Started again, it is judged against the log as it is.
	if parent < len(chain)-1 {
		return fmt.Errorf("%s: outdated by a later change\nhint: whoever started it redoes it", path)
	}
	if _, err := auth.Builder().Check(aum); err != nil {
		return fmt.Errorf("%s does not apply; not signed: %v", path, err)
	}
	return nil
}

func wanted(aum *types.AUM, id types.Identity, auth *log.Authority) bool {
	// Genesis is checked against the keys it declares, not any earlier state.
	if aum.Kind == types.KindGenesis && aum.State != nil {
		_, ok := aum.State.Admin(id)
		return ok
	}
	if auth == nil {
		return true
	}
	_, isAdmin := auth.State().Admin(id)
	return isAdmin
}

// adminKeys loads this user's admin keys. Run under sudo, the keystore is
// root's, which is rarely what was meant: the keys belong to the person.
func (a *app) adminKeys() ([]types.PrivateIdentity, error) {
	files, err := a.adminKeyFiles()
	return privateKeys(files), err
}

func (a *app) adminKeyFiles() ([]adminKeyFile, error) {
	files, err := a.home.adminKeyFiles()
	if err != nil || len(files) > 0 {
		return files, err
	}
	if u := a.sudoUser(); u != "" {
		return nil, fmt.Errorf("run as %s, without sudo: admin keys are in your keystore", u)
	}
	return nil, nil
}

// sudoUser names who ran sudo when juist runs as root through it on the
// default keystore — root's, which is not where that person's admin keys
// are, nor where new ones belong. Every command that writes to the keystore
// refuses then.
func (a *app) sudoUser() string {
	if u := os.Getenv("SUDO_USER"); u != "" && u != "root" && os.Geteuid() == 0 && !a.homeExplicit {
		return u
	}
	return ""
}

// applyRecords commits authorized records to this device's node: through the
// daemon if one runs, which owns the log and gossips them at once.
func (a *app) applyRecords(records []types.AUM, report bool) error {
	n, err := a.openNode()
	if err != nil {
		return err
	}
	if auth, err := n.log(); err == nil && auth.Disabled() != nil &&
		slices.ContainsFunc(records, func(r types.AUM) bool { return r.Kind != types.KindDisable }) {
		return fmt.Errorf("%q is disabled; nothing changes it any more", auth.State().Network())
	}
	// A rotation of this device's keys is adopted where the keys are; what
	// the device calls itself before and after says whether it happened.
	var before *ipc.Self
	if slices.ContainsFunc(records, func(r types.AUM) bool {
		return r.Kind == types.KindRotateNodeKey || r.Kind == types.KindRotateIdentity
	}) {
		before, _ = n.self()
	}
	if err := n.apply(records); err != nil {
		return err
	}
	if before != nil {
		if after, err := n.self(); err == nil && (after.Keys != before.Keys || after.Identity != before.Identity) {
			a.ok("new keys live")
		}
	}
	auth, err := n.log()
	if err != nil {
		return err
	}
	if alarm := auth.Alarm(); alarm != nil {
		a.alarm("%v", alarm)
	}
	if report {
		st := auth.State()
		a.ok("applied %s; %s", count(len(records), "change"), count(len(st.Nodes()), "device"))
	}
	return nil
}

// networkLog is this device's verified log. The member list is the
// operator's to read, so a user who is not one is offered to become it.
func (a *app) networkLog() (*log.Authority, error) {
	n, err := a.openNode()
	if err != nil {
		return nil, err
	}
	if err := a.requireOperator(); err != nil {
		return nil, err
	}
	auth, err := n.log()
	if err == nil && a.sudoUser() == "" {
		state := auth.State()
		a.home.fileAdminKeys(state.Network(), func(id types.Identity) bool {
			_, ok := state.Admin(id)
			return ok
		})
	}
	return auth, err
}

// optionalLog is networkLog where a machine with no network is a normal
// state: an air-gapped admin machine holds keys and nothing else.
func (a *app) optionalLog() (*log.Authority, error) {
	auth, err := a.networkLog()
	if errors.Is(err, errNoNetwork) {
		return nil, nil
	}
	return auth, err
}

// freshLog drops what this invocation has read of the log, for a caller
// waiting on a change made elsewhere.
func (a *app) freshLog() (*log.Authority, error) {
	if a.node != nil {
		a.node.forget()
	}
	return a.networkLog()
}

// selfID is this device's identity, if it has one yet.
func (a *app) selfID() (types.Identity, bool, error) {
	n, err := a.openNode()
	if err != nil {
		return types.Identity{}, false, err
	}
	if st := n.status(); st != nil {
		return st.Self, true, nil
	}
	k, err := a.home.optionalNodeKeys()
	if err != nil || k == nil {
		return types.Identity{}, false, err
	}
	return k.Identity.Public(), true, nil
}

// resolveDevice finds a member by name, identity key, the start of one, or
// an overlay address.
func resolveDevice(state *log.State, arg string) (types.NodeRecord, error) {
	nodes := state.Nodes()
	var matches []types.NodeRecord
	addr, addrErr := netip.ParseAddr(arg)
	for _, n := range nodes {
		switch {
		case strings.EqualFold(n.Name, arg),
			n.Identity.String() == arg,
			len(arg) >= 8 && strings.HasPrefix(n.Identity.String(), arg),
			len(arg) >= 8 && strings.HasPrefix(n.Identity.String(), "nid:"+arg),
			addrErr == nil && (state.Addr6(n.Identity) == addr || slices.Contains(n.V4Addrs(), addr)):
			matches = append(matches, n)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return types.NodeRecord{}, fmt.Errorf("no device %q in %q\nhint: juist devices", arg, state.Network())
	default:
		names := make([]string, len(matches))
		for i, m := range matches {
			names[i] = displayMember(m) + " " + m.Identity.ShortString()
		}
		return types.NodeRecord{}, fmt.Errorf("%q matches %d devices (%s); use a key",
			arg, len(matches), strings.Join(names, ", "))
	}
}

func displayMember(n types.NodeRecord) string {
	if n.Name != "" {
		return n.Name
	}
	return n.Identity.ShortString()
}

// sealer returns the epoch sealer, drawing a fresh group secret per epoch. The
// secret is not kept: every member recovers it from its own wrap.
func sealer() log.Sealer {
	return func(epoch uint64, members []types.NodeRecord) (*types.EpochRecord, error) {
		_, rec, err := secrets.NewEpoch(epoch, members)
		return rec, err
	}
}

// nextV4 returns the lowest overlay IPv4 address in the network's range that
// is not [givenOut]: handing on one a removed device still believes it holds
// would have members route one device's traffic to another. history includes
// the records off the chain, whose admissions may yet be reissued.
func nextV4(state *log.State, history []types.AUM) (netip.Addr, error) {
	taken := map[netip.Addr]bool{}
	for v4 := range givenOut(state, history) {
		taken[v4] = true
	}
	v4, err := firstFreeV4(state.V4Range(), taken)
	if err != nil && len(state.Nodes()) < types.MaxNodes {
		// Full by history rather than by members: every address has been
		// given out once. A range of its own is 1022 addresses for good.
		return netip.Addr{}, fmt.Errorf("%w: every address in it went to a device once, and none is "+
			"handed out twice\nhint: juist network renumber PREFIX, into a larger range", err)
	}
	return v4, err
}

// firstFreeV4 skips r's first and last address, which some systems treat as
// the network and broadcast address.
func firstFreeV4(r netip.Prefix, taken map[netip.Addr]bool) (netip.Addr, error) {
	last := netipx.PrefixLastIP(r)
	for a := r.Addr().Next(); a.Less(last); a = a.Next() {
		if !taken[a] {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("IPv4 range %v full", r)
}

// uniqueName returns name, or name with a number appended if a member already
// uses it: devices are removed and addressed by name, so two alike are a trap.
//
// Names are compared as resolveDevice compares them, folded, so that no two
// members are told apart only by what "juist remove" ignores.
func uniqueName(state *log.State, name string) string {
	used := map[string]bool{}
	for _, n := range state.Nodes() {
		used[foldName(n.Name)] = true
	}
	if !used[foldName(name)] {
		return name
	}
	for i := 2; ; i++ {
		suffix := fmt.Sprintf("-%d", i)
		base := name
		for len(base)+len(suffix) > types.MaxNameLen {
			_, size := utf8.DecodeLastRuneInString(base)
			base = base[:len(base)-size]
		}
		candidate := strings.TrimRight(base, " \t") + suffix
		if types.ValidateName(candidate) == nil && !used[foldName(candidate)] {
			return candidate
		}
	}
}

// fileSafe turns a member name into something usable in a file name.
func fileSafe(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "device"
	}
	return b.String()
}

// foldName is how names are compared: the log's rule for holders, and the
// CLI's for every other name.
func foldName(s string) string { return types.FoldName(s) }

// checkName holds a name a person gives — a device's, an admin key's, the
// network's — to one spelling: ASCII letters and digits, and ".", "_" and "-"
// after the first. The log accepts more, but names are what "juist remove"
// takes and what reaches everyone's terminal and command line, so a name
// that looks like another, or that a shell would read as code, is refused
// where it is first given.
func checkName(what, name string) error {
	if err := types.ValidateName(name); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	for i, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			i > 0 && strings.ContainsRune("._-", r)) {
			return fmt.Errorf("%s %q: letters, digits, then also . _ -", what, name)
		}
	}
	return nil
}

// memberName makes a name a joining device proposed into one checkName
// accepts: the device chose it, and the admin's log is where it ends up.
func memberName(proposed string) string {
	var b strings.Builder
	dash := false
	for _, r := range proposed {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_'
		switch {
		case ok:
			b.WriteRune(r)
			dash = false
		case b.Len() > 0 && !dash:
			b.WriteByte('-')
			dash = true
		}
	}
	name := strings.TrimLeft(strings.TrimRight(b.String(), "-"), "._-")
	if len(name) > types.MaxNameLen {
		name = strings.TrimRight(name[:types.MaxNameLen], "._-")
	}
	if name == "" || checkName("name", name) != nil {
		return "device"
	}
	return name
}
