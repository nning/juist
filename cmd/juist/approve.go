package main

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/nning/juist/internal/changelog"
	"github.com/nning/juist/internal/waiting"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

func cmdApprove(a *app, args []string) error {
	s := spec{name: "juist approve", args: "[FILE...]", max: -1, about: `
Sign change files with this keystore's admin keys, in place, and apply each
once fully approved. Without files, ask about each change waiting for your
vote on this admin device. Alias: juist apply.

Each change's effect is shown from the record and the log, never from the
file's name or comments. Changes to who may approve need the log here.
Records that do not fit this device's log are refused: a signature cannot be
taken back.`}
	fs := newFlags(s.name)
	r := &approval{a: a}
	fs.BoolVar(&r.noApply, "no-apply", false, "sign only")
	fs.StringVar(&a.keyName, "key", "", "sign with the admin key `NAME` only, as \"juist admins\" lists it")
	fs.BoolVar(&r.yes, "yes", false, "do not ask")
	files, err := a.parse(s, fs, args)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		if r.yes || r.noApply {
			return fmt.Errorf("--yes and --no-apply take files: a waiting change is asked about\n%s", s.usage(fs))
		}
		return a.approveWaiting()
	}
	// A genesis belongs to no network this device is in: one founded on a
	// device in some already runs beside them, as with juist create.
	if allGenesis(a, files) {
		a.purpose = forFounding
	} else if r.auth, err = a.optionalLog(); err != nil {
		return err
	}
	r.haveNetwork = r.auth != nil
	// Whatever is fully approved when a later file fails is applied all the
	// same, rather than left signed and waiting.
	for _, path := range files {
		if err := r.file(path); err != nil {
			return errors.Join(r.flush(), err)
		}
	}
	return r.flush()
}

// allGenesis reports whether every file holds a genesis record.
func allGenesis(a *app, files []string) bool {
	for _, path := range files {
		aum, err := readRecordFile(a.path(path))
		if err != nil || aum.Kind != types.KindGenesis {
			return false
		}
	}
	return true
}

// An approval is one run of "juist approve" over its files.
type approval struct {
	a               *app
	noApply, yes    bool
	auth            *log.Authority // nil on a machine with no network
	haveNetwork     bool
	warnedUnchecked bool

	// batch is the fully approved records not applied yet, read from paths.
	// They are applied together, as one delivery: two changes started at the
	// same point are siblings, and fork choice has to see both to pick the
	// right one. A record that builds on one of them applies the batch first.
	batch []types.AUM
	paths []string
}

func (r *approval) flush() error {
	a := r.a
	if len(r.batch) == 0 {
		return nil
	}
	if err := a.applyRecords(r.batch, false); err != nil {
		return err
	}
	var err error
	if r.auth, err = a.freshLog(); err != nil {
		return err
	}
	// A record the chain does not hold lost fork choice to a sibling: asked
	// of the chain, since a daemon hands over only that.
	chain, err := a.node.chain()
	if err != nil {
		return err
	}
	held := map[[32]byte]bool{}
	for i := range chain {
		held[chain[i].SigHash()] = true
	}
	for i, p := range r.paths {
		if !held[r.batch[i].SigHash()] {
			a.warn("%s lost to a concurrent change; not applied, redo it", p)
		} else {
			a.ok("%s: applied", p)
		}
	}
	r.batch, r.paths = nil, nil
	return nil
}

// file checks, shows, signs and settles one change file.
func (r *approval) file(path string) error {
	a := r.a
	aum, err := readRecordFile(a.path(path))
	if err != nil {
		return err
	}
	if n := len(r.batch); n > 0 && aum.Prev != nil && *aum.Prev == r.batch[n-1].Hash() {
		if err := r.flush(); err != nil {
			return err
		}
	}
	if done, err := r.check(path, &aum); done || err != nil {
		return err
	}
	var state *log.State
	if r.haveNetwork {
		state = r.auth.State()
	}
	a.printf("%s: %s\n", path, describeKind(aum.Kind))
	for _, line := range effect(&aum, state, a.now().Unix()) {
		a.printf("  %s\n", line)
	}
	if state != nil {
		if n, ok := voucherLost(state, &aum); ok {
			// Asked by "approve?" below.
			if err := a.checkAdminDeviceLoss(state, n, true); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		}
	}
	part, signed, err := a.partIn(&aum, r.auth)
	if err != nil {
		return err
	}
	if part && !signed {
		if ok, err := r.sign(path, &aum); !ok || err != nil {
			return err
		}
	} else if signed {
		a.printf("  signed by you already\n")
	}
	return r.settle(path, aum, part, signed)
}

// check refuses a change that does not fit this device's log, and is done
// with one the log holds already.
func (r *approval) check(path string, aum *types.AUM) (done bool, err error) {
	a := r.a
	if aum.Kind == types.KindGenesis {
		return false, nil
	}
	if !r.haveNetwork {
		if changesAuthority(aum) {
			return false, fmt.Errorf("%s may change who approves or vouches (%s); approve it where the log is",
				path, describeKind(aum.Kind))
		}
		if !r.warnedUnchecked {
			a.warn("no network here; records unchecked, and your signature spoils one from a network " +
				"your key does not govern")
			r.warnedUnchecked = true
		}
		return false, nil
	}
	err = a.checkApplicable(path, r.auth, aum)
	if !errors.Is(err, errInLog) {
		return false, err
	}
	a.ok("%s: in the log already", path)
	// Handed on all the same: it is a no-op, and what has this device adopt
	// a rotation of its own keys at once.
	return true, a.applyRecords([]types.AUM{*aum}, false)
}

// sign asks, then signs aum with every admin key here that has a part in it
// and writes it back; ok is false where the person said no.
func (r *approval) sign(path string, aum *types.AUM) (ok bool, err error) {
	a := r.a
	if r.auth != nil && r.auth.Disabled() != nil {
		return false, fmt.Errorf("%q is disabled; nothing changes it any more", r.auth.State().Network())
	}
	if !r.yes {
		if ok, err := a.confirm("approve?"); err != nil || !ok {
			if err == nil {
				a.printf("  not approved\n")
			}
			return false, err
		}
	}
	added, err := a.signLocally(aum, r.auth)
	if err != nil {
		return false, err
	}
	if err := writeRecordFile(a.path(path), aum); err != nil {
		return false, err
	}
	for _, id := range added {
		a.ok("%s: signed as %s", path, a.adminName(r.auth, id))
	}
	return true, nil
}

// settle applies a change that is fully approved, or says what it needs.
func (r *approval) settle(path string, aum types.AUM, part, signed bool) error {
	a := r.a
	switch {
	case aum.Kind == types.KindGenesis:
		st, err := log.GenesisStatus(&aum)
		if err != nil {
			return err
		}
		founder := fileExists(a.home.join(genesisFileFor(aum.State.Network)))
		if st.Authorized() && !r.haveNetwork && founder && !r.noApply {
			return a.createFromGenesis([]types.AUM{aum})
		}
		if !st.Authorized() && (!part || signed) {
			return fmt.Errorf("%s needs %s; no key here can add one", path,
				approvalsNeeded(st, aum.State.Admins, &aum))
		}
		a.reportGenesisStatus(path, &aum)
	case r.auth == nil:
		a.printf("  apply on a device in the network: juist approve %s\n", path)
	default:
		sst := r.auth.State().SignatureStatus(&aum)
		switch {
		case !sst.Authorized() && (!part || signed) && len(sst.Untrusted)+len(sst.Invalid) == 0:
			return fmt.Errorf("%s needs %s; no key here can add one", path,
				approvalsNeeded(sst, r.auth.State().Admins(), &aum))
		case !sst.Authorized():
			a.reportStatus(path, sst, r.auth.State().Admins(), &aum)
			if part {
				r.carryApproval(&aum)
			}
		case r.noApply:
			a.printf("  approved; apply: juist approve %s\n", path)
		default:
			r.batch, r.paths = append(r.batch, aum), append(r.paths, path)
		}
	}
	return nil
}

// carryApproval hands on a change approved from its file: for as long as it
// waits on the admin devices already, or where it waits nowhere, for as long
// as a change may, but for an admission, which waits no longer than its
// invite and so is never carried from a file.
func (r *approval) carryApproval(aum *types.AUM) {
	a := r.a
	changes, err := a.waitingChanges(r.auth)
	if err != nil {
		a.warn("%v", err)
		return
	}
	ttl, proposer := waiting.MaxLifetime, types.Identity{}
	switch i := slices.IndexFunc(changes, func(w waitingChange) bool { return w.aum.SigHash() == aum.SigHash() }); {
	case i >= 0:
		// With the votes the copies carry, the proposer's among them.
		aum.Signatures = mergeSignatures(r.auth.State(), aum, changes[i].aum.Signatures)
		ttl, proposer = time.Unix(changes[i].expires, 0).Sub(a.now()), changes[i].proposer
	case aum.Kind == types.KindAddNode:
		return
	default:
		proposer = a.handedOn(r.auth.State(), aum)
	}
	if _, _, err := a.carry(r.auth, aum, ttl, proposer); err != nil {
		a.warn("%v", err)
	}
}

// handedOn is who handed on a change approved from its file before any copy
// of it arrived: the one admin key that signed it and is not this keystore's,
// zero where there is none, or more.
func (a *app) handedOn(state *log.State, aum *types.AUM) types.Identity {
	files, err := a.adminKeyFiles()
	if err != nil {
		return types.Identity{}
	}
	var other types.Identity
	hash := aum.SigHash()
	for _, s := range aum.Signatures {
		_, admin := state.Admin(s.KeyID)
		mine := slices.ContainsFunc(files, func(k adminKeyFile) bool { return k.priv.Public() == s.KeyID })
		switch {
		case !admin || mine || !s.KeyID.Verify(hash[:], s.Sig):
		case !other.IsZero():
			return types.Identity{}
		default:
			other = s.KeyID
		}
	}
	return other
}

// createFromGenesis completes a genesis ceremony whose record collected the
// rest of its quorum elsewhere: no single machine holds k keys.
func (a *app) createFromGenesis(records []types.AUM) error {
	if len(records) != 1 || records[0].Kind != types.KindGenesis {
		return errNoNetwork
	}
	genesis := records[0]
	status, err := log.GenesisStatus(&genesis)
	if err != nil {
		return err
	}
	if !status.Authorized() {
		return fmt.Errorf("cannot create the network yet: needs %s",
			approvalsNeeded(status, genesis.State.Admins, &genesis))
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	op, err := defaultOperator(optionalString{}, n.status())
	if err != nil {
		return err
	}
	if err := n.create(genesis, op); err != nil {
		return err
	}
	_ = os.Remove(a.home.join(genesisFileFor(genesis.State.Network)))
	a.markFounded(genesis.State.Network)
	return a.reportCreated(nil, nil)
}

func (a *app) reportGenesisStatus(path string, aum *types.AUM) {
	st, err := log.GenesisStatus(aum)
	if err != nil {
		a.warn("%s: %v", path, err)
		return
	}
	if st.Authorized() {
		a.printf("  approved; the founder runs: juist approve %s\n", path)
		return
	}
	a.reportStatus(path, st, aum.State.Admins, aum)
}

// reportStatus says what a record still needs, so the operator knows whether
// to pass it on.
func (a *app) reportStatus(path string, st log.SignatureStatus, keys []types.AdminKey, aum *types.AUM) {
	kind := aum.Kind
	switch {
	case len(st.Untrusted) > 0:
		a.warn("%s spoiled: %v may not sign a %s; redo the change", path, st.Untrusted[0].ShortString(),
			describeKind(kind))
	case len(st.Invalid) > 0:
		a.warn("%s spoiled: bad signature by %v", path, st.Invalid[0].ShortString())
	default:
		a.printf("  needs %s; pass it on\n", approvalsNeeded(st, keys, aum))
	}
}

// describeKind names a record kind the way an operator thinks of it.
func describeKind(k types.Kind) string { return changelog.KindName(k) }
