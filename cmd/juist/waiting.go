package main

import (
	"cmp"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nning/juist/internal/waiting"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// Changes that wait for votes travel between the network's admin devices,
// sealed to the admins (internal/waiting): handed on where a change needs
// more votes than this keystore gives, and listed where one waits for a key
// of it.

// adminRecipient is an admin key's encryption key, which follows from it.
func adminRecipient(priv types.PrivateIdentity) (types.RecipientKey, error) {
	keys, err := secrets.AdminRecipient(priv.Seed())
	if err != nil {
		return types.RecipientKey{}, err
	}
	return keys.Recipient()
}

// A waitingChange is a change waiting for votes as the copies here show it.
type waitingChange struct {
	// aum carries the signatures of every copy that the network trusts.
	aum types.AUM
	// proposer is the admin key that handed the change on first, issued
	// when the earliest copy here was handed on, and expires when the last
	// stops waiting.
	proposer types.Identity
	issued   int64
	expires  int64
}

// carry hands aum to this device's juistd, for the network's other admin
// devices, sealed to every admin key with an encryption key and expiring
// after ttl; proposer is who proposed it, zero for this keystore. It reports
// whether it did, and the admins whose missing votes no key of theirs can
// read it for.
func (a *app) carry(auth *log.Authority, aum *types.AUM, ttl time.Duration, proposer types.Identity) (bool, []string,
	error) {
	state := auth.State()
	if state.Schema() < types.SchemaSealing || a.node == nil || a.node.status() == nil {
		return false, nil, nil
	}
	files, err := a.adminKeyFiles()
	if err != nil {
		return false, nil, err
	}
	i := slices.IndexFunc(files, func(k adminKeyFile) bool {
		_, admin := state.Admin(k.priv.Public())
		return admin && state.SignedBy(aum, k.priv.Public())
	})
	if i < 0 {
		return false, nil, nil
	}
	signer := files[i].priv
	held, err := a.node.waiting(nil)
	if err != nil {
		return false, nil, fmt.Errorf("handing the change on: %w", err)
	}
	// A copy that replaces this key's last one says so by its time.
	now := a.now()
	for _, b := range held {
		if c, err := waiting.Decode(b); err == nil && c.ID == aum.SigHash() && c.Signer == signer.Public() &&
			c.Issued >= now.Unix() {
			next := time.Unix(c.Issued+1, 0)
			ttl -= next.Sub(now)
			now = next
		}
	}
	c, err := waiting.Seal(state.GenesisHash(), aum, state.Admins(), state.SigningKey, signer, proposer, now, ttl)
	if errors.Is(err, waiting.ErrNoReaders) {
		return false, unreadable(state, aum, nil), nil
	}
	if err != nil {
		return false, nil, err
	}
	b, err := c.Encode()
	if err != nil {
		return false, nil, err
	}
	if _, err := a.node.waiting([][]byte{b}); err != nil {
		return false, nil, fmt.Errorf("handing the change on: %w", err)
	}
	return true, unreadable(state, aum, c), nil
}

// unreadable names the admins whose votes aum lacks and none of whose keys
// c is sealed to.
func unreadable(state *log.State, aum *types.AUM, c *waiting.Change) []string {
	var out []string
	for _, p := range adminPeople(state.Admins()) {
		signed := 0
		sealed := false
		for _, k := range p.keys {
			if aum.VerifySignature(k.Public, k.Signing) {
				signed++
			}
			sealed = sealed || c != nil && c.SealedTo(k.Public)
		}
		if uint32(signed) < p.keys[0].NeededKeys() && !sealed {
			out = append(out, p.name)
		}
	}
	return out
}

// waitingChanges lists the changes waiting here that a key of this keystore
// can read and that fit the log as it is, with the signatures of all their
// copies. A copy that is not what it says, or not from a current admin key,
// is dropped unseen.
func (a *app) waitingChanges(auth *log.Authority) ([]waitingChange, error) {
	n, err := a.openNode()
	if err != nil || n.status() == nil || auth.State().Schema() < types.SchemaSealing {
		return nil, err
	}
	files, err := a.adminKeyFiles()
	if err != nil || len(files) == 0 {
		return nil, err
	}
	raw, err := n.waiting(nil)
	if err != nil {
		return nil, err
	}
	state := auth.State()
	var out []waitingChange
	for _, b := range raw {
		c, err := waiting.Decode(b)
		if err != nil || c.Network != state.GenesisHash() || c.Prev != state.Head() || c.Expires <= a.now().Unix() {
			continue
		}
		if _, ok := state.Admin(c.Signer); !ok {
			continue
		}
		if state.PQ() && c.VerifyPQ(state.SigningKey(c.Signer)) != nil {
			continue
		}
		for _, k := range files {
			if !c.SealedTo(k.priv.Public()) {
				continue
			}
			aum, err := c.Open(k.priv, state.SigningKey)
			if err != nil {
				break
			}
			i := slices.IndexFunc(out, func(w waitingChange) bool { return w.aum.SigHash() == c.ID })
			if i < 0 {
				bare := aum
				bare.Signatures = nil
				out = append(out, waitingChange{aum: bare, proposer: c.Proposer, issued: c.Issued, expires: c.Expires})
				i = len(out) - 1
			}
			out[i].issued, out[i].expires = min(out[i].issued, c.Issued), max(out[i].expires, c.Expires)
			out[i].aum.Signatures = mergeSignatures(state, &out[i].aum, aum.Signatures)
			break
		}
	}
	slices.SortFunc(out, func(x, y waitingChange) int { return cmp.Compare(x.issued, y.issued) })
	return out, nil
}

// mergeSignatures adds to aum's signatures those of sigs that verify and that
// the network trusts for it: anything else would spoil it.
func mergeSignatures(state *log.State, aum *types.AUM, sigs []types.Signature) []types.Signature {
	out := slices.Clone(aum.Signatures)
	self := log.SelfSigners(aum, state.Schema())
	for _, s := range sigs {
		_, admin := state.Admin(s.KeyID)
		switch {
		case slices.ContainsFunc(out, func(o types.Signature) bool { return o.KeyID == s.KeyID }):
		case !admin && !slices.Contains(self, s.KeyID):
		case !state.ValidSignature(aum, &s):
		default:
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(x, y types.Signature) int { return x.KeyID.Compare(y.KeyID) })
	return out
}

// forMyVote are the waiting changes a key of this keystore has yet to sign.
func (a *app) forMyVote(auth *log.Authority, changes []waitingChange) ([]waitingChange, error) {
	var out []waitingChange
	for _, w := range changes {
		part, signed, err := a.partIn(&w.aum, auth)
		if err != nil {
			return nil, err
		}
		if part && !signed {
			out = append(out, w)
		}
	}
	return out, nil
}

// summary is one line on a waiting change: what it does, and who proposed it.
func (a *app) summary(auth *log.Authority, w *waitingChange) string {
	what := describeKind(w.aum.Kind)
	if lines := effect(&w.aum, auth.State(), a.now().Unix()); len(lines) > 0 {
		what = lines[0]
	}
	return fmt.Sprintf("%s, proposed by %s", what, a.adminName(auth, w.proposer))
}

// waitingNote says in a status which changes wait for this keystore's vote.
// It says nothing where it cannot tell.
func (a *app) waitingNote() {
	auth, err := a.networkLog()
	if err != nil {
		return
	}
	changes, err := a.waitingChanges(auth)
	if err != nil {
		return
	}
	mine, err := a.forMyVote(auth, changes)
	if err != nil || len(mine) == 0 {
		return
	}
	var what []string
	for i := range mine {
		what = append(what, a.summary(auth, &mine[i]))
	}
	verb := "waits"
	if len(mine) > 1 {
		verb = "wait"
	}
	a.printf("\n%s %s for your vote: %s\n", count(len(mine), "change"), verb, strings.Join(what, "; "))
	a.hint("juist approve")
}

// approveWaiting asks about each change waiting for this keystore's vote,
// shown from the log here, and signs those the person approves: applied where
// that completes the quorum, and handed on again where it does not.
func (a *app) approveWaiting() error {
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	changes, err := a.waitingChanges(auth)
	if err != nil {
		return err
	}
	mine, err := a.forMyVote(auth, changes)
	if err != nil {
		return err
	}
	if len(mine) == 0 {
		a.printf("no change waits for your vote\n")
		return nil
	}
	for i := range mine {
		w := &mine[i]
		if i > 0 {
			// An approval before this one may have moved the log past it.
			if auth, err = a.freshLog(); err != nil {
				return err
			}
			if *w.aum.Prev != auth.State().Head() {
				a.printf("%s: outdated by the change before it\n", describeKind(w.aum.Kind))
				continue
			}
		}
		if err := a.approveOne(auth, w); err != nil {
			return err
		}
	}
	return nil
}

func (a *app) approveOne(auth *log.Authority, w *waitingChange) error {
	a.printf("%s, proposed by %s:\n", describeKind(w.aum.Kind), a.adminName(auth, w.proposer))
	for _, line := range effect(&w.aum, auth.State(), a.now().Unix()) {
		a.printf("  %s\n", line)
	}
	if err := a.checkApplicable("the change", auth, &w.aum); err != nil {
		a.warn("%v", err)
		return nil
	}
	if n, ok := voucherLost(auth.State(), &w.aum); ok {
		if err := a.checkAdminDeviceLoss(auth.State(), n, true); err != nil {
			a.warn("%v", err)
			return nil
		}
	}
	if auth.Disabled() != nil {
		return fmt.Errorf("%q is disabled; nothing changes it any more", auth.State().Network())
	}
	ok, err := a.askNow(a.ctx, "approve?")
	if err != nil {
		return err
	}
	if !ok {
		a.printf("  not approved\n")
		return nil
	}
	if a.now().Unix() >= w.expires {
		a.printf("  expired while you were asked; not approved\n")
		return nil
	}
	added, err := a.signLocally(&w.aum, auth)
	if err != nil {
		return err
	}
	for _, id := range added {
		a.ok("signed as %s", a.adminName(auth, id))
	}
	st := auth.State().SignatureStatus(&w.aum)
	if st.Authorized() {
		if err := a.applyRecords([]types.AUM{w.aum}, false); err != nil {
			return err
		}
		a.ok("applied")
		return nil
	}
	needs := approvalsNeeded(st, auth.State().Admins(), &w.aum)
	carried, _, err := a.carry(auth, &w.aum, time.Unix(w.expires, 0).Sub(a.now()), w.proposer)
	if err == nil && carried {
		a.printf("  needs %s\n", needs)
		return nil
	}
	// The signature is given; where it cannot travel, a file keeps it, but
	// for an admission, which must not outlive its invite.
	if w.aum.Kind == types.KindAddNode {
		return fmt.Errorf("your approval of the admission could not be handed on: %w", cmp.Or(err,
			errors.New("no admin device takes it")))
	}
	path, ferr := a.writePending("approved-"+w.aum.Kind.String()+".rec", &w.aum)
	if ferr != nil {
		return errors.Join(err, ferr)
	}
	if err != nil {
		a.warn("%v", err)
	}
	a.printf("pending %s: needs %s; another admin runs:\n", path, needs)
	a.command("juist approve %s", filepath.Base(path))
	return nil
}
