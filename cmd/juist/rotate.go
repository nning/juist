package main

import (
	"errors"
	"fmt"
	"slices"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// rotations are what "juist rotate" replaces other than this device's keys.
var rotations = []string{"identity", "group-secret", "abandon"}

func cmdRotate(a *app, args []string) error {
	s := spec{name: "juist rotate", args: "[identity|group-secret|abandon]", max: 1, about: `
Replace keys.

  juist rotate                 this device's WireGuard and sealing keys;
                               name and addresses stay
  juist rotate identity        this device's identity key; its IPv6 moves
  juist rotate group-secret    the network's group secret, after a leak
  juist rotate abandon         drop a rotation awaiting approval`}
	pos, err := a.parse(s, newFlags(s.name), args)
	if err != nil {
		return err
	}
	what := ""
	if len(pos) == 1 {
		what = pos[0]
	}
	if what != "" && !slices.Contains(rotations, what) {
		return fmt.Errorf("unknown rotation %q%s\n%s", what, didYouMean(what, rotations...), s.usage(nil))
	}
	switch what {
	case "abandon":
		return rotateAbandon(a)
	case "group-secret":
		return rotateGroupSecret(a)
	default:
		return rotateKeys(a, what == "identity")
	}
}

// rotateAbandon needs no log: it is this device's staged keys alone.
func rotateAbandon(a *app) error {
	n, err := a.openNode()
	if err != nil {
		return err
	}
	if err := a.requireOperator(); err != nil {
		return err
	}
	if err := n.unstage(); err != nil && err.Error() == ipc.ErrNothingStaged {
		a.ok("no rotation pending")
		return nil
	} else if err != nil {
		return err
	}
	a.ok("rotation abandoned")
	return nil
}

func rotateGroupSecret(a *app) error {
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	aum, err := auth.Builder().EpochBump(sealer())
	if err != nil {
		return err
	}
	_, err = a.submit(auth, &change{aum: aum, file: "rotate-group-secret.rec", done: "rotated the group secret"})
	return err
}

// rotateKeys has the node stage new keys, and the admins approve the record
// naming them.
func rotateKeys(a *app, identity bool) error {
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	n, err := a.openNode()
	if err != nil {
		return err
	}
	self, _, err := a.selfID()
	if err != nil {
		return err
	}
	me, ok := auth.State().Node(self)
	if !ok {
		return errors.New("this device is not a member")
	}
	if identity && auth.State().Schema() < types.SchemaSignedRotation {
		return needsUpgrade("rotating an identity key")
	}
	aum, proof, err := n.rotate(identity)
	if err != nil {
		return err
	}
	if err := checkRotation(auth, self, identity, &aum, proof); err != nil {
		// Not signed, so no log can name the staged keys.
		_ = n.unstage()
		return err
	}
	if identity {
		a.printf("new identity key %v\n", aum.NewIdentity.ShortString())
	} else {
		a.printf("new keys %s\n", keysDigest(*aum.Keys))
	}
	_, err = a.submit(auth, &change{aum: aum, file: "rotate-" + fileSafe(displayMember(me)) + ".rec",
		done: "rotated this device's keys"})
	var notSubmitted errNotSubmitted
	switch {
	case errors.As(err, &notSubmitted):
		// No log can name the staged keys, so they can go.
		_ = n.unstage()
	case err != nil:
		// The record may have reached the log regardless — a daemon that timed
		// out answering may still apply it — and deleting keys the log comes
		// to name would cut this device off.
		err = fmt.Errorf("%w\nhint: the new keys stay staged until the log names them or: juist rotate abandon", err)
	}
	return err
}

// checkRotation holds the less trusted daemon's rotation record, before any
// admin key here signs it, to what this device's verified log builds from its
// new keys and sealed epoch alone, signed by the device and proven by its
// current identity key; docs/11-enrollment-and-freshness-notes.md says why.
func checkRotation(auth *log.Authority, self types.Identity, identity bool, aum *types.AUM, proof types.Sig) error {
	refuse := errors.New("juistd answered with a record that is not this rotation; not signed. " +
		"If this recurs, juistd here may be compromised")
	if aum.Subject == nil || *aum.Subject != self || !self.Verify(ipc.RotationProof(aum), proof) {
		return refuse
	}
	if st := auth.State().SignatureStatus(aum); len(st.Unsigned) > 0 || len(st.Invalid) > 0 ||
		len(st.Untrusted) > 0 {
		return refuse
	}
	epoch := func(uint64, []types.NodeRecord) (*types.EpochRecord, error) { return aum.Epoch, nil }
	var want types.AUM
	var err error
	switch {
	case identity && aum.Kind == types.KindRotateIdentity && aum.NewIdentity != nil && aum.NewSigning != nil:
		want, err = auth.Builder().RotateIdentity(self, *aum.NewIdentity, *aum.NewSigning, epoch)
	case !identity && aum.Kind == types.KindRotateNodeKey && aum.Keys != nil:
		want, err = auth.Builder().RotateNodeKey(self, *aum.Keys, epoch)
	default:
		return refuse
	}
	if err != nil || want.SigHash() != aum.SigHash() {
		return refuse
	}
	return nil
}
