package log

import (
	"errors"
	"fmt"

	"github.com/nning/wg-p2p/types"
)

// SignatureStatus reports how far a record is from being authorized. It exists
// for the signing ceremony: with admin keys deliberately held on separate
// machines, whoever assembles a record needs to know what is still missing.
type SignatureStatus struct {
	// Votes is the weight of the valid admin signatures present.
	Votes uint32

	// Quorum is the weight required.
	Quorum uint32

	// SelfSigner is the node key that must also sign, if the record kind
	// requires one.
	SelfSigner *types.Identity

	// SelfSigned reports whether that signature is present and valid.
	SelfSigned bool

	// Untrusted lists signatures by keys the network does not trust for this
	// record. Any of them makes the record invalid outright, rather than
	// merely unauthorized.
	Untrusted []types.Identity

	// Invalid lists signers whose signature is present but does not verify.
	Invalid []types.Identity
}

// Authorized reports whether the record is fully authorized.
func (s SignatureStatus) Authorized() bool {
	return len(s.Untrusted) == 0 && len(s.Invalid) == 0 &&
		s.Votes >= s.Quorum && (s.SelfSigner == nil || s.SelfSigned)
}

// selfSigner returns the non-admin key a record must additionally be signed
// by, if any.
//
// Two kinds need one. A key rotation is signed by the node whose keys change:
// quorum decides that the membership may re-key, and the node's signature is
// what shows the new keys came from the device rather than from whoever asked.
// An identity rotation is signed by the *new* key, proving some device holds
// it — a membership slot bound to a key nobody has is a slot nobody can use
// and a record nobody can undo except by removal. The old key is deliberately
// not required: a planned rotation away from a key that is being retired is
// exactly the case where it may already be gone.
func selfSigner(a *types.AUM) *types.Identity {
	switch a.Kind {
	case types.KindRotateNodeKey:
		return a.Subject
	case types.KindRotateIdentity:
		return a.NewIdentity
	default:
		return nil
	}
}

// SelfSigner returns the non-admin key a record must additionally be signed
// by, or nil. It depends only on the record, so an admin holding nothing but a
// keystore can tell what a record needs.
func SelfSigner(a *types.AUM) *types.Identity { return selfSigner(a) }

// SignatureStatus evaluates a record's signatures against this state.
func (s *State) SignatureStatus(a *types.AUM) SignatureStatus {
	return signatureStatus(a, s.admins, s.quorum)
}

func signatureStatus(a *types.AUM, admins map[types.Identity]types.AdminKey, quorum uint32) SignatureStatus {
	st := SignatureStatus{Quorum: quorum, SelfSigner: selfSigner(a)}
	sigHash := a.SigHash()
	for i := range a.Signatures {
		sig := &a.Signatures[i]
		admin, isAdmin := admins[sig.KeyID]
		isSelf := st.SelfSigner != nil && sig.KeyID == *st.SelfSigner
		if !isAdmin && !isSelf {
			// A signature from a key that has no role in this record is not
			// ignored, it invalidates the record. Ignoring it would let
			// anyone mint a second valid encoding of an authorized record —
			// same content, extra signature, different hash — and forks are
			// expensive enough without handing out a way to manufacture them.
			st.Untrusted = append(st.Untrusted, sig.KeyID)
			continue
		}
		// Trust first, verify second: an untrusted key ID is a map lookup,
		// while a signature check is not, and a record may carry dozens.
		if !sig.KeyID.Verify(sigHash[:], sig.Sig) {
			st.Invalid = append(st.Invalid, sig.KeyID)
			continue
		}
		// A key can be both: an admin signing a rotation of its own device
		// satisfies the self-signature requirement and casts its votes.
		if isAdmin {
			st.Votes += admin.Votes
		}
		if isSelf {
			st.SelfSigned = true
		}
	}
	return st
}

// verifyAgainst checks that a record is authorized by the given authority
// state and chains to it.
//
// It answers only the authorization question. Whether the record's substance
// is acceptable — subject exists, no collisions, epoch covers the right
// members — is [State.apply]'s job.
func verifyAgainst(a *types.AUM, parent *State) error {
	if err := a.StaticValidate(); err != nil {
		return fmt.Errorf("log: %w", err)
	}
	if a.Kind == types.KindGenesis {
		return errors.New("log: a genesis record cannot follow another record")
	}
	if a.Prev == nil || *a.Prev != parent.head {
		return fmt.Errorf("log: record's parent is not %v", parent.head)
	}
	return checkStatus(a, parent.SignatureStatus(a))
}

// GenesisStatus reports how far a genesis record is from being authorized
// under the policy it declares.
//
// It exists because a genesis is the one record whose progress cannot be
// measured against a chain: there is no earlier state, and the node running the
// ceremony has no network yet. Without it a tool can only attempt creation and
// read failure, which cannot tell "this ceremony is still collecting
// signatures" — the normal state of a k-of-n genesis, where no single machine
// holds k keys — from "this record is broken".
func GenesisStatus(a *types.AUM) (SignatureStatus, error) {
	if a.Kind != types.KindGenesis {
		return SignatureStatus{}, fmt.Errorf("log: %v is not a genesis record", a.Kind)
	}
	if err := a.ValidateUnsigned(); err != nil {
		return SignatureStatus{}, fmt.Errorf("log: %w", err)
	}
	return signatureStatus(a, genesisAdmins(a), a.State.Quorum), nil
}

// genesisAdmins indexes the admin keys a genesis or self-signed checkpoint
// declares, which is what its own signatures are checked against.
func genesisAdmins(a *types.AUM) map[types.Identity]types.AdminKey {
	admins := make(map[types.Identity]types.AdminKey, len(a.State.Admins))
	for _, k := range a.State.Admins {
		admins[k.Public] = k
	}
	return admins
}

// verifyGenesis checks a genesis record against the admin keys it declares.
//
// Self-referential by necessity: there is no earlier state to check against.
// The consequence is that a genesis record is only as trustworthy as the way
// it reached you — which is why the genesis hash is what names the network
// everywhere afterwards, and why docs/02-threat-model.md treats the genesis
// ceremony as the root of trust rather than something the log can defend.
func verifyGenesis(a *types.AUM) error {
	if err := a.StaticValidate(); err != nil {
		return fmt.Errorf("log: %w", err)
	}
	if a.Kind != types.KindGenesis {
		return fmt.Errorf("log: %v is not a genesis record", a.Kind)
	}
	return checkStatus(a, signatureStatus(a, genesisAdmins(a), a.State.Quorum))
}

// verifyCheckpointSelfSigned checks a checkpoint against the admin keys it
// itself declares, for the one case where there is no ancestry to check it
// against: adopting a checkpoint as a bootstrap anchor.
//
// This is the weakest verification in the package and the only place history
// is taken on the signers' word. A node that holds the ancestry instead
// compares the checkpoint against the state the chain produces (see
// [State.apply]), which a mismatched checkpoint cannot survive.
func verifyCheckpointSelfSigned(a *types.AUM) error {
	if err := a.StaticValidate(); err != nil {
		return fmt.Errorf("log: %w", err)
	}
	if a.Kind != types.KindCheckpoint {
		return fmt.Errorf("log: %v is not a checkpoint", a.Kind)
	}
	return checkStatus(a, signatureStatus(a, genesisAdmins(a), a.State.Quorum))
}

func checkStatus(a *types.AUM, st SignatureStatus) error {
	if len(st.Untrusted) > 0 {
		return fmt.Errorf("log: %v record carries a signature by %v, which this network does not trust for it",
			a.Kind, st.Untrusted[0].ShortString())
	}
	if len(st.Invalid) > 0 {
		return fmt.Errorf("log: %v record has an invalid signature by %v",
			a.Kind, st.Invalid[0].ShortString())
	}
	if st.SelfSigner != nil && !st.SelfSigned {
		return fmt.Errorf("log: %v record is not signed by %v, whose key it changes",
			a.Kind, st.SelfSigner.ShortString())
	}
	if st.Votes < st.Quorum {
		return fmt.Errorf("log: %v record carries %d vote weight, quorum is %d",
			a.Kind, st.Votes, st.Quorum)
	}
	return nil
}
