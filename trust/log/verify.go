package log

import (
	"errors"
	"fmt"

	"github.com/nning/juist/types"
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
// by, if any. A key rotation is signed by the node whose keys change, which is
// what shows they came from the device. An identity rotation is signed by the
// new key, proving some device holds it; the old key is deliberately not
// required, since a planned rotation is where it may already be gone.
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
			// A signature from a key with no role invalidates the record
			// rather than being ignored: otherwise anyone could mint a second
			// valid encoding of it, with a different hash.
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
// state and chains to it. Whether its substance is acceptable is
// [State.apply]'s job.
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
// under the policy it declares. A genesis is the one record whose progress
// cannot be measured against a chain, so without this a tool cannot tell a
// ceremony still collecting signatures from a broken record.
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
// Self-referential by necessity, so a genesis is only as trustworthy as the
// way it reached you — which is why its hash names the network afterwards.
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
// declares, for adopting one as a bootstrap anchor. The weakest verification
// in the package and the only place history is taken on the signers' word; a
// node holding the ancestry compares it against what the chain produces.
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
