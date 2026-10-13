package log

import (
	"errors"
	"fmt"
	"slices"

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

	// SelfSigners are the node keys that must also sign, if the record kind
	// requires any, and Unsigned those of them whose signature is missing.
	SelfSigners []types.Identity
	Unsigned    []types.Identity

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
		s.Votes >= s.Quorum && len(s.Unsigned) == 0
}

// SelfSigners returns the non-admin keys a record must additionally be signed
// by, under a network at schema. A key rotation is signed by the node whose
// keys change, which is what shows they came from the device. An identity
// rotation is signed by the new key, proving some device holds it, and from
// schema 1 by the old one too: otherwise admins alone could move a member's
// slot — an admin device's, with its role — to a key of their choosing, and
// the device it belonged to would have had no say. Schema 0 networks keep the
// rule they were written under. An admin key signs for its own encryption key,
// in a genesis as in [types.KindSetAdminRecipient], and for its signing key
// ([types.KindSetAdminSigning]).
func SelfSigners(a *types.AUM, schema types.SchemaVersion) []types.Identity {
	switch a.Kind {
	case types.KindGenesis:
		var out []types.Identity
		for _, k := range a.State.Admins {
			if k.Recipient != nil {
				out = append(out, k.Public)
			}
		}
		return out
	case types.KindSetAdminRecipient:
		return []types.Identity{*a.Subject}
	case types.KindSetAdminSigning:
		return []types.Identity{a.Signing.Members[0].Identity}
	case types.KindRotateNodeKey:
		return []types.Identity{*a.Subject}
	case types.KindRotateIdentity:
		if schema >= types.SchemaVouchers {
			return []types.Identity{*a.Subject, *a.NewIdentity}
		}
		return []types.Identity{*a.NewIdentity}
	default:
		return nil
	}
}

// SignAsDevice adds every signature of a device's that a record needs: those
// of the keys held, old and new, that it names as its self-signers.
func SignAsDevice(a *types.AUM, schema types.SchemaVersion, held ...types.PrivateIdentity) error {
	for _, want := range SelfSigners(a, schema) {
		for _, k := range held {
			if k.Public() == want {
				if err := a.SignUnder(k, schema); err != nil {
					return err
				}
				break
			}
		}
	}
	return nil
}

// SignatureStatus evaluates a record's signatures against this state.
func (s *State) SignatureStatus(a *types.AUM) SignatureStatus {
	return signatureStatus(a, s.admins, s.quorum, SelfSigners(a, s.schema), s.PQ(), s.SigningKey)
}

// signatureStatus evaluates a record's signatures: by ML-DSA where pq, against
// the key keyOf names or that the signature introduces; by Ed25519 where not.
func signatureStatus(a *types.AUM, admins map[types.Identity]types.AdminKey, quorum uint32,
	selfSigners []types.Identity, pq bool, keyOf func(types.Identity) *types.SigningKey) SignatureStatus {
	st := SignatureStatus{Quorum: quorum, SelfSigners: selfSigners}
	signed := map[types.Identity]bool{}
	voted := map[types.Identity]bool{}
	sigHash := a.SigHash()
	for i := range a.Signatures {
		sig := &a.Signatures[i]
		admin, isAdmin := admins[sig.KeyID]
		isSelf := slices.Contains(selfSigners, sig.KeyID)
		if !isAdmin && !isSelf {
			// A signature from a key with no role invalidates the record
			// rather than being ignored: otherwise anyone could mint a second
			// valid encoding of it, with a different hash.
			st.Untrusted = append(st.Untrusted, sig.KeyID)
			continue
		}
		// Trust first, verify second: an untrusted key ID is a map lookup,
		// while a signature check is not, and a record may carry dozens.
		if !verifyEntry(a, sig, sigHash, pq, keyOf) {
			st.Invalid = append(st.Invalid, sig.KeyID)
			continue
		}
		// A key can be both: an admin signing a rotation of its own device
		// satisfies the self-signature requirement and casts its votes.
		if isAdmin {
			voted[admin.Public] = true
		}
		if isSelf {
			signed[sig.KeyID] = true
		}
	}
	for _, id := range selfSigners {
		if !signed[id] {
			st.Unsigned = append(st.Unsigned, id)
		}
	}
	// A holder's keys vote together, once, and only as many as it needs.
	if len(voted) > 0 {
		keys := make([]types.AdminKey, 0, len(admins))
		for _, k := range admins {
			keys = append(keys, k)
		}
		st.Votes = types.CountVotes(keys, func(id types.Identity) bool { return voted[id] })
	}
	return st
}

// verifyAgainst checks that a record is authorized by the given authority
// state and chains to it. Whether its substance is acceptable is
// [State.apply]'s job.
func verifyAgainst(a *types.AUM, parent *State) error { return verify(a, parent, false) }

// verify is [verifyAgainst], or with votesPending everything but the quorum
// and the signatures of the keys the record changes, for a record still
// collecting them.
func verify(a *types.AUM, parent *State, votesPending bool) error {
	validate := a.StaticValidate
	if votesPending {
		validate = a.ValidateUnsigned
	}
	if err := validate(); err != nil {
		return reject(RuleMalformed, fmt.Errorf("log: %w", err))
	}
	if a.Kind == types.KindGenesis {
		return reject(RuleMalformed, errors.New("log: a genesis record cannot follow another record"))
	}
	if a.Prev == nil || *a.Prev != parent.head {
		return reject(RuleParent, fmt.Errorf("log: record's parent is not %v", parent.head))
	}
	if a.Kind == types.KindDisable {
		if !parent.ValidDisablement(a.Secret[:]) {
			return reject(RuleUnauthorized, errors.New("log: disable record reveals none of this network's break-glass secrets"))
		}
		return nil
	}
	st := parent.SignatureStatus(a)
	if votesPending {
		st.Votes, st.Unsigned = max(st.Votes, st.Quorum), nil
	}
	return checkStatus(a, st)
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
	return signatureStatus(a, genesisAdmins(a), a.State.Quorum, SelfSigners(a, a.State.Schema),
		a.State.Schema >= types.SchemaMLDSA, stateKeys(a.State)), nil
}

// stateKeys looks signing keys up in a genesis's or checkpoint's own state.
func stateKeys(snap *types.Snapshot) func(types.Identity) *types.SigningKey {
	return func(id types.Identity) *types.SigningKey {
		if k, ok := snap.Admin(id); ok && k.Signing != nil {
			return k.Signing
		}
		if n, ok := snap.Node(id); ok && n.Signing != nil {
			return n.Signing
		}
		return nil
	}
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

// verifySelfSigned checks a genesis, or a checkpoint adopted as a bootstrap
// anchor, against the admin keys it declares. Self-referential by necessity:
// such a record is only as trustworthy as the way it reached you, the one
// place history is taken on the signers' word. A node that later holds a
// checkpoint's ancestry compares it against what the chain produces.
func verifySelfSigned(a *types.AUM, kind types.Kind) error {
	if err := a.StaticValidate(); err != nil {
		return reject(RuleMalformed, fmt.Errorf("log: %w", err))
	}
	if a.Kind != kind {
		return reject(RuleMalformed, fmt.Errorf("log: %v is not a %v record", a.Kind, kind))
	}
	var self []types.Identity
	if kind == types.KindGenesis {
		self = SelfSigners(a, a.State.Schema)
	}
	return checkStatus(a, signatureStatus(a, genesisAdmins(a), a.State.Quorum, self,
		a.State.Schema >= types.SchemaMLDSA, stateKeys(a.State)))
}

// SignedBy reports whether a carries a valid signature by id, under this
// state's rules: whether id may sign it is [State.SignatureStatus]'s.
func (s *State) SignedBy(a *types.AUM, id types.Identity) bool {
	sig, ok := a.Signature(id)
	return ok && s.ValidSignature(a, sig)
}

// ValidSignature reports whether sig is a valid signature of a under this
// state's rules.
func (s *State) ValidSignature(a *types.AUM, sig *types.Signature) bool {
	return verifyEntry(a, sig, a.SigHash(), s.PQ(), s.SigningKey)
}

// verifyEntry checks one signature of a record: past the cut-over by ML-DSA,
// carrying the key where the record introduces it alone; below, by Ed25519.
func verifyEntry(a *types.AUM, sig *types.Signature, sigHash types.Hash, pq bool,
	keyOf func(types.Identity) *types.SigningKey) bool {
	if !pq {
		return sig.PQ == nil && sig.Key == nil && sig.KeyID.Verify(sigHash[:], sig.Sig)
	}
	if sig.PQ == nil || !sig.Sig.IsZero() || (sig.Key != nil) != a.Introduces(sig.KeyID) {
		return false
	}
	key := sig.Key
	if key == nil {
		key = keyOf(sig.KeyID)
	}
	return key != nil && key.Verify(sigHash[:], sig.PQ)
}

func checkStatus(a *types.AUM, st SignatureStatus) error {
	var err error
	switch {
	case len(st.Untrusted) > 0:
		err = fmt.Errorf("log: %v record carries a signature by %v, which this network does not trust for it",
			a.Kind, st.Untrusted[0].ShortString())
	case len(st.Invalid) > 0:
		err = fmt.Errorf("log: %v record has an invalid signature by %v",
			a.Kind, st.Invalid[0].ShortString())
	case len(st.Unsigned) > 0:
		err = fmt.Errorf("log: %v record is not signed by %v, whose key it changes",
			a.Kind, st.Unsigned[0].ShortString())
	case st.Votes < st.Quorum:
		err = fmt.Errorf("log: %v record carries %d vote weight, quorum is %d",
			a.Kind, st.Votes, st.Quorum)
	default:
		return nil
	}
	return reject(RuleUnauthorized, err)
}
