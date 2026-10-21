package gossip

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/nning/juist/internal/aead"
	"github.com/nning/juist/internal/malformed"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// A catch-up lets a member that holds no epoch its peers still speak sync
// again by identity: it signs a nonce the peer draws, the peer checks its own
// current log lists it and seals a session key to the recipient keys that log
// names, and the four-frame session then runs under that key.
//
//	initiator → ask        in the clear, under [catchUpEpoch]
//	responder → challenge  a nonce
//	initiator → proof      its identity, and a signature over the nonce
//	responder → grant      a session key only that member can open, signed;
//	                       or a signed refusal, naming the responder's epoch
//
// The initiator cannot tell yet whether the responder is a member — it may be
// one under an identity its log has not caught up with — so it speaks last:
// its hello carries nothing but what it holds, it takes the responder's
// records first, and it sends its own, its announcements and its leases only
// once its log lists the responder.
//
// Epoch labels start at 1, so a build without catch-up reads the ask as a
// frame under an epoch it does not hold and hangs up.
const catchUpEpoch = 0

// maxCatchUpMsg caps a catch-up message; a grant, the largest, is about
// 3.6 KiB.
const maxCatchUpMsg = 8 << 10

const catchUpNonceSize = 32

// ErrCatchUpRefused is a member ahead of this node whose log does not list it:
// most likely it was removed.
var ErrCatchUpRefused = errors.New("gossip: the peer's log does not list this node")

// CatchUpKeys are this node's identity key, which signs its steps of a
// catch-up, and its recipient keys, which open a grant.
type CatchUpKeys struct {
	Identity  types.PrivateIdentity
	Recipient *secrets.PrivateKeys
}

type catchUpStep uint8

const (
	stepInvalid   catchUpStep = 0
	stepAsk       catchUpStep = 1
	stepChallenge catchUpStep = 2
	stepProof     catchUpStep = 3
	stepGrant     catchUpStep = 4
	stepRefused   catchUpStep = 5
)

func (s catchUpStep) String() string {
	switch s {
	case stepAsk:
		return "ask"
	case stepChallenge:
		return "challenge"
	case stepProof:
		return "proof"
	case stepGrant:
		return "grant"
	case stepRefused:
		return "refusal"
	default:
		return fmt.Sprintf("step?<%d>", uint8(s))
	}
}

// A catchUpMsg is one step of the exchange. Each step carries exactly its own
// fields: a proof, a grant and a refusal are signed by their sender, by
// Ed25519 and ML-DSA.
type catchUpMsg struct {
	Step     catchUpStep     `cbor:"1,keyasint"`
	Nonce    []byte          `cbor:"2,keyasint,omitempty"`
	Identity *types.Identity `cbor:"3,keyasint,omitempty"`
	Sig      *types.Sig      `cbor:"4,keyasint,omitempty"`
	Sealed   []byte          `cbor:"5,keyasint,omitempty"`
	Epoch    uint64          `cbor:"6,keyasint,omitempty"`
	MLDSA    *types.PQSig    `cbor:"7,keyasint,omitempty"`
}

func (m *catchUpMsg) validate() error {
	nonce, sealed, epoch := m.Nonce != nil, m.Sealed != nil, m.Epoch != 0
	signed := m.Identity != nil && m.Sig != nil
	unsigned := m.Identity == nil && m.Sig == nil && m.MLDSA == nil
	if m.MLDSA != nil && m.MLDSA.IsZero() {
		return errors.New("gossip: a catch-up message carries a zero ML-DSA signature")
	}
	switch m.Step {
	case stepAsk:
		if nonce || sealed || epoch || !unsigned {
			return errors.New("gossip: a catch-up ask must carry nothing")
		}
	case stepChallenge:
		if len(m.Nonce) != catchUpNonceSize || sealed || epoch || !unsigned {
			return errors.New("gossip: a catch-up challenge must carry a nonce and nothing else")
		}
	case stepProof:
		if !signed || nonce || sealed || epoch {
			return errors.New("gossip: a catch-up proof must carry an identity and a signature and nothing else")
		}
	case stepGrant:
		if len(m.Sealed) != types.SealedSecretSize || !signed || nonce || epoch {
			return errors.New("gossip: a catch-up grant must carry a sealed key and a signature and nothing else")
		}
	case stepRefused:
		if !epoch || !signed || nonce || sealed {
			return errors.New("gossip: a catch-up refusal must carry an epoch and a signature and nothing else")
		}
	default:
		return fmt.Errorf("gossip: catch-up message has %v", m.Step)
	}
	return nil
}

// decodeCatchUp decodes and shape-checks a catch-up message's body.
func decodeCatchUp(b []byte) (_ catchUpMsg, err error) {
	defer malformed.Recover(&err)
	if len(b) > maxCatchUpMsg {
		return catchUpMsg{}, fmt.Errorf("gossip: catch-up message is %d bytes, over the %d limit", len(b), maxCatchUpMsg)
	}
	m, err := types.DecodeCanonical[catchUpMsg](decMode, b, MaxFrameSize)
	if err != nil {
		return catchUpMsg{}, err
	}
	if err := m.validate(); err != nil {
		return catchUpMsg{}, err
	}
	return m, nil
}

// catchUpSigned is what a step's signature covers: the network, so a device in
// two networks cannot have one carried to the other, the responder's nonce, so
// none is good for a second session, and the initiator it concerns.
func catchUpSigned(label string, network types.Hash, nonce []byte, initiator types.Identity, rest ...[]byte) []byte {
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(network[:])
	h.Write(nonce)
	h.Write(initiator[:])
	for _, b := range rest {
		h.Write(b)
	}
	return h.Sum(nil)
}

func catchUpProofBytes(network types.Hash, nonce []byte, id types.Identity) []byte {
	return catchUpSigned(types.LabelCatchUpProof, network, nonce, id)
}

func catchUpGrantBytes(network types.Hash, nonce []byte, initiator types.Identity, sealed []byte) []byte {
	return catchUpSigned(types.LabelCatchUpGrant, network, nonce, initiator, sealed)
}

func catchUpRefusalBytes(network types.Hash, nonce []byte, initiator types.Identity, epoch uint64) []byte {
	return catchUpSigned(types.LabelCatchUpRefusal, network, nonce, initiator, binary.BigEndian.AppendUint64(nil, epoch))
}

// isCatchUp reports whether a blob read off the stream opens a catch-up
// rather than an ordinary session.
func isCatchUp(blob []byte) bool {
	return len(blob) >= aead.EpochLen && binary.BigEndian.Uint64(blob[:aead.EpochLen]) == catchUpEpoch
}

func writeCatchUp(c net.Conn, m *catchUpMsg) error {
	body, err := encode(m)
	if err != nil {
		return err
	}
	blob := make([]byte, aead.EpochLen, aead.EpochLen+len(body))
	return writeBlob(c, append(blob, body...), m.Step.String())
}

func readCatchUp(c net.Conn) (catchUpMsg, error) {
	blob, err := readBlob(c)
	if err != nil {
		return catchUpMsg{}, err
	}
	return parseCatchUp(blob)
}

func parseCatchUp(blob []byte) (catchUpMsg, error) {
	if !isCatchUp(blob) {
		return catchUpMsg{}, errors.New("gossip: expected a catch-up message, got a sealed frame")
	}
	return decodeCatchUp(blob[aead.EpochLen:])
}

// askCatchUp runs the initiator's half of the exchange and returns the
// session key the grant carried, and who signed it — which the caller does not
// yet know to be a member. view's epoch is this node's: a refusal from a peer
// that is not past it is a peer that is behind, not a verdict on this node.
// The proof is signed by both keys, and the answer must be too, by the key
// this node's log names for its signer, where it names one.
func (n *Node) askCatchUp(c net.Conn, view *View) (*[secrets.CatchUpKeySize]byte, types.Identity, error) {
	network, own := view.Network, view.Epoch
	keys := n.opts.CatchUp
	if err := writeCatchUp(c, &catchUpMsg{Step: stepAsk}); err != nil {
		return nil, types.Identity{}, err
	}
	ch, err := readCatchUp(c)
	if err != nil {
		return nil, types.Identity{}, fmt.Errorf("%w: %w", errNoCatchUp, err)
	}
	if ch.Step != stepChallenge {
		return nil, types.Identity{}, fmt.Errorf("gossip: expected a catch-up challenge, got a %v", ch.Step)
	}
	self := n.opts.Self
	sig, pq, err := keys.Identity.SignBoth(catchUpProofBytes(network, ch.Nonce, self))
	if err != nil {
		return nil, types.Identity{}, err
	}
	if err := writeCatchUp(c, &catchUpMsg{Step: stepProof, Identity: &self, Sig: &sig, MLDSA: pq}); err != nil {
		return nil, types.Identity{}, err
	}
	ans, err := readCatchUp(c)
	if err != nil {
		return nil, types.Identity{}, fmt.Errorf("gossip: the peer took the catch-up proof and answered nothing: %w", err)
	}
	if ans.Step != stepGrant && ans.Step != stepRefused {
		return nil, types.Identity{}, fmt.Errorf("gossip: expected a catch-up grant, got a %v", ans.Step)
	}
	// Both steps are signed, which validate guarantees. One by a key the log
	// names is held to its ML-DSA signature; one by an identity it does not
	// name, as a member rotated to while this node slept, is taken on no
	// authority: this node speaks only once its log lists it.
	from := *ans.Identity
	key := n.opts.Log.SigningKey(from)
	signedBy := func(msg []byte) bool {
		return from.Verify(msg, *ans.Sig) && (key == nil || key.Verify(msg, ans.MLDSA))
	}
	switch {
	case ans.Step == stepRefused:
		if !signedBy(catchUpRefusalBytes(network, ch.Nonce, self, ans.Epoch)) {
			return nil, from, errors.New("gossip: a catch-up refusal is not signed by the key it names")
		}
		// Only a member this node knows, and one ahead of it, speaks for the
		// network: anyone may refuse, and a peer behind has merely not seen
		// this node admitted yet.
		if _, listed, err := n.opts.Log.Member(from); err != nil || !listed {
			return nil, from, fmt.Errorf("gossip: refused a catch-up by %v, which this node's log does not list", from.ShortString())
		}
		if ans.Epoch <= own {
			return nil, from, fmt.Errorf("gossip: refused a catch-up by %v, at epoch %d and not yet past this node's %d",
				from.ShortString(), ans.Epoch, own)
		}
		return nil, from, ErrCatchUpRefused
	case from == self:
		return nil, from, errors.New("gossip: a catch-up grant names this node")
	case !signedBy(catchUpGrantBytes(network, ch.Nonce, self, ans.Sealed)):
		return nil, from, errors.New("gossip: a catch-up grant is not signed by the key it names")
	}
	session, err := secrets.OpenCatchUp(network, self, n.recipient.Load(), ch.Nonce, ans.Sealed)
	if err != nil {
		return nil, from, fmt.Errorf("gossip: %w", err)
	}
	return &session, from, nil
}

// errNoCatchUp is a peer that hung up on the ask: a build without catch-up.
var errNoCatchUp = errors.New("the peer does not answer a catch-up")

// grantCatchUp runs the responder's half, given the ask already read, and
// returns the session key it granted and to whom. A proof that does not
// verify gets nothing; a verified one the log does not list gets a refusal
// where it was once listed ([Node.onceListed]), and nothing otherwise.
func (n *Node) grantCatchUp(c net.Conn, ask []byte, view *View) (*[secrets.CatchUpKeySize]byte, types.Identity, error) {
	m, err := parseCatchUp(ask)
	if err != nil {
		return nil, types.Identity{}, err
	}
	if m.Step != stepAsk {
		return nil, types.Identity{}, fmt.Errorf("gossip: a catch-up began with a %v", m.Step)
	}
	keys := n.opts.CatchUp
	if keys == nil {
		return nil, types.Identity{}, errors.New("gossip: this node holds no keys to answer a catch-up with")
	}
	nonce := make([]byte, catchUpNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, types.Identity{}, fmt.Errorf("gossip: drawing a catch-up nonce: %w", err)
	}
	if err := writeCatchUp(c, &catchUpMsg{Step: stepChallenge, Nonce: nonce}); err != nil {
		return nil, types.Identity{}, err
	}
	proof, err := readCatchUp(c)
	if err != nil {
		return nil, types.Identity{}, err
	}
	if proof.Step != stepProof {
		return nil, types.Identity{}, fmt.Errorf("gossip: expected a catch-up proof, got a %v", proof.Step)
	}
	id, network := *proof.Identity, view.Network
	msg := catchUpProofBytes(network, nonce, id)
	if !id.Verify(msg, *proof.Sig) {
		return nil, id, fmt.Errorf("gossip: a catch-up proof for %v does not verify", id.ShortString())
	}
	if id == n.opts.Self {
		return nil, id, errors.New("gossip: a catch-up proof names this node")
	}
	rec, listed, err := n.opts.Log.Member(id)
	if err != nil {
		return nil, id, fmt.Errorf("gossip: not answering the catch-up of %v: %w", id.ShortString(), err)
	}
	self := n.opts.Self
	if !listed {
		if !n.onceListed(id, msg, proof.MLDSA) {
			return nil, id, fmt.Errorf("gossip: not answering the catch-up of %v, which the log has not listed", id.ShortString())
		}
		sig, mldsa, err := keys.Identity.SignBoth(catchUpRefusalBytes(network, nonce, id, view.Epoch))
		if err != nil {
			return nil, id, err
		}
		if err := writeCatchUp(c, &catchUpMsg{Step: stepRefused, Identity: &self, Sig: &sig, Epoch: view.Epoch,
			MLDSA: mldsa}); err != nil {
			return nil, id, err
		}
		return nil, id, fmt.Errorf("gossip: refused the catch-up of %v, which the log does not list", id.ShortString())
	}
	if rec.Signing == nil || !rec.Signing.Verify(msg, proof.MLDSA) {
		return nil, id, fmt.Errorf("gossip: a catch-up proof for %v carries no valid ML-DSA signature", id.ShortString())
	}
	key, sealed, err := secrets.SealCatchUp(network, &rec, nonce)
	if err != nil {
		return nil, id, fmt.Errorf("gossip: %w", err)
	}
	sig, mldsa, err := keys.Identity.SignBoth(catchUpGrantBytes(network, nonce, id, sealed))
	if err != nil {
		return nil, id, err
	}
	if err := writeCatchUp(c, &catchUpMsg{Step: stepGrant, Sealed: sealed, Identity: &self, Sig: &sig,
		MLDSA: mldsa}); err != nil {
		return nil, id, err
	}
	n.logf("gossip: granted %v a catch-up", id.ShortString())
	return &key, id, nil
}

// onceListed reports whether id, which the log does not list as a member now,
// is owed a refusal: one its chain once named, whose proof verifies under the
// signing key it had then. Anyone else is not told who this node is.
func (n *Node) onceListed(id types.Identity, proof []byte, pq *types.PQSig) bool {
	key := n.opts.Log.ListedSigningKey(id)
	return key != nil && key.Verify(proof, pq)
}

// stillMember reports whether the counterpart of a catch-up session is a
// member now: the log may have moved on since the grant, and the counterpart
// sets the pace.
func (n *Node) stillMember(id types.Identity) error {
	_, listed, err := n.opts.Log.Member(id)
	switch {
	case err != nil:
		return fmt.Errorf("not going on with the catch-up of %v: %w", id.ShortString(), err)
	case !listed:
		return fmt.Errorf("the log does not list %v, the other side of this catch-up", id.ShortString())
	}
	return nil
}
