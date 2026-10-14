package enroll

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/nning/juist/types"
)

// A MessageKind says what a [Message] inside the channel does. Numbers are
// permanent; 0 is invalid.
type MessageKind uint8

const (
	msgInvalid MessageKind = 0

	// KindJoin is the guest asking to be admitted, with its public keys.
	KindJoin MessageKind = 1

	// KindWaiting is the host reporting that admission is waiting for more
	// admins to approve it.
	KindWaiting MessageKind = 2

	// KindRecord carries one log record, anchor first.
	KindRecord MessageKind = 3

	// KindWelcome ends the log and carries hints for finding the members.
	KindWelcome MessageKind = 4

	// KindJoined is the guest confirming it verified and stored the log.
	KindJoined MessageKind = 5

	// KindRefused is either side giving up, with a reason for its operator.
	KindRefused MessageKind = 6

	// KindCompare is the host handing the guest the salt the words a person
	// compares on both screens are made from; see [Fingerprint].
	KindCompare MessageKind = 7

	// KindReveal is the guest's answer to it: the nonce its join request
	// committed to, which goes into the words too.
	KindReveal MessageKind = 8
)

func (k MessageKind) String() string {
	switch k {
	case msgInvalid:
		return "no kind"
	case KindJoin:
		return "join request"
	case KindWaiting:
		return "waiting"
	case KindRecord:
		return "record"
	case KindWelcome:
		return "welcome"
	case KindJoined:
		return "joined"
	case KindRefused:
		return "refusal"
	case KindCompare:
		return "words to compare"
	case KindReveal:
		return "the words' nonce"
	default:
		return fmt.Sprintf("message?<%d>", uint8(k))
	}
}

// Limits on what a message may carry, before anything in it is verified.
const (
	// maxWelcomeItems bounds a welcome's announcements and leases.
	maxWelcomeItems = types.MaxNodes

	// MaxReasonLen bounds a refusal's text.
	MaxReasonLen = 512

	// MaxRecords bounds how many records a host may send.
	MaxRecords = 1 << 16
)

// A Message is one unit of the enrollment conversation. Exactly the field
// its kind names is set.
type Message struct {
	Kind    MessageKind  `cbor:"1,keyasint"`
	Join    *JoinRequest `cbor:"2,keyasint,omitempty"`
	Waiting *Waiting     `cbor:"3,keyasint,omitempty"`

	// Record is an encoded AUM, which enters only through types.DecodeAUM.
	Record []byte `cbor:"4,keyasint,omitempty"`

	Welcome *Welcome `cbor:"5,keyasint,omitempty"`
	Reason  string   `cbor:"6,keyasint,omitempty"`
	Compare *Salt    `cbor:"7,keyasint,omitempty"`
	Reveal  *Nonce   `cbor:"8,keyasint,omitempty"`

	// Announcement, optional on a KindJoined, is the guest's signed endpoint
	// record as it starts in the network, which the host checks as it would
	// any announcement. It is how the host learns where the guest is when the
	// guest can open no connection to it.
	Announcement []byte `cbor:"9,keyasint,omitempty"`
}

// MaxAnnouncementLen bounds a guest's announcement.
const MaxAnnouncementLen = 4096

// A Salt is what the inviting admin draws once it has seen a join request,
// for the words both screens show.
type Salt [16]byte

// A Nonce is what the guest draws before it asks to join, commits to in the
// request ([CommitNonce]), and reveals once it holds the admin's salt. Each
// side fixes its value before it learns the other's, so neither can search
// for a pair that makes two devices' words agree.
type Nonce [16]byte

// CommitNonce is what a join request carries for n.
func CommitNonce(n Nonce) [32]byte {
	return sha256.Sum256(append([]byte("juist words commit v1\x00"), n[:]...))
}

// A JoinRequest is what a guest asks to be admitted as.
type JoinRequest struct {
	// Name is the member name the device proposes. The host may override it.
	Name string `cbor:"1,keyasint,omitempty"`

	Identity types.Identity `cbor:"2,keyasint"`
	Keys     types.NodeKeys `cbor:"3,keyasint"`

	// Proof is the identity key's signature over the channel binding: the
	// guest holds the key it asks to be admitted under, in this session.
	Proof types.Sig `cbor:"4,keyasint"`

	// Commit is [CommitNonce] of the nonce the guest reveals once it holds
	// the admin's salt.
	Commit [32]byte `cbor:"5,keyasint"`

	// Signing is the guest's ML-DSA key, and SigningProof its signature over
	// what Proof covers: the guest holds it, in this session.
	Signing      types.SigningKey `cbor:"6,keyasint"`
	SigningProof types.PQSig      `cbor:"7,keyasint"`
}

// Waiting reports an admission that needs more approvals than the host holds.
type Waiting struct {
	Votes  uint32 `cbor:"1,keyasint"`
	Quorum uint32 `cbor:"2,keyasint"`
}

// A Welcome ends the log a host sends. Its hints are self-certifying, so it
// adds no trust the records do not already carry.
type Welcome struct {
	// Name is the member name the device was admitted under.
	Name string `cbor:"1,keyasint,omitempty"`

	// Records is how many record messages preceded this one.
	Records uint32 `cbor:"2,keyasint"`

	// Endpoints are signed member announcements, as gossip encodes them.
	Endpoints [][]byte `cbor:"3,keyasint,omitempty"`

	// Leases are encoded freshness leases.
	Leases [][]byte `cbor:"4,keyasint,omitempty"`

	// Admission is the inviting admin's statement that the guest is in the
	// log it was sent. A guest whose link names that admin requires it.
	Admission *Admission `cbor:"5,keyasint,omitempty"`
}

// An Admission is an admin key's signed statement that a guest is a member
// of a network as of a head. It is what binds a guest to the admin who
// invited it rather than to whatever answered: the device that runs the
// invite holds the invite's secret and sends the log, so a compromised
// daemon there could otherwise enroll the guest into a network of its own.
// The admin signs only after checking the log against its own keystore's
// anchor, and the link the guest was handed names the admin's key.
type Admission struct {
	Admin   types.Identity `cbor:"1,keyasint"`
	Network types.Hash     `cbor:"2,keyasint"`
	Head    types.Hash     `cbor:"3,keyasint"`
	Guest   types.Identity `cbor:"4,keyasint"`
	Sig     types.Sig      `cbor:"5,keyasint"`

	// Signing is the admin key's signing key, which the link names by
	// fingerprint, and MLDSA its signature.
	MLDSA   types.PQSig      `cbor:"6,keyasint"`
	Signing types.SigningKey `cbor:"7,keyasint"`
}

// SignAdmission states that guest is a member of network as of head.
func SignAdmission(admin types.PrivateIdentity, network, head types.Hash, guest types.Identity) (*Admission, error) {
	a := &Admission{Admin: admin.Public(), Network: network, Head: head, Guest: guest, Signing: admin.SigningKey()}
	sig, pq, err := admin.SignBoth(a.message())
	if err != nil {
		return nil, err
	}
	a.Sig, a.MLDSA = sig, *pq
	return a, nil
}

// Verify checks the admission's signatures by the key it names, whose
// signing key fingerprint names, as a link does, and that it is key, the one
// the log names for the admin key.
func (a *Admission) Verify(fingerprint [fingerprintLen]byte, key *types.SigningKey) error {
	switch {
	case SigningFingerprint(&a.Signing) != fingerprint:
		return errors.New("enroll: the admission is signed by another signing key than the link names")
	case key != nil && *key != a.Signing:
		return errors.New("enroll: the admission is signed by another signing key than the log names")
	case !a.Admin.Verify(a.message(), a.Sig) || !a.Signing.Verify(a.message(), &a.MLDSA):
		return errors.New("enroll: the admission's signature does not verify")
	}
	return nil
}

func (a *Admission) message() []byte {
	b := append([]byte("juist enroll admission v2\x00"), a.Admin[:]...)
	b = append(b, a.Network[:]...)
	b = append(b, a.Head[:]...)
	b = append(b, a.Guest[:]...)
	b = append(b, a.Signing[:]...)
	sum := sha256.Sum256(b)
	return sum[:]
}

func (m *Message) validate() error {
	set := [...]bool{m.Join != nil, m.Waiting != nil, m.Record != nil, m.Welcome != nil, m.Reason != "",
		m.Compare != nil, m.Reveal != nil, m.Announcement != nil}
	var want [len(set)]bool
	switch m.Kind {
	case KindJoin:
		want[0] = true
	case KindWaiting:
		want[1] = true
	case KindRecord:
		want[2] = true
	case KindWelcome:
		want[3] = true
	case KindJoined:
		want[7] = set[7]
		if len(m.Announcement) > MaxAnnouncementLen {
			return fmt.Errorf("enroll: an announcement of %d bytes, over the %d limit",
				len(m.Announcement), MaxAnnouncementLen)
		}
	case KindRefused:
		want[4] = true
	case KindCompare:
		want[5] = true
	case KindReveal:
		want[6] = true
	default:
		return fmt.Errorf("enroll: message has %v", m.Kind)
	}
	if set != want {
		return fmt.Errorf("enroll: malformed %v message", m.Kind)
	}
	switch {
	case m.Join != nil:
		if m.Join.Name != "" {
			if err := types.ValidateName(m.Join.Name); err != nil {
				return fmt.Errorf("enroll: proposed member name: %w", err)
			}
		}
		if err := m.Join.Identity.Validate(); err != nil {
			return fmt.Errorf("enroll: join request: %w", err)
		}
		if err := m.Join.Signing.Validate(); err != nil {
			return fmt.Errorf("enroll: join request: %w", err)
		}
	case m.Welcome != nil:
		if m.Welcome.Name != "" {
			if err := types.ValidateName(m.Welcome.Name); err != nil {
				return fmt.Errorf("enroll: member name: %w", err)
			}
		}
		if len(m.Welcome.Endpoints) > maxWelcomeItems || len(m.Welcome.Leases) > maxWelcomeItems {
			return errors.New("enroll: welcome carries too many hints")
		}
		if m.Welcome.Records == 0 || m.Welcome.Records > MaxRecords {
			return fmt.Errorf("enroll: welcome counts %d records", m.Welcome.Records)
		}
		if a := m.Welcome.Admission; a != nil {
			if err := a.Admin.Validate(); err != nil {
				return fmt.Errorf("enroll: admission: %w", err)
			}
			if err := a.Signing.Validate(); err != nil {
				return fmt.Errorf("enroll: admission: %w", err)
			}
		}
	case m.Record != nil:
		if len(m.Record) == 0 || len(m.Record) > types.MaxRecordSize {
			return fmt.Errorf("enroll: record is %d bytes", len(m.Record))
		}
	case m.Reason != "":
		if err := types.ValidateText("reason", m.Reason, MaxReasonLen); err != nil {
			return fmt.Errorf("enroll: %w", err)
		}
	}
	return nil
}

// DecodeMessage decodes and shape-checks one message. Exported for the fuzz
// target.
func DecodeMessage(b []byte) (Message, error) {
	m, err := decodeCanonical[Message](b)
	if err != nil {
		return Message{}, err
	}
	if err := m.validate(); err != nil {
		return Message{}, err
	}
	return m, nil
}

// NewJoinRequest builds a join request for the given keys, proving
// possession of the identity key and its signing key in this session.
func NewJoinRequest(c *Channel, name string, id types.PrivateIdentity, keys types.NodeKeys,
	nonce Nonce) (*JoinRequest, error) {
	msg := proofMessage(c.Binding())
	proof, pq, err := id.SignBoth(msg)
	if err != nil {
		return nil, err
	}
	return &JoinRequest{Name: name, Identity: id.Public(), Keys: keys, Proof: proof, Commit: CommitNonce(nonce),
		Signing: id.SigningKey(), SigningProof: *pq}, nil
}

// Verify checks a join request's proofs of possession against this session.
func (r *JoinRequest) Verify(c *Channel) error {
	msg := proofMessage(c.Binding())
	if !r.Identity.Verify(msg, r.Proof) || !r.Signing.Verify(msg, &r.SigningProof) {
		return errors.New("enroll: the join request's proof of key possession does not verify")
	}
	return nil
}

func proofMessage(binding [32]byte) []byte {
	sum := sha256.Sum256(append([]byte("juist enroll proof v1\x00"), binding[:]...))
	return sum[:]
}

// NodeRecord is the membership the request asks for, under the given name.
func (r *JoinRequest) NodeRecord(name string) types.NodeRecord {
	key := r.Signing
	return types.NodeRecord{
		Identity:  r.Identity,
		Name:      name,
		WireGuard: r.Keys.WireGuard,
		X25519:    r.Keys.X25519,
		MLKEM:     r.Keys.MLKEM,
		Signing:   &key,
	}
}

// ReasonText renders an error as a refusal's reason: one line, within
// [MaxReasonLen], and something the other side's terminal can print.
func ReasonText(err error) string {
	s := strings.Join(strings.Fields(err.Error()), " ")
	if n := MaxReasonLen; len(s) > n {
		for n > 0 && s[n]&0xc0 == 0x80 {
			n--
		}
		s = strings.TrimSpace(s[:n])
	}
	if s == "" || types.ValidateText("reason", s, MaxReasonLen) != nil {
		return "the other side gave up"
	}
	return s
}
