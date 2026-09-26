package enroll

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"filippo.io/edwards25519"
)

// SPAKE2 (RFC 9382) over edwards25519 with SHA-256, HKDF and HMAC: the
// SPAKE2-edwards25519-SHA256-HKDF-HMAC suite. The guest is party A and the
// host party B.

// The RFC's M and N for edwards25519, which TestSPAKE2Constants regenerates
// from their seeds.
var (
	spakeM = mustPoint("d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf")
	spakeN = mustPoint("d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab")
)

// Party identities. Fixed role labels rather than empty strings: the RFC
// allows empty identities only where they are implicit, and a label is what
// stops one side's messages being reflected back at it as the other's.
var (
	guestIdentity = []byte("juist enroll guest")
	hostIdentity  = []byte("juist enroll host")
)

// elementLen is the length of an encoded group element.
const elementLen = 32

// errBadElement reports a peer's message that is not a usable group element.
var errBadElement = errors.New("enroll: the peer's key exchange message is not a valid group element")

// errPasswordElement reports a peer's element that makes K the identity. The
// only way to send one is to build it from the password itself — w·M, with no
// secret scalar — so it is a guess, and a right one; an honest peer produces
// it with negligible probability. RFC 9382 has the party abort, which, left
// at that, would let a guest test code after code for nothing: a host that
// aborts on the right guess and answers every wrong one is an oracle. The
// host therefore counts it as the invite's one guess ([Invite.Accept]).
var errPasswordElement = errors.New("enroll: the peer's element was built from the password")

// A spake is one party's half of a SPAKE2 run. Single use: x must never be
// reused, so a finished or failed run is discarded.
type spake struct {
	guest bool
	w     *edwards25519.Scalar
	x     *edwards25519.Scalar
	own   []byte
	aad   []byte
}

// spakeKeys is what a completed run yields. Ke is the shared secret; the two
// confirmations are what each side sends and expects.
type spakeKeys struct {
	ke           []byte
	confirmGuest []byte
	confirmHost  []byte
	transcript   []byte
}

// newSpake starts a run. The password is hashed to w without a memory-hard
// function: w is never stored, and SPAKE2 gives an attacker who does not
// observe K nothing to test offline, so the one online guess is the only one.
func newSpake(guest bool, password, aad []byte) (*spake, error) {
	w, err := passwordScalar(password)
	if err != nil {
		return nil, err
	}
	var seed [64]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("enroll: drawing a key exchange scalar: %w", err)
	}
	x, err := edwards25519.NewScalar().SetUniformBytes(seed[:])
	if err != nil {
		return nil, err
	}
	blind := spakeN
	if guest {
		blind = spakeM
	}
	// pA = x*P + w*M for the guest, pB = y*P + w*N for the host.
	own := new(edwards25519.Point).ScalarBaseMult(x)
	own.Add(own, new(edwards25519.Point).ScalarMult(w, blind))
	return &spake{guest: guest, w: w, x: x, own: own.Bytes(), aad: slices.Clone(aad)}, nil
}

// message is this party's element, to send to the peer.
func (s *spake) message() []byte { return slices.Clone(s.own) }

// finish combines the peer's element into the key schedule.
func (s *spake) finish(peer []byte) (spakeKeys, error) {
	p, err := decodeElement(peer)
	if err != nil {
		return spakeKeys{}, err
	}
	unblind := spakeM
	if s.guest {
		unblind = spakeN
	}
	// K = h*x*(peer - w*unblind); h clears any torsion component.
	k := new(edwards25519.Point).ScalarMult(s.w, unblind)
	k.Subtract(p, k)
	k.ScalarMult(s.x, k)
	k.MultByCofactor(k)
	if k.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return spakeKeys{}, errPasswordElement
	}
	pA, pB := s.own, peer
	if !s.guest {
		pA, pB = peer, s.own
	}
	return keySchedule(guestIdentity, hostIdentity, pA, pB, k.Bytes(), scalarBigEndian(s.w), s.aad)
}

// keySchedule is RFC 9382 sections 3.3 and 4, independent of the group, so it
// can be checked against the RFC's P-256 vectors.
func keySchedule(a, b, pA, pB, k, w, aad []byte) (spakeKeys, error) {
	var tt []byte
	for _, part := range [][]byte{a, b, pA, pB, k, w} {
		tt = binary.LittleEndian.AppendUint64(tt, uint64(len(part)))
		tt = append(tt, part...)
	}
	sum := sha256.Sum256(tt)
	ke, ka := sum[:16], sum[16:]
	kc, err := hkdf.Key(sha256.New, ka, nil, "ConfirmationKeys"+string(aad), 32)
	if err != nil {
		return spakeKeys{}, fmt.Errorf("enroll: deriving confirmation keys: %w", err)
	}
	return spakeKeys{
		ke:           slices.Clone(ke),
		confirmGuest: mac(kc[:16], tt),
		confirmHost:  mac(kc[16:], tt),
		transcript:   tt,
	}, nil
}

func mac(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// passwordScalar maps a password to w, reduced from 512 bits so the bias the
// RFC warns about is negligible.
func passwordScalar(password []byte) (*edwards25519.Scalar, error) {
	h := sha512.New()
	h.Write([]byte("juist enroll spake2 w v1\x00"))
	h.Write(password)
	return edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
}

// scalarBigEndian encodes w as the transcript requires: big-endian, padded
// to the length of the group order.
func scalarBigEndian(s *edwards25519.Scalar) []byte {
	b := s.Bytes()
	slices.Reverse(b)
	return b
}

// decodeElement accepts only the canonical encoding of a point of large
// order. edwards25519 accepts non-canonical encodings, and two encodings of
// one element would give one run two transcripts.
func decodeElement(b []byte) (*edwards25519.Point, error) {
	if len(b) != elementLen {
		return nil, errBadElement
	}
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil || !slices.Equal(p.Bytes(), b) {
		return nil, errBadElement
	}
	if new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, errBadElement
	}
	return p, nil
}

func mustPoint(h string) *edwards25519.Point {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		panic(err)
	}
	return p
}
