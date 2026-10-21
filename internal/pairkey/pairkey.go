// Package pairkey derives the preshared key each pair of members mixes into
// its WireGuard handshakes, so that tunnel traffic recorded today stays
// confidential against a quantum computer later.
//
// A pair starts on a group key, which every member holding the epoch's group
// secret can derive ([Group]), and moves to a pair key once the two have each
// encapsulated to the other's ML-KEM key ([Pair]), which no third member can.
// docs/07-embedding-notes.md, "The preshared-key path", says why the exchange
// runs as it does.
package pairkey

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/nning/juist/types"
)

// A Key is a WireGuard preshared key. The zero Key is none.
type Key [32]byte

// IsZero reports whether k is no key.
func (k Key) IsZero() bool { return k == Key{} }

// A Stage is what a pair's handshakes mix in.
type Stage uint8

const (
	// StageNone is no preshared key: towards a peer that announces none.
	StageNone Stage = iota
	// StageUnknown is a key nobody holds: the pair's epoch is one this node
	// keeps nothing of, so no handshake completes.
	StageUnknown
	// StageGroup is a key from the group secret.
	StageGroup
	// StagePair is a key the pair alone holds.
	StagePair
)

func (s Stage) String() string {
	switch s {
	case StageNone:
		return "none"
	case StageUnknown:
		return "no key in common"
	case StageGroup:
		return "group key"
	case StagePair:
		return "pair key"
	}
	return fmt.Sprintf("stage?<%d>", uint8(s))
}

// Group is the key the members with WireGuard keys a and b use in epoch,
// whose seed ([secrets.Secret.PSKSeed]) is seed.
func Group(seed [32]byte, epoch uint64, a, b types.WGKey) Key {
	lo, hi := a, b
	if string(hi[:]) < string(lo[:]) {
		lo, hi = hi, lo
	}
	info := append([]byte(types.LabelPSKGroup+"\x00"), lo[:]...)
	info = append(info, hi[:]...)
	return Key(expand(seed[:], binary.BigEndian.AppendUint64(nil, epoch), info))
}

// Unknown is a key no peer holds, drawn per process: a peer given it
// completes no handshake, where the zero key would complete one without.
var Unknown = func() Key {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		panic(fmt.Sprintf("pairkey: drawing: %v", err))
	}
	return k
}()

// A Side is one member of a pair, as the log names it.
type Side struct {
	ID types.Identity
	WG types.WGKey
}

// derive is a generation's pair key. sharedL is what the leader
// encapsulated, ctL its ciphertext, sharedF and ctF the follower's; group is
// the pair's group key in the generation's epoch, so the result needs both an
// ML-KEM secret and the group secret.
func derive(network types.Hash, leader, follower types.WGKey, gen, epoch uint64, group Key,
	sharedL, ctL, sharedF, ctF []byte) Key {
	ikm := append(append([]byte(nil), sharedL...), sharedF...)
	transcript := sha256.New()
	transcript.Write(ctL)
	transcript.Write(ctF)
	info := append([]byte(types.LabelPSKPair+"\x00"), network[:]...)
	info = append(info, leader[:]...)
	info = append(info, follower[:]...)
	info = binary.BigEndian.AppendUint64(info, gen)
	info = binary.BigEndian.AppendUint64(info, epoch)
	info = transcript.Sum(info)
	return Key(expand(ikm, group[:], info))
}

// checkSize is the length of a key confirmation.
const checkSize = 16

// check confirms holding k, as role says who confirms: neither side moves to
// a key the other has not shown it derived alike.
func check(k Key, role string) []byte {
	m := hmac.New(sha256.New, k[:])
	m.Write([]byte(types.LabelPSKCheck + "\x00" + role))
	return m.Sum(nil)[:checkSize]
}

func expand(secret, salt, info []byte) []byte {
	out, err := hkdf.Key(sha256.New, secret, salt, string(info), 32)
	if err != nil {
		// HKDF-SHA256 fails on lengths over 255 blocks alone.
		panic(fmt.Sprintf("pairkey: deriving: %v", err))
	}
	return out
}

// encapsulate draws a secret for the holder of the ML-KEM key pub.
func encapsulate(pub types.MLKEMKey) (shared, ct []byte, err error) {
	ek, err := mlkem.NewEncapsulationKey768(pub[:])
	if err != nil {
		return nil, nil, fmt.Errorf("pairkey: the peer's ML-KEM key: %w", err)
	}
	shared, ct = ek.Encapsulate()
	return shared, ct, nil
}

// Leads reports whether the member with WireGuard key self drives the
// exchange with the one with peer: the lower key does, which an identity
// rotation keeps.
func Leads(self, peer types.WGKey) bool { return string(self[:]) < string(peer[:]) }
