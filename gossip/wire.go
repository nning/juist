package gossip

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/nning/juist/internal/aead"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// Structural limits on a gossip frame.
//
// These are not policy. They bound what a peer can make this node allocate or
// hash before anything in the frame has been authenticated, which is the whole
// job of a parser sitting on an untrusted transport
// (docs/04-architecture.md: the sync layer moves self-certifying data over
// transports it does not trust).
const (
	// MaxFrameSize caps a frame's plaintext. The largest legitimate one is a
	// batch of records containing a checkpoint, which at [types.MaxNodes]
	// members runs to about 1.3 MiB; the limit leaves room for a few of them
	// and stays far below anything that threatens memory.
	MaxFrameSize = 8 << 20

	// MaxRecordsPerFrame caps the log records one frame may carry. Anti-
	// entropy sends what a peer is missing in as many frames as it takes.
	MaxRecordsPerFrame = 256

	// MaxHashesPerFrame caps the "what I already hold" set in a hello. A
	// node with more records than this sends the newest ones and converges
	// over more rounds.
	MaxHashesPerFrame = 4096

	// MaxEndpointsPerFrame caps the announcements one frame may carry: one
	// per member, since holding two for one member is pointless.
	MaxEndpointsPerFrame = types.MaxNodes

	// maxArrayElements, maxMapPairs and maxNestedLevels bound the CBOR
	// decoder itself, below the schema-level limits above.
	maxArrayElements = MaxHashesPerFrame
	maxMapPairs      = 64
	maxNestedLevels  = 8
)

// A frameKind identifies what a frame does. Numbers are permanent; 0 is
// reserved as invalid so a frame whose kind field was dropped cannot be
// mistaken for a real one.
type frameKind uint8

const (
	kindInvalid frameKind = 0

	// kindHello opens a session: what network the sender belongs to, where
	// its chain is, and which records it already holds.
	kindHello frameKind = 1

	// kindRecords answers a hello with the records and announcements the
	// peer turned out to be missing.
	kindRecords frameKind = 2
)

func (k frameKind) String() string {
	switch k {
	case kindInvalid:
		return "no kind"
	case kindHello:
		return "hello"
	case kindRecords:
		return "records"
	default:
		return fmt.Sprintf("kind?<%d>", uint8(k))
	}
}

// A frame is one anti-entropy message.
//
// Log records travel as raw byte strings rather than as a nested schema, so
// that they can only enter this process through [types.DecodeAUM] — the
// decoder that enforces the canonical encoding the hash chain and every
// signature rest on. A gossip frame must not be a second way to build an AUM.
type frame struct {
	Kind frameKind `cbor:"1,keyasint"`

	// Network is the sender's genesis hash. A frame for another network is
	// dropped before anything in it is looked at; this is what keeps two
	// juist networks sharing a LAN from feeding each other records their
	// logs would only reject one by one.
	Network types.Hash `cbor:"2,keyasint"`

	// Epoch and Head are the log-head beacon docs/04-architecture.md puts on
	// every gossip message: where the sender's chain is. They are hints that
	// decide whether there is anything to exchange, never anything the
	// receiver adopts.
	Epoch uint64     `cbor:"3,keyasint"`
	Head  types.Hash `cbor:"4,keyasint"`

	// Have is the set of record hashes the sender already holds, in a hello.
	Have []types.Hash `cbor:"5,keyasint,omitempty"`

	// Anchor is the record the sender's chain is resolved from: its genesis,
	// or the newest checkpoint it has compacted to. It is what the peer
	// walks when deciding which records to send back — after a compaction,
	// "everything you are missing" is wrong in both directions: records
	// below the receiver's anchor are ones it can no longer accept, and one
	// of them in a batch poisons the whole batch, since Inform is atomic.
	Anchor types.Hash `cbor:"9,keyasint"`

	// Records are encoded AUMs, in a records frame, ordered so that every
	// record's parent precedes it.
	Records [][]byte `cbor:"6,keyasint,omitempty"`

	// Self is the sender's own announcement, kept apart from the relayed
	// ones so that "who am I talking to" has an answer. It is a hint, not
	// authentication: the signature proves the announcement is genuine, not
	// that the peer holding the socket is its author. Nothing is authorized
	// on the strength of it — it only chooses which epoch key a reply is
	// sealed under, and getting that wrong costs one failed session.
	Self *Endpoint `cbor:"7,keyasint,omitempty"`

	// Endpoints are announcements the sender is relaying from its cache.
	Endpoints []Endpoint `cbor:"8,keyasint,omitempty"`
}

func (f *frame) validate() error {
	switch f.Kind {
	case kindHello, kindRecords:
	default:
		return fmt.Errorf("gossip: frame has %v", f.Kind)
	}
	if f.Network.IsZero() {
		return errors.New("gossip: frame names no network")
	}
	if len(f.Have) > MaxHashesPerFrame {
		return fmt.Errorf("gossip: frame lists %d held records, over the %d limit",
			len(f.Have), MaxHashesPerFrame)
	}
	if len(f.Records) > MaxRecordsPerFrame {
		return fmt.Errorf("gossip: frame carries %d records, over the %d limit",
			len(f.Records), MaxRecordsPerFrame)
	}
	if len(f.Endpoints) > MaxEndpointsPerFrame {
		return fmt.Errorf("gossip: frame carries %d announcements, over the %d limit",
			len(f.Endpoints), MaxEndpointsPerFrame)
	}
	if f.Kind == kindHello && len(f.Records) > 0 {
		return errors.New("gossip: a hello frame must not carry records")
	}
	if f.Anchor.IsZero() {
		return errors.New("gossip: frame names no anchor")
	}
	return nil
}

// --- canonical CBOR --------------------------------------------------------

// encMode and decMode mirror the choices in types: CTAP2 canonical CBOR, and
// a decoder that rejects everything a permissive one would repair.
//
// They are a separate pair rather than the trust layer's, deliberately. A
// gossip frame is a different wire format with different limits, it is not
// hashed or signed as a whole, and docs/06-verification.md gives it its own
// fuzz target from this milestone. Sharing the modes would tie the frame
// parser's blast radius to the record parser's, and the record parser is the
// one inside the audit scope.
var encMode = func() cbor.EncMode {
	m, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("gossip: building CBOR encoder: %v", err))
	}
	return m
}()

var decMode = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		UTF8:              cbor.UTF8RejectInvalid,
		MaxNestedLevels:   maxNestedLevels,
		MaxArrayElements:  maxArrayElements,
		MaxMapPairs:       maxMapPairs,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("gossip: building CBOR decoder: %v", err))
	}
	return m
}()

func encode(v any) ([]byte, error) {
	b, err := encMode.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("gossip: encoding: %w", err)
	}
	if len(b) > MaxFrameSize {
		return nil, fmt.Errorf("gossip: encoded %d bytes, over the %d limit", len(b), MaxFrameSize)
	}
	return b, nil
}

// decodeCanonical decodes b and rejects it unless b is exactly what encoding
// the result produces.
//
// The re-encode check carries real weight for endpoint records, whose
// signature covers their encoding: without it, a peer could re-spell a record
// it received and the signature would still verify over a different byte
// string. For frames it is cheap insurance and keeps one rule for the whole
// format.
func decodeCanonical[T any](b []byte) (T, error) {
	var zero, v T
	if len(b) == 0 {
		return zero, errors.New("gossip: empty input")
	}
	if len(b) > MaxFrameSize {
		return zero, fmt.Errorf("gossip: input is %d bytes, over the %d limit", len(b), MaxFrameSize)
	}
	if err := decMode.Unmarshal(b, &v); err != nil {
		return zero, fmt.Errorf("gossip: decoding: %w", err)
	}
	re, err := encMode.Marshal(v)
	if err != nil {
		return zero, fmt.Errorf("gossip: re-encoding to check canonicality: %w", err)
	}
	if !bytes.Equal(re, b) {
		return zero, errors.New("gossip: non-canonical encoding")
	}
	return v, nil
}

// decodeFrame decodes and shape-checks a frame's plaintext. It does not
// verify anything the frame carries: records go through types.DecodeAUM and
// announcements through their own signature check, both at the point of use.
func decodeFrame(b []byte) (frame, error) {
	f, err := decodeCanonical[frame](b)
	if err != nil {
		return frame{}, err
	}
	if err := f.validate(); err != nil {
		return frame{}, err
	}
	return f, nil
}

// --- sealing ---------------------------------------------------------------

// Frames are sealed with internal/aead under the epoch's gossip key. See that
// package for the layout and for what the sealing does and does not buy.
const (
	sealOverhead  = aead.Overhead
	maxSealedSize = MaxFrameSize + sealOverhead
)

// seal encrypts a frame under an epoch's group secret.
func seal(s secrets.Secret, epoch uint64, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxFrameSize {
		return nil, fmt.Errorf("gossip: frame is %d bytes, over the %d limit", len(plaintext), MaxFrameSize)
	}
	key := s.GossipKey(epoch)
	return aead.Seal(key, epoch, plaintext)
}

// errUnknownEpoch reports a frame sealed under an epoch this node cannot open.
// It is an ordinary condition, not an attack: a peer more than
// [secrets.KeyringDepth] epochs away, and a device that is not a member at
// all, both look like this and both are handled by dropping the frame.
var errUnknownEpoch = errors.New("gossip: frame is sealed under an epoch this node does not hold")

// open decrypts a sealed frame with whichever epoch key it names, returning
// that epoch so a reply can be sealed under the same one.
func open(kr *secrets.Keyring, blob []byte) (epoch uint64, plaintext []byte, err error) {
	if len(blob) > maxSealedSize {
		return 0, nil, fmt.Errorf("gossip: sealed frame is %d bytes, over the %d limit",
			len(blob), maxSealedSize)
	}
	epoch, err = aead.Epoch(blob)
	if err != nil {
		return 0, nil, fmt.Errorf("gossip: %w", err)
	}
	s, ok := kr.Secret(epoch)
	if !ok {
		return epoch, nil, fmt.Errorf("%w: epoch %d", errUnknownEpoch, epoch)
	}
	key := s.GossipKey(epoch)
	pt, err := aead.Open(key, blob)
	if err != nil {
		return epoch, nil, fmt.Errorf("gossip: frame sealed under epoch %d: %w", epoch, err)
	}
	return epoch, pt, nil
}
