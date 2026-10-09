// Package enroll is how a device joins a network: an admin's device issues an
// invite, a new device redeems it, and the two agree on a key by SPAKE2 over
// whatever connection the caller provides. The invite admits exactly one
// guess — a wrong one voids it, loudly — and what travels inside the channel
// is a join request and, once a quorum has admitted the device, the log.
//
// Nothing here opens a socket or reads a clock: the caller dials, listens and
// sets deadlines, so the protocol is a function of the bytes alone.
package enroll

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/fxamacker/cbor/v2"

	"github.com/nning/juist/types"
)

// ProtocolVersion is the enrollment protocol a hello speaks. It changes with
// any message a peer of the other version could not decode, so the two
// devices refuse at the hello, with a reason a person can act on, instead of
// failing on a field one of them does not know. 2: a join request commits to
// the nonce the words are made from.
const ProtocolVersion = 2

// Frame size limits. A handshake frame is a few dozen bytes; a channel frame
// carries at most one log record and its envelope.
const (
	maxHandshakeFrame = 512
	maxChannelFrame   = types.MaxRecordSize + 64<<10
)

var (
	// ErrWrongCode is the host's verdict on a guest that did not know the
	// code. The invite is void from then on: that is what bounds an attacker
	// to one guess.
	ErrWrongCode = errors.New("enroll: someone tried this invite with the wrong code; the code is now void")

	// ErrLinkSpent is the host's verdict on a guest that holds the link and
	// answered with an element built from it, which spends the invite.
	ErrLinkSpent = errors.New("enroll: a holder of the link spent the invite without joining")

	// ErrWrongLink is the host's verdict on a guest whose link secret did
	// not match. It voids nothing: at 128 bits an online guess is worth
	// nothing, and voiding would let anyone who reaches the port end the
	// invite with one connection.
	ErrWrongLink = errors.New("enroll: a guest's link did not match this invite")

	// ErrInviteClosed is returned for a session against an invite that was
	// used or voided.
	ErrInviteClosed = errors.New("enroll: the invite has already been used or voided")

	// ErrImpostor is the guest's verdict on a host that did not know the
	// code: whoever answered is not the device that issued the invite.
	ErrImpostor = errors.New("enroll: the device that answered does not know the invite code, " +
		"so it is not the one that issued it")
)

// A Refusal is the host's reason for turning a guest away before a channel
// exists.
type Refusal uint8

const (
	refusalNone Refusal = 0

	// RefusedWrongCode: the guest's code did not match, and the code is
	// now void; the invite's link still works.
	RefusedWrongCode Refusal = 1

	// RefusedNoSuchInvite: the host issued no invite with this nameplate.
	// No guess was made.
	RefusedNoSuchInvite Refusal = 2

	// RefusedClosed: the invite was already used or voided.
	RefusedClosed Refusal = 3

	// RefusedVersion: the host does not speak the guest's protocol version.
	RefusedVersion Refusal = 4

	// RefusedWrongLink: the guest's link secret did not match. The invite
	// stays open.
	RefusedWrongLink Refusal = 5
)

func (r Refusal) String() string {
	switch r {
	case RefusedWrongCode:
		return "the code is wrong, and no longer works; use the link, or ask for a new invite"
	case RefusedNoSuchInvite:
		return "that device has no invite with this number"
	case RefusedClosed:
		return "the invite has already been used or has been voided; ask for a new one"
	case RefusedVersion:
		return "the inviting device runs an incompatible version of juist"
	case RefusedWrongLink:
		return "the link does not match the invite; copy it again"
	default:
		return fmt.Sprintf("refused for an unknown reason (%d)", uint8(r))
	}
}

// A RefusedError is a host's refusal as the guest sees it.
type RefusedError struct{ Reason Refusal }

func (e *RefusedError) Error() string { return "enroll: " + e.Reason.String() }

// An Invite is the host's half of an invite: a typed code and a link, either
// of which admits one device. It is not safe for concurrent use, and must
// not be: sessions are serial so that an invite can never be guessed at twice
// at once.
type Invite struct {
	code Code
	link Link

	// closed is the invite spent: a device joined, or proved it knows it.
	// codeVoid is the typed code alone voided by a wrong guess at it, or by
	// too many guesses at its nameplate; the link, a secret of its own,
	// still works.
	closed   bool
	codeVoid bool
	misses   int
}

// MaxNameplateMisses is how many hellos for another nameplate an invite
// answers before it takes its code out of use. Asking costs a guesser
// nothing, and 999 nameplates are few, so without a bound anyone could find
// the right one and then spend the code's one guess.
const MaxNameplateMisses = 32

// NewInvite draws an invite for a host listening at addrs.
func NewInvite(addrs []netip.AddrPort) (*Invite, error) {
	code, err := NewCode()
	if err != nil {
		return nil, err
	}
	link, err := NewLink(addrs)
	if err != nil {
		return nil, err
	}
	return &Invite{code: code, link: link}, nil
}

// Code returns the invite's typed form.
func (inv *Invite) Code() Code { return inv.code }

// Link returns the invite's copy-and-paste form.
func (inv *Invite) Link() Link { return inv.link }

// WaitAt names the relays the invite's host waits at, in its link, by
// address and by name.
func (inv *Invite) WaitAt(relays []netip.AddrPort, named []string) {
	inv.link = inv.link.WithRelays(relays, named)
}

// Open reports whether the invite can still admit a device.
func (inv *Invite) Open() bool { return !inv.closed }

// CodeOpen reports whether the typed code still works.
func (inv *Invite) CodeOpen() bool { return !inv.closed && !inv.codeVoid }

// Accept runs the host's half of the handshake over one connection. The
// invite is spent once a guest proves it knows the code, and void once one
// proves it does not ([ErrWrongCode]). Any other failure leaves it as it was:
// a session that ends before the guest's confirmation gave its peer nothing
// to test a guess against.
func (inv *Invite) Accept(rw io.ReadWriter) (*Channel, error) {
	hello, err := ReadHello(rw)
	if err != nil {
		return nil, err
	}
	return inv.AcceptHello(hello, rw)
}

// A Hello is a guest's first message, read before its session is let near
// the invite: reading it concurrently, with a short deadline, is what keeps a
// connection that says nothing from holding the one session at a time.
type Hello struct{ frame hsFrame }

// ReadHello reads a guest's first message.
func ReadHello(r io.Reader) (*Hello, error) {
	f, err := readHandshake(r)
	if err != nil {
		return nil, err
	}
	if f.Kind != hsHello {
		return nil, fmt.Errorf("enroll: expected a hello, got %v", f.Kind)
	}
	return &Hello{frame: f}, nil
}

// Code reports whether the guest is using the typed code rather than the link.
func (h *Hello) Code() bool { return h.frame.Mode == modeCode }

// AcceptHello is [Invite.Accept] for a guest whose hello has been read.
func (inv *Invite) AcceptHello(h *Hello, rw io.ReadWriter) (*Channel, error) {
	hello := h.frame
	if inv.closed {
		refuse(rw, RefusedClosed)
		return nil, ErrInviteClosed
	}
	if hello.Version != ProtocolVersion {
		refuse(rw, RefusedVersion)
		return nil, fmt.Errorf("enroll: the guest speaks protocol version %d", hello.Version)
	}
	var secret Secret
	switch hello.Mode {
	case modeCode:
		if inv.codeVoid {
			refuse(rw, RefusedClosed)
			return nil, ErrInviteClosed
		}
		if hello.Nameplate != inv.code.Nameplate {
			if inv.misses++; inv.misses >= MaxNameplateMisses {
				inv.codeVoid = true
			}
			refuse(rw, RefusedNoSuchInvite)
			return nil, fmt.Errorf("enroll: a guest asked for invite %d", hello.Nameplate)
		}
		secret = inv.code
	case modeLink:
		secret = inv.link
	default:
		return nil, fmt.Errorf("enroll: the guest asked for mode %d", hello.Mode)
	}

	s, err := newSpake(false, secret.password(), aadFor(secret.mode()))
	if err != nil {
		return nil, err
	}
	keys, err := s.finish(hello.Element)
	if errors.Is(err, errPasswordElement) {
		if hello.Mode == modeLink {
			// Whoever sent it holds the link, and has spent it.
			inv.closed = true
			refuse(rw, RefusedClosed)
			return nil, ErrLinkSpent
		}
		inv.codeVoid = true
		refuse(rw, RefusedWrongCode)
		return nil, ErrWrongCode
	}
	if err != nil {
		return nil, err
	}
	if err := writeHandshake(rw, &hsFrame{Kind: hsReply, Element: s.message()}); err != nil {
		return nil, err
	}
	confirm, err := readHandshake(rw)
	if err != nil {
		return nil, err
	}
	if confirm.Kind != hsConfirm {
		return nil, fmt.Errorf("enroll: expected a confirmation, got %v", confirm.Kind)
	}
	if subtle.ConstantTimeCompare(confirm.MAC, keys.confirmGuest) != 1 {
		if hello.Mode == modeLink {
			refuse(rw, RefusedWrongLink)
			return nil, ErrWrongLink
		}
		// The code's one guess is spent; the link is another secret, and a
		// guess at the code says nothing about it.
		inv.codeVoid = true
		refuse(rw, RefusedWrongCode)
		return nil, ErrWrongCode
	}
	inv.closed = true
	if err := writeHandshake(rw, &hsFrame{Kind: hsConfirm, MAC: keys.confirmHost}); err != nil {
		return nil, err
	}
	return newChannel(rw, keys, false)
}

// Join runs the guest's half of the handshake.
func Join(rw io.ReadWriter, secret Secret) (*Channel, error) {
	s, err := newSpake(true, secret.password(), aadFor(secret.mode()))
	if err != nil {
		return nil, err
	}
	if err := writeHandshake(rw, &hsFrame{
		Kind:      hsHello,
		Version:   ProtocolVersion,
		Mode:      secret.mode(),
		Nameplate: secret.nameplate(),
		Element:   s.message(),
	}); err != nil {
		return nil, err
	}
	reply, err := readHandshake(rw)
	if err != nil {
		return nil, err
	}
	if reply.Kind == hsRefuse {
		return nil, &RefusedError{Reason: reply.Refusal}
	}
	if reply.Kind != hsReply {
		return nil, fmt.Errorf("enroll: expected a reply, got %v", reply.Kind)
	}
	keys, err := s.finish(reply.Element)
	if err != nil {
		return nil, err
	}
	if err := writeHandshake(rw, &hsFrame{Kind: hsConfirm, MAC: keys.confirmGuest}); err != nil {
		return nil, err
	}
	confirm, err := readHandshake(rw)
	if err != nil {
		return nil, err
	}
	if confirm.Kind == hsRefuse {
		return nil, &RefusedError{Reason: confirm.Refusal}
	}
	if confirm.Kind != hsConfirm || subtle.ConstantTimeCompare(confirm.MAC, keys.confirmHost) != 1 {
		return nil, ErrImpostor
	}
	return newChannel(rw, keys, true)
}

func aadFor(m mode) []byte { return []byte{'j', 'u', 'i', 's', 't', ProtocolVersion, byte(m)} }

func refuse(w io.Writer, r Refusal) { _ = writeHandshake(w, &hsFrame{Kind: hsRefuse, Refusal: r}) }

// --- handshake frames ------------------------------------------------------

type hsKind uint8

const (
	hsInvalid hsKind = 0
	hsHello   hsKind = 1
	hsReply   hsKind = 2
	hsConfirm hsKind = 3
	hsRefuse  hsKind = 4
)

func (k hsKind) String() string {
	switch k {
	case hsInvalid:
		return "no kind"
	case hsHello:
		return "hello"
	case hsReply:
		return "reply"
	case hsConfirm:
		return "confirmation"
	case hsRefuse:
		return "refusal"
	default:
		return fmt.Sprintf("frame?<%d>", uint8(k))
	}
}

type hsFrame struct {
	Kind      hsKind  `cbor:"1,keyasint"`
	Version   uint8   `cbor:"2,keyasint,omitempty"`
	Mode      mode    `cbor:"3,keyasint,omitempty"`
	Nameplate uint16  `cbor:"4,keyasint,omitempty"`
	Element   []byte  `cbor:"5,keyasint,omitempty"`
	MAC       []byte  `cbor:"6,keyasint,omitempty"`
	Refusal   Refusal `cbor:"7,keyasint,omitempty"`
}

// validate requires each kind to carry exactly its own fields.
func (f *hsFrame) validate() error {
	has := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}
	fields := [...]int{
		has(f.Version != 0), has(f.Mode != modeInvalid), has(f.Nameplate != 0),
		has(f.Element != nil), has(f.MAC != nil), has(f.Refusal != refusalNone),
	}
	var want [len(fields)]int
	switch f.Kind {
	case hsHello:
		want = [...]int{1, 1, has(f.Mode == modeCode), 1, 0, 0}
	case hsReply:
		want = [...]int{0, 0, 0, 1, 0, 0}
	case hsConfirm:
		want = [...]int{0, 0, 0, 0, 1, 0}
	case hsRefuse:
		want = [...]int{0, 0, 0, 0, 0, 1}
	default:
		return fmt.Errorf("enroll: handshake frame has %v", f.Kind)
	}
	if fields != want {
		return fmt.Errorf("enroll: malformed %v frame", f.Kind)
	}
	if f.Element != nil && len(f.Element) != elementLen {
		return fmt.Errorf("enroll: key exchange message is %d bytes", len(f.Element))
	}
	if f.MAC != nil && len(f.MAC) != sha256.Size {
		return fmt.Errorf("enroll: confirmation is %d bytes", len(f.MAC))
	}
	if f.Nameplate > MaxNameplate {
		return fmt.Errorf("enroll: nameplate %d is out of range", f.Nameplate)
	}
	return nil
}

func readHandshake(r io.Reader) (hsFrame, error) {
	b, err := readFrame(r, maxHandshakeFrame)
	if err != nil {
		return hsFrame{}, err
	}
	return decodeHandshake(b)
}

func decodeHandshake(b []byte) (hsFrame, error) {
	f, err := decodeCanonical[hsFrame](b)
	if err != nil {
		return hsFrame{}, err
	}
	if err := f.validate(); err != nil {
		return hsFrame{}, err
	}
	return f, nil
}

func writeHandshake(w io.Writer, f *hsFrame) error {
	b, err := encMode.Marshal(f)
	if err != nil {
		return fmt.Errorf("enroll: encoding a handshake frame: %w", err)
	}
	return writeFrame(w, b)
}

// --- the channel -----------------------------------------------------------

// A Channel is the encrypted session a completed handshake yields: AES-256-GCM
// in each direction under keys derived from SPAKE2's Ke, with counter nonces,
// so a frame cannot be replayed, reordered or reflected.
type Channel struct {
	rw         io.ReadWriter
	send, recv cipher.AEAD
	sent, rcvd uint64
	binding    [32]byte
}

func newChannel(rw io.ReadWriter, keys spakeKeys, guest bool) (*Channel, error) {
	g2h, err := directionKey(keys.ke, "guest to host")
	if err != nil {
		return nil, err
	}
	h2g, err := directionKey(keys.ke, "host to guest")
	if err != nil {
		return nil, err
	}
	c := &Channel{rw: rw, binding: sha256.Sum256(append([]byte("juist enroll binding v1\x00"), keys.transcript...))}
	if guest {
		c.send, c.recv = g2h, h2g
	} else {
		c.send, c.recv = h2g, g2h
	}
	return c, nil
}

func directionKey(ke []byte, label string) (cipher.AEAD, error) {
	k, err := hkdf.Key(sha256.New, ke, nil, "juist enroll v1 "+label, 32)
	if err != nil {
		return nil, fmt.Errorf("enroll: deriving a channel key: %w", err)
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Binding identifies this session: both ends compute the same value and no
// other session has it. A join request's proof of key possession signs it,
// so the proof cannot be replayed into another session.
func (c *Channel) Binding() [32]byte { return c.binding }

// Send encrypts and writes one message.
func (c *Channel) Send(m *Message) error {
	if err := m.validate(); err != nil {
		return err
	}
	b, err := encMode.Marshal(m)
	if err != nil {
		return fmt.Errorf("enroll: encoding a message: %w", err)
	}
	nonce := counterNonce(c.sent)
	c.sent++
	return writeFrame(c.rw, c.send.Seal(nil, nonce, b, nil))
}

// Receive reads and decrypts one message.
func (c *Channel) Receive() (Message, error) {
	b, err := readFrame(c.rw, maxChannelFrame)
	if err != nil {
		return Message{}, err
	}
	nonce := counterNonce(c.rcvd)
	c.rcvd++
	pt, err := c.recv.Open(nil, nonce, b, nil)
	if err != nil {
		return Message{}, errors.New("enroll: a message failed authentication")
	}
	return DecodeMessage(pt)
}

func counterNonce(n uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], n)
	return nonce
}

// --- framing and encoding ----------------------------------------------------

func readFrame(r io.Reader, limit int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("enroll: reading a frame: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > uint32(limit) {
		return nil, fmt.Errorf("enroll: peer announced a %d-byte frame, over the %d limit", n, limit)
	}
	// Grown as bytes arrive rather than allocated from the announced size.
	var buf bytes.Buffer
	buf.Grow(min(int(n), 64<<10))
	if _, err := io.CopyN(&buf, r, int64(n)); err != nil {
		return nil, fmt.Errorf("enroll: reading a frame: %w", err)
	}
	return buf.Bytes(), nil
}

func writeFrame(w io.Writer, b []byte) error {
	frame := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(b)), uint32(len(b)))
	if _, err := w.Write(append(frame, b...)); err != nil {
		return fmt.Errorf("enroll: writing a frame: %w", err)
	}
	return nil
}

var encMode = func() cbor.EncMode {
	m, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("enroll: building the CBOR encoder: %v", err))
	}
	return m
}()

var decMode = func() cbor.DecMode {
	m, err := types.StrictDecOptions(4, maxWelcomeItems, 16).DecMode()
	if err != nil {
		panic(fmt.Sprintf("enroll: building the CBOR decoder: %v", err))
	}
	return m
}()

// decodeCanonical decodes b and rejects it unless re-encoding reproduces it,
// the rule every parser in this project follows.
func decodeCanonical[T any](b []byte) (T, error) {
	var zero, v T
	if err := decMode.Unmarshal(b, &v); err != nil {
		return zero, fmt.Errorf("enroll: decoding: %w", err)
	}
	re, err := encMode.Marshal(v)
	if err != nil {
		return zero, fmt.Errorf("enroll: re-encoding: %w", err)
	}
	if !bytes.Equal(re, b) {
		return zero, errors.New("enroll: non-canonical encoding")
	}
	return v, nil
}
