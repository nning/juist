// Package ipc is the local API between juistd and the CLI: its wire types,
// their codec and the client. The daemon serves it.
package ipc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"

	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/types"
)

// Limits on an IPC message. A request is a verb and at most a batch of records;
// a response may carry the whole log.
const (
	// MaxRequest caps one encoded request, which any local user can send.
	MaxRequest = 8 << 20

	// MaxResponse caps one encoded response.
	MaxResponse = 256 << 20

	// MaxRecords caps the records one inform request may carry.
	MaxRecords = 256

	// maxInvite bounds the invite text a join request carries.
	maxInvite = 1024

	maxNestedLevels = 6
	// maxMapPairs must exceed the fields of the largest struct, Status:
	// a struct travels as a map with a key per field.
	maxMapPairs = 96
)

// A Command is an IPC verb. Numbers are permanent; 0 is invalid.
type Command uint8

const (
	cmdInvalid Command = 0

	// CmdStatus asks what state the daemon is in. Any local user may ask.
	CmdStatus Command = 1

	// CmdInform hands the daemon log records to apply and gossip.
	CmdInform Command = 2

	// CmdBootstrap asks for what a device joining through this one should
	// start from: member announcements and freshness leases.
	CmdBootstrap Command = 3

	// CmdLog asks for the active chain, anchor first.
	CmdLog Command = 4

	// CmdSelf asks for this device's public keys and proposed name.
	CmdSelf Command = 5

	// CmdCreate creates a network from a fully signed genesis record that
	// admits this device.
	CmdCreate Command = 6

	// CmdJoin redeems an invite. The daemon streams [Event]s while it runs.
	CmdJoin Command = 7

	// CmdRotate stages new keys for this device and returns the rotation
	// record, signed by the device where it must be.
	CmdRotate Command = 8

	// CmdUnstage abandons staged keys the log does not name.
	CmdUnstage Command = 9

	// CmdSetOperator sets which local user may operate the daemon.
	CmdSetOperator Command = 10

	// CmdInvite offers an invite and runs its sessions, streaming [Event]s.
	// It is a conversation: the caller answers an admission event with
	// [CmdInviteReply] requests on the same connection, since the admin
	// keys that sign the admission are on the caller's side.
	CmdInvite Command = 11

	// CmdInviteReply answers a running [CmdInvite]. It is never a call of
	// its own.
	CmdInviteReply Command = 12

	// CmdReset returns the device to a fresh install: no network, new keys,
	// no operator. A member is reset only with [Request.Force].
	CmdReset Command = 13

	// CmdWaiting hands the daemon changes waiting for votes, if the request
	// carries any, and answers with every one it holds.
	CmdWaiting Command = 14

	// CmdExit chooses this device's exit node, [Request.ExitNode], or none,
	// [Request.ExitOff], or says whether it serves as one, [Request.Serve].
	CmdExit Command = 15

	// CmdSubnet says whether this device routes its peers' subnets,
	// [Request.AcceptSubnets], or routes its own for them,
	// [Request.ServeSubnets].
	CmdSubnet Command = 16
)

func (c Command) String() string {
	switch c {
	case cmdInvalid:
		return "no command"
	case CmdStatus:
		return "status"
	case CmdInform:
		return "inform"
	case CmdBootstrap:
		return "bootstrap"
	case CmdLog:
		return "log"
	case CmdSelf:
		return "self"
	case CmdCreate:
		return "create"
	case CmdJoin:
		return "join"
	case CmdRotate:
		return "rotate"
	case CmdUnstage:
		return "unstage"
	case CmdSetOperator:
		return "set-operator"
	case CmdInvite:
		return "invite"
	case CmdInviteReply:
		return "invite-reply"
	case CmdReset:
		return "reset"
	case CmdWaiting:
		return "waiting"
	case CmdExit:
		return "exit"
	case CmdSubnet:
		return "subnet"
	default:
		return fmt.Sprintf("command?<%d>", uint8(c))
	}
}

// A Request is one IPC call.
type Request struct {
	Command Command `cbor:"1,keyasint"`

	// Records are encoded AUMs, for [CmdInform] and [CmdCreate]. They travel
	// as raw bytes so that they can only enter through types.DecodeAUM.
	Records [][]byte `cbor:"2,keyasint,omitempty"`

	// Invite and Name are the code or link to redeem and the member name to
	// ask for, for [CmdJoin].
	Invite string `cbor:"3,keyasint,omitempty"`
	Name   string `cbor:"4,keyasint,omitempty"`

	// SetOperator asks for the operator to become OperatorUID, for
	// [CmdSetOperator], [CmdCreate] and [CmdJoin]; 0 clears it. Only root or
	// the daemon's own user may.
	SetOperator bool   `cbor:"5,keyasint,omitempty"`
	OperatorUID uint32 `cbor:"6,keyasint,omitempty"`

	// Identity asks [CmdRotate] for a new identity key rather than new
	// WireGuard and encryption keys.
	Identity bool `cbor:"7,keyasint,omitempty"`

	// Offer configures a [CmdInvite], and Reply is a [CmdInviteReply].
	Offer *InviteOffer `cbor:"8,keyasint,omitempty"`
	Reply *InviteReply `cbor:"9,keyasint,omitempty"`

	// Orphans asks [CmdLog] for the stored records off the active chain as
	// well: what a caller needs to redo fork choice itself.
	Orphans bool `cbor:"10,keyasint,omitempty"`

	// Probe is accepted from older clients and ignored: the tunnels are
	// checked in the background, and a status carries the last result.
	Probe bool `cbor:"11,keyasint,omitempty"`

	// Force lets [CmdReset] reset a device the log still lists.
	Force bool `cbor:"12,keyasint,omitempty"`

	// Elsewhere are the networks the host is in through its other juistd
	// instances, which [CmdJoin] refuses to join a second time.
	Elsewhere []types.Hash `cbor:"13,keyasint,omitempty"`

	// Waiting are encoded changes waiting for votes, for [CmdWaiting].
	Waiting [][]byte `cbor:"14,keyasint,omitempty"`

	// ExitNode, ExitOff and Serve are what a [CmdExit] sets, one of them.
	ExitNode types.Identity `cbor:"15,keyasint,omitempty"`
	ExitOff  bool           `cbor:"16,keyasint,omitempty"`
	Serve    *bool          `cbor:"17,keyasint,omitempty"`

	// ServeSubnets and AcceptSubnets are what a [CmdSubnet] sets, one of
	// them.
	ServeSubnets  *bool `cbor:"18,keyasint,omitempty"`
	AcceptSubnets *bool `cbor:"19,keyasint,omitempty"`
}

// MaxWaiting caps the changes one [CmdWaiting] request hands on.
const MaxWaiting = 16

// An InviteOffer is how an invite is offered.
type InviteOffer struct {
	// Port is the TCP port to listen on; host.DefaultPort gives way when
	// taken, any other is held to.
	Port uint16 `cbor:"1,keyasint,omitempty"`

	// LAN answers for the code on the local network, and DHT meets a guest
	// through the public DHT where the daemon is configured to.
	LAN bool `cbor:"2,keyasint,omitempty"`
	DHT bool `cbor:"3,keyasint,omitempty"`

	// Expires is how long the invite stays open, in seconds.
	Expires uint32 `cbor:"4,keyasint"`
}

// maxInviteExpiry bounds how long an invite may stay open.
const maxInviteExpiry = 7 * 24 * 3600

// An InviteReply is the caller's answer to an admission event: keep the
// guest waiting, admit it with the admin's statement, or refuse it.
type InviteReply struct {
	Waiting   *enroll.Waiting   `cbor:"1,keyasint,omitempty"`
	Name      string            `cbor:"2,keyasint,omitempty"`
	Admission *enroll.Admission `cbor:"3,keyasint,omitempty"`
	Refused   string            `cbor:"4,keyasint,omitempty"`

	// Salt is handed to the guest for the words the admin compares.
	Salt *enroll.Salt `cbor:"5,keyasint,omitempty"`
}

// A Response is one IPC reply. Err is set when the call failed, in which case
// nothing else is meaningful. A response carrying Event is not the last: the
// call is still running.
type Response struct {
	Err       string     `cbor:"1,keyasint,omitempty"`
	Status    *Status    `cbor:"2,keyasint,omitempty"`
	Bootstrap *Bootstrap `cbor:"3,keyasint,omitempty"`
	Records   [][]byte   `cbor:"4,keyasint,omitempty"`
	Self      *Self      `cbor:"5,keyasint,omitempty"`
	Event     *Event     `cbor:"6,keyasint,omitempty"`

	// Orphans are encoded records off the active chain, for [Request.Orphans].
	Orphans [][]byte `cbor:"7,keyasint,omitempty"`

	// Proof answers [CmdRotate]: the rotated device's current identity key
	// signs [RotationProof] of the record. It is what shows the CLI that the
	// daemon holds the key of the device it claims to be, which a schema 0
	// identity rotation does not otherwise carry.
	Proof *types.Sig `cbor:"8,keyasint,omitempty"`

	// Admission answers [CmdJoin] by a link that names its admin: that
	// admin's admission of this device, which the CLI checks against the
	// link itself rather than take the daemon's word for the network.
	Admission *enroll.Admission `cbor:"9,keyasint,omitempty"`

	// Waiting answers [CmdWaiting]: the encoded changes waiting for votes
	// the daemon holds.
	Waiting [][]byte `cbor:"10,keyasint,omitempty"`
}

// RotationProof is what a rotated device's current identity key signs for
// [Response.Proof]. It is labelled, so the signature is not also one over
// the record itself.
func RotationProof(aum *types.AUM) []byte {
	h := aum.SigHash()
	return append([]byte("juist rotation proof v1\x00"), h[:]...)
}

// Bootstrap is the answer to [CmdBootstrap]. Everything in it is signed by its
// author, so handing it to a new member extends no trust.
type Bootstrap struct {
	// Endpoints are encoded member announcements, this node's own first.
	Endpoints [][]byte `cbor:"1,keyasint,omitempty"`

	// Leases are encoded freshness leases.
	Leases [][]byte `cbor:"2,keyasint,omitempty"`
}

// Self is the answer to [CmdSelf]: what an admin needs to put this device in
// a genesis record.
type Self struct {
	Identity types.Identity `cbor:"1,keyasint"`
	Keys     types.NodeKeys `cbor:"2,keyasint"`

	// Name is the member name this device proposes.
	Name string `cbor:"3,keyasint,omitempty"`
}

// An Event reports progress of a [CmdJoin] or a [CmdInvite].
type Event struct {
	Kind   uint8  `cbor:"1,keyasint"`
	Addr   string `cbor:"2,keyasint,omitempty"`
	Votes  uint32 `cbor:"3,keyasint,omitempty"`
	Quorum uint32 `cbor:"4,keyasint,omitempty"`

	// For a [CmdInvite]: the code and link offered and the port they listen
	// on, a guest's name and identity, a failure's text, and the join
	// request an admission event asks the caller to decide.
	Code     string              `cbor:"5,keyasint,omitempty"`
	Link     string              `cbor:"6,keyasint,omitempty"`
	Port     uint16              `cbor:"7,keyasint,omitempty"`
	Name     string              `cbor:"8,keyasint,omitempty"`
	Identity *types.Identity     `cbor:"9,keyasint,omitempty"`
	Text     string              `cbor:"10,keyasint,omitempty"`
	Join     *enroll.JoinRequest `cbor:"11,keyasint,omitempty"`

	// Reveal is the nonce the guest revealed for the salt the caller sent,
	// for [EventInviteReveal]. The caller holds it to Join's commitment.
	Reveal *enroll.Nonce `cbor:"12,keyasint,omitempty"`
}

// Kinds of a [CmdInvite] event. A join's events use guest.EventKind, below
// these.
const (
	EventInviteReady   uint8 = 16 // Code, Link and Port are offered
	EventInviteFailed  uint8 = 18 // a connection ended; the invite is open
	EventInviteJoined  uint8 = 19 // the guest stored the log
	EventInviteNoLAN   uint8 = 20 // the code cannot be found on the LAN
	EventInviteNoDHT   uint8 = 21 // the link cannot meet through the DHT
	EventInviteAdmit   uint8 = 22 // decide Join, and answer with replies
	EventCodeVoided    uint8 = 23 // a wrong code spent the code; the link works
	EventInviteNoRelay uint8 = 24 // the invite cannot wait at the relay at Addr; it keeps trying
	EventInviteReveal  uint8 = 25 // the guest's nonce, for the salt the caller sent
)

// A reqField is one of a [Request]'s optional fields.
type reqField uint16

const (
	fRecords     reqField = 1 << iota
	fInvite               // Invite
	fName                 // Name
	fSetOperator          // SetOperator and OperatorUID
	fIdentity
	fOffer
	fReply
	fOrphans
	fProbe
	fForce
	fWaiting
	fExit
	fSubnet
)

// present lists the optional fields r sets.
func (r *Request) present() reqField {
	var f reqField
	for _, p := range []struct {
		set bool
		f   reqField
	}{
		{len(r.Records) > 0, fRecords}, {r.Invite != "", fInvite}, {r.Name != "", fName},
		{r.SetOperator || r.OperatorUID != 0, fSetOperator}, {r.Identity, fIdentity},
		{r.Offer != nil, fOffer}, {r.Reply != nil, fReply}, {r.Orphans, fOrphans},
		{r.Probe, fProbe}, {r.Force, fForce}, {len(r.Waiting) > 0, fWaiting},
		{!r.ExitNode.IsZero() || r.ExitOff || r.Serve != nil, fExit},
		{r.ServeSubnets != nil || r.AcceptSubnets != nil, fSubnet},
	} {
		if p.set {
			f |= p.f
		}
	}
	return f
}

// A requestShape is what a command's request may carry, and how it is refused.
type requestShape struct {
	takes reqField
	check func(*Request) bool // what the command needs, nil for nothing
	shape string              // the refusal's text, empty for the generic one
}

var requestShapes = map[Command]requestShape{
	CmdStatus:    {takes: fProbe},
	CmdBootstrap: {},
	CmdLog:       {takes: fOrphans},
	CmdSelf:      {},
	CmdUnstage:   {},
	CmdRotate:    {takes: fIdentity},
	CmdReset:     {takes: fForce},
	CmdExit: {takes: fExit, shape: "an exit request sets an exit node, off, or serving, and one of them",
		check: func(r *Request) bool {
			n := 0
			for _, set := range []bool{!r.ExitNode.IsZero(), r.ExitOff, r.Serve != nil} {
				if set {
					n++
				}
			}
			return n == 1
		}},
	CmdSubnet: {takes: fSubnet, shape: "a subnet request sets serving or accepting, and one of them",
		check: func(r *Request) bool { return (r.ServeSubnets != nil) != (r.AcceptSubnets != nil) }},
	CmdWaiting: {takes: fWaiting, shape: fmt.Sprintf("a waiting request carries at most %d changes and nothing else", MaxWaiting),
		check: func(r *Request) bool { return len(r.Waiting) <= MaxWaiting }},
	CmdInform: {takes: fRecords, shape: "an inform request carries records and nothing else",
		check: func(r *Request) bool { return len(r.Records) > 0 }},
	CmdCreate: {takes: fRecords | fSetOperator, shape: "a create request carries one genesis record",
		check: func(r *Request) bool { return len(r.Records) == 1 }},
	CmdJoin: {takes: fInvite | fName | fSetOperator, shape: "a join request carries an invite",
		check: func(r *Request) bool { return r.Invite != "" && len(r.Invite) <= maxInvite }},
	CmdSetOperator: {takes: fSetOperator, shape: "a set-operator request carries an operator and nothing else",
		check: func(r *Request) bool { return r.SetOperator }},
	CmdInvite: {takes: fOffer, shape: "an invite request carries how the invite is offered and nothing else",
		check: func(r *Request) bool {
			return r.Offer != nil && r.Offer.Expires != 0 && r.Offer.Expires <= maxInviteExpiry
		}},
	CmdInviteReply: {takes: fReply, shape: "an invite reply carries the reply and nothing else",
		check: func(r *Request) bool { return r.Reply != nil }},
}

func (r *Request) validate() error {
	s, ok := requestShapes[r.Command]
	if !ok {
		return fmt.Errorf("ipc: request has %v", r.Command)
	}
	if r.present()&^s.takes != 0 || s.check != nil && !s.check(r) {
		if s.shape == "" {
			return fmt.Errorf("ipc: a %v request carries fields it does not take", r.Command)
		}
		return errors.New("ipc: " + s.shape)
	}
	if !r.SetOperator && r.OperatorUID != 0 {
		return errors.New("ipc: an operator is only named when setting one")
	}
	if len(r.Records) > MaxRecords {
		return fmt.Errorf("ipc: request carries %d records, over the %d limit", len(r.Records), MaxRecords)
	}
	switch {
	case r.Name != "":
		if err := types.ValidateName(r.Name); err != nil {
			return fmt.Errorf("ipc: member name: %w", err)
		}
	case r.Reply != nil:
		return r.Reply.validate()
	}
	return nil
}

// validate holds a reply to exactly one answer, well formed.
func (p *InviteReply) validate() error {
	answers := 0
	if p.Waiting != nil {
		answers++
	}
	if p.Salt != nil {
		answers++
	}
	if p.Admission != nil {
		answers++
		if err := types.ValidateName(p.Name); err != nil || p.Name == "" {
			return errors.New("ipc: an admission reply names the member it admitted")
		}
	}
	if p.Refused != "" {
		answers++
		if err := types.ValidateText("reason", p.Refused, enroll.MaxReasonLen); err != nil {
			return fmt.Errorf("ipc: %w", err)
		}
	}
	if answers != 1 {
		return errors.New("ipc: an invite reply carries exactly one answer")
	}
	return nil
}

// The IPC codec is the same canonical CBOR discipline as the rest of the
// project, with its own limits. It is fuzzed: this is the one parser every
// local user can reach.
var encMode = func() cbor.EncMode {
	m, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("ipc: building the IPC encoder: %v", err))
	}
	return m
}()

func decMode(maxArray int) cbor.DecMode {
	m, err := types.StrictDecOptions(maxNestedLevels, maxArray, maxMapPairs).DecMode()
	if err != nil {
		panic(fmt.Sprintf("ipc: building the IPC decoder: %v", err))
	}
	return m
}

var (
	requestDec  = decMode(types.MaxNodes)
	responseDec = decMode(1 << 16)
)

func encode(v any, limit int) ([]byte, error) {
	b, err := encMode.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("ipc: encoding an IPC message: %w", err)
	}
	if len(b) > limit {
		return nil, fmt.Errorf("ipc: IPC message is %d bytes, over the %d limit", len(b), limit)
	}
	return b, nil
}

func decode[T any](dec cbor.DecMode, b []byte, limit int) (T, error) {
	var zero, v T
	if len(b) == 0 {
		return zero, errors.New("ipc: empty IPC message")
	}
	if len(b) > limit {
		return zero, fmt.Errorf("ipc: IPC message is %d bytes, over the %d limit", len(b), limit)
	}
	if err := dec.Unmarshal(b, &v); err != nil {
		return zero, fmt.Errorf("ipc: decoding an IPC message: %w", err)
	}
	re, err := encMode.Marshal(v)
	if err != nil {
		return zero, fmt.Errorf("ipc: re-encoding an IPC message: %w", err)
	}
	if !bytes.Equal(re, b) {
		return zero, errors.New("ipc: non-canonical IPC message")
	}
	return v, nil
}

// DecodeRequest decodes and shape-checks an IPC request. Exported for the
// fuzz target.
func DecodeRequest(b []byte) (Request, error) {
	r, err := decode[Request](requestDec, b, MaxRequest)
	if err != nil {
		return Request{}, err
	}
	if err := r.validate(); err != nil {
		return Request{}, err
	}
	return r, nil
}

// DecodeResponse decodes an IPC reply.
func DecodeResponse(b []byte) (Response, error) {
	return decode[Response](responseDec, b, MaxResponse)
}

// makePrintable makes every string in a reply safe to print. The daemon is
// the less trusted side of the socket, and a reply is printed to the
// operator's terminal: one that carried escape sequences could rewrite what
// the operator sees, or what the terminal does.
func (r *Response) makePrintable() {
	r.Err = printable(r.Err)
	if st := r.Status; st != nil {
		for _, f := range []*string{&st.NetworkName, &st.SelfName, &st.StartError, &st.Operator,
			&st.Alarm, &st.EpochError, &st.SchemaAlarm, &st.DataPlaneError, &st.HomeRelay} {
			*f = printable(*f)
		}
		for i := range st.Silent {
			st.Silent[i] = printable(st.Silent[i])
		}
		for i := range st.TunnelsDown {
			st.TunnelsDown[i] = printable(st.TunnelsDown[i])
		}
		for i := range st.SyncFailing {
			st.SyncFailing[i] = printable(st.SyncFailing[i])
		}
		for i := range st.Devices {
			d := &st.Devices[i]
			d.Name, d.V4, d.V6 = printable(d.Name), printable(d.V4), printable(d.V6)
			d.Retiring = printable(d.Retiring)
			for j := range d.Roles {
				d.Roles[j] = types.Role(printable(string(d.Roles[j])))
			}
		}
		for i := range st.Unrevoked {
			st.Unrevoked[i] = printable(st.Unrevoked[i])
		}
		for i := range st.Lost {
			st.Lost[i] = printable(st.Lost[i])
		}
		for i := range st.Seeking {
			st.Seeking[i] = printable(st.Seeking[i])
		}
		for i := range st.Absent {
			st.Absent[i] = printable(st.Absent[i])
		}
		for i := range st.Unmoved {
			st.Unmoved[i] = printable(st.Unmoved[i])
		}
	}
	if e := r.Event; e != nil {
		for _, f := range []*string{&e.Addr, &e.Code, &e.Link, &e.Name, &e.Text} {
			*f = printable(*f)
		}
		if e.Join != nil {
			e.Join.Name = printable(e.Join.Name)
		}
	}
	if r.Self != nil {
		r.Self.Name = printable(r.Self.Name)
	}
}

// printable replaces control, format and bidirectional-override characters,
// and line and paragraph separators, keeping newlines, which the daemon's
// errors use to add a hint.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n':
			return r
		case unicode.IsControl(r), unicode.Is(unicode.Bidi_Control, r), unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp),
			r == utf8.RuneError:
			return '\uFFFD'
		}
		return r
	}, s)
}

// Timeouts on a call.
const (
	// CallTimeout bounds each step of a call that reports no progress.
	CallTimeout = 30 * time.Second

	// eventTimeout is how long a streaming client waits for the next frame
	// of a call that is still running.
	eventTimeout = 3 * time.Minute
)

// MaxReply caps one reply inside a conversation.
const MaxReply = 64 << 10

// Messages on the socket are length-prefixed, checked against the limit before
// anything is buffered.
func ReadMessage(c net.Conn, limit uint32) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, fmt.Errorf("ipc: reading an IPC header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > limit {
		return nil, fmt.Errorf("ipc: peer announced a %d-byte IPC message, over the %d limit", n, limit)
	}
	// Grown as the bytes arrive, not allocated from the announced size, so a
	// caller that announces the maximum and sends nothing costs nothing.
	var buf bytes.Buffer
	buf.Grow(min(int(n), 32<<10))
	if _, err := io.CopyN(&buf, c, int64(n)); err != nil {
		return nil, fmt.Errorf("ipc: reading an IPC body: %w", err)
	}
	return buf.Bytes(), nil
}

func WriteMessage(c net.Conn, v any, limit int) error {
	b, err := encode(v, limit)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := c.Write(append(hdr[:], b...)); err != nil {
		return fmt.Errorf("ipc: writing an IPC message: %w", err)
	}
	return nil
}

// --- client side -----------------------------------------------------------

// Call sends one request to a daemon's IPC socket and returns its reply. The
// CLI's half of the protocol, kept here so both halves stay in one file.
func Call(path string, req Request) (Response, error) {
	return Stream(context.Background(), path, req, nil)
}

// Stream is [Call] for a request that reports progress: onEvent receives each
// event until the reply arrives. A nil onEvent refuses a streaming reply.
// Ending ctx hangs up, which ends the call on the daemon's side too.
func Stream(ctx context.Context, path string, req Request, onEvent func(*Event)) (Response, error) {
	if onEvent == nil {
		return converse(ctx, path, req, nil, eventTimeout)
	}
	return converse(ctx, path, req, func(_ context.Context, e *Event, _ func(Request) error) error {
		onEvent(e)
		return nil
	}, eventTimeout)
}

// Converse is [Stream] for a [CmdInvite]: onEvent may answer an event with
// replies, and an error from it hangs up. The context onEvent gets ends when
// the connection does, so a caller waiting on something else hears that the
// daemon gave up. An invite waits for its guest as long as it is open, so no
// silence ends the call; ctx does.
func Converse(ctx context.Context, path string, req Request,
	onEvent func(ctx context.Context, e *Event, reply func(Request) error) error) (Response, error) {
	return converse(ctx, path, req, onEvent, 0)
}

// converse runs a call, waiting at most idle between frames once the first
// has come; zero waits for as long as ctx lets it.
func converse(ctx context.Context, path string, req Request,
	onEvent func(context.Context, *Event, func(Request) error) error, idle time.Duration) (Response, error) {
	c, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return Response{}, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	first := CallTimeout
	if onEvent != nil {
		// Before its first report a call may be dialling and shaking hands.
		first = eventTimeout
	}
	_ = c.SetWriteDeadline(time.Now().Add(CallTimeout))
	if err := WriteMessage(c, &req, MaxRequest); err != nil {
		return Response{}, err
	}
	reply := func(r Request) error {
		r.Command = CmdInviteReply
		_ = c.SetWriteDeadline(time.Now().Add(CallTimeout))
		return WriteMessage(c, &r, MaxReply)
	}

	// Frames are read on their own goroutine, so that the connection ending
	// is noticed while onEvent is still busy.
	type frame struct {
		raw []byte
		err error
	}
	// The reader closes frames when it stops, so the loop below always
	// ends; quit tells it that nobody is left to take a frame.
	frames := make(chan frame, 8)
	quit := make(chan struct{})
	defer close(quit)
	connCtx, connDone := context.WithCancel(ctx)
	defer connDone()
	go func() {
		defer close(frames)
		wait := first
		for {
			var until time.Time
			if wait > 0 {
				until = time.Now().Add(wait)
			}
			_ = c.SetReadDeadline(until)
			raw, err := ReadMessage(c, MaxResponse)
			if err != nil {
				connDone()
			}
			select {
			case frames <- frame{raw, err}:
			case <-quit:
				return
			}
			if err != nil {
				return
			}
			wait = idle
		}
	}()
	for f := range frames {
		if f.err != nil {
			if ctx.Err() != nil {
				return Response{}, ctx.Err()
			}
			return Response{}, f.err
		}
		resp, err := DecodeResponse(f.raw)
		if err != nil {
			return Response{}, err
		}
		resp.makePrintable()
		if resp.Event == nil {
			if resp.Err != "" {
				return resp, errors.New(resp.Err)
			}
			return resp, nil
		}
		if onEvent == nil {
			return Response{}, errors.New("ipc: an unexpected progress report")
		}
		if err := onEvent(connCtx, resp.Event, reply); err != nil {
			return Response{}, err
		}
	}
	return Response{}, errors.New("ipc: the connection ended")
}

// SocketName is the socket's name inside a juist state directory.
const SocketName = "daemon.sock"

// SocketPath returns the control socket's path for a state directory.
func SocketPath(home string) string { return filepath.Join(home, SocketName) }

// SystemSocket is where the packaged service listens.
const SystemSocket = "/run/juist/juistd.sock"
