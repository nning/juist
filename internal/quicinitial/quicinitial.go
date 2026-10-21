// Package quicinitial reads the server name a QUIC client asks for from its
// Initial packets, without any key of the server's: Initial keys follow from
// the client's Destination Connection ID (RFC 9001, 5.2), so anyone on the
// path reads them. It reads versions 1 and 2, and drops what does not parse
// without keeping anything of it.
package quicinitial

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/nning/juist/internal/malformed"
)

// The versions read.
const (
	Version1 = 0x00000001
	Version2 = 0x6b3343cf
)

// MinDatagram is the size every datagram a client sends with an Initial
// packet has at least (RFC 9000, 14.1).
const MinDatagram = 1200

var (
	salt1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
		0xcc, 0xbb, 0x7f, 0x0a}
	salt2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
		0xf9, 0xbd, 0x2e, 0xd9}
)

// errNotInitial is a packet that is no client's Initial.
var errNotInitial = errors.New("quicinitial: no Initial packet")

// A Packet is one Initial packet a client sent, its payload decrypted.
type Packet struct {
	Version    uint32
	DCID, SCID []byte
	Token      []byte
	Number     uint64
	Payload    []byte
}

// IsLong reports whether b starts with a long header packet of version 1 or
// 2.
func IsLong(b []byte) bool {
	if len(b) < 5 || b[0]&0xc0 != 0xc0 {
		return false
	}
	v := binary.BigEndian.Uint32(b[1:5])
	return v == Version1 || v == Version2
}

// IsInitial reports whether b starts with an Initial packet of version 1
// or 2: what a client sends before it holds any key of the server's.
func IsInitial(b []byte) bool {
	return IsLong(b) && packetType(binary.BigEndian.Uint32(b[1:5]), b[0]) == typeInitial
}

type longType int

const (
	typeInitial longType = iota
	typeZeroRTT
	typeHandshake
	typeRetry
)

// packetType is the long header type first carries, as version numbers it.
func packetType(version uint32, first byte) longType {
	t := longType(first >> 4 & 0x03)
	if version == Version2 {
		// Version 2 numbers them one on (RFC 9369, 3.2).
		t = (t + 3) % 4
	}
	return t
}

// ConnectionIDs are the Destination and Source Connection IDs of the long
// header packet b starts with, read without any key.
func ConnectionIDs(b []byte) (dcid, scid []byte, ok bool) {
	if !IsLong(b) {
		return nil, nil, false
	}
	r := reader{b: b, off: 5}
	dcid, ok1 := r.vec8(20)
	scid, ok2 := r.vec8(20)
	return dcid, scid, ok1 && ok2
}

// SourceIDs are the Source Connection IDs of the long header packets
// coalesced at the start of datagram b, read without any key: a server
// may give its own in each.
func SourceIDs(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 && len(out) < maxPackets && IsLong(b) {
		v := binary.BigEndian.Uint32(b[1:5])
		r := reader{b: b, off: 5}
		_, ok1 := r.vec8(20)
		scid, ok2 := r.vec8(20)
		if !ok1 || !ok2 {
			break
		}
		out = append(out, scid)
		t := packetType(v, b[0])
		if t == typeRetry {
			break // the rest is its token and tag
		}
		if t == typeInitial {
			if _, ok := r.vecVarint(len(b)); !ok {
				break
			}
		}
		length, ok := r.varint()
		if !ok || length > uint64(len(b)-r.off) {
			break
		}
		b = b[r.off+int(length):]
	}
	return out
}

// Parse reads the Initial packets at the start of datagram b, coalesced
// ones too, of the first one's version and connection, by keys derived
// once; it stops at a packet of another type, which needs keys it does not
// have, or of another connection, which a client does not coalesce (RFC
// 9000, 12.2). It fails where the first is no Initial or any does not
// decrypt.
func Parse(b []byte) (_ []Packet, err error) {
	defer malformed.Recover(&err)
	if !IsInitial(b) {
		return nil, errNotInitial
	}
	var out []Packet
	var k *keys
	for len(b) > 0 && len(out) < maxPackets && IsInitial(b) {
		p, n, err := parseOne(b, &k)
		if errors.Is(err, errOtherConnection) {
			break
		}
		if err != nil {
			return nil, err
		}
		out = append(out, p)
		b = b[n:]
	}
	return out, nil
}

// maxPackets bounds the packets read of one datagram: a client coalesces
// an Initial with a 0-RTT packet, or splits its hello in a few.
const maxPackets = 4

// errOtherConnection is a coalesced packet of another version or
// connection than the first.
var errOtherConnection = errors.New("quicinitial: a packet of another connection")

// keys are a connection's Initial keys, ready to use.
type keys struct {
	version uint32
	dcid    []byte
	hp      cipher.Block
	aead    cipher.AEAD
	iv      []byte
}

func newKeys(version uint32, dcid []byte) (*keys, error) {
	key, iv, hp := initialKeys(version, dcid)
	hpb, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	kb, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(kb)
	if err != nil {
		return nil, err
	}
	return &keys{version: version, dcid: dcid, hp: hpb, aead: aead, iv: iv}, nil
}

// parseOne reads the Initial packet b starts with, and returns its length,
// by *k, or keys it derives into *k for the first.
func parseOne(b []byte, k **keys) (Packet, int, error) {
	p := Packet{Version: binary.BigEndian.Uint32(b[1:5])}
	r := reader{b: b, off: 5}
	dcid, ok1 := r.vec8(20)
	scid, ok2 := r.vec8(20)
	token, ok3 := r.vecVarint(len(b))
	length, ok4 := r.varint()
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return p, 0, errors.New("quicinitial: a truncated header")
	}
	if len(dcid) < 8 {
		// A client's first Destination Connection ID has 8 bytes at least
		// (RFC 9000, 7.2).
		return p, 0, fmt.Errorf("quicinitial: a destination connection ID of %d bytes", len(dcid))
	}
	pnOffset := r.off
	if length < 4+16 || length > uint64(len(b)-pnOffset) {
		return p, 0, fmt.Errorf("quicinitial: a packet of %d bytes in %d", length, len(b)-pnOffset)
	}
	end := pnOffset + int(length)
	switch {
	case *k == nil:
		var err error
		if *k, err = newKeys(p.Version, dcid); err != nil {
			return p, 0, err
		}
	case p.Version != (*k).version || !bytes.Equal(dcid, (*k).dcid):
		return p, 0, errOtherConnection
	}
	kk := *k

	// Header protection, with a sample 4 bytes past the packet number's
	// start (RFC 9001, 5.4.2).
	var mask [16]byte
	kk.hp.Encrypt(mask[:], b[pnOffset+4:pnOffset+4+16])
	header := make([]byte, pnOffset+4)
	copy(header, b[:pnOffset+4])
	header[0] ^= mask[0] & 0x0f
	pnLen := int(header[0]&0x03) + 1
	var pn uint64
	for i := range pnLen {
		header[pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint64(header[pnOffset+i])
	}
	header = header[:pnOffset+pnLen]
	if header[0]&0x0c != 0 {
		return p, 0, errors.New("quicinitial: reserved bits set")
	}

	nonce := make([]byte, len(kk.iv))
	copy(nonce, kk.iv)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	payload, err := kk.aead.Open(nil, nonce, b[pnOffset+pnLen:end], header)
	if err != nil {
		return p, 0, errors.New("quicinitial: a packet that does not decrypt")
	}
	p.DCID, p.SCID, p.Token, p.Number, p.Payload = dcid, scid, token, pn, payload
	return p, end, nil
}

// initialKeys are the client's Initial key, IV and header protection key
// for a connection version opens to dcid (RFC 9001, 5.2; RFC 9369, 3.3).
func initialKeys(version uint32, dcid []byte) (key, iv, hp []byte) {
	salt, prefix := salt1, "quic "
	if version == Version2 {
		salt, prefix = salt2, "quicv2 "
	}
	initial, _ := hkdf.Extract(sha256.New, dcid, salt)
	client := expandLabel(initial, "client in", sha256.Size)
	return expandLabel(client, prefix+"key", 16), expandLabel(client, prefix+"iv", 12), expandLabel(client, prefix+"hp", 16)
}

// expandLabel is TLS 1.3's HKDF-Expand-Label with an empty context.
func expandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, _ := hkdf.Expand(sha256.New, secret, string(info), n)
	return out
}

// Frames calls crypto with each CRYPTO frame's offset and data in an
// Initial packet's payload, and fails on a frame an Initial may not carry
// (RFC 9000, 12.4) or one that does not parse.
func Frames(payload []byte, crypto func(offset uint64, data []byte) error) error {
	r := reader{b: payload}
	for r.off < len(r.b) {
		typ, ok := r.varint()
		if !ok {
			return errors.New("quicinitial: a truncated frame")
		}
		switch typ {
		case 0x00, 0x01: // PADDING, PING
		case 0x02, 0x03: // ACK, with ECN counts for 0x03
			if !r.ack(typ == 0x03) {
				return errors.New("quicinitial: a truncated ACK frame")
			}
		case 0x06: // CRYPTO
			off, ok1 := r.varint()
			data, ok2 := r.vecVarint(len(payload))
			if !ok1 || !ok2 || off > maxCryptoOffset {
				return errors.New("quicinitial: a CRYPTO frame that does not parse")
			}
			if err := crypto(off, data); err != nil {
				return err
			}
		case 0x1c: // CONNECTION_CLOSE
			return errors.New("quicinitial: the client closes")
		default:
			return fmt.Errorf("quicinitial: a frame of type %#x in an Initial", typ)
		}
	}
	return nil
}

// maxCryptoOffset is past any ClientHello this reads.
const maxCryptoOffset = 1 << 20

// reader reads b from off on.
type reader struct {
	b   []byte
	off int
}

func (r *reader) varint() (uint64, bool) {
	if r.off >= len(r.b) {
		return 0, false
	}
	n := 1 << (r.b[r.off] >> 6)
	if r.off+n > len(r.b) {
		return 0, false
	}
	v := uint64(r.b[r.off] & 0x3f)
	for _, c := range r.b[r.off+1 : r.off+n] {
		v = v<<8 | uint64(c)
	}
	r.off += n
	return v, true
}

// vec8 reads a vector of at most max bytes behind a one-byte length.
func (r *reader) vec8(max int) ([]byte, bool) {
	if r.off >= len(r.b) {
		return nil, false
	}
	n := int(r.b[r.off])
	if n > max || r.off+1+n > len(r.b) {
		return nil, false
	}
	v := r.b[r.off+1 : r.off+1+n]
	r.off += 1 + n
	return v, true
}

// vecVarint reads a vector of at most max bytes behind a varint length.
func (r *reader) vecVarint(max int) ([]byte, bool) {
	n, ok := r.varint()
	if !ok || n > uint64(max) || n > uint64(len(r.b)-r.off) {
		return nil, false
	}
	v := r.b[r.off : r.off+int(n)]
	r.off += int(n)
	return v, true
}

// ack skips an ACK frame's fields after its type: the largest number
// acknowledged, the delay, the count of ranges after the first, the first,
// a gap and a length for each further one, and three ECN counts where ecn.
func (r *reader) ack(ecn bool) bool {
	var ranges uint64 // the third field read
	for range 3 {
		v, ok := r.varint()
		if !ok {
			return false
		}
		ranges = v
	}
	if ranges > uint64(len(r.b)) {
		return false
	}
	n := 1 + 2*ranges
	if ecn {
		n += 3
	}
	for range n {
		if _, ok := r.varint(); !ok {
			return false
		}
	}
	return true
}
