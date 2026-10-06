// Package proxyproto writes and reads PROXY protocol v2 headers, which tell a
// TCP server the client's address a proxy hides.
package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

var signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

// maxLength bounds a header's address block, TLVs included.
const maxLength = 512

// Header is a v2 header for a TCP connection from src to dst, IPv4 where both
// are, IPv6 otherwise.
func Header(src, dst netip.AddrPort) []byte { return header(src, dst, 0x1) }

// HeaderUDP is a v2 header for UDP datagrams from src to dst.
func HeaderUDP(src, dst netip.AddrPort) []byte { return header(src, dst, 0x2) }

func header(src, dst netip.AddrPort, transport byte) []byte {
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	h := append(bytes.Clone(signature), 0x21)
	if src.Addr().Is4() && dst.Addr().Is4() {
		h = append(h, 0x10|transport, 0, 12)
		s4, d4 := src.Addr().As4(), dst.Addr().As4()
		h = append(append(h, s4[:]...), d4[:]...)
	} else {
		h = append(h, 0x20|transport, 0, 36)
		s16, d16 := src.Addr().As16(), dst.Addr().As16()
		h = append(append(h, s16[:]...), d16[:]...)
	}
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(h, src.Port()), dst.Port())
}

// LocalUDP is a v2 LOCAL header for UDP naming src, as a proxy's own
// connection a receiver is to take for none of a client's; done adds an empty
// NOOP TLV.
func LocalUDP(src netip.AddrPort, done bool) []byte {
	dst := netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	if !src.Addr().Unmap().Is4() {
		dst = netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
	}
	h := header(src, dst, 0x2)
	h[12] = 0x20
	if done {
		h = append(h, 0x04, 0, 0)
		binary.BigEndian.PutUint16(h[14:16], binary.BigEndian.Uint16(h[14:16])+3)
	}
	return h
}

// ReadLocalUDP reads datagram b as a [LocalUDP] header, and reports the
// client it names and whether it is done.
func ReadLocalUDP(b []byte) (src netip.AddrPort, done, ok bool) {
	if len(b) < 16 || !bytes.Equal(b[:12], signature) || b[12] != 0x20 {
		return netip.AddrPort{}, false, false
	}
	addrs := 12
	if b[13]&0xf0 == 0x20 {
		addrs = 36
	}
	switch n := int(binary.BigEndian.Uint16(b[14:16])); {
	case n == addrs && len(b) == 16+n:
	case n == addrs+3 && len(b) == 16+n && bytes.Equal(b[16+addrs:], []byte{0x04, 0, 0}):
		done = true
	default:
		return netip.AddrPort{}, false, false
	}
	h := bytes.Clone(b[:16+addrs])
	h[12] = 0x21
	binary.BigEndian.PutUint16(h[14:16], uint16(addrs))
	src, err := ReadUDP(h)
	return src, done, err == nil
}

// IsHeader reports whether datagram b starts as a v2 header does, which no
// QUIC packet does: its fixed bit is clear.
func IsHeader(b []byte) bool { return bytes.HasPrefix(b, signature) }

// ReadUDP reads datagram b as a v2 header for UDP alone, and reports the
// client it names.
func ReadUDP(b []byte) (netip.AddrPort, error) {
	src, ok, err := read(bufio.NewReaderSize(bytes.NewReader(b), 16+maxLength), 0x2)
	switch {
	case err != nil:
		return netip.AddrPort{}, err
	case !ok || !src.IsValid():
		return netip.AddrPort{}, errors.New("proxyproto: a datagram naming no client")
	case len(b) != 16+int(binary.BigEndian.Uint16(b[14:16])):
		return netip.AddrPort{}, errors.New("proxyproto: a datagram carrying more than its header")
	}
	return src, nil
}

// Read consumes a v2 header for TCP where r holds one next, and reports the
// client it names; ok is false where r holds none, and a LOCAL header names
// none.
func Read(r *bufio.Reader) (src netip.AddrPort, ok bool, err error) { return read(r, 0x1) }

func read(r *bufio.Reader, transport byte) (src netip.AddrPort, ok bool, err error) {
	head, err := r.Peek(16)
	if err != nil || !bytes.Equal(head[:12], signature) {
		if errors.Is(err, io.EOF) || errors.Is(err, bufio.ErrBufferFull) || err == nil {
			return netip.AddrPort{}, false, nil
		}
		return netip.AddrPort{}, false, err
	}
	verCmd, fam, n := head[12], head[13], int(binary.BigEndian.Uint16(head[14:16]))
	if verCmd>>4 != 2 || verCmd&0xf > 1 || n > maxLength {
		return netip.AddrPort{}, false, fmt.Errorf("proxyproto: a header of version %d, command %d, %d bytes",
			verCmd>>4, verCmd&0xf, n)
	}
	b := make([]byte, 16+n)
	if _, err := io.ReadFull(r, b); err != nil {
		return netip.AddrPort{}, false, err
	}
	addrs := b[16:]
	if verCmd&0xf == 0 {
		return netip.AddrPort{}, true, nil
	}
	if fam&0x0f != transport {
		return netip.AddrPort{}, false, fmt.Errorf("proxyproto: a header of family %#x", fam)
	}
	switch {
	case fam&0xf0 == 0x10 && n >= 12:
		a := netip.AddrFrom4([4]byte(addrs[0:4]))
		return netip.AddrPortFrom(a, binary.BigEndian.Uint16(addrs[8:10])), true, nil
	case fam&0xf0 == 0x20 && n >= 36:
		a := netip.AddrFrom16([16]byte(addrs[0:16])).Unmap()
		return netip.AddrPortFrom(a, binary.BigEndian.Uint16(addrs[32:34])), true, nil
	}
	return netip.AddrPort{}, false, fmt.Errorf("proxyproto: a header of family %#x", fam)
}
