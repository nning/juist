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
func Header(src, dst netip.AddrPort) []byte {
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	h := append(bytes.Clone(signature), 0x21)
	if src.Addr().Is4() && dst.Addr().Is4() {
		h = append(h, 0x11, 0, 12)
		s4, d4 := src.Addr().As4(), dst.Addr().As4()
		h = append(append(h, s4[:]...), d4[:]...)
	} else {
		h = append(h, 0x21, 0, 36)
		s16, d16 := src.Addr().As16(), dst.Addr().As16()
		h = append(append(h, s16[:]...), d16[:]...)
	}
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(h, src.Port()), dst.Port())
}

// Read consumes a v2 header where r holds one next, and reports the client
// it names; ok is false where r holds none, and a LOCAL header names none.
func Read(r *bufio.Reader) (src netip.AddrPort, ok bool, err error) {
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
	switch {
	case fam == 0x11 && n >= 12:
		a := netip.AddrFrom4([4]byte(addrs[0:4]))
		return netip.AddrPortFrom(a, binary.BigEndian.Uint16(addrs[8:10])), true, nil
	case fam == 0x21 && n >= 36:
		a := netip.AddrFrom16([16]byte(addrs[0:16])).Unmap()
		return netip.AddrPortFrom(a, binary.BigEndian.Uint16(addrs[32:34])), true, nil
	}
	return netip.AddrPort{}, false, fmt.Errorf("proxyproto: a header of family %#x", fam)
}
