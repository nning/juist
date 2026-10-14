package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
)

// pcapFlows reads a capture tcpdump wrote of an Ethernet link and prints a
// line for each TCP flow to port 443, with the server name its first
// ClientHello asks for, or "empty" where it carried no byte, one for each DNS
// query, and one for every packet that is neither.
func pcapFlows(file string) error {
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if len(b) < 24 {
		return errors.New("no pcap header")
	}
	var order binary.ByteOrder
	switch binary.LittleEndian.Uint32(b) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		order = binary.LittleEndian
	default:
		order = binary.BigEndian
	}
	if link := order.Uint32(b[20:]); link != 1 {
		return fmt.Errorf("a capture of link type %d, not Ethernet", link)
	}
	type flow struct {
		key   string
		hello []byte
		sni   string
	}
	var flows []*flow
	byKey := map[string]*flow{}
	for off := 24; off+16 <= len(b); {
		n := int(order.Uint32(b[off+8:]))
		if off+16+n > len(b) {
			break
		}
		pkt := b[off+16 : off+16+n]
		off += 16 + n
		if len(pkt) < 14 {
			continue
		}
		eth := binary.BigEndian.Uint16(pkt[12:])
		if eth == 0x0806 {
			continue // ARP: no IP leaves by it
		}
		if eth != 0x0800 {
			fmt.Printf("other ethertype %#04x\n", eth)
			continue
		}
		ip := pkt[14:]
		if len(ip) < 20 {
			continue
		}
		ihl := int(ip[0]&0xf) * 4
		proto := ip[9]
		src, dst := netip.AddrFrom4([4]byte(ip[12:16])), netip.AddrFrom4([4]byte(ip[16:20]))
		if len(ip) < ihl+8 {
			continue
		}
		l4 := ip[ihl:]
		sport, dport := binary.BigEndian.Uint16(l4), binary.BigEndian.Uint16(l4[2:])
		switch {
		case (proto == 6 || proto == 17) && (sport == 53 || dport == 53):
			if dport == 53 {
				fmt.Printf("dns %s %v > %v\n", map[byte]string{6: "tcp", 17: "udp"}[proto], src, dst)
			}
		case proto == 6 && (sport == 443 || dport == 443):
			if dport != 443 {
				continue // the server's side
			}
			k := fmt.Sprintf("%v:%d > %v:443", src, sport, dst)
			f := byKey[k]
			if f == nil {
				f = &flow{key: k}
				byKey[k] = f
				flows = append(flows, f)
			}
			if len(l4) < 20 {
				continue
			}
			payload := l4[int(l4[12]>>4)*4:]
			if f.sni == "" && len(payload) > 0 && len(f.hello) < 16<<10 {
				f.hello = append(f.hello, payload...)
				f.sni = serverName(f.hello)
			}
		default:
			fmt.Printf("other proto %d %v:%d > %v:%d\n", proto, src, sport, dst, dport)
		}
	}
	for _, f := range flows {
		if len(f.hello) == 0 {
			fmt.Printf("tcp %s empty\n", f.key)
			continue
		}
		fmt.Printf("tls %s sni %s\n", f.key, cmpOr(f.sni, "-"))
	}
	return nil
}

// serverName is the SNI of the ClientHello b starts with, "" where b holds
// none yet, or is none.
func serverName(b []byte) string {
	// Records: type 22, then the handshake across them.
	var hs []byte
	for len(b) >= 5 && b[0] == 22 {
		n := int(binary.BigEndian.Uint16(b[3:]))
		if len(b) < 5+n {
			hs = append(hs, b[5:]...)
			break
		}
		hs = append(hs, b[5:5+n]...)
		b = b[5+n:]
	}
	if len(hs) < 4 || hs[0] != 1 {
		return ""
	}
	r := reader{hs[4:]}
	r.skip(2 + 32)       // version, random
	r.skip(int(r.u8()))  // session id
	r.skip(int(r.u16())) // cipher suites
	r.skip(int(r.u8()))  // compression
	ext := reader{r.take(int(r.u16()))}
	for len(ext.b) >= 4 {
		typ, body := ext.u16(), ext.take(int(ext.u16()))
		if typ != 0 {
			continue
		}
		list := reader{body}
		names := reader{list.take(int(list.u16()))}
		for len(names.b) >= 3 {
			kind, name := names.u8(), names.take(int(names.u16()))
			if kind == 0 {
				return string(name)
			}
		}
	}
	return ""
}

type reader struct{ b []byte }

func (r *reader) take(n int) []byte {
	if n > len(r.b) {
		n = len(r.b)
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) skip(n int) { r.take(n) }

func (r *reader) u8() byte {
	if len(r.b) < 1 {
		return 0
	}
	return r.take(1)[0]
}

func (r *reader) u16() uint16 {
	if len(r.b) < 2 {
		r.b = nil
		return 0
	}
	return binary.BigEndian.Uint16(r.take(2))
}
