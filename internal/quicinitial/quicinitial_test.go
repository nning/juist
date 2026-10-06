package quicinitial

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"math/rand/v2"
	"strings"
	"testing"
)

// The keys a client derives for its first Initial, as RFC 9001 (A.1) and
// RFC 9369 (A.1) give them for the Destination Connection ID 8394c8f03e515708.
func TestInitialKeys(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	for _, c := range []struct {
		version     uint32
		key, iv, hp string
	}{
		{Version1, "1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c", "9f50449e04a0e810283a1e9933adedd2"},
		{Version2, "8b1a0bc121284290a29e0971b5cd045d", "91f73e2351d8fa91660e909f", "45b95e15235d6f45a6b19cbcb0294ba9"},
	} {
		key, iv, hp := initialKeys(c.version, dcid)
		if got := hex.EncodeToString(key); got != c.key {
			t.Errorf("version %#x: key %s", c.version, got)
		}
		if got := hex.EncodeToString(iv); got != c.iv {
			t.Errorf("version %#x: iv %s", c.version, got)
		}
		if got := hex.EncodeToString(hp); got != c.hp {
			t.Errorf("version %#x: hp %s", c.version, got)
		}
	}
}

// RFC 9001's sample of A.2 masks the header to 437b9aec36.
func TestHeaderProtectionMask(t *testing.T) {
	_, _, hp := initialKeys(Version1, mustHex("8394c8f03e515708"))
	block, err := aes.NewCipher(hp)
	if err != nil {
		t.Fatal(err)
	}
	var mask [16]byte
	block.Encrypt(mask[:], mustHex("d1b1c98dd7689fb8ec11d242b123dc9b"))
	if got := hex.EncodeToString(mask[:5]); got != "437b9aec36" {
		t.Errorf("mask %s", got)
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// initial protects payload as the client's Initial packet number pn of
// version to dcid, as a client would (RFC 9001, 5).
func initial(version uint32, dcid, scid []byte, pn uint64, payload []byte) []byte {
	key, iv, hp := initialKeys(version, dcid)
	for len(payload) < 4 {
		payload = append(payload, 0) // PADDING, so that the header protection has its sample
	}
	typ := byte(0x00)
	if version == Version2 {
		typ = 0x01
	}
	pnLen := 2
	b := []byte{0xc0 | typ<<4 | byte(pnLen-1)}
	b = binary.BigEndian.AppendUint32(b, version)
	b = append(append(b, byte(len(dcid))), dcid...)
	b = append(append(b, byte(len(scid))), scid...)
	b = append(b, 0) // no token
	length := pnLen + len(payload) + 16
	b = binary.BigEndian.AppendUint16(b, 0x4000|uint16(length))
	pnOffset := len(b)
	b = binary.BigEndian.AppendUint16(b, uint16(pn))
	blk, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(blk)
	nonce := bytes.Clone(iv)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	b = aead.Seal(b, nonce, payload, b)
	hpb, _ := aes.NewCipher(hp)
	var mask [16]byte
	hpb.Encrypt(mask[:], b[pnOffset+4:pnOffset+20])
	b[0] ^= mask[0] & 0x0f
	for i := range pnLen {
		b[pnOffset+i] ^= mask[1+i]
	}
	return b
}

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return binary.BigEndian.AppendUint16(b, 0x4000|uint16(v))
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(b, 0x80000000|uint32(v))
	}
	return binary.BigEndian.AppendUint64(b, 0xc000000000000000|v)
}

func cryptoFrame(off uint64, data []byte) []byte {
	b := appendVarint([]byte{0x06}, off)
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

// padded pads a datagram to the size a client sends Initials in.
func padded(b []byte) []byte {
	for len(b) < MinDatagram {
		b = append(b, 0)
	}
	return b
}

// clientHello is a QUIC ClientHello for name, as crypto/tls writes one,
// post-quantum key share included.
func clientHello(t testing.TB, name string) []byte {
	t.Helper()
	c := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{ServerName: name, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"}, InsecureSkipVerify: name == ""}})
	c.SetTransportParameters([]byte{0x01, 0x02, 0x67, 0x10})
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var hello []byte
	for e := c.NextEvent(); e.Kind != tls.QUICNoEvent; e = c.NextEvent() {
		if e.Kind == tls.QUICWriteData && e.Level == tls.QUICEncryptionLevelInitial {
			hello = append(hello, e.Data...)
		}
	}
	return hello
}

// The server name is read from a ClientHello in pieces, out of order and
// over two datagrams, PINGs and PADDING between them, as a browser sends
// it, in either version; until it is whole, none.
func TestTheNameOfAHelloInPieces(t *testing.T) {
	hello := clientHello(t, "immich.pub.example.org")
	if len(hello) < 1200 {
		t.Fatalf("a ClientHello of %d bytes fits one packet", len(hello))
	}
	dcid, scid := mustHex("8394c8f03e515708"), mustHex("01020304")
	for _, version := range []uint32{Version1, Version2} {
		cut := []int{0, 300, 700, 1100, len(hello)}
		var frames [][]byte
		for i := range len(cut) - 1 {
			frames = append(frames, cryptoFrame(uint64(cut[i]), hello[cut[i]:cut[i+1]]))
		}
		// The last piece first, then the second with a PING, then the rest.
		first := append(append(frames[3], 0x01), frames[1]...)
		second := append(append(frames[0], make([]byte, 10)...), frames[2]...)
		var h Hello
		for i, payload := range [][]byte{first, second} {
			d := padded(initial(version, dcid, scid, uint64(i), payload))
			if !IsInitial(d) {
				t.Fatalf("version %#x: datagram %d is no Initial", version, i)
			}
			ps, err := Parse(d)
			if err != nil {
				t.Fatalf("version %#x: datagram %d: %v", version, i, err)
			}
			name, done, err := h.Add(ps)
			switch {
			case err != nil:
				t.Fatalf("version %#x: datagram %d: %v", version, i, err)
			case i == 0 && done:
				t.Fatalf("version %#x: a name after half a hello: %q", version, name)
			case i == 1 && (!done || name != "immich.pub.example.org"):
				t.Fatalf("version %#x: after the whole hello, %q, %v", version, name, done)
			}
		}
		h.Close()
	}
}

// Two Initial packets coalesced in one datagram are both read.
func TestCoalescedInitials(t *testing.T) {
	hello := clientHello(t, "a.example.org")
	dcid := mustHex("0011223344556677")
	d := append(initial(Version1, dcid, nil, 0, cryptoFrame(0, hello[:600])),
		initial(Version1, dcid, nil, 1, cryptoFrame(600, hello[600:]))...)
	ps, err := Parse(d)
	if err != nil || len(ps) != 2 {
		t.Fatalf("%d packets, %v", len(ps), err)
	}
	var h Hello
	defer h.Close()
	if name, done, err := h.Add(ps); err != nil || !done || name != "a.example.org" {
		t.Errorf("%q, %v, %v", name, done, err)
	}
}

// What is no client's Initial, does not decrypt, belongs to another
// connection, carries a frame an Initial may not, or is too large, is
// refused.
func TestWhatIsRefused(t *testing.T) {
	hello := clientHello(t, "a.example.org")
	dcid := mustHex("0011223344556677")
	good := initial(Version1, dcid, nil, 0, cryptoFrame(0, hello))
	flipped := bytes.Clone(good)
	flipped[len(flipped)-1] ^= 1
	handshake := bytes.Clone(good)
	handshake[0] = handshake[0]&^0x30 | 0x20
	shortDCID := initial(Version1, mustHex("0011"), nil, 0, cryptoFrame(0, hello))
	for name, d := range map[string][]byte{
		"empty":            nil,
		"a short header":   append([]byte{0x40}, good[1:]...),
		"version 3":        append(append([]byte{good[0]}, 0, 0, 0, 3), good[5:]...),
		"a Handshake":      handshake,
		"a flipped bit":    flipped,
		"a truncated one":  good[:len(good)-30],
		"a 2-byte DCID":    shortDCID,
		"a header alone":   good[:12],
		"a Retry, version": append(append([]byte{0xf0}, 0, 0, 0, 1), good[5:]...),
	} {
		if ps, err := Parse(d); err == nil {
			t.Errorf("%s: %d packets read", name, len(ps))
		}
	}

	var h Hello
	defer h.Close()
	ps, _ := Parse(initial(Version1, dcid, nil, 0, cryptoFrame(0, hello[:500])))
	if _, _, err := h.Add(ps); err != nil {
		t.Fatal(err)
	}
	other, _ := Parse(initial(Version1, mustHex("8899aabbccddeeff"), nil, 1, cryptoFrame(500, hello[500:])))
	if _, _, err := h.Add(other); err == nil {
		t.Error("a packet of another connection taken")
	}
	for name, payload := range map[string][]byte{
		"a STREAM frame":   append([]byte{0x08, 0x00}, "x"...),
		"a close":          {0x1c, 0x00, 0x00, 0x00},
		"past the bound":   cryptoFrame(MaxHello, []byte("x")),
		"a cut CRYPTO":     {0x06, 0x00, 0x05, 'x'},
		"a cut ACK":        {0x02, 0x01},
		"a varint cut off": {0xc0},
	} {
		var h Hello
		ps, err := Parse(initial(Version1, dcid, nil, 0, payload))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, _, err := h.Add(ps); err == nil {
			t.Errorf("%s taken", name)
		}
		h.Close()
	}
	var many Hello
	defer many.Close()
	var err error
	for i := 0; i <= MaxSegments && err == nil; i++ {
		ps, _ := Parse(initial(Version1, dcid, nil, uint64(i), cryptoFrame(uint64(100+2*i), []byte("x"))))
		_, _, err = many.Add(ps)
	}
	if err == nil {
		t.Error("pieces past the bound taken")
	}
}

// An ACK frame, which a client's later Initials carry, is read past.
func TestAnACKIsReadPast(t *testing.T) {
	hello := clientHello(t, "a.example.org")
	ack := []byte{0x03, 0x05, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00}
	ps, err := Parse(initial(Version1, mustHex("0011223344556677"), nil, 0, append(ack, cryptoFrame(0, hello)...)))
	if err != nil {
		t.Fatal(err)
	}
	var h Hello
	defer h.Close()
	if name, done, err := h.Add(ps); err != nil || !done || name != "a.example.org" {
		t.Errorf("%q, %v, %v", name, done, err)
	}
}

// A ClientHello naming no server names nothing to serve.
func TestAHelloNamingNothing(t *testing.T) {
	hello := clientHello(t, "")
	ps, err := Parse(initial(Version1, mustHex("0011223344556677"), nil, 0, cryptoFrame(0, hello)))
	if err != nil {
		t.Fatal(err)
	}
	var h Hello
	defer h.Close()
	if _, _, err := h.Add(ps); err == nil || !strings.Contains(err.Error(), "naming no server") {
		t.Errorf("%v", err)
	}
}

// FuzzParse feeds Parse and Frames whatever a datagram may hold: nothing
// panics, and what parses was checked.
func FuzzParse(f *testing.F) {
	hello := clientHello(f, "immich.pub.example.org")
	dcid := mustHex("8394c8f03e515708")
	f.Add(padded(initial(Version1, dcid, nil, 0, cryptoFrame(0, hello))))
	f.Add(initial(Version2, dcid, mustHex("01"), 7, append([]byte{0x01, 0x00}, cryptoFrame(10, hello[10:900])...)))
	f.Add(append(initial(Version1, dcid, nil, 0, cryptoFrame(0, hello[:20])), initial(Version1, dcid, nil, 1, []byte{0x02, 0, 0, 0, 0})...))
	f.Fuzz(func(t *testing.T, b []byte) {
		if ids := SourceIDs(b); len(ids) > maxPackets {
			t.Fatalf("%d source IDs", len(ids))
		}
		ConnectionIDs(b)
		ps, err := Parse(b)
		if err != nil {
			return
		}
		var h Hello
		defer h.Close()
		_, _, _ = h.Add(ps)
	})
}

// FuzzPayloads feeds Parse and a Hello Initials whose plaintext the fuzzer
// chooses, two coalesced in one datagram and a third in another: each
// parses, and nothing panics.
func FuzzPayloads(f *testing.F) {
	hello := clientHello(f, "immich.pub.example.org")
	f.Add(false, cryptoFrame(0, hello[:600]), cryptoFrame(600, hello[600:]), []byte{})
	f.Add(true, append([]byte{0x02, 0, 0, 0, 0}, cryptoFrame(900, hello[900:])...), cryptoFrame(0, hello[:900]), []byte{0x01})
	f.Add(false, cryptoFrame(0, hello[:10]), cryptoFrame(5, hello[5:20]), cryptoFrame(20, hello[20:]))
	f.Fuzz(func(t *testing.T, v2 bool, a, b, c []byte) {
		version := uint32(Version1)
		if v2 {
			version = Version2
		}
		dcid := mustHex("8394c8f03e515708")
		var h Hello
		defer h.Close()
		for i, d := range [][]byte{append(initial(version, dcid, nil, 0, a), initial(version, dcid, nil, 1, b)...),
			initial(version, dcid, nil, 2, c)} {
			ps, err := Parse(d)
			if err != nil {
				t.Fatalf("datagram %d: %v", i, err)
			}
			if _, _, err := h.Add(ps); err != nil {
				return
			}
		}
	})
}

// FuzzHello feeds a Hello the CRYPTO frames of a real ClientHello, cut and
// ordered as the fuzzer says, and frames of its own: nothing panics, and a
// whole hello names its server.
func FuzzHello(f *testing.F) {
	hello := clientHello(f, "immich.pub.example.org")
	f.Add(uint64(1), []byte{})
	f.Add(uint64(42), []byte{0x06, 0x00, 0x01, 0x16})
	f.Fuzz(func(t *testing.T, seed uint64, extra []byte) {
		r := rand.New(rand.NewPCG(seed, seed>>1))
		var frames [][]byte
		for off := 0; off < len(hello); {
			n := min(1+r.IntN(400), len(hello)-off)
			frames = append(frames, cryptoFrame(uint64(off), hello[off:off+n]))
			off += n
		}
		r.Shuffle(len(frames), func(i, j int) { frames[i], frames[j] = frames[j], frames[i] })
		var h Hello
		defer h.Close()
		dcid := mustHex("8394c8f03e515708")
		ps, err := Parse(initial(Version1, dcid, nil, 0, extra))
		if err == nil {
			if _, _, err := h.Add(ps); err != nil {
				return
			}
		}
		var name string
		var done bool
		for i, fr := range frames {
			ps, err := Parse(initial(Version1, dcid, nil, uint64(i+1), fr))
			if err != nil {
				t.Fatal(err)
			}
			if name, done, err = h.Add(ps); err != nil {
				if len(frames) > MaxSegments || len(extra) > 0 {
					return
				}
				t.Fatalf("frame %d: %v", i, err)
			}
		}
		if !done || name != "immich.pub.example.org" {
			if len(extra) > 0 {
				return // what the fuzzer added may have closed or cut it
			}
			t.Fatalf("a whole hello named %q, %v", name, done)
		}
	})
}

// longHeader is a long header packet of type first, from scid, carrying n
// bytes after its length; Initials an empty token.
func longHeader(first byte, scid []byte, n int) []byte {
	b := append([]byte{first, 0, 0, 0, 1, 0, byte(len(scid))}, scid...)
	if first&0x30 == 0 {
		b = append(b, 0)
	}
	b = append(b, 0x40|byte(n>>8), byte(n))
	return append(b, make([]byte, n)...)
}

// The Source Connection IDs of a server's coalesced packets are read
// without keys, a Retry's last.
func TestSourceIDs(t *testing.T) {
	d := append(longHeader(0xc0, []byte{1, 2, 3, 4}, 30), longHeader(0xe0, []byte{5, 6, 7, 8}, 20)...)
	d = append(d, 0x40, 9, 9) // a short header, which carries none
	if got := SourceIDs(d); len(got) != 2 || !bytes.Equal(got[0], []byte{1, 2, 3, 4}) || !bytes.Equal(got[1], []byte{5, 6, 7, 8}) {
		t.Errorf("coalesced: %x", got)
	}
	retry := append([]byte{0xf0, 0, 0, 0, 1, 0, 2, 9, 9}, make([]byte, 40)...)
	if got := SourceIDs(append(retry, longHeader(0xc0, []byte{1}, 1)...)); len(got) != 1 || !bytes.Equal(got[0], []byte{9, 9}) {
		t.Errorf("a Retry: %x", got)
	}
	if got := SourceIDs(longHeader(0xc0, []byte{1}, 30)[:10]); len(got) != 1 {
		t.Errorf("a truncated packet: %x", got)
	}
}
