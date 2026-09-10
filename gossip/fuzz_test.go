package gossip

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// seedFrames gives the fuzzer valid encodings to mutate, so it starts inside
// the format rather than spending its budget rediscovering CBOR.
func seedFrames(f *testing.F) {
	f.Helper()
	priv, err := types.GenerateIdentity()
	if err != nil {
		f.Fatal(err)
	}
	ep := Endpoint{
		Identity:   priv.Public(),
		Disco:      DiscoKey{1, 2, 3},
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")},
		GossipPort: 41642,
		Seq:        7,
	}
	if err := ep.Sign(priv); err != nil {
		f.Fatal(err)
	}
	frames := []frame{
		{Kind: kindHello, Network: types.Hash{1}, Anchor: types.Hash{9}},
		{Kind: kindHello, Network: types.Hash{1}, Epoch: 4, Head: types.Hash{2},
			Anchor: types.Hash{9}, Have: []types.Hash{{3}, {4}}, Self: &ep},
		{Kind: kindRecords, Network: types.Hash{1}, Epoch: 4, Anchor: types.Hash{9},
			Records: [][]byte{{0xa1, 0x01, 0x01}}, Endpoints: []Endpoint{ep}},
	}
	for i := range frames {
		b, err := encode(&frames[i])
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	b, err := ep.Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte(nil))
	f.Add([]byte{0})
}

// FuzzDecodeFrame asserts injectivity rather than only the absence of crashes:
// a frame that decodes must re-encode to the same bytes. Announcements nest
// inside frames and their signatures cover their encoding, so a second
// spelling would let a relay respell what it forwards.
func FuzzDecodeFrame(f *testing.F) {
	seedFrames(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		fr, err := decodeFrame(data)
		if err != nil {
			return
		}
		re, err := encode(&fr)
		if err != nil {
			t.Fatalf("a decoded frame failed to re-encode: %v", err)
		}
		if !bytes.Equal(re, data) {
			t.Fatalf("re-encoding changed the bytes:\ninput: %x\nagain: %x", data, re)
		}
		// Whatever the frame carries, reading it must stay inside the limits
		// the shape check promised.
		if len(fr.Records) > MaxRecordsPerFrame ||
			len(fr.Have) > MaxHashesPerFrame ||
			len(fr.Endpoints) > MaxEndpointsPerFrame {
			t.Fatal("an accepted frame is over a limit validate() should have enforced")
		}
		for i := range fr.Endpoints {
			// Verification of a hostile announcement must terminate without
			// panicking; whether it passes is not this target's business.
			_ = fr.Endpoints[i].Verify()
			_ = fr.Endpoints[i].GossipAddrs()
		}
		if fr.Self != nil {
			_ = fr.Self.Verify()
		}
		for _, raw := range fr.Records {
			_, _ = types.DecodeAUM(raw)
		}
	})
}

// FuzzDecodeEndpoint targets the announcement decoder directly, and asserts
// the property the reconciler depends on: anything DecodeEndpoint accepts is
// signed by the node it names, and re-encodes to the bytes that signature
// covers.
func FuzzDecodeEndpoint(f *testing.F) {
	seedFrames(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := DecodeEndpoint(data)
		if err != nil {
			return
		}
		if err := e.Verify(); err != nil {
			t.Fatalf("DecodeEndpoint accepted a record that does not verify: %v", err)
		}
		re, err := e.Encode()
		if err != nil {
			t.Fatalf("a decoded announcement failed to re-encode: %v", err)
		}
		if !bytes.Equal(re, data) {
			t.Fatalf("re-encoding changed the bytes:\ninput: %x\nagain: %x", data, re)
		}
	})
}

// FuzzOpenFrame drives the sealed-frame parser: the length, epoch and nonce
// handling before any key is applied, and the AEAD below it. The fuzzer does
// not hold the keyring's secret, so the assertion is that everything is
// rejected without panicking.
func FuzzOpenFrame(f *testing.F) {
	var s secrets.Secret
	for i := range s {
		s[i] = byte(i)
	}
	kr := secrets.NewKeyring()
	kr.Adopt(1, s)

	if blob, err := seal(s, 1, []byte{0xa1, 0x01, 0x01}); err == nil {
		f.Add(blob)
	}
	f.Add([]byte(nil))
	f.Add(make([]byte, sealOverhead))

	f.Fuzz(func(t *testing.T, data []byte) {
		epoch, pt, err := open(kr, data)
		if err != nil {
			return
		}
		if epoch != 1 {
			t.Fatalf("opened a frame at epoch %d, but the keyring only holds 1", epoch)
		}
		if pt == nil {
			t.Fatal("open reported success with no plaintext")
		}
		_, _ = decodeFrame(pt)
	})
}
