package types

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// testAUM builds a fully populated genesis record, so that the codec tests
// exercise every field type in the schema at once.
func testAUM(t *testing.T) (AUM, PrivateIdentity) {
	t.Helper()
	admin := mustIdentity(t)
	node := mustIdentity(t)
	v4 := netip.MustParseAddr("100.64.0.7")
	snap := Snapshot{
		Network:     "test-net",
		Quorum:      1,
		Epoch:       1,
		EpochCommit: EpochCommit([]byte("secret")),
		Disablement: []Hash{DisablementCommit(bytes.Repeat([]byte{1}, DisablementSecretSize))},
		Admins:      []AdminKey{{Public: admin.Public(), Votes: 1, Name: "root"}},
		Nodes: []NodeRecord{{
			Identity:  node.Public(),
			Name:      "laptop",
			WireGuard: WGKey{1},
			X25519:    X25519Key{2},
			MLKEM:     MLKEMKey{3},
			V4:        &v4,
			Roles:     []Role{RoleAdmin, RoleExitNode},
			Routes:    []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("10.0.0.0/8")},
			Expiry:    1 << 40,
		}},
		EpochWraps: []EpochWrap{{Recipient: node.Public(), Sealed: bytes.Repeat([]byte{4}, SealedSecretSize)}},
	}
	a := AUM{Kind: KindGenesis, State: &snap}
	if err := a.Sign(admin); err != nil {
		t.Fatalf("signing: %v", err)
	}
	if err := a.StaticValidate(); err != nil {
		t.Fatalf("StaticValidate on a record built to be valid: %v", err)
	}
	return a, admin
}

func mustIdentity(t *testing.T) PrivateIdentity {
	t.Helper()
	p, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	return p
}

func TestRoundTrip(t *testing.T) {
	a, _ := testAUM(t)
	b, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := DecodeAUM(b)
	if err != nil {
		t.Fatalf("DecodeAUM: %v", err)
	}
	again, err := got.Encode()
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(b, again) {
		t.Fatalf("re-encoding a decoded record changed the bytes:\n%x\n%x", b, again)
	}
	if got.Hash() != a.Hash() {
		t.Error("hash changed across a round trip")
	}
	if got.SigHash() != a.SigHash() {
		t.Error("signing hash changed across a round trip")
	}
}

// TestSchemaUsesByteStrings guards the assumption the whole encoding rests on:
// that the CBOR library honours MarshalBinary for the key and address types,
// giving fixed-length byte strings rather than arrays of integers. If that ever
// stopped holding, records would still round-trip but every hash in every
// deployed log would change.
func TestSchemaUsesByteStrings(t *testing.T) {
	a, _ := testAUM(t)
	b, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	id := a.State.Nodes[0].Identity
	if !bytes.Contains(b, id[:]) {
		t.Error("node identity key does not appear verbatim in the encoding")
	}
	wg := a.State.Nodes[0].WireGuard
	if !bytes.Contains(b, wg[:]) {
		t.Error("WireGuard key does not appear verbatim in the encoding")
	}
	if !bytes.Contains(b, []byte{100, 64, 0, 7}) {
		t.Error("overlay v4 address does not appear as 4 bytes in the encoding")
	}
	// A 1184-byte ML-KEM key encoded as a CBOR array of integers would be
	// well over 1184 bytes on its own; catch that shape change by size.
	if len(b) > 4096 {
		t.Errorf("encoding is %d bytes; expected roughly 2.5 KiB, so some field is not a byte string", len(b))
	}
}

func TestDecodeRejectsNonCanonical(t *testing.T) {
	a, _ := testAUM(t)
	canonical, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Each of the following is a valid CBOR encoding of the same record under
	// a permissive decoder, and each must be rejected: two encodings of one
	// record would be two chain entries from one authorization.

	t.Run("unsorted map keys", func(t *testing.T) {
		// Declaring the fields in descending key order and disabling the
		// encoder's sort produces the same record with its top-level map
		// written back to front.
		type unsortedAUM struct {
			Signatures []Signature `cbor:"23,keyasint,omitempty"`
			State      *Snapshot   `cbor:"3,keyasint,omitempty"`
			Kind       Kind        `cbor:"1,keyasint"`
		}
		opts := cbor.CTAP2EncOptions()
		opts.Sort = cbor.SortNone
		em, err := opts.EncMode()
		if err != nil {
			t.Fatalf("EncMode: %v", err)
		}
		b, err := em.Marshal(unsortedAUM{Signatures: a.Signatures, State: a.State, Kind: a.Kind})
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if bytes.Equal(b, canonical) {
			t.Fatal("the unsorted encoder produced the canonical bytes; the test no longer tests anything")
		}
		if _, err := DecodeAUM(b); err == nil {
			t.Fatal("accepted a record whose map keys are not sorted")
		}
	})

	t.Run("indefinite-length map", func(t *testing.T) {
		// 0xa3 is a definite-length 3-pair map; 0xbf opens the indefinite
		// form, which a break byte closes.
		if canonical[0] != 0xa3 {
			t.Fatalf("expected the record to start with a 3-pair map, got %#x", canonical[0])
		}
		b := append([]byte{0xbf}, canonical[1:]...)
		b = append(b, 0xff)
		if _, err := DecodeAUM(b); err == nil {
			t.Fatal("accepted an indefinite-length map")
		}
	})

	t.Run("non-minimal integer key", func(t *testing.T) {
		// The first map key is 1, canonically the single byte 0x01. Writing
		// it as a one-byte-argument uint (0x18 0x01) is the same number
		// spelled longer.
		if canonical[1] != 0x01 {
			t.Fatalf("expected the first map key to be 0x01, got %#x", canonical[1])
		}
		b := append([]byte{}, canonical[:1]...)
		b = append(b, 0x18, 0x01)
		b = append(b, canonical[2:]...)
		if _, err := DecodeAUM(b); err == nil {
			t.Fatal("accepted a non-minimally encoded map key")
		}
	})

	t.Run("trailing bytes", func(t *testing.T) {
		if _, err := DecodeAUM(append(bytes.Clone(canonical), 0x00)); err == nil {
			t.Fatal("accepted trailing bytes after the record")
		}
	})

	t.Run("truncated", func(t *testing.T) {
		if _, err := DecodeAUM(canonical[:len(canonical)-1]); err == nil {
			t.Fatal("accepted a truncated record")
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		// Splice an extra map entry (key 22, value 0) into the top-level map
		// by re-encoding through a generic map, which is how a future or
		// hostile encoder would add one.
		var raw map[any]any
		dm, err := cbor.DecOptions{}.DecMode()
		if err != nil {
			t.Fatalf("DecMode: %v", err)
		}
		if err := dm.Unmarshal(canonical, &raw); err != nil {
			t.Fatalf("Unmarshal to map: %v", err)
		}
		raw[uint64(22)] = uint64(0)
		b, err := encMode.Marshal(raw)
		if err != nil {
			t.Fatalf("Marshal map: %v", err)
		}
		if _, err := DecodeAUM(b); err == nil {
			t.Fatal("accepted a record carrying an unknown field")
		}
	})

	t.Run("empty array instead of absent", func(t *testing.T) {
		// Roles is omitempty, so an explicitly empty Roles array is a second
		// encoding of "no roles".
		var raw map[any]any
		dm, err := cbor.DecOptions{}.DecMode()
		if err != nil {
			t.Fatalf("DecMode: %v", err)
		}
		if err := dm.Unmarshal(canonical, &raw); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		state, ok := raw[uint64(3)].(map[any]any)
		if !ok {
			t.Fatalf("state field is %T, not a map", raw[uint64(3)])
		}
		nodes, ok := state[uint64(8)].([]any)
		if !ok {
			t.Fatalf("nodes field is %T, not an array", state[uint64(8)])
		}
		node, ok := nodes[0].(map[any]any)
		if !ok {
			t.Fatalf("node is %T, not a map", nodes[0])
		}
		delete(node, uint64(9)) // drop Expiry
		node[uint64(9)] = uint64(0)
		b, err := encMode.Marshal(raw)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if _, err := DecodeAUM(b); err == nil {
			t.Fatal("accepted an explicitly-zero value for an omitempty field")
		}
	})
}

func TestStaticValidateRejectsFieldSmuggling(t *testing.T) {
	a, admin := testAUM(t)
	// A genesis record may carry only State. Attaching a node record to it
	// must be rejected outright rather than ignored.
	sub := a.State.Nodes[0].Identity
	a.Subject = &sub
	a.Signatures = nil
	if err := a.Sign(admin); err != nil {
		t.Fatalf("signing: %v", err)
	}
	if err := a.StaticValidate(); err == nil {
		t.Fatal("accepted a genesis record carrying a Subject")
	}
	b, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := DecodeAUM(b); err == nil {
		t.Fatal("decoded a genesis record carrying a Subject")
	}
}

func TestUnknownKindRejected(t *testing.T) {
	a, admin := testAUM(t)
	a.Kind = Kind(200)
	a.Signatures = nil
	if err := a.Sign(admin); err != nil {
		t.Fatalf("signing: %v", err)
	}
	if err := a.StaticValidate(); err == nil {
		t.Fatal("accepted an unknown record kind")
	}
}

func TestSigHashExcludesSignatures(t *testing.T) {
	a, _ := testAUM(t)
	before := a.SigHash()
	second := mustIdentity(t)
	if err := a.Sign(second); err != nil {
		t.Fatalf("signing: %v", err)
	}
	if a.SigHash() != before {
		t.Error("adding a signature changed the signing hash")
	}
	if !a.VerifySignature(second.Public()) {
		t.Error("signature added second does not verify")
	}
	stripped := AUM{Kind: KindGenesis, State: a.State}
	if a.Hash() == stripped.Hash() {
		t.Error("record hash does not cover the signature set")
	}
}

func TestSignRejectsDuplicateSigner(t *testing.T) {
	a, admin := testAUM(t)
	if err := a.Sign(admin); err == nil {
		t.Fatal("signing twice with the same key was accepted")
	}
}

func TestHashLabelsAreDistinct(t *testing.T) {
	a, _ := testAUM(t)
	if a.Hash() == a.SigHash() {
		t.Fatal("record hash and signing hash collide")
	}
	// Nothing should let a signing hash be presented as a record hash, which
	// the domain-separation labels are what prevent.
	unsigned := a
	unsigned.Signatures = nil
	if a.SigHash() == hashLabeled(labelAUM, mustEncode(&unsigned)) {
		t.Fatal("signing hash equals the unlabelled record hash of the unsigned record")
	}
}
