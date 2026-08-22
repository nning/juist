package types

import (
	"bytes"
	"net/netip"
	"testing"
)

// FuzzDecodeAUM is the record-decoder target docs/06-verification.md schedules
// for M1. It asserts the property the whole encoding rests on, which is
// stronger than "does not crash":
//
//	Decode is injective. Whatever DecodeAUM accepts, re-encoding reproduces
//	byte for byte.
//
// If that ever fails, a record has two encodings and therefore two hashes, and
// a quorum's signature over one could be presented as authorizing the other.
func FuzzDecodeAUM(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := DecodeAUM(data)
		if err != nil {
			return
		}
		re, err := a.Encode()
		if err != nil {
			t.Fatalf("a decoded record failed to re-encode: %v", err)
		}
		if !bytes.Equal(re, data) {
			t.Fatalf("re-encoding changed the bytes:\ninput: %x\nagain: %x", data, re)
		}
		// Anything that decoded is structurally valid, so the hashes must be
		// computable without panicking, and must differ from one another.
		if a.Hash() == a.SigHash() {
			t.Fatal("record hash and signing hash collide")
		}
		// A second decode of the same bytes must produce the same record.
		b, err := DecodeAUM(data)
		if err != nil {
			t.Fatalf("second decode of accepted input failed: %v", err)
		}
		if b.Hash() != a.Hash() {
			t.Fatal("decoding the same bytes twice produced different records")
		}
	})
}

// FuzzValidate feeds the validator records assembled by mutating a valid one,
// rather than raw bytes, so it explores the semantic rules rather than the
// decoder. It asserts only that validation terminates without panicking: a
// panic in the trust layer is a denial of service reachable from any record a
// peer sends.
func FuzzValidateAUM(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := decodeCanonical[AUM](data)
		if err != nil {
			return
		}
		_ = a.StaticValidate()
		_ = a.ValidateUnsigned()
		if a.State != nil {
			_ = a.State.StaticValidate(a.Kind == KindGenesis)
			if a.State.GenesisHash != nil {
				_ = a.State.ValidateInNetwork()
			}
			_ = a.State.Clone()
		}
		if a.Node != nil {
			_ = a.Node.StaticValidate()
			_ = a.Node.ValidateRoutes(ULA(Hash{}))
			_ = a.Node.Clone()
		}
		if a.Epoch != nil {
			_ = a.Epoch.StaticValidate()
		}
		_ = a.Clone()
	})
}

func seedCorpus(f *testing.F) {
	f.Helper()
	for _, seed := range corpusSeeds(f) {
		f.Add(seed)
	}
	// Shapes the structured seeds cannot reach: empty input, a bare map, and
	// the CBOR forms the decoder must refuse.
	f.Add([]byte{})
	f.Add([]byte{0xa0})             // empty map
	f.Add([]byte{0xbf, 0xff})       // indefinite-length empty map
	f.Add([]byte{0xc0, 0x61, 0x61}) // tagged text string
	f.Add([]byte{0xf9, 0x3c, 0x00}) // half-precision float
}

// corpusSeeds returns the canonical encodings of one record of every kind, so
// the fuzzer starts from inputs that reach every branch of the field table.
func corpusSeeds(t interface{ Fatalf(string, ...any) }) [][]byte {
	priv, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	node, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	v4 := netip.MustParseAddr("100.64.0.1")
	rec := NodeRecord{
		Identity:  node.Public(),
		Name:      "n",
		WireGuard: WGKey{1},
		X25519:    X25519Key{2},
		MLKEM:     MLKEMKey{3},
		V4:        &v4,
		Roles:     []Role{RoleExitNode},
		Routes:    []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		Expiry:    99,
	}
	epoch := &EpochRecord{
		Epoch:  2,
		Commit: EpochCommit([]byte("s")),
		Wraps:  []EpochWrap{{Recipient: node.Public(), Sealed: bytes.Repeat([]byte{7}, SealedSecretSize)}},
	}
	snap := &Snapshot{
		Network:     "net",
		Quorum:      1,
		Epoch:       1,
		EpochCommit: EpochCommit([]byte("g")),
		Disablement: []Hash{DisablementCommit(bytes.Repeat([]byte{2}, DisablementSecretSize))},
		Admins:      []AdminKey{{Public: priv.Public(), Votes: 1}},
	}
	parent := Hash{1, 2, 3}
	id := node.Public()
	quorum := uint32(2)
	fresh, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	freshPub := fresh.Public()

	checkpointSnap := snap.Clone()
	gh := Hash{9}
	checkpointSnap.GenesisHash = &gh

	records := []AUM{
		{Kind: KindGenesis, State: snap},
		{Kind: KindAddNode, Prev: &parent, Node: &rec, Epoch: epoch},
		{Kind: KindRemoveNode, Prev: &parent, Subject: &id, Epoch: epoch},
		{Kind: KindSetNodeRoutes, Prev: &parent, Subject: &id,
			Grant: &RouteGrant{Roles: []Role{RoleRelayCapable}}},
		{Kind: KindRotateNodeKey, Prev: &parent, Subject: &id,
			Keys: &NodeKeys{WireGuard: WGKey{4}, X25519: X25519Key{5}, MLKEM: MLKEMKey{6}}, Epoch: epoch},
		{Kind: KindRotateIdentity, Prev: &parent, Subject: &id, NewIdentity: &freshPub, Epoch: epoch},
		{Kind: KindAddAdminKey, Prev: &parent, Admin: &AdminKey{Public: freshPub, Votes: 3}},
		{Kind: KindRemoveAdminKey, Prev: &parent, Subject: &id},
		{Kind: KindSetQuorum, Prev: &parent, Quorum: &quorum},
		{Kind: KindCheckpoint, Prev: &parent, State: checkpointSnap},
		{Kind: KindEpochBump, Prev: &parent, Epoch: epoch},
	}
	out := make([][]byte, 0, len(records))
	for i := range records {
		a := records[i]
		if err := a.Sign(priv); err != nil {
			t.Fatalf("signing seed %v: %v", a.Kind, err)
		}
		b, err := a.Encode()
		if err != nil {
			t.Fatalf("encoding seed %v: %v", a.Kind, err)
		}
		out = append(out, b)
	}
	return out
}

// TestCorpusSeedsAreValid keeps the fuzz corpus honest: if a seed stopped
// decoding, the fuzzer would still run but would be exploring only the
// rejection paths.
func TestCorpusSeedsAreValid(t *testing.T) {
	for i, seed := range corpusSeeds(t) {
		a, err := DecodeAUM(seed)
		if err != nil {
			t.Fatalf("seed %d does not decode: %v", i, err)
		}
		re, err := a.Encode()
		if err != nil {
			t.Fatalf("seed %d does not re-encode: %v", i, err)
		}
		if !bytes.Equal(re, seed) {
			t.Fatalf("seed %d is not canonical", i)
		}
	}
}
