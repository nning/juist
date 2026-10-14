package types

import (
	"bytes"
	"net/netip"
	"testing"
)

// FuzzDecodeAUM asserts the property the encoding rests on, which is stronger
// than "does not crash": whatever DecodeAUM accepts, re-encoding reproduces
// byte for byte. Without it a record has two hashes, and a quorum's signature
// over one could be presented as authorizing the other.
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

// FuzzValidate mutates a valid record rather than feeding raw bytes, so it
// explores the semantic rules rather than the decoder. It asserts only that
// validation terminates without panicking.
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
			_ = a.Node.ValidateInNetwork(ULA(Hash{}), V4Ranges(nil))
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
	nodeKey := node.SigningKey()
	rec := NodeRecord{
		Identity:  node.Public(),
		Name:      "n",
		WireGuard: WGKey{1},
		X25519:    X25519Key{2},
		MLKEM:     MLKEMKey{3},
		V4:        &v4,
		Roles:     []Role{RoleExit},
		Routes:    []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		Expiry:    99,
		Signing:   &nodeKey,
	}
	epoch := &EpochRecord{
		Epoch:  2,
		Commit: EpochCommit([]byte("s")),
		Wraps:  []EpochWrap{{Recipient: node.Public(), Sealed: bytes.Repeat([]byte{7}, SealedSecretSize)}},
	}
	snap := &Snapshot{
		Schema:      CurrentSchema,
		Network:     "net",
		Quorum:      1,
		Epoch:       1,
		EpochCommit: EpochCommit([]byte("g")),
		Disablement: []Hash{DisablementCommit(bytes.Repeat([]byte{2}, DisablementSecretSize))},
		Admins:      []AdminKey{{Public: priv.Public(), Votes: 1, Signing: new(priv.SigningKey()), Endorsement: priv.Endorsement()}},
	}
	parent := Hash{1, 2, 3}
	id := node.Public()
	quorum := uint32(2)
	schema := CurrentSchema + 1
	fresh, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	freshPub := fresh.Public()

	holderSnap := snap.Clone()
	holderSnap.Admins[0].Holder = "h"

	checkpointSnap := snap.Clone()
	gh := Hash{9}
	checkpointSnap.GenesisHash = &gh

	renumberTo := netip.MustParsePrefix("10.7.0.0/22")
	renumberedSnap := checkpointSnap.Clone()
	renumberedSnap.V4Prefix = &renumberTo
	renumberedSnap.V4Retiring = &RetiringRanges{Prefixes: []netip.Prefix{OverlayV4}, Until: 99}
	moved := rec
	newV4 := netip.MustParseAddr("10.7.0.1")
	moved.V4, moved.Retiring = &newV4, &RetiringV4{Addr: v4, Until: 99}
	moved.Names = []string{"imap.example.org", "mx.example.org"}
	moved.Published = []PublishedName{{Label: "immich", Port: 443, Proxy: true}, {Label: "mc", Port: 25565, Public: 25565}}
	renumberedSnap.Domain = "pub.example.org"
	renumberedSnap.Nodes = []NodeRecord{moved}
	renumberedSnap.EpochWraps = epoch.Wraps
	policySnap := renumberedSnap.Clone()
	policySnap.Policy = seedPolicy(moved.Identity)
	freshAdmin := func(holder string, needed uint32) *AdminKey {
		return &AdminKey{Public: freshPub, Votes: 3, Holder: holder, Needed: needed,
			Signing: new(fresh.SigningKey()), Endorsement: fresh.Endorsement()}
	}

	records := []AUM{
		{Kind: KindGenesis, State: snap},
		{Kind: KindAddNode, Prev: &parent, Node: &rec, Epoch: epoch},
		{Kind: KindRemoveNode, Prev: &parent, Subject: &id, Epoch: epoch},
		{Kind: KindSetNodeRoutes, Prev: &parent, Subject: &id,
			Grant: &RouteGrant{Roles: []Role{RoleRelayCapable}}},
		{Kind: KindRotateNodeKey, Prev: &parent, Subject: &id,
			Keys: &NodeKeys{WireGuard: WGKey{4}, X25519: X25519Key{5}, MLKEM: MLKEMKey{6}}, Epoch: epoch},
		{Kind: KindRotateIdentity, Prev: &parent, Subject: &id, NewIdentity: &freshPub,
			NewSigning: new(fresh.SigningKey()), Epoch: epoch},
		{Kind: KindAddAdminKey, Prev: &parent, Admin: freshAdmin("", 0)},
		{Kind: KindRemoveAdminKey, Prev: &parent, Subject: &id},
		{Kind: KindSetQuorum, Prev: &parent, Quorum: &quorum},
		{Kind: KindCheckpoint, Prev: &parent, State: checkpointSnap},
		{Kind: KindEpochBump, Prev: &parent, Epoch: epoch},
		{Kind: KindSchemaUpgrade, Prev: &parent, Schema: &schema},
		{Kind: KindSetVouchers, Prev: &parent, Vouchers: &quorum},
		{Kind: KindSetHolder, Prev: &parent, Holder: &HolderPolicy{Name: "h", Votes: 1, Needed: 2}},
		{Kind: KindAddAdminKey, Prev: &parent, Admin: freshAdmin("h", 2)},
		{Kind: KindGenesis, State: holderSnap},
		{Kind: KindRenumberNetwork, Prev: &parent, Renumber: &Renumbering{Until: 99, Prefix: &renumberTo,
			Addrs: []MemberV4{{Identity: id, V4: netip.MustParseAddr("10.7.0.1")}}}},
		{Kind: KindRenumberNode, Prev: &parent, Subject: &id, Renumber: &Renumbering{Until: 99, V4: &v4}},
		{Kind: KindRetireAddresses, Prev: &parent},
		{Kind: KindRenameNetwork, Prev: &parent, Network: new("office")},
		{Kind: KindSetAdminRecipient, Prev: &parent, Subject: &id,
			Recipient: &RecipientKey{X25519: X25519Key{8}, MLKEM: MLKEMKey{9}}},
		{Kind: KindCheckpoint, Prev: &parent, State: policySnap},
		{Kind: KindCheckpoint, Prev: &parent, State: renumberedSnap},
		{Kind: KindSetNodeNames, Prev: &parent, Subject: &id, Names: &NameGrant{Names: []string{"mx.example.org"}}},
		{Kind: KindSetDomain, Prev: &parent, Domain: new("pub.example.org")},
		{Kind: KindSetPublished, Prev: &parent, Subject: &id,
			Publish: &PublishGrant{Names: []PublishedName{{Label: "immich", Port: 443}}}},
		{Kind: KindSetPublished, Prev: &parent, Subject: &id,
			Publish: &PublishGrant{Names: []PublishedName{{Label: "ssh", Port: 22, Proxy: true, Public: 2222}}}},
		{Kind: KindRenameNode, Prev: &parent, Subject: &id, NodeName: new("laptop")},
		{Kind: KindDisable, Prev: &parent, Secret: &DisablementSecret{2}},
		{Kind: KindSetPolicy, Prev: &parent, Policy: seedPolicy(id)},
	}
	// An identity rotation signed by the identity rotated to.
	rotated := AUM{Kind: KindRotateIdentity, Prev: &parent, Subject: &id, NewIdentity: &freshPub,
		NewSigning: new(fresh.SigningKey()), Epoch: epoch}
	if err := rotated.Sign(fresh); err != nil {
		t.Fatalf("signing seed %v: %v", rotated.Kind, err)
	}
	records = append(records, rotated)
	out := make([][]byte, 0, len(records))
	for i := range records {
		a := records[i]
		if a.Kind != KindDisable {
			if err := a.Sign(priv); err != nil {
				t.Fatalf("signing seed %v: %v", a.Kind, err)
			}
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

// seedPolicy is a policy naming id in every place a policy names a member.
func seedPolicy(id Identity) *Policy {
	return &Policy{
		Tables:   []PolicyTable{{Name: "admins", Nodes: []Identity{id}}, {Name: "staff", Tables: []string{"admins"}}},
		Services: []PolicyService{{Name: "web", Ports: []PortRange{{Proto: ProtoTCP, First: 80, Last: 80}, {Proto: ProtoTCP, First: 443, Last: 443}}}},
		Rules: []PolicyRule{
			{From: PolicyRefs{Tables: []string{"staff"}}, To: PolicyRefs{Any: true}, Services: []string{"web"}},
			{From: PolicyRefs{Nodes: []Identity{id}}, To: PolicyRefs{Internet: true, ViaNodes: []Identity{id},
				Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")}}, Ports: []PortRange{{Proto: ProtoUDP, First: 53, Last: 53}}},
		},
		Tests: []PolicyTest{{From: id, To: PolicyRefs{Nodes: []Identity{id}}, Port: PortRange{Proto: ProtoTCP, First: 443, Last: 443}},
			{Block: true, From: id, To: PolicyRefs{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.10.7/32")}}}},
	}
}
