package secrets

import (
	"bytes"
	"crypto/hpke"
	"testing"

	"github.com/nning/juist/types"
)

func testNode(t *testing.T) (types.NodeRecord, *PrivateKeys) {
	t.Helper()
	id, err := types.GenerateIdentity()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	priv, err := GenerateKeys()
	if err != nil {
		t.Fatalf("generating recipient keys: %v", err)
	}
	x, m, err := priv.Public()
	if err != nil {
		t.Fatalf("public keys: %v", err)
	}
	return types.NodeRecord{
		Identity:  id.Public(),
		WireGuard: types.WGKey{1},
		X25519:    x,
		MLKEM:     m,
	}, priv
}

// TestCiphersuiteIsTheIntendedOne pins the KEM the recipient key assembles to.
// The post-quantum hedge is the whole reason for the ML-KEM half, and it would
// be lost silently if the hybrid construction ever resolved to something else.
func TestCiphersuiteIsTheIntendedOne(t *testing.T) {
	node, _ := testNode(t)
	pub, err := recipientKey(node.X25519, node.MLKEM)
	if err != nil {
		t.Fatalf("recipientKey: %v", err)
	}
	if got, want := pub.KEM().ID(), hpke.MLKEM768X25519().ID(); got != want {
		t.Fatalf("recipient key uses KEM %d, want DHKEM(X25519)+ML-KEM-768 (%d)", got, want)
	}
	if got, want := len(pub.Bytes()), types.X25519KeySize+types.MLKEMKeySize; got != want {
		t.Fatalf("serialized recipient key is %d bytes, want %d", got, want)
	}
}

// TestSealedSizeMatchesSchema pins the constant the record schema validates
// wraps against. If the ciphersuite changes, this fails rather than letting
// every epoch record be silently rejected at the length check.
func TestSealedSizeMatchesSchema(t *testing.T) {
	node, _ := testNode(t)
	rec, err := SealTo(Secret{}, 1, []types.NodeRecord{node})
	if err != nil {
		t.Fatalf("SealTo: %v", err)
	}
	if got := len(rec.Wraps[0].Sealed); got != types.SealedSecretSize {
		t.Fatalf("sealed wrap is %d bytes, types.SealedSecretSize says %d", got, types.SealedSecretSize)
	}
}

func TestSealAndOpen(t *testing.T) {
	var nodes []types.NodeRecord
	var privs []*PrivateKeys
	for range 3 {
		n, p := testNode(t)
		nodes = append(nodes, n)
		privs = append(privs, p)
	}
	secret, rec, err := NewEpoch(7, nodes)
	if err != nil {
		t.Fatalf("NewEpoch: %v", err)
	}
	if rec.Epoch != 7 || rec.Commit != secret.Commit() {
		t.Fatal("epoch record does not describe the secret it was built from")
	}
	for i := range nodes {
		got, err := Open(rec, nodes[i].Identity, privs[i])
		if err != nil {
			t.Fatalf("node %d Open: %v", i, err)
		}
		if !got.Equal(secret) {
			t.Fatalf("node %d recovered a different secret", i)
		}
	}
}

func TestOpenRejectsWrongRecipient(t *testing.T) {
	a, privA := testNode(t)
	b, privB := testNode(t)
	_, rec, err := NewEpoch(1, []types.NodeRecord{a, b})
	if err != nil {
		t.Fatalf("NewEpoch: %v", err)
	}
	// B's keys against A's wrap: the info string binds each wrap to its
	// recipient, so this must fail even though both are members.
	if _, err := Open(rec, a.Identity, privB); err == nil {
		t.Fatal("opened another member's wrap")
	}
	if _, err := Open(rec, b.Identity, privA); err == nil {
		t.Fatal("opened another member's wrap")
	}
}

func TestOpenRejectsNonMember(t *testing.T) {
	member, _ := testNode(t)
	outsider, privOut := testNode(t)
	_, rec, err := NewEpoch(1, []types.NodeRecord{member})
	if err != nil {
		t.Fatalf("NewEpoch: %v", err)
	}
	if _, err := Open(rec, outsider.Identity, privOut); err == nil {
		t.Fatal("a non-member found a wrap to open")
	}
}

// TestOpenRejectsReplayedEpoch covers lifting a wrap out of one epoch's record
// into another's: the recipient key does not change between epochs, so only the
// info binding stops it.
func TestOpenRejectsReplayedEpoch(t *testing.T) {
	node, priv := testNode(t)
	secret, rec1, err := NewEpoch(1, []types.NodeRecord{node})
	if err != nil {
		t.Fatalf("NewEpoch: %v", err)
	}
	replayed := &types.EpochRecord{Epoch: 2, Commit: secret.Commit(), Wraps: rec1.Wraps}
	if _, err := Open(replayed, node.Identity, priv); err == nil {
		t.Fatal("opened an epoch-1 wrap presented as epoch 2")
	}
}

// TestOpenDetectsMismatchedSecrets is the split-discovery attack: a quorum
// seals a different secret to each member. The commitment is what makes it
// visible.
func TestOpenDetectsMismatchedSecrets(t *testing.T) {
	a, privA := testNode(t)
	b, privB := testNode(t)
	honest, honestRec, err := NewEpoch(1, []types.NodeRecord{a, b})
	if err != nil {
		t.Fatalf("NewEpoch: %v", err)
	}
	var other Secret
	other[0] = 0xff
	if other.Equal(honest) {
		t.Fatal("test secrets collided")
	}
	evilRec, err := SealTo(other, 1, []types.NodeRecord{b})
	if err != nil {
		t.Fatalf("SealTo: %v", err)
	}
	// Keep the honest commitment, but swap in a wrap of a different secret
	// for B.
	forged := &types.EpochRecord{Epoch: 1, Commit: honestRec.Commit}
	for _, w := range honestRec.Wraps {
		if w.Recipient == b.Identity {
			w = evilRec.Wraps[0]
		}
		forged.Wraps = append(forged.Wraps, w)
	}
	if _, err := Open(forged, a.Identity, privA); err != nil {
		t.Fatalf("A's untouched wrap stopped opening: %v", err)
	}
	if _, err := Open(forged, b.Identity, privB); err == nil {
		t.Fatal("B accepted a secret that does not match the record's commitment")
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	node, priv := testNode(t)
	_, rec, err := NewEpoch(1, []types.NodeRecord{node})
	if err != nil {
		t.Fatalf("NewEpoch: %v", err)
	}
	rec.Wraps[0].Sealed[0] ^= 0x01
	if _, err := Open(rec, node.Identity, priv); err == nil {
		t.Fatal("opened a tampered wrap")
	}
}

func TestSealRejectsInvalidRecipientKeys(t *testing.T) {
	node, _ := testNode(t)
	bad := node
	// All-ones fails ML-KEM's modulus check: the packed coefficients decode
	// to values at or above q. Note what does *not* fail it — an all-zero key
	// is a structurally valid encoding of the all-zero polynomial, so nothing
	// here can reject it. That is why the record schema rejects a zero
	// ML-KEM key by shape; see the assertion below.
	for i := range bad.MLKEM {
		bad.MLKEM[i] = 0xff
	}
	if _, err := SealTo(Secret{}, 1, []types.NodeRecord{bad}); err == nil {
		t.Fatal("sealed to an ML-KEM key that fails the modulus check")
	}
	zeroKeyed := node
	zeroKeyed.MLKEM = types.MLKEMKey{}
	if err := zeroKeyed.StaticValidate(); err == nil {
		t.Fatal("the schema accepted a zero ML-KEM key, which the KEM cannot reject")
	}
	bad = node
	bad.X25519 = types.X25519Key{} // low-order point
	if _, err := SealTo(Secret{}, 1, []types.NodeRecord{bad}); err == nil {
		t.Fatal("sealed to a low-order X25519 key")
	}
}

func TestKeyPersistenceRoundTrip(t *testing.T) {
	node, priv := testNode(t)
	x, m := priv.Bytes()
	restored, err := NewPrivateKeys(x, m)
	if err != nil {
		t.Fatalf("NewPrivateKeys: %v", err)
	}
	gotX, gotM, err := restored.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	if gotX != node.X25519 || gotM != node.MLKEM {
		t.Fatal("restored keys have different public halves")
	}
	_, rec, err := NewEpoch(1, []types.NodeRecord{node})
	if err != nil {
		t.Fatalf("NewEpoch: %v", err)
	}
	if _, err := Open(rec, node.Identity, restored); err != nil {
		t.Fatalf("restored keys cannot open a wrap: %v", err)
	}
}

// TestDerivationsAreSeparated checks that no two derived values collide and
// that each changes with the epoch: a revoked member must not keep a usable
// topic or key from the epoch it was removed in.
func TestDerivationsAreSeparated(t *testing.T) {
	s, err := NewSecret()
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	dk := s.DiscoveryKey(1)
	alice, bob := types.Identity{1}, types.Identity{2}
	seedE1W0A := s.TopicSeed(1, 0, alice)
	seedE1W1A := s.TopicSeed(1, 1, alice)
	seedE2W0A := s.TopicSeed(2, 0, alice)
	seedE1W0B := s.TopicSeed(1, 0, bob)
	seen := map[string]string{
		// Every axis a topic must separate on: two members, two windows and
		// two epochs must never land on one another's item.
		"topic e1 w0 alice": string(seedE1W0A[:]),
		"topic e1 w1 alice": string(seedE1W1A[:]),
		"topic e2 w0 alice": string(seedE2W0A[:]),
		"topic e1 w0 bob":   string(seedE1W0B[:]),
		"mdns e1":           string(s.MDNSName(1)),
		"mdns e2":           string(s.MDNSName(2)),
		"discovery e1":      string(dk[:]),
		"secret itself":     string(s[:]),
	}
	byValue := map[string]string{}
	for name, v := range seen {
		if other, dup := byValue[v]; dup {
			t.Errorf("%s and %s derive the same bytes", other, name)
		}
		byValue[v] = name
	}
	dk2 := s.DiscoveryKey(2)
	if bytes.Equal(dk[:], dk2[:]) {
		t.Error("the discovery key does not change with the epoch")
	}
}
