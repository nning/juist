package log

import (
	"bytes"
	"crypto/sha256"

	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// Deterministic fixtures: fuzz targets and property tests need the same
// network on every run, since a failure that cannot be replayed is not a
// report. Nothing under test depends on a key being unpredictable — the log's
// rules are about who signed.

func fixedIdentity(n byte) types.PrivateIdentity {
	seed := sha256.Sum256([]byte{'i', n})
	priv, err := types.NewPrivateIdentity(seed[:])
	if err != nil {
		panic(err)
	}
	return priv
}

func fixedNode(n byte) types.NodeRecord {
	id := fixedIdentity(100 + n)
	rec := types.NodeRecord{Identity: id.Public()}
	wg := sha256.Sum256([]byte{'w', n})
	copy(rec.WireGuard[:], wg[:])
	x := sha256.Sum256([]byte{'x', n})
	copy(rec.X25519[:], x[:])
	// A structurally valid ML-KEM encapsulation key is not something to
	// synthesize by hand, so this one is a real key derived from a fixed seed.
	priv := fixedRecipientKeys(n)
	xk, mk, err := priv.Public()
	if err != nil {
		panic(err)
	}
	rec.X25519, rec.MLKEM = xk, mk
	return rec
}

// fixedGenesis returns a one-admin, quorum-of-one network with no members,
// together with the admin's private key.
func fixedGenesis() (types.AUM, types.PrivateIdentity, error) {
	admin := fixedIdentity(0)
	commit := types.DisablementCommit(fixedDisablementSecret())
	genesis, err := Genesis("fuzz-net", 1,
		[]types.AdminKey{{Public: admin.Public(), Votes: 1, Name: "admin", Holder: "admin"}},
		[]types.Hash{commit}, nil, testSealer())
	if err != nil {
		return types.AUM{}, admin, err
	}
	if err := genesis.Sign(admin); err != nil {
		return types.AUM{}, admin, err
	}
	return genesis, admin, nil
}

// fixedRecipientKeys returns a node's HPKE recipient keys derived from a
// counter.
func fixedRecipientKeys(n byte) *secrets.PrivateKeys {
	x := sha256.Sum256([]byte{'X', n})
	a := sha256.Sum256([]byte{'m', n})
	b := sha256.Sum256([]byte{'M', n})
	priv, err := secrets.NewPrivateKeys(x[:], append(a[:], b[:]...))
	if err != nil {
		panic(err)
	}
	return priv
}

// testSealer seals every epoch to a fixed group secret, so a genesis record
// with no members is byte-identical on every run. HPKE seals are randomized,
// so records carrying wraps still differ; nothing here depends otherwise.
func testSealer() Sealer {
	return func(epoch uint64, members []types.NodeRecord) (*types.EpochRecord, error) {
		seed := sha256.Sum256([]byte("group secret"))
		var secret secrets.Secret
		copy(secret[:], seed[:])
		return secrets.SealTo(secret, epoch, members)
	}
}

// fixedSealer is testSealer without the randomness: wraps are placeholders of
// the right length, which the log checks but never opens, so a record carrying
// them hashes alike on every run — and so does every fork choice between them.
func fixedSealer() Sealer {
	return func(epoch uint64, members []types.NodeRecord) (*types.EpochRecord, error) {
		rec := &types.EpochRecord{Epoch: epoch, Commit: types.EpochCommit([]byte("group secret"))}
		for _, m := range members {
			sealed := bytes.Repeat([]byte{byte(epoch)}, types.SealedSecretSize)
			copy(sealed, m.Identity[:])
			rec.Wraps = append(rec.Wraps, types.EpochWrap{Recipient: m.Identity, Sealed: sealed})
		}
		return rec, nil
	}
}

func fixedDisablementSecret() []byte {
	s := sha256.Sum256([]byte("disablement"))
	return s[:]
}
