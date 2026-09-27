package waiting

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

func adminKey(t *testing.T) (types.PrivateIdentity, types.AdminKey) {
	t.Helper()
	priv, err := types.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := secrets.AdminRecipient(priv.Seed())
	if err != nil {
		t.Fatal(err)
	}
	r, err := keys.Recipient()
	if err != nil {
		t.Fatal(err)
	}
	return priv, types.AdminKey{Public: priv.Public(), Votes: 1, Recipient: &r}
}

// subject is the device the removals here are about.
var subject = func() types.Identity {
	id, err := types.GenerateIdentity()
	if err != nil {
		panic(err)
	}
	return id.Public()
}()

func removal(t *testing.T, signer types.PrivateIdentity) *types.AUM {
	t.Helper()
	aum := &types.AUM{Kind: types.KindRemoveNode, Prev: &types.Hash{1}, Subject: &subject,
		Epoch: &types.EpochRecord{Epoch: 2, Commit: types.Hash{2}}}
	if err := aum.Sign(signer); err != nil {
		t.Fatal(err)
	}
	return aum
}

// A change sealed to admins travels as bytes, and opens for each of them to
// the record it was, and for no other key.
func TestAChangeOpensForItsAdminsAlone(t *testing.T) {
	alice, aliceKey := adminKey(t)
	bob, bobKey := adminKey(t)
	carol, _ := adminKey(t)
	network := types.Hash{9}
	aum := removal(t, alice)
	c, err := Seal(network, aum, []types.AdminKey{aliceKey, bobKey, {Public: carol.Public(), Votes: 1}}, alice, types.Identity{},
		time.Unix(1000, 0), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsAbout(subject) || c.SealedTo(carol.Public()) {
		t.Fatalf("about %v, sealed to %v", c.About, c.Readers)
	}
	b, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []types.PrivateIdentity{alice, bob} {
		rec, err := got.Open(k)
		if err != nil || rec.SigHash() != aum.SigHash() || !rec.VerifySignature(alice.Public()) {
			t.Fatalf("%v opened %v, %v", k.Public().ShortString(), rec.Kind, err)
		}
	}
	// Carol has no encryption key in the log, so nothing is sealed to her;
	// a device's keys, which hold the group secret, open nothing either.
	if _, err := got.Open(carol); err == nil {
		t.Fatal("a key the change is not sealed to opened it")
	}
	device, err := secrets.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got.Readers {
		if _, err := secrets.OpenKey(got.context(), r.Admin, device, r.Key); err == nil {
			t.Fatal("a device's keys opened a change sealed to an admin")
		}
	}
}

// A copy whose bytes were changed after it was signed is refused, and so is
// one its signer signed but that breaks the bounds on a copy.
func TestAChangedCopyIsRefused(t *testing.T) {
	alice, aliceKey := adminKey(t)
	c, err := Seal(types.Hash{9}, removal(t, alice), []types.AdminKey{aliceKey}, alice, types.Identity{}, time.Unix(1000, 0), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mutated := func(change func(*Change), resign bool) []byte {
		copied := *c
		copied.About = append([]types.Identity(nil), c.About...)
		copied.Readers = append([]Reader(nil), c.Readers...)
		change(&copied)
		if resign {
			if copied.Sig, err = alice.Sign(copied.signed()); err != nil {
				t.Fatal(err)
			}
		}
		b, err := copied.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, change := range map[string]func(*Change){
		"a later expiry": func(c *Change) { c.Expires++ },
		"fewer devices":  func(c *Change) { c.About = nil },
		"another parent": func(c *Change) { c.Prev = types.Hash{3} },
		"another body":   func(c *Change) { c.Body = append([]byte{0}, c.Body[1:]...) },
	} {
		if _, err := Decode(mutated(change, false)); err == nil {
			t.Errorf("%s, not signed again: decoded", name)
		}
	}
	for name, change := range map[string]func(*Change){
		"a lifetime too long": func(c *Change) { c.Expires = c.Issued + int64(MaxLifetime/time.Second) + 1 },
		"a lifetime that overflows": func(c *Change) {
			c.Expires = c.Issued + int64(math.MaxInt64/int64(time.Second)) + 1
		},
		"issued before 1970": func(c *Change) { c.Issued, c.Expires = -10, 10 },
		"about too many devices": func(c *Change) {
			c.About = make([]types.Identity, MaxAbout+1)
			for i := range c.About {
				c.About[i] = subject
			}
		},
		"readers twice":    func(c *Change) { c.Readers = append(c.Readers, c.Readers[0]) },
		"a short key":      func(c *Change) { c.Readers[0].Key = c.Readers[0].Key[1:] },
		"sealed to nobody": func(c *Change) { c.Readers = nil },
	} {
		if _, err := Decode(mutated(change, true)); err == nil {
			t.Errorf("%s, signed by its signer: decoded", name)
		}
	}
	b, _ := c.Encode()
	if _, err := Decode(append(b, 0)); err == nil {
		t.Error("trailing bytes decoded")
	}
	if _, err := Decode(mutated(func(*Change) {}, true)); err != nil {
		t.Fatalf("the copy as it was, signed again: %v", err)
	}
}

// An admin key whose encryption key cannot be sealed to is left out, rather
// than stopping every change from being carried.
func TestAnUnusableReaderIsLeftOut(t *testing.T) {
	alice, aliceKey := adminKey(t)
	bad := types.RecipientKey{X25519: types.X25519Key{9}}
	for i := range bad.MLKEM {
		bad.MLKEM[i] = 0xff
	}
	c, err := Seal(types.Hash{9}, removal(t, alice), []types.AdminKey{aliceKey,
		{Public: subject, Votes: 1, Recipient: &bad}}, alice, types.Identity{}, time.Unix(1000, 0), time.Hour)
	if err != nil {
		t.Fatalf("a reader with an unusable key stopped the change: %v", err)
	}
	if !c.SealedTo(alice.Public()) || c.SealedTo(subject) {
		t.Fatalf("sealed to %v", c.Readers)
	}
}

// A signer who lies about which devices a change is about, or seals another
// record than it names, is found out where the change is opened.
func TestASignerLyingAboutItsChangeIsFoundOut(t *testing.T) {
	alice, aliceKey := adminKey(t)
	aum := removal(t, alice)
	c, err := Seal(types.Hash{9}, aum, []types.AdminKey{aliceKey}, alice, types.Identity{}, time.Unix(1000, 0), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c.About = nil
	if c.Sig, err = alice.Sign(c.signed()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Open(alice); err == nil || !strings.Contains(err.Error(), "other devices") {
		t.Fatalf("a copy hiding whom it is about: %v", err)
	}
	unsigned := *aum
	unsigned.Signatures = nil
	c, err = Seal(types.Hash{9}, &unsigned, []types.AdminKey{aliceKey}, alice, types.Identity{}, time.Unix(1000, 0), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Open(alice); err == nil {
		t.Fatal("a copy of a record its signer did not sign opened")
	}
	if _, err := Seal(types.Hash{9}, aum, []types.AdminKey{{Public: alice.Public(), Votes: 1}}, alice, types.Identity{},
		time.Unix(1000, 0), time.Hour); err != ErrNoReaders {
		t.Fatalf("sealed to admins without encryption keys: %v", err)
	}
}

// A copy naming as its proposer a key that did not sign the record is found
// out where it is opened.
func TestAProposerWhoDidNotSignIsFoundOut(t *testing.T) {
	alice, aliceKey := adminKey(t)
	bob, _ := adminKey(t)
	if _, err := Seal(types.Hash{9}, removal(t, alice), []types.AdminKey{aliceKey}, alice, bob.Public(),
		time.Unix(1000, 0), time.Hour); err == nil {
		t.Fatal("sealed a copy naming a proposer who did not sign the record")
	}
	c, err := Seal(types.Hash{9}, removal(t, alice), []types.AdminKey{aliceKey}, alice, types.Identity{},
		time.Unix(1000, 0), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c.Proposer = bob.Public()
	if c.Sig, err = alice.Sign(c.signed()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Open(alice); err == nil {
		t.Fatal("a copy naming a proposer who did not sign it opened")
	}
}
