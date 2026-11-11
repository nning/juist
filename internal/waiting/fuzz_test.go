package waiting

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/nning/juist/types"
)

// FuzzDecode reads a copy as a daemon takes one from a member: what decodes
// encodes again to the same bytes, and no input panics. With resign the input
// is signed again by a known admin key first, so that what lies past the
// signature is reached: such a copy decodes exactly when its shape is valid,
// and opens for each admin without panicking.
func FuzzDecode(f *testing.F) {
	alice, aliceKey := adminKey(f)
	bob, bobKey := adminKey(f)
	keys := keysOf([]types.AdminKey{aliceKey, bobKey})
	c, err := Seal(types.Hash{9}, removal(f, alice), []types.AdminKey{aliceKey, bobKey}, keys, alice,
		types.Identity{}, time.Unix(1000, 0), time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	ed := *c
	ed.PQ = nil
	for _, s := range []*Change{c, &ed} {
		b, err := s.Encode()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b, false)
		f.Add(b, true)
	}
	f.Add([]byte{}, false)
	f.Add([]byte{0xa0}, true)
	f.Fuzz(func(t *testing.T, data []byte, resign bool) {
		if resign {
			c, err := types.DecodeCanonical[Change](decMode, data, MaxSize)
			if err != nil {
				refusedCleanly(t, err)
				return
			}
			c.Signer = bob.Public()
			if c.Sig, c.PQ, err = bob.SignBoth(c.signed()); err != nil {
				t.Fatal(err)
			}
			if data, err = c.Encode(); err != nil {
				t.Fatalf("a decoded change failed to encode: %v", err)
			}
			_, err = Decode(data)
			if len(data) <= MaxSize && (err == nil) != (c.validate() == nil) {
				t.Fatalf("a signed copy decodes as %v, its shape is %v", err, c.validate())
			}
		}
		c, err := Decode(data)
		if err != nil {
			refusedCleanly(t, err)
			return
		}
		re, err := c.Encode()
		if err != nil {
			t.Fatalf("a decoded change failed to re-encode: %v", err)
		}
		if !bytes.Equal(re, data) {
			t.Fatalf("re-encoding changed the bytes:\ninput: %x\nagain: %x", data, re)
		}
		if c.VerifyPQ(nil) == nil {
			t.Fatal("a copy verified against no key")
		}
		for _, admin := range []types.PrivateIdentity{alice, bob} {
			if _, err := c.Open(admin, keys); err != nil {
				refusedCleanly(t, err)
			}
		}
	})
}

// refusedCleanly fails on an error malformed.Recover made of a panic.
func refusedCleanly(t *testing.T, err error) {
	t.Helper()
	if strings.Contains(err.Error(), "malformed input: ") {
		t.Fatalf("a decoder panicked: %v", err)
	}
}
