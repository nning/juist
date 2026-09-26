package enroll

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"filippo.io/edwards25519"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(strings.Join(strings.Fields(s), ""), "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSPAKE2Constants regenerates M and N with the procedure in RFC 9382
// Appendix A, so the constants are not taken on trust.
func TestSPAKE2Constants(t *testing.T) {
	order := edwards25519.NewScalar().Subtract(edwards25519.NewScalar(), scalarOne())
	for name, want := range map[string]*edwards25519.Point{"M": spakeM, "N": spakeN} {
		h := []byte("edwards25519 point generation seed (" + name + ")")
		var got []byte
		for i := 1; i < 1000 && got == nil; i++ {
			sum := sha256.Sum256(h)
			h = sum[:]
			p, err := new(edwards25519.Point).SetBytes(h)
			if err != nil || !bytes.Equal(p.Bytes(), h) || p.Equal(edwards25519.NewIdentityPoint()) == 1 {
				continue
			}
			// l*P == identity, computed as (l-1)*P + P.
			lp := new(edwards25519.Point).ScalarMult(order, p)
			if lp.Add(lp, p).Equal(edwards25519.NewIdentityPoint()) == 1 {
				got = bytes.Clone(h)
			}
		}
		if !bytes.Equal(got, want.Bytes()) {
			t.Errorf("%s: generated %x, the constant is %x", name, got, want.Bytes())
		}
	}
}

func scalarOne() *edwards25519.Scalar {
	var b [32]byte
	b[0] = 1
	s, err := edwards25519.NewScalar().SetCanonicalBytes(b[:])
	if err != nil {
		panic(err)
	}
	return s
}

// TestKeyScheduleMatchesRFC checks the transcript encoding and key schedule
// against RFC 9382 Appendix B. The vectors are P-256 ones, which is why the
// schedule takes encoded elements rather than points.
func TestKeyScheduleMatchesRFC(t *testing.T) {
	pA := unhex(t, `04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470
		f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c`)
	pB := unhex(t, `0406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676
		d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b7`)
	k := unhex(t, `0412af7e89717850671913e6b469ace67bd90a4df8ce45c2af19010175e37eed
		69f75897996d539356e2fa6a406d528501f907e04d97515fbe83db277b715d3325`)
	w := unhex(t, `2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f`)

	got, err := keySchedule([]byte("server"), []byte("client"), pA, pB, k, w, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name      string
		got, want []byte
	}{
		{"Ke", got.ke, unhex(t, "0e0672dc86f8e45565d338b0540abe69")},
		{"A conf", got.confirmGuest, unhex(t, "58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0")},
		{"B conf", got.confirmHost, unhex(t, "d3e2e547f1ae04f2dbdbf0fc4b79f8ecff2dff314b5d32fe9fcef2fb26dc459b")},
	} {
		if !bytes.Equal(c.got, c.want) {
			t.Errorf("%s = %x, want %x", c.name, c.got, c.want)
		}
	}
}

func runSpake(t *testing.T, guestPW, hostPW string) (spakeKeys, spakeKeys) {
	t.Helper()
	g, err := newSpake(true, []byte(guestPW), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := newSpake(false, []byte(hostPW), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	gk, err := g.finish(h.message())
	if err != nil {
		t.Fatal(err)
	}
	hk, err := h.finish(g.message())
	if err != nil {
		t.Fatal(err)
	}
	return gk, hk
}

func TestSPAKE2Agrees(t *testing.T) {
	gk, hk := runSpake(t, "42-word", "42-word")
	if !bytes.Equal(gk.ke, hk.ke) || !bytes.Equal(gk.confirmGuest, hk.confirmGuest) ||
		!bytes.Equal(gk.confirmHost, hk.confirmHost) {
		t.Fatal("both sides of a run with one password derived different keys")
	}
	if bytes.Equal(gk.confirmGuest, gk.confirmHost) {
		t.Fatal("the two confirmations are equal, so one side's could be reflected as the other's")
	}
}

func TestSPAKE2WrongPasswordDisagrees(t *testing.T) {
	gk, hk := runSpake(t, "42-word", "42-ward")
	if bytes.Equal(gk.ke, hk.ke) || bytes.Equal(gk.confirmGuest, hk.confirmGuest) {
		t.Fatal("a run with two different passwords agreed on a key")
	}
}

func TestDecodeElementRejects(t *testing.T) {
	identity := edwards25519.NewIdentityPoint().Bytes()
	nonCanonical := bytes.Repeat([]byte{0xff}, 32)
	nonCanonical[31] = 0x7f // y = 2^255-1, which is y-p reduced: valid but non-canonical
	for name, b := range map[string][]byte{
		"short":         make([]byte, 31),
		"identity":      identity,
		"non-canonical": nonCanonical,
	} {
		if _, err := decodeElement(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := decodeElement(spakeM.Bytes()); err != nil {
		t.Errorf("M rejected: %v", err)
	}
}
