package gossip

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/nning/juist/internal/addrkey"
	"github.com/nning/juist/types"
)

// What a signature covers is wire format: a record an older build signed must
// verify.
func TestSignaturesCoverTheLabelledUnsignedEncoding(t *testing.T) {
	priv, err := types.NewPrivateIdentity(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	digest := func(label string, v any) []byte {
		body, err := encode(v)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(append(append([]byte(label), 0), body...))
		return h[:]
	}
	k := AddrKey{Owner: priv.Public(), ID: 7, Seq: 2, Wraps: [][]byte{bytes.Repeat([]byte{1}, addrkey.WrapSize)}}
	unsignedKey := k
	if k.Sig, err = priv.Sign(digest("juist/addr-key/v1", &unsignedKey)); err != nil {
		t.Fatal(err)
	}
	if err := k.Verify(); err != nil {
		t.Errorf("an address key signed as before: %v", err)
	}
	e := Endpoint{Identity: priv.Public(), Seq: 1, Disco: DiscoKey{1}, GossipPort: 7, Schema: types.CurrentSchema}
	unsignedEndpoint := e
	if e.Sig, err = priv.Sign(digest("juist/endpoint/v1", &unsignedEndpoint)); err != nil {
		t.Fatal(err)
	}
	if err := e.Verify(); err != nil {
		t.Errorf("an endpoint record signed as before: %v", err)
	}
	other, _ := types.NewPrivateIdentity(bytes.Repeat([]byte{4}, 32))
	if err := e.Sign(other); err == nil {
		t.Error("an endpoint record was signed by a key it does not name")
	}
}
