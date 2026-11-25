package gossip

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/nning/juist/internal/modelspec"
	"github.com/nning/juist/types"
)

// What catch-up signs is what models/catchup.pv says, label for label and
// field for field.
func TestCatchUpFollowsItsModel(t *testing.T) {
	spec, err := modelspec.Read("../models/catchup.pv")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range spec.Mismatches(map[string]string{
		"LabelCatchUpProof":   types.LabelCatchUpProof,
		"LabelCatchUpGrant":   types.LabelCatchUpGrant,
		"LabelCatchUpRefusal": types.LabelCatchUpRefusal,
		"LabelCatchUp":        types.LabelCatchUp,
	}) {
		t.Error(m)
	}
	var network types.Hash
	var initiator types.Identity
	for i := range network {
		network[i], initiator[i] = byte(i), byte(100+i)
	}
	nonce, sealed := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{8}, 40)
	v := map[string][]byte{"network": network[:], "nonce": nonce, "initiator": initiator[:], "sealed": sealed,
		"epoch": binary.BigEndian.AppendUint64(nil, 9)}
	for _, c := range []struct {
		name string
		got  []byte
	}{
		{"proof", catchUpProofBytes(network, nonce, initiator)},
		{"grant", catchUpGrantBytes(network, nonce, initiator, sealed)},
		{"refusal", catchUpRefusalBytes(network, nonce, initiator, 9)},
	} {
		b, err := spec.Join(c.name, v)
		if err != nil {
			t.Fatal(err)
		}
		if want := sha256.Sum256(b); !bytes.Equal(c.got, want[:]) {
			t.Errorf("a catch-up %s signs other bytes than the model's", c.name)
		}
	}
}
