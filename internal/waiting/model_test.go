package waiting

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/nning/juist/internal/modelspec"
	"github.com/nning/juist/types"
)

// A waiting change is sealed and signed over what models/waiting.pv says.
func TestAChangeFollowsItsModel(t *testing.T) {
	spec, err := modelspec.Read("../../models/waiting.pv")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range spec.Mismatches(map[string]string{
		"LabelWaitingChange": types.LabelWaitingChange,
		"LabelWaitingKey":    types.LabelWaitingKey,
		"LabelWaitingBody":   types.LabelWaitingBody,
		"LabelAdminX25519":   types.LabelAdminX25519,
	}) {
		t.Error(m)
	}
	c := &Change{Issued: 1, Expires: 2}
	for i := range c.Network {
		c.Network[i], c.ID[i] = byte(i), byte(90+i)
	}
	ctx, err := spec.Join("context", map[string][]byte{"network": c.Network[:], "id": c.ID[:]})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.context(), ctx) {
		t.Error("a change's context is not the model's")
	}
	unsigned := *c
	body, err := encMode.Marshal(&unsigned)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := spec.Join("signed", map[string][]byte{"change": body})
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256(signed); !bytes.Equal(c.signed(), want[:]) {
		t.Error("a change is signed over other bytes than the model's")
	}
}
