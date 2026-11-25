package forward

import (
	"bytes"
	"testing"

	"github.com/nning/juist/internal/modelspec"
)

// A host registers over what models/relay.pv says.
func TestARegistrationFollowsItsModel(t *testing.T) {
	spec, err := modelspec.Read("../../models/relay.pv")
	if err != nil {
		t.Fatal(err)
	}
	var cert, nonce [32]byte
	var id [16]byte
	for i := range cert {
		cert[i], nonce[i] = byte(i), byte(200-i)
	}
	for i := range id {
		id[i] = byte(70 + i)
	}
	want, err := spec.Join("registration", map[string][]byte{"certHash": cert[:], "id": id[:], "nonce": nonce[:]})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Message(cert, id, nonce), want) {
		t.Error("a registration is signed over other bytes than the model's")
	}
}
