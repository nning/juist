package secrets

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"testing"

	"github.com/nning/juist/internal/modelspec"
	"github.com/nning/juist/types"
)

// The HPKE infos of a catch-up grant and of a waiting change's key, and an
// admin key's recipient key, are what models/catchup.pv and
// models/waiting.pv say.
func TestSealingFollowsTheModels(t *testing.T) {
	catchUp, err := modelspec.Read("../../models/catchup.pv")
	if err != nil {
		t.Fatal(err)
	}
	waiting, err := modelspec.Read("../../models/waiting.pv")
	if err != nil {
		t.Fatal(err)
	}
	var network types.Hash
	var reader types.Identity
	for i := range network {
		network[i], reader[i] = byte(i), byte(50+i)
	}
	nonce, context := bytes.Repeat([]byte{3}, 32), []byte("a context")
	v := map[string][]byte{"network": network[:], "recipient": reader[:], "reader": reader[:], "nonce": nonce,
		"context": context}
	for _, c := range []struct {
		spec *modelspec.Spec
		name string
		got  []byte
	}{
		{catchUp, "grantInfo", catchUpInfo(network, reader, nonce)},
		{waiting, "keyInfo", keyInfo(context, reader)},
	} {
		want, err := c.spec.Join(c.name, v)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(c.got, want) {
			t.Errorf("%s is not the model's", c.name)
		}
	}

	seed := bytes.Repeat([]byte{5}, 32)
	priv, err := AdminRecipient(seed)
	if err != nil {
		t.Fatal(err)
	}
	x, err := hkdf.Key(sha256.New, seed, nil, waiting.Labels["LabelAdminX25519"], 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv.x25519.Bytes(), x) {
		t.Error("an admin key's X25519 key is not derived under the model's label")
	}
}
