package pairkey

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/nning/juist/internal/modelspec"
	"github.com/nning/juist/types"
)

// modelFile is the ProVerif library the pair key's models share.
const modelFile = "../../models/pairkey.pvl"

// readModel returns the labels and field lists the model names.
func readModel(t *testing.T) (labels map[string]string, fields map[string][]string) {
	t.Helper()
	spec, err := modelspec.Read(modelFile)
	if err != nil {
		t.Fatal(err)
	}
	return spec.Labels, spec.Fields
}

// The labels the model names are the code's, byte for byte.
func TestTheModelNamesTheCodesLabels(t *testing.T) {
	code := map[string]string{
		"LabelPSKGroup": types.LabelPSKGroup,
		"LabelPSKPair":  types.LabelPSKPair,
		"LabelPSKCheck": types.LabelPSKCheck,
		"LabelPairMsg":  types.LabelPairMsg,
		"roleLeader":    roleLeader,
		"roleFollower":  roleFollower,
	}
	labels, _ := readModel(t)
	if len(labels) == 0 {
		t.Fatalf("%s names no labels", modelFile)
	}
	for name, v := range labels {
		got, ok := code[name]
		switch {
		case !ok:
			t.Errorf("the model names %s, which this test does not know", name)
		case got != v:
			t.Errorf("%s is %q in the model, %q in the code", name, v, got)
		}
	}
}

// Every value the model builds from fields, the code builds from the same
// fields in the same order.
func TestTheModelNamesTheCodesFields(t *testing.T) {
	labels, fields := readModel(t)
	joined := func(name string, values map[string][]byte) []byte {
		t.Helper()
		list, ok := fields[name]
		if !ok {
			t.Fatalf("%s lists no fields for %s", modelFile, name)
		}
		var b []byte
		for _, f := range list {
			if l, ok := labels[f]; ok {
				b = append(append(b, l...), 0)
				continue
			}
			v, ok := values[f]
			if !ok {
				t.Fatalf("the model names a field %s, which this test does not know", f)
			}
			b = append(b, v...)
		}
		return b
	}
	expand := func(name string, values map[string][]byte) Key {
		t.Helper()
		k, err := hkdf.Key(sha256.New, joined(name+".secret", values), joined(name+".salt", values),
			string(joined(name+".info", values)), 32)
		if err != nil {
			t.Fatal(err)
		}
		return Key(k)
	}

	var network types.Hash
	var seed [32]byte
	var lower, higher types.WGKey
	for i := range 32 {
		network[i], seed[i], lower[i], higher[i] = byte(i), byte(100+i), 1, 2
	}
	const gen, epoch = 7, 9
	v := map[string][]byte{
		"network": network[:], "seed": seed[:], "lower": lower[:], "higher": higher[:],
		"leader": lower[:], "follower": higher[:],
		"gen":     binary.BigEndian.AppendUint64(nil, gen),
		"epoch":   binary.BigEndian.AppendUint64(nil, epoch),
		"sharedL": bytes.Repeat([]byte{3}, 32), "sharedF": bytes.Repeat([]byte{4}, 32),
		"ctL": bytes.Repeat([]byte{5}, 40), "ctF": bytes.Repeat([]byte{6}, 40),
	}

	group := Group(seed, epoch, higher, lower)
	if group != expand("groupKey", v) {
		t.Error("the group key is not derived from the model's fields")
	}
	v["groupKey"] = group[:]
	tr := sha256.Sum256(joined("transcript", v))
	v["transcript"] = tr[:]
	k := derive(network, lower, higher, gen, epoch, group, v["sharedL"], v["ctL"], v["sharedF"], v["ctF"])
	if k != expand("pairKey", v) {
		t.Error("the pair key is not derived from the model's fields")
	}

	for _, role := range []string{roleLeader, roleFollower} {
		w := map[string][]byte{"key": k[:], "role": []byte(role)}
		m := hmac.New(sha256.New, joined("check.key", w))
		m.Write(joined("check.message", w))
		if !bytes.Equal(check(k, role), m.Sum(nil)[:checkSize]) {
			t.Errorf("the %s's confirmation is not the model's", role)
		}
	}

	msg := Msg{Store: 1, ToStore: 2, FromWG: lower, ToWG: higher, Gen: gen}
	msg.From[0], msg.To[0] = 1, 2
	body, err := encMode.Marshal(&msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := msg.signingBytes(network)
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256(joined("pairMsg", map[string][]byte{"network": network[:], "body": body})); !bytes.Equal(got, want[:]) {
		t.Error("a message is signed over other bytes than the model's")
	}
}
