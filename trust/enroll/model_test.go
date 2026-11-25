package enroll

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"strings"
	"testing"

	"filippo.io/edwards25519"

	"github.com/nning/juist/internal/modelspec"
	"github.com/nning/juist/types"
)

// modelFile is the ProVerif library the enrollment's models share.
const modelFile = "../../models/enroll.pvl"

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
		"LabelEnrollSPAKE2W": types.LabelEnrollSPAKE2W,
		"LabelEnrollV1":      types.LabelEnrollV1,
		"LabelEnrollV3":      types.LabelEnrollV3,
		"LabelEnrollBinding": types.LabelEnrollBinding,
		"LabelEnrollProof":   types.LabelEnrollProof,
		"LabelWordsCommit":   types.LabelWordsCommit,
		"LabelDeviceWords":   types.LabelDeviceWords,
		"guestIdentity":      string(guestIdentity),
		"hostIdentity":       string(hostIdentity),
		"confirmationKeys":   "ConfirmationKeys", // RFC 9382's; TestKeyScheduleMatchesRFC holds the code to it
		"guestToHost":        guestToHost,
		"hostToGuest":        hostToGuest,
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

// joined builds a value from the model's fields: labels with a zero byte
// after them, the rest as values gives them.
func joined(t *testing.T, labels map[string]string, fields []string, values map[string][]byte) []byte {
	t.Helper()
	var b []byte
	for _, f := range fields {
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

func lengthPrefixed(order binary.AppendByteOrder, fields []string, values map[string][]byte) []byte {
	var b []byte
	for _, f := range fields {
		b = order.AppendUint64(b, uint64(len(values[f])))
		b = append(b, values[f]...)
	}
	return b
}

func field(t *testing.T, fields map[string][]string, name string) []string {
	t.Helper()
	f, ok := fields[name]
	if !ok {
		t.Fatalf("%s lists no fields for %s", modelFile, name)
	}
	return f
}

// Every value the model builds from fields, the code builds from the same
// fields in the same order.
func TestTheModelNamesTheCodesFields(t *testing.T) {
	labels, fields := readModel(t)
	v := map[string][]byte{}
	for i, name := range []string{"password", "pA", "pB", "K", "ek", "ct", "salt", "nonce", "identity",
		"wireguard", "x25519", "mlkem", "signing", "binding"} {
		v[name] = bytes.Repeat([]byte{byte(i + 1)}, 3+i)
	}
	v["guestIdentity"], v["hostIdentity"] = guestIdentity, hostIdentity

	t.Run("w", func(t *testing.T) {
		got, err := passwordScalar(v["password"])
		if err != nil {
			t.Fatal(err)
		}
		sum := sha512.Sum512(joined(t, labels, field(t, fields, "w"), v))
		want, err := edwards25519.NewScalar().SetUniformBytes(sum[:])
		if err != nil {
			t.Fatal(err)
		}
		if got.Equal(want) != 1 {
			t.Error("w is not hashed from the model's fields")
		}
	})

	v["w"] = bytes.Repeat([]byte{0x77}, 32)
	keys, err := keySchedule(v["guestIdentity"], v["hostIdentity"], v["pA"], v["pB"], v["K"], v["w"], []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("keySchedule", func(t *testing.T) {
		if want := lengthPrefixed(binary.LittleEndian, field(t, fields, "keySchedule"), v); !bytes.Equal(keys.transcript, want) {
			t.Error("the key schedule's transcript is not the model's fields in its order")
		}
	})

	v["keySchedule"] = keys.transcript
	t.Run("transcript and binding", func(t *testing.T) {
		c := &Channel{ke: keys.ke, transcript: keys.transcript}
		if err := c.agreed(bytes.Repeat([]byte{9}, 32), v["ek"], v["ct"]); err != nil {
			t.Fatal(err)
		}
		tr := sha256.Sum256(lengthPrefixed(binary.BigEndian, field(t, fields, "transcript"), v))
		w := map[string][]byte{"transcript": tr[:]}
		if want := sha256.Sum256(joined(t, labels, field(t, fields, "binding"), w)); c.Binding() != want {
			t.Error("the binding is not hashed from the model's fields")
		}
	})

	t.Run("channel", func(t *testing.T) {
		c := &Channel{ke: keys.ke, transcript: keys.transcript}
		ss := bytes.Repeat([]byte{9}, 32)
		if err := c.agreed(ss, v["ek"], v["ct"]); err != nil {
			t.Fatal(err)
		}
		tr := sha256.Sum256(lengthPrefixed(binary.BigEndian, field(t, fields, "transcript"), v))
		w := map[string][]byte{"Ke": keys.ke, "ss": ss, "transcript": tr[:]}
		k, err := hkdf.Key(sha256.New, joined(t, labels, field(t, fields, "channel.secret"), w),
			joined(t, labels, field(t, fields, "channel.salt"), w), labels["LabelEnrollV3"]+labels["hostToGuest"], 32)
		if err != nil {
			t.Fatal(err)
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			t.Fatal(err)
		}
		want, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("a frame")
		if !bytes.Equal(c.send.Seal(nil, counterNonce(0), msg, nil), want.Seal(nil, counterNonce(0), msg, nil)) {
			t.Error("the channel's key is not derived from the model's fields")
		}
	})

	t.Run("proof", func(t *testing.T) {
		var b [32]byte
		copy(b[:], v["binding"])
		w := map[string][]byte{"binding": b[:]}
		if want := sha256.Sum256(joined(t, labels, field(t, fields, "proof"), w)); !bytes.Equal(proofMessage(b), want[:]) {
			t.Error("the proof of possession signs another message than the model's")
		}
	})

	t.Run("commit", func(t *testing.T) {
		var n Nonce
		copy(n[:], v["nonce"])
		w := map[string][]byte{"nonce": n[:]}
		if CommitNonce(n) != sha256.Sum256(joined(t, labels, field(t, fields, "commit"), w)) {
			t.Error("the nonce's commitment is not hashed from the model's fields")
		}
	})

	t.Run("deviceWords", func(t *testing.T) {
		var req JoinRequest
		var salt Salt
		var nonce Nonce
		for _, f := range []struct {
			dst  []byte
			name string
		}{
			{salt[:], "salt"}, {nonce[:], "nonce"}, {req.Identity[:], "identity"},
			{req.Keys.WireGuard[:], "wireguard"}, {req.Keys.X25519[:], "x25519"},
			{req.Keys.MLKEM[:], "mlkem"}, {req.Signing[:], "signing"},
		} {
			for i := range f.dst {
				f.dst[i] = byte(len(f.name) + i)
			}
			v[f.name] = f.dst
		}
		sum := sha256.Sum256(joined(t, labels, field(t, fields, "deviceWords"), v))
		want := make([]string, 4)
		for i := range want {
			want[i] = wordAt(i, sum[i])
		}
		if got := Fingerprint(salt, nonce, &req); got != strings.Join(want, "-") {
			t.Errorf("the words are %s, the model's fields give %s", got, strings.Join(want, "-"))
		}
	})
}

// A link's forward id and rendezvous keys derive as models/relay.pv says,
// and an admission signs what models/rebase.pv says.
func TestTheRelayAndRebaseModelsNameTheCodes(t *testing.T) {
	relay, err := modelspec.Read("../../models/relay.pv")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range relay.Mismatches(map[string]string{
		"LabelInviteForward":    types.LabelInviteForward,
		"LabelInviteRendezvous": types.LabelInviteRendezvous,
		"LabelRelayForward":     types.LabelRelayForward,
		"roleHost":              rendezvousHost,
		"roleGuest":             rendezvousGuest,
		"roleSeal":              rendezvousSeal,
	}) {
		t.Error(m)
	}
	l, err := NewLink(nil)
	if err != nil {
		t.Fatal(err)
	}
	derive := func(info string, n int) []byte {
		k, err := hkdf.Key(sha256.New, l.secret[:], nil, info, n)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	if id := l.ForwardID(); !bytes.Equal(id[:], derive(relay.Labels["LabelInviteForward"], 16)) {
		t.Error("the forward id is not derived as the model says")
	}
	host, guest, seal := l.RendezvousKeys()
	for _, k := range []struct {
		got  [32]byte
		role string
	}{{host, "roleHost"}, {guest, "roleGuest"}, {seal, "roleSeal"}} {
		if !bytes.Equal(k.got[:], derive(relay.Labels["LabelInviteRendezvous"]+relay.Labels[k.role], 32)) {
			t.Errorf("the rendezvous key for %s is not derived as the model says", k.role)
		}
	}

	rebase, err := modelspec.Read("../../models/rebase.pv")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range rebase.Mismatches(map[string]string{"LabelEnrollAdmission": types.LabelEnrollAdmission}) {
		t.Error(m)
	}
	var a Admission
	for i := range a.Admin {
		a.Admin[i], a.Network[i], a.Head[i], a.Guest[i] = byte(i), byte(40+i), byte(80+i), byte(120+i)
	}
	a.Signing[0] = 9
	want, err := rebase.Join("admission", map[string][]byte{"admin": a.Admin[:], "network": a.Network[:],
		"head": a.Head[:], "guest": a.Guest[:], "signing": a.Signing[:]})
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(want); !bytes.Equal(a.message(), sum[:]) {
		t.Error("an admission signs other bytes than the model's")
	}
}
