package types

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
)

// The rules below are kept in step with AUM's fields by hand: presentFields,
// fieldNames, kindFields, Clone and ValidateUnsigned. These tests fail when a
// field is added to one and not the others.

// payloadFields are AUM's fields other than Kind, Prev and Signatures.
func payloadFields() []reflect.StructField {
	var out []reflect.StructField
	for _, f := range reflect.VisibleFields(reflect.TypeFor[AUM]()) {
		switch f.Name {
		case "Kind", "Prev", "Signatures":
		default:
			out = append(out, f)
		}
	}
	return out
}

func TestEveryPayloadFieldIsTracked(t *testing.T) {
	var carried fieldSet
	for _, want := range kindFields {
		carried |= want
	}
	var seen fieldSet
	for _, f := range payloadFields() {
		if f.Type.Kind() != reflect.Pointer {
			t.Errorf("%s is not a pointer, so presentFields cannot tell it absent", f.Name)
			continue
		}
		var a AUM
		reflect.ValueOf(&a).Elem().FieldByIndex(f.Index).Set(reflect.New(f.Type.Elem()))
		bit := a.presentFields()
		if bit == 0 || bit&(bit-1) != 0 {
			t.Errorf("%s sets presentFields %v, want exactly one field", f.Name, bit)
			continue
		}
		if bit.String() != f.Name {
			t.Errorf("%s is named %q in fieldNames", f.Name, bit.String())
		}
		if seen&bit != 0 {
			t.Errorf("%s shares its field bit with another field", f.Name)
		}
		seen |= bit
		if carried&bit == 0 {
			t.Errorf("no kind in kindFields carries %s", f.Name)
		}
	}
	if len(fieldNames) != len(payloadFields()) {
		t.Errorf("fieldNames has %d entries for %d payload fields", len(fieldNames), len(payloadFields()))
	}
}

// fill sets every reachable field of v to a non-zero value, allocating
// pointers and giving slices two elements.
func fill(v reflect.Value, n *uint64) {
	*n++
	switch v.Type() {
	case reflect.TypeFor[netip.Addr]():
		v.Set(reflect.ValueOf(netip.AddrFrom4([4]byte{100, 64, 0, byte(*n)})))
		return
	case reflect.TypeFor[netip.Prefix]():
		v.Set(reflect.ValueOf(netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(*n), 0, 0}), 16)))
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fill(v.Elem(), n)
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 2, 2))
		for i := range v.Len() {
			fill(v.Index(i), n)
		}
	case reflect.Array:
		for i := range v.Len() {
			fill(v.Index(i), n)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if !v.Type().Field(i).IsExported() {
				panic(fmt.Sprintf("fill: %v has unexported field %s", v.Type(), v.Type().Field(i).Name))
			}
			fill(v.Field(i), n)
		}
	case reflect.String:
		v.SetString(fmt.Sprint("s", *n))
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(*n)
	default:
		panic(fmt.Sprintf("fill: unhandled %v", v.Type()))
	}
}

// shared returns the pointers and slices two values have in common.
func shared(path string, a, b reflect.Value) []string {
	var out []string
	switch a.Kind() {
	case reflect.Pointer:
		if a.IsNil() {
			return nil
		}
		if a.Pointer() == b.Pointer() {
			return []string{path}
		}
		return shared(path, a.Elem(), b.Elem())
	case reflect.Slice:
		if a.Len() > 0 && a.Pointer() == b.Pointer() {
			return []string{path}
		}
		for i := range a.Len() {
			out = append(out, shared(fmt.Sprintf("%s[%d]", path, i), a.Index(i), b.Index(i))...)
		}
	case reflect.Struct:
		if a.Type().PkgPath() != reflect.TypeFor[AUM]().PkgPath() {
			return nil // netip values are immutable
		}
		for i := range a.NumField() {
			out = append(out, shared(path+"."+a.Type().Field(i).Name, a.Field(i), b.Field(i))...)
		}
	}
	return out
}

func TestCloneCopiesEveryField(t *testing.T) {
	var a AUM
	var n uint64
	fill(reflect.ValueOf(&a).Elem(), &n)
	c := a.Clone()
	orig, clone := reflect.ValueOf(&a).Elem(), reflect.ValueOf(c).Elem()
	for i := range orig.NumField() {
		if !reflect.DeepEqual(orig.Field(i).Interface(), clone.Field(i).Interface()) {
			t.Errorf("Clone changes %s", orig.Type().Field(i).Name)
		}
	}
	for _, p := range shared("AUM", orig, clone) {
		t.Errorf("Clone shares %s with its original", p)
	}
}

// TestEveryPayloadIsValidated: a payload at its zero value is refused, so a
// field that reaches the record without a rule in ValidateUnsigned shows.
// An empty route grant is the one zero payload with a meaning.
func TestEveryPayloadIsValidated(t *testing.T) {
	meaningful := map[string]bool{"Grant": true}
	checked := map[string]bool{}
	for i, seed := range corpusSeeds(t) {
		a, err := DecodeAUM(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		for _, f := range payloadFields() {
			field := reflect.ValueOf(&a).Elem().FieldByIndex(f.Index)
			if field.IsNil() || meaningful[f.Name] {
				continue
			}
			checked[f.Name] = true
			zeroed := *a.Clone()
			reflect.ValueOf(&zeroed).Elem().FieldByIndex(f.Index).Set(reflect.New(f.Type.Elem()))
			if err := zeroed.ValidateUnsigned(); err == nil {
				t.Errorf("%v record with a zero %s validates", a.Kind, f.Name)
			}
		}
	}
	for _, f := range payloadFields() {
		if !checked[f.Name] && !meaningful[f.Name] {
			t.Errorf("no seed carries %s", f.Name)
		}
	}
}

func TestDecodeUnsignedAUM(t *testing.T) {
	seed := corpusSeeds(t)[1]
	a, err := DecodeAUM(seed)
	if err != nil {
		t.Fatalf("DecodeAUM: %v", err)
	}
	a.Signatures = nil
	unsigned, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := DecodeAUM(unsigned); err == nil {
		t.Error("DecodeAUM accepted an unsigned record")
	}
	got, err := DecodeUnsignedAUM(unsigned)
	if err != nil {
		t.Fatalf("DecodeUnsignedAUM refused an unsigned record: %v", err)
	}
	if got.SigHash() != a.SigHash() {
		t.Error("DecodeUnsignedAUM changed the record")
	}
	if _, err := DecodeUnsignedAUM(seed); err != nil {
		t.Errorf("DecodeUnsignedAUM refused a signed record: %v", err)
	}
	a.Kind = KindRemoveNode // carries a Node it may not
	bad, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := DecodeUnsignedAUM(bad); err == nil {
		t.Error("DecodeUnsignedAUM accepted a record carrying another kind's fields")
	}
	if _, err := DecodeUnsignedAUM(append(unsigned, 0)); err == nil {
		t.Error("DecodeUnsignedAUM accepted trailing bytes")
	}
}
