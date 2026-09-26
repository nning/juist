package ipc

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// fullStatus sets every field of a status, each to a value derived from its
// CBOR key, so two layouts of the same wire format fill alike.
func fullStatus(t *testing.T) Status {
	t.Helper()
	var st Status
	v := reflect.ValueOf(&st).Elem()
	for _, sf := range reflect.VisibleFields(v.Type()) {
		if sf.Anonymous {
			continue
		}
		key, err := strconv.Atoi(strings.Split(sf.Tag.Get("cbor"), ",")[0])
		if err != nil {
			t.Fatalf("field %s has no integer CBOR key", sf.Name)
		}
		f := v.FieldByIndex(sf.Index)
		switch f.Kind() {
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Int, reflect.Int64, reflect.Int32:
			f.SetInt(int64(key))
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			f.SetUint(uint64(key))
		case reflect.String:
			f.SetString(fmt.Sprintf("s%d", key))
		case reflect.Slice:
			f.Set(reflect.MakeSlice(f.Type(), 1, 1))
			if e := f.Index(0); e.Kind() == reflect.String {
				e.SetString(fmt.Sprintf("s%d", key))
			}
		case reflect.Pointer:
			f.Set(reflect.New(f.Type().Elem()))
		case reflect.Array:
			f.Index(0).Set(reflect.ValueOf(byte(key)).Convert(f.Type().Elem()))
		default:
			t.Fatalf("field %s is a %v, which fullStatus cannot fill", sf.Name, f.Kind())
		}
	}
	return st
}

// A status with every field set still reaches the CLI: the IPC decoder bounds
// how many keys a map may carry, and a struct is a map with a key per field.
func TestAFullStatusDecodes(t *testing.T) {
	st := fullStatus(t)
	b, err := encode(&Response{Status: &st}, MaxResponse)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponse(b); err != nil {
		t.Fatalf("a full status does not decode: %v", err)
	}
}

// statusGolden is a full status as the CLI reads it. Adding a field changes it;
// nothing else may.
const statusGolden = "b8390158200100000000000000000000000000000000000000000000000000000000000000028141ff" +
	"03582003000000000000000000000000000000000000000000000000000000000000000462733405582005" +
	"0000000000000000000000000000000000000000000000000000000000000006060707080809090a637331" +
	"300b637331310c0c0d0d0e0e0f0f10f511f5121213637331391463733230151516f5171718186373323418" +
	"191819181a181a181b181b181cf5181df5181ef5181f637333311820f51821637333331822a01823182318" +
	"24182418258163733337182681637333381827f51828182818298163733431182a81a10158200000000000" +
	"000000000000000000000000000000000000000000000000000000182b182b182c63733434182d81a10158" +
	"200000000000000000000000000000000000000000000000000000000000000000182e8163733436182ff5" +
	"183081637334381831816373343918328163733530183381637335311834f51835637335331836f5" +
	"183718371838f518391839"

// operatorOnly are the status fields a caller who may not operate is not
// shown. Every other field must be copied by [Status.ForReader].
var operatorOnly = map[string]bool{"Devices": true, "Unmoved": true}

// A field added to Status is shown to every local user or kept from them by
// decision, not by default.
func TestEveryStatusFieldIsClassifiedForReaders(t *testing.T) {
	full := fullStatus(t)
	read := full.ForReader()
	fv, rv := reflect.ValueOf(full), reflect.ValueOf(read)
	for _, sf := range reflect.VisibleFields(fv.Type()) {
		if sf.Anonymous {
			continue
		}
		shown := rv.FieldByIndex(sf.Index)
		switch {
		case operatorOnly[sf.Name] && !shown.IsZero():
			t.Errorf("%s is operator-only, and ForReader shows it", sf.Name)
		case !operatorOnly[sf.Name] && !reflect.DeepEqual(shown.Interface(), fv.FieldByIndex(sf.Index).Interface()):
			t.Errorf("%s is neither copied by ForReader nor listed in operatorOnly", sf.Name)
		}
	}
}

func TestStatusWireFormatIsUnchanged(t *testing.T) {
	st := fullStatus(t)
	b, err := encode(&st, MaxResponse)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(b); got != statusGolden {
		t.Fatalf("a full status encodes as\n%s\nwant\n%s", got, statusGolden)
	}
}
