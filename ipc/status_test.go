package ipc

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
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
const statusGolden = "b8490158200100000000000000000000000000000000000000000000000000000000000000028141ff" +
	"0358200300000000000000000000000000000000000000000000000000000000000000046273340558" +
	"2005000000000000000000000000000000000000000000000000000000000000000606070708080909" +
	"0a637331300b637331310c0c0d0d0e0e0f0f10f511f5121213637331391463733230151516f5171718" +
	"186373323418191819181a181a181b181b181cf5181df5181ef5181f637333311820f5182163733333" +
	"1822a0182318231824182418258163733337182681637333381827f51828182818298163733431182a" +
	"81a10158200000000000000000000000000000000000000000000000000000000000000000182b182b" +
	"182c63733434182d81a101582000000000000000000000000000000000000000000000000000000000" +
	"00000000182e8163733436182ff5183081637334381831816373343918328163733530183381637335" +
	"311834f51835637335331836f5183718371838f518391839183a183a183ba301000441ff0541ff183c" +
	"63733630183d8141ff183e183e183fa101582000000000000000000000000000000000000000000000" +
	"000000000000000000001840a01841a01842a01843a01845a0184618461847637337311848a0184981" +
	"a10260184aa0"

// operatorOnly are the status fields a caller who may not operate is not
// shown. Every other field must be copied by [Status.ForReader].
var operatorOnly = map[string]bool{"Devices": true, "Unmoved": true, "Waiting": true, "Publish": true, "Ingress": true,
	"Shares": true, "Terminator": true}

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

// A reader sees how names resolve, the public domain included, not which
// devices public names point at, as it sees no device list.
func TestAReaderSeesNoPublicNames(t *testing.T) {
	st := Status{Derived: Derived{Names: &Names{Domain: "home.juist", Public: "pub.example.org", Resolved: true,
		Accepted: true, Overrides: []NameOverride{{Name: "mx.example.net", Device: "mailer"}}}}}
	got := st.ForReader().Names
	if got == nil || got.Domain != "home.juist" || got.Public != "pub.example.org" || !got.Resolved || !got.Accepted ||
		got.Overrides != nil {
		t.Fatalf("a reader sees %+v", got)
	}
	if len(st.Names.Overrides) != 1 {
		t.Fatal("the operator's status lost its public names")
	}
}

// A reader sees a network's claims, not the member addresses they are made
// of where it has no prefix of its own.
func TestAReaderSeesClaimsCoarsely(t *testing.T) {
	p := netip.MustParsePrefix
	st := Status{V4Claims: []netip.Prefix{p("198.18.0.5/32"), p("198.18.1.9/32"), p("10.7.0.0/24")}}
	got := st.ForReader().V4Claims
	if want := []netip.Prefix{p("198.18.0.0/22"), p("10.7.0.0/24")}; !slices.Equal(got, want) {
		t.Fatalf("a reader sees %v, want %v", got, want)
	}
	if !slices.Equal(st.V4Claims, []netip.Prefix{p("198.18.0.5/32"), p("198.18.1.9/32"), p("10.7.0.0/24")}) {
		t.Fatalf("coarsening changed the operator's status: %v", st.V4Claims)
	}
}

// A fresh node warns once the lease completing its threshold is past half
// its life, which hourly renewals never let happen, and not when stale or
// where nothing is enforced.
func TestFreshnessEndsOnlyPastHalfTheLease(t *testing.T) {
	const now, ttl = 1_800_000_000, 48 * 3600
	for _, c := range []struct {
		name  string
		since int64
		stale bool
		want  bool
	}{
		{"renewed an hour ago", now - 3600, false, false},
		{"exactly half", now - ttl/2, false, false},
		{"past half", now - ttl/2 - 1, false, true},
		{"stale", now - ttl - 1, true, false},
	} {
		s := Status{Derived: Derived{LeaseSigners: 2, Vouchers: 2, Vouching: 2,
			FreshSince: c.since, FreshUntil: c.since + ttl, Stale: c.stale}}
		if left, got := s.FreshnessEnding(now); got != c.want {
			t.Errorf("%s: ending=%v (%v left), want %v", c.name, got, left, c.want)
		}
	}
	if _, got := (&Status{}).FreshnessEnding(now); got {
		t.Error("a network without vouchers warned that freshness ends")
	}
}

func TestVouchAgainAgreesWithTheCount(t *testing.T) {
	for n, want := range map[int]string{1: "a voucher vouches again", 2: "2 vouchers vouch again"} {
		if got := (&Status{Derived: Derived{Vouchers: n}}).VouchAgain(); got != want {
			t.Errorf("%d needed: %q, want %q", n, got, want)
		}
	}
}
