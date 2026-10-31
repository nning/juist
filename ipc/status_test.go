package ipc

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/nning/juist/types"
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
const statusGolden = "b8540158200100000000000000000000000000000000000000000000000000000000000000028141ff03582003000000" +
	"000000000000000000000000000000000000000000000000000000000462733405582005000000000000000000000000" +
	"0000000000000000000000000000000000000006060707080809090a637331300b637331310c0c0d0d0e0e0f0f10f511" +
	"f5121213637331391463733230151516f5171718186373323418191819181a181a181b181b181cf5181df5181ef5181f" +
	"637333311820f51821637333331822a0182318231824182418258163733337182681637333381827f518281828182981" +
	"63733431182a81a10158200000000000000000000000000000000000000000000000000000000000000000182b182b18" +
	"2c63733434182d81a10158200000000000000000000000000000000000000000000000000000000000000000182e8163" +
	"733436182ff5183081637334381831816373343918328163733530183381637335311834f51835637335331836f51837" +
	"18371838f518391839183a183a183ba301000441ff0541ff183c63733630183d8141ff183e183e183fa1015820000000" +
	"00000000000000000000000000000000000000000000000000000000001840a01841a01842a01843a01845a018461846" +
	"1847637337311848a0184981a10260184b8163733735184c8163733736184d8163733737184e8163733738184f816373" +
	"37391850f51851637338311852637338321853185318548163733834185563733835185681a201582000000000000000" +
	"000000000000000000000000000000000000000000000000000200"

// operatorOnly are the status fields a caller who may not operate is not
// shown. Every other field must be copied by [Status.ForReader].
var operatorOnly = map[string]bool{"Devices": true, "Builds": true, "Unmoved": true, "Waiting": true, "Publish": true, "Ingress": true,
	"Shares": true, "Terminator": true}

// byPseudonym are the fields a reader is shown with other members renamed.
var byPseudonym = map[string]bool{"Silent": true, "Unrevoked": true, "Lost": true, "NoKey": true, "TunnelsDown": true,
	"Reach": true, "HomeRelay": true, "Seeking": true, "Absent": true, "NotAtRelay": true, "SyncFailing": true,
	"SyncNewer": true, "SyncBroken": true, "Outdated": true, "OlderBuild": true}

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
		case byPseudonym[sf.Name]:
			if s, ok := shown.Interface().(string); ok && strings.HasPrefix(s, "s") ||
				shown.Kind() == reflect.Slice && shown.Index(0).Kind() == reflect.String && strings.HasPrefix(shown.Index(0).String(), "s") {
				t.Errorf("%s is shown to a reader as it is", sf.Name)
			}
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

// A reader is shown no other member's name or identity: each name is a
// pseudonym, the same wherever it recurs in one status, and this device's
// own name stays.
func TestAReaderSeesNoMembersNames(t *testing.T) {
	phone, laptop := types.Identity{0xa1}, types.Identity{0xb2}
	st := Status{Self: types.Identity{0xc3}, Derived: Derived{SelfName: "lx",
		Silent: []string{"phone"}, Unrevoked: []string{"remove-node of phone"}, Lost: []string{"the admission of laptop"},
		NoKey: []string{"laptop"}, Exit: &Exit{Node: laptop, Name: "laptop"}},
		Tunnels: Tunnels{TunnelsDown: []string{"phone", "laptop"}, Seeking: []string{"phone"}, Absent: []string{"laptop"},
			NotAtRelay: []string{"phone"}, SyncFailing: []string{"laptop"}, SyncNewer: []string{"phone"},
			SyncBroken: []string{"laptop"}, Outdated: []string{"phone"}, OlderBuild: []string{"laptop"},
			Reach: []PeerReach{{Identity: phone, Relay: "laptop"}, {Identity: laptop, Relay: "lx"}}, HomeRelay: "laptop"}}
	read := st.ForReader()
	b, err := encode(&read, MaxResponse)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{[]byte("phone"), []byte("laptop"), phone[:], laptop[:]} {
		if bytes.Contains(b, secret) {
			t.Errorf("a reader is shown %q", secret)
		}
	}
	if read.SelfName != "lx" || read.Reach[1].Relay != "lx" || read.Self != st.Self {
		t.Errorf("a reader is not shown this device as itself: %q, %q", read.SelfName, read.Reach[1].Relay)
	}
	if p := read.TunnelsDown[0]; p == "" || read.Seeking[0] != p || read.NotAtRelay[0] != p || read.Silent[0] != p {
		t.Errorf("phone's pseudonym differs between lists: %v %v %v %v", read.TunnelsDown, read.Seeking, read.NotAtRelay, read.Silent)
	}
	if p := read.TunnelsDown[1]; p == read.TunnelsDown[0] || read.HomeRelay != p || read.Exit.Name != p || read.Reach[0].Relay != p {
		t.Errorf("laptop's pseudonym differs between fields: %v %q %q %q", read.TunnelsDown, read.HomeRelay, read.Exit.Name, read.Reach[0].Relay)
	}
	if st.TunnelsDown[0] != "phone" || st.Reach[0].Identity != phone || st.Exit.Name != "laptop" {
		t.Error("the operator's status lost its names")
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

// Neither the way nor a lag is blamed for a member offline or outdated: one
// offline is read from an announcement made before this device joined.
func TestOnlyARunningCurrentMemberIsBlockedOrBehind(t *testing.T) {
	s := Status{Derived: Derived{NoKey: []string{"laptop", "nas", "phone", "tv"}},
		Tunnels: Tunnels{TunnelsDown: []string{"desk", "laptop", "nas", "phone", "tv"},
			Seeking: []string{"tv"}, Absent: []string{"laptop"}, Outdated: []string{"phone"}}}
	if got := s.Blocked(); !slices.Equal(got, []string{"desk", "nas"}) {
		t.Errorf("blocked: %v", got)
	}
	if got := s.Behind(); !slices.Equal(got, []string{"nas"}) {
		t.Errorf("behind: %v", got)
	}
	if !slices.Equal(s.TunnelsDown, []string{"desk", "laptop", "nas", "phone", "tv"}) {
		t.Errorf("the status itself changed: %v", s.TunnelsDown)
	}
}

// Each struct the socket carries keys its fields apart, those of the structs
// it embeds among them: two fields under one CBOR key fail to decode alone.
func TestCBORKeysAreApart(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(ty reflect.Type) {
		for ty.Kind() == reflect.Pointer || ty.Kind() == reflect.Slice || ty.Kind() == reflect.Array || ty.Kind() == reflect.Map {
			if ty.Kind() == reflect.Map {
				walk(ty.Key())
			}
			ty = ty.Elem()
		}
		if ty.Kind() != reflect.Struct || seen[ty] || ty.PkgPath() != reflect.TypeFor[Status]().PkgPath() {
			return
		}
		seen[ty] = true
		keys := map[string]string{}
		for _, sf := range reflect.VisibleFields(ty) {
			if sf.Anonymous || !sf.IsExported() {
				continue
			}
			walk(sf.Type)
			key, _, _ := strings.Cut(sf.Tag.Get("cbor"), ",")
			if key == "" || key == "-" {
				continue
			}
			if other, ok := keys[key]; ok {
				t.Errorf("%s: %s and %s share the CBOR key %s", ty.Name(), other, sf.Name, key)
			}
			keys[key] = sf.Name
		}
	}
	for _, v := range []any{Request{}, Response{}, Status{}} {
		walk(reflect.TypeOf(v))
	}
	if len(seen) < 10 {
		t.Errorf("walked %d structs, want those the socket carries", len(seen))
	}
}
