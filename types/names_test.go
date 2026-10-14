package types

import (
	"strings"
	"testing"
)

// A name is taken in one form alone, of two labels or more, and never one of
// an address, juist's own domain or one the host keeps to itself.
func TestHostNames(t *testing.T) {
	for _, ok := range []string{
		"mx.example.net", "a.b", "xn--mnchen-3ya.de", "1.example.org", "a-b.c-d.example",
		strings.Repeat("a", 63) + ".org",
	} {
		if err := ValidateHostName(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "org", "mx.example.net.", "MX.example.net", "münchen.de", "mx..net", ".mx.net",
		"-mx.net", "mx-.net", "mx_1.net", "mx .net", "10.0.0.1", "1.2.3.4.5", "host.123",
		"mailer.home.juist", "a.juist", "x.local", "localhost.localhost", "1.0.0.127.in-addr.arpa",
		"x.onion", "x.invalid", strings.Repeat("a", 64) + ".org",
		strings.Repeat("a.", 127) + "org",
	} {
		if err := ValidateHostName(bad); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
}

// A member's names are sorted and unique, within the limit, and no name is
// two members'.
func TestNameSets(t *testing.T) {
	if err := validateNames([]string{"a.org", "b.org"}); err != nil {
		t.Error(err)
	}
	for _, bad := range [][]string{{"b.org", "a.org"}, {"a.org", "a.org"}} {
		if err := validateNames(bad); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
	many := make([]string, MaxNamesPerNode+1)
	for i := range many {
		many[i] = strings.Repeat("a", i+1) + ".org"
	}
	if err := validateNames(many); err == nil {
		t.Error("names over the limit taken")
	}
	ix := NewMemberIndex(Hash{1}, 2)
	ix.Add(&NodeRecord{Identity: Identity{1}, WireGuard: WGKey{1}, X25519: X25519Key{1}, MLKEM: MLKEMKey{1}, Names: []string{"mx.org"}})
	other := &NodeRecord{Identity: Identity{2}, WireGuard: WGKey{2}, X25519: X25519Key{2}, MLKEM: MLKEMKey{2}, Names: []string{"mx.org"}}
	if err := ix.Check(other); err == nil || !strings.Contains(err.Error(), "mx.org") {
		t.Errorf("one name two members': %v", err)
	}
	other.Names = []string{"imap.org"}
	if err := ix.Check(other); err != nil {
		t.Error(err)
	}
}
