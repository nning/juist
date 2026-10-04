package types

import (
	"net/netip"
	"strings"
	"testing"
)

// A member's published names are DNS labels, the empty one the domain
// itself, on a port, sorted, each once, within the limit.
func TestPublishedNameSets(t *testing.T) {
	ok := []PublishedName{{Port: 443}, {Label: "immich", Port: 2283, Proxy: true}, {Label: "xn--mnchen-3ya", Port: 443}}
	if err := validatePublished(ok); err != nil {
		t.Error(err)
	}
	for _, bad := range [][]PublishedName{
		{{Label: "photos", Port: 443}, {Label: "immich", Port: 443}},
		{{Label: "immich", Port: 443}, {Label: "immich", Port: 80}},
		{{Label: "immich"}},
		{{Label: "immich", Port: 443}, {Port: 443}},
		{{Port: 443}, {Port: 8443}},
		{{Label: "Immich", Port: 443}},
		{{Label: "a.b", Port: 443}},
		{{Label: "-a", Port: 443}},
	} {
		if err := validatePublished(bad); err == nil {
			t.Errorf("%+v taken", bad)
		}
	}
	many := make([]PublishedName, MaxPublishedPerNode+1)
	for i := range many {
		many[i] = PublishedName{Label: strings.Repeat("a", i+1), Port: 443}
	}
	if err := validatePublished(many); err == nil {
		t.Error("published names over the limit taken")
	}
}

// An ingress holds no other authority: never a voucher, never an exit node.
func TestAnIngressIsNothingElse(t *testing.T) {
	if err := validateRoles([]Role{RoleIngress, RoleRelayCapable}); err != nil {
		t.Error(err)
	}
	for _, bad := range [][]Role{{RoleAdmin, RoleIngress}, {RoleExit, RoleIngress}} {
		if err := validateRoles(bad); err == nil {
			t.Errorf("%v taken", bad)
		}
	}
	if err := validateGrant([]Role{RoleIngress}, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}); err == nil {
		t.Error("an ingress routing a subnet taken")
	}
	if err := validateGrant([]Role{RoleService}, nil); err != nil {
		t.Error(err)
	}
	for _, bad := range [][]Role{{RoleRelayCapable, RoleService}, {RoleIngress, RoleService}} {
		if err := validateGrant(bad, nil); err == nil {
			t.Errorf("%v taken", bad)
		}
	}
	if err := validateGrant([]Role{RoleService}, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}); err == nil {
		t.Error("a service member routing a subnet taken")
	}
}

// A state publishes names only under a domain of its own, from schema 9.
func TestPublishedNamesNeedTheirDomain(t *testing.T) {
	var snap *Snapshot
	for _, b := range corpusSeeds(t) {
		a, err := DecodeAUM(b)
		if err != nil {
			t.Fatal(err)
		}
		if a.Kind == KindCheckpoint && a.State.Domain != "" {
			snap = a.State
		}
	}
	if snap == nil {
		t.Fatal("no seed state has a domain")
	}
	if err := snap.StaticValidate(false); err != nil {
		t.Fatal(err)
	}
	without := snap.Clone()
	without.Domain = ""
	if err := without.StaticValidate(false); err == nil || !strings.Contains(err.Error(), "no domain") {
		t.Errorf("published names without a domain: %v", err)
	}
	old := snap.Clone()
	old.Schema = SchemaNames
	old.Nodes[0].Published = nil
	if err := old.StaticValidate(false); err == nil || !strings.Contains(err.Error(), "domain") {
		t.Errorf("a domain at schema 8: %v", err)
	}
	old.Domain = ""
	if err := old.StaticValidate(false); err != nil {
		t.Errorf("the same state without the domain: %v", err)
	}
}
