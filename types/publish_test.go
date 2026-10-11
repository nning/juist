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

// A name published by TCP has a public port of its own, neither the
// ingress's TLS ports nor juist's, and a port of the member no other name
// goes to.
func TestNamesPublishedByTCP(t *testing.T) {
	for _, ok := range [][]PublishedName{
		{{Label: "mc", Port: 25565, Public: 25565}},
		{{Label: "ssh", Port: 22, Public: 2222}, {Label: "web", Port: 443}},
		{{Label: "a", Port: 25565, Public: 25565}, {Label: "b", Port: 25566, Public: 25566}},
		{{Label: "a", Port: 8080, Public: 2222}, {Label: "b", Port: 2222, Public: 8080}},
		{{Label: "api", Port: 443}, {Label: "web", Port: 443}},
		{{Label: "mc", Port: 443, Public: 25565}},
		{{Label: "x", Port: 1, Public: FirstJuistPort - 1}, {Label: "y", Port: 2, Public: LastJuistPort + 1}},
	} {
		if err := validatePublished(ok); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	for _, bad := range [][]PublishedName{
		{{Label: "web", Port: 8080, Public: 80}},
		{{Label: "web", Port: 8443, Public: 443}},
		{{Label: "x", Port: 1, Public: FirstJuistPort}},
		{{Label: "x", Port: 1, Public: 41643}},
		{{Label: "x", Port: 1, Public: LastJuistPort}},
		{{Label: "a", Port: 1, Public: 2222}, {Label: "b", Port: 2, Public: 2222}},
		{{Label: "a", Port: 22, Public: 2222}, {Label: "b", Port: 22, Public: 2223}},
		{{Label: "a", Port: 443}, {Label: "b", Port: 443, Public: 2222}},
		{{Label: "a", Port: 443, Public: 2222}, {Label: "b", Port: 443}},
	} {
		if err := validatePublished(bad); err == nil {
			t.Errorf("%+v taken", bad)
		}
	}
	n := &NodeRecord{Published: []PublishedName{{Label: "mc", Port: 25565, Public: 25565}}}
	if need, _ := n.NeedsSchema(); need != SchemaTCP {
		t.Errorf("a name by TCP needs %v", need)
	}
	n.Published[0].Public = 0
	if need, _ := n.NeedsSchema(); need != SchemaPublish {
		t.Errorf("a name by TLS needs %v", need)
	}
}

// An ingress holds every public port: none of its own names goes to one,
// whichever member publishes it; a member holding the publish role shares
// on 443, which no name of its by TCP goes to.
func TestTheIngressHoldsThePublicPorts(t *testing.T) {
	id := func(b byte) Identity { return Identity{b} }
	keyed := func(n *NodeRecord) *NodeRecord {
		b := n.Identity[0]
		n.WireGuard, n.X25519, n.MLKEM = WGKey{b}, X25519Key{b}, MLKEMKey{b}
		return n
	}
	ingress := &NodeRecord{Identity: id(1), Roles: []Role{RoleIngress},
		Published: []PublishedName{{Label: "web", Port: 8443}}}
	if err := ingress.ValidatePublishing(); err != nil {
		t.Fatal(err)
	}
	own := &NodeRecord{Identity: id(1), Roles: []Role{RoleIngress},
		Published: []PublishedName{{Label: "mc", Port: 2222, Public: 25565}, {Label: "web", Port: 25565}}}
	if err := own.ValidatePublishing(); err == nil {
		t.Error("an ingress whose own name goes to its public port taken")
	}
	sharer := &NodeRecord{Identity: id(3), Name: "mailer", Roles: []Role{RolePublish},
		Published: []PublishedName{{Label: "mc", Port: 443, Public: 25565}}}
	if err := sharer.ValidatePublishing(); err == nil {
		t.Error("a name by TCP to the port a member shares on taken")
	}

	ingress = keyed(ingress)
	tcp := keyed(&NodeRecord{Identity: id(2), Published: []PublishedName{{Label: "alt", Port: 8443, Public: 8443}}})
	ix := NewMemberIndex(Hash{}, 2)
	ix.SetDomain("pub.example.org")
	ix.Add(ingress)
	if err := ix.Check(tcp); err == nil || !strings.Contains(err.Error(), "port 8443") {
		t.Errorf("a public port an ingress's own name goes to: %v", err)
	}
	ix = NewMemberIndex(Hash{}, 2)
	ix.SetDomain("pub.example.org")
	ix.Add(tcp)
	if err := ix.Check(ingress); err == nil || !strings.Contains(err.Error(), "port 8443") {
		t.Errorf("an ingress whose name goes to a public port: %v", err)
	}
	other := keyed(&NodeRecord{Identity: id(4), Published: []PublishedName{{Label: "alt2", Port: 1, Public: 8443}}})
	if err := ix.Check(other); err == nil || !strings.Contains(err.Error(), "both publish on port 8443") {
		t.Errorf("a public port published twice: %v", err)
	}
	other.Published[0].Public = 8444
	if err := ix.Check(other); err != nil {
		t.Error(err)
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

// A name for members alone needs its schema, and is no name the ingress
// passes by TCP or with the client's address, which members would reach
// through it.
func TestNamesForMembersAlone(t *testing.T) {
	ok := []PublishedName{{Label: "photos", Port: 443, Members: true}, {Label: "wiki", Port: 443, Members: true}}
	if err := validatePublished(ok); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []PublishedName{
		{Label: "mc", Port: 25565, Public: 25565, Members: true},
		{Label: "web", Port: 443, Proxy: true, Members: true},
		{Label: "wiki", Port: 8443, Members: true},
	} {
		if err := validatePublished([]PublishedName{bad}); err == nil {
			t.Errorf("%+v taken", bad)
		}
	}
	n := &NodeRecord{Published: ok}
	if need, _ := n.NeedsSchema(); need != SchemaMembers {
		t.Errorf("a name for members alone needs %v", need)
	}
}
