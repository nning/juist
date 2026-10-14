package log

import (
	"slices"
	"strings"
	"testing"

	"github.com/nning/juist/types"
)

func publishedOf(t *testing.T, st *State, id types.Identity) []types.PublishedName {
	t.Helper()
	n, ok := st.Node(id)
	if !ok {
		t.Fatalf("%v is no member", id.ShortString())
	}
	return n.Published
}

// A quorum sets the domain and publishes names on a member, sorted by label;
// they survive reopening and a checkpoint, and the domain goes only once no
// name is published under it.
func TestPublishedNamesNeedTheDomain(t *testing.T) {
	h := newHarness(t, 1, 1)
	nas := h.addNode("nas")
	immich := types.PublishedName{Label: "immich", Port: 2283, Proxy: true}
	photos := types.PublishedName{Label: "photos", Port: 443}
	publish := func(id types.Identity, ps ...types.PublishedName) types.AUM {
		return h.signed(types.AUM{Kind: types.KindSetPublished, Subject: &id, Publish: &types.PublishGrant{Names: ps}})
	}
	h.mustReject("a name before the domain", RuleState, publish(nas.Identity, immich))

	h.apply(h.auth.Builder().SetDomain("pub.example.org"))
	h.apply(h.auth.Builder().SetPublished(nas.Identity, []types.PublishedName{photos, immich, photos}))
	if got := publishedOf(t, h.auth.State(), nas.Identity); !slices.Equal(got, []types.PublishedName{immich, photos}) {
		t.Fatalf("nas publishes %+v", got)
	}
	if got := publishedOf(t, h.fork().State(), nas.Identity); len(got) != 2 || h.fork().State().Domain() != "pub.example.org" {
		t.Fatalf("reopened, nas publishes %+v", got)
	}
	cp := h.apply(h.auth.Builder().Checkpoint())
	boot, err := Bootstrap(NewMemStorage(), cp)
	if err != nil {
		t.Fatal(err)
	}
	if got := publishedOf(t, boot.State(), nas.Identity); len(got) != 2 || boot.State().Domain() != "pub.example.org" {
		t.Fatalf("bootstrapped from a checkpoint, nas publishes %+v", got)
	}

	domain := func(d string) types.AUM { return h.signed(types.AUM{Kind: types.KindSetDomain, Domain: &d}) }
	h.mustReject("the domain withdrawn under published names", RuleState, domain(""))
	h.mustReject("the domain it has", RuleState, domain("pub.example.org"))
	h.apply(h.auth.Builder().SetDomain("pub.example.net"))
	h.apply(h.auth.Builder().SetPublished(nas.Identity, nil))
	h.apply(h.auth.Builder().SetDomain(""))
	if h.auth.State().Domain() != "" {
		t.Fatal("the domain was not withdrawn")
	}
}

// A label is one member's, and a published name is no name pointed at a
// member, whichever comes first, the domain included.
func TestPublishedNamesAreOneMembers(t *testing.T) {
	h := newHarness(t, 1, 1)
	nas, vps := h.addNode("nas"), h.addNode("vps")
	h.apply(h.auth.Builder().SetDomain("pub.example.org"))
	h.apply(h.auth.Builder().SetPublished(nas.Identity, []types.PublishedName{{Label: "immich", Port: 443}}))
	publish := func(id types.Identity, label string) types.AUM {
		return h.signed(types.AUM{Kind: types.KindSetPublished, Subject: &id,
			Publish: &types.PublishGrant{Names: []types.PublishedName{{Label: label, Port: 443}}}})
	}
	names := func(id types.Identity, n string) types.AUM {
		return h.signed(types.AUM{Kind: types.KindSetNodeNames, Subject: &id, Names: &types.NameGrant{Names: []string{n}}})
	}
	h.mustReject("a label another member publishes", RuleState, publish(vps.Identity, "immich"))
	h.mustReject("a name pointed at what another publishes", RuleState, names(vps.Identity, "immich.pub.example.org"))
	h.mustReject("a name pointed at what it publishes", RuleState, names(nas.Identity, "immich.pub.example.org"))

	h.apply(h.auth.Builder().SetNodeNames(vps.Identity, []string{"mx.pub.example.org", "photos.example.net"}))
	h.mustReject("a label whose name points at another", RuleState, publish(nas.Identity, "mx"))
	h.apply(h.auth.Builder().SetPublished(nas.Identity, []types.PublishedName{{Label: "photos", Port: 443}}))
	h.mustReject("a domain under which a published name points at another", RuleState,
		h.signed(types.AUM{Kind: types.KindSetDomain, Domain: new("example.net")}))
}

// The ingress role is never beside admin or exit.
func TestTheIngressRole(t *testing.T) {
	h := newHarness(t, 1, 1)
	vps := h.addNode("vps")
	h.apply(h.auth.Builder().SetNodeRoutes(vps.Identity, []types.Role{types.RoleIngress, types.RoleRelayCapable}, nil))
	for _, roles := range [][]types.Role{{types.RoleAdmin, types.RoleIngress}, {types.RoleExit, types.RoleIngress}} {
		if _, err := h.auth.Builder().SetNodeRoutes(vps.Identity, roles, nil); err == nil {
			t.Errorf("an ingress granted %v", roles)
		}
	}
}

// A member admitted with published names needs the domain, as one granted
// them later does.
func TestAnAdmissionPublishesUnderTheDomainAlone(t *testing.T) {
	h := newHarness(t, 1, 1)
	n := h.newNode("nas")
	n.Published = []types.PublishedName{{Label: "immich", Port: 443}}
	if aum, err := h.auth.Builder().AddNode(n, h.sealer()); err == nil {
		h.signQuorum(&aum)
		h.mustReject("an admission publishing before the domain", RuleState, aum)
	}
	h.apply(h.auth.Builder().SetDomain("pub.example.org"))
	aum, err := h.auth.Builder().AddNode(n, h.sealer())
	if err != nil {
		t.Fatal(err)
	}
	h.signQuorum(&aum)
	if err := h.auth.Inform(aum); err != nil {
		t.Fatalf("an admission publishing under the domain: %v", err)
	}
}

// A published name is no longer than a DNS name may be, whether the label or
// the domain comes last.
func TestAPublishedNameFitsDNS(t *testing.T) {
	h := newHarness(t, 1, 1)
	nas := h.addNode("nas")
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 59)
	h.apply(h.auth.Builder().SetDomain(long))
	if _, err := h.auth.Builder().SetPublished(nas.Identity, []types.PublishedName{{Label: "immich", Port: 443}}); err == nil {
		t.Error("a name of more than 253 bytes was published")
	}
	h.apply(h.auth.Builder().SetDomain("pub.example.org"))
	h.apply(h.auth.Builder().SetPublished(nas.Identity, []types.PublishedName{{Label: "immich", Port: 443}}))
	h.mustReject("a domain the published name no longer fits under", RuleState,
		h.signed(types.AUM{Kind: types.KindSetDomain, Domain: &long}))
}

// A label given twice, on two ports, is refused rather than one dropped.
func TestALabelIsPublishedOnce(t *testing.T) {
	h := newHarness(t, 1, 1)
	nas := h.addNode("nas")
	h.apply(h.auth.Builder().SetDomain("pub.example.org"))
	if _, err := h.auth.Builder().SetPublished(nas.Identity,
		[]types.PublishedName{{Label: "immich", Port: 443}, {Label: "immich", Port: 8443}}); err == nil {
		t.Error("a label on two ports was published")
	}
}

// An ingress publishes nothing on 80 or 443, which it holds itself, whether
// the name or the role comes first.
func TestAnIngressPublishesNothingOnItsOwnPorts(t *testing.T) {
	h := newHarness(t, 1, 1)
	vps, nas := h.addNode("vps"), h.addNode("nas")
	h.apply(h.auth.Builder().SetDomain("pub.example.org"))
	h.apply(h.auth.Builder().SetNodeRoutes(vps.Identity, []types.Role{types.RoleIngress}, nil))
	for _, port := range []uint16{443, 80} {
		h.mustReject("an ingress publishing on its own port", RuleState, h.signed(types.AUM{Kind: types.KindSetPublished,
			Subject: &vps.Identity, Publish: &types.PublishGrant{Names: []types.PublishedName{{Label: "web", Port: port}}}}))
	}
	h.apply(h.auth.Builder().SetPublished(vps.Identity, []types.PublishedName{{Label: "web", Port: 8443}}))

	h.apply(h.auth.Builder().SetPublished(nas.Identity, []types.PublishedName{{Label: "immich", Port: 443}}))
	h.mustReject("the ingress role for a device publishing on 443", RuleState, h.signed(types.AUM{Kind: types.KindSetNodeRoutes,
		Subject: &nas.Identity, Grant: &types.RouteGrant{Roles: []types.Role{types.RoleIngress}}}))
}

// The publish role is never beside the ingress role, and for a
// member whose name gives a label, which is then its alone: no other member
// publishes it, holds the role under it, or points a name of it elsewhere.
func TestThePublishRole(t *testing.T) {
	h := newHarness(t, 1, 1)
	mailer, nas, dotted := h.addNode("Mailer"), h.addNode("nas"), h.addNode("my.laptop")
	h.apply(h.auth.Builder().SetDomain("pub.example.org"))
	grant := func(id types.Identity, roles ...types.Role) types.AUM {
		return h.signed(types.AUM{Kind: types.KindSetNodeRoutes, Subject: &id, Grant: &types.RouteGrant{Roles: roles}})
	}
	h.mustReject("the publish role for a name that gives no label", RuleState, grant(dotted.Identity, types.RolePublish))
	if _, err := h.auth.Builder().SetNodeRoutes(nas.Identity, []types.Role{types.RoleIngress, types.RolePublish}, nil); err == nil {
		t.Error("an ingress granted the publish role")
	}
	h.apply(h.auth.Builder().SetPublished(nas.Identity, []types.PublishedName{{Label: "mailer", Port: 8443}}))
	h.mustReject("the publish role under a label another publishes", RuleState, grant(mailer.Identity, types.RolePublish))
	h.apply(h.auth.Builder().SetPublished(nas.Identity, nil))
	h.apply(h.auth.Builder().SetNodeRoutes(mailer.Identity, []types.Role{types.RolePublish}, nil))

	h.mustReject("a label a member publishes under its name", RuleState, h.signed(types.AUM{Kind: types.KindSetPublished,
		Subject: &nas.Identity, Publish: &types.PublishGrant{Names: []types.PublishedName{{Label: "mailer", Port: 443}}}}))
	h.mustReject("a name pointed elsewhere under it", RuleState, h.signed(types.AUM{Kind: types.KindSetNodeNames,
		Subject: &nas.Identity, Names: &types.NameGrant{Names: []string{"mailer.pub.example.org"}}}))

	twin := h.addNode("mailer")
	h.mustReject("the publish role for a second name that gives the same label", RuleState, grant(twin.Identity, types.RolePublish))
}

// The domain itself is published by one member at most, and never also a
// name pointed at a member, whichever comes first, the domain moving
// included.
func TestTheDomainItselfIsOneMembers(t *testing.T) {
	h := newHarness(t, 1, 1)
	nas, vps := h.addNode("nas"), h.addNode("vps")
	h.apply(h.auth.Builder().SetDomain("pub.example.org"))
	apex := func(id types.Identity) types.AUM {
		return h.signed(types.AUM{Kind: types.KindSetPublished, Subject: &id,
			Publish: &types.PublishGrant{Names: []types.PublishedName{{Port: 443}}}})
	}
	h.apply(h.auth.Builder().SetPublished(nas.Identity, []types.PublishedName{{Port: 443}, {Label: "web", Port: 443}}))
	if got := publishedOf(t, h.auth.State(), nas.Identity); len(got) != 2 || got[0].Under("pub.example.org") != "pub.example.org" {
		t.Fatalf("nas publishes %+v", got)
	}
	h.mustReject("the domain a second member publishes", RuleState, apex(vps.Identity))
	h.mustReject("a name pointed elsewhere at the domain", RuleState, h.signed(types.AUM{Kind: types.KindSetNodeNames,
		Subject: &vps.Identity, Names: &types.NameGrant{Names: []string{"pub.example.org"}}}))

	h.apply(h.auth.Builder().SetNodeNames(vps.Identity, []string{"example.net"}))
	h.mustReject("a domain a published apex lands on a name pointed elsewhere", RuleState,
		h.signed(types.AUM{Kind: types.KindSetDomain, Domain: new("example.net")}))
	h.apply(h.auth.Builder().SetPublished(nas.Identity, nil))
	h.apply(h.auth.Builder().SetDomain("example.net"))
	h.mustReject("the domain a name points elsewhere at", RuleState, apex(nas.Identity))
}

// A name published by TCP has a public port that is one member's, and no
// ingress's own name goes to it, whichever comes first.
func TestNamesPublishedByTCP(t *testing.T) {
	tcp := func(h *harness, id types.Identity, ps ...types.PublishedName) types.AUM {
		return h.signed(types.AUM{Kind: types.KindSetPublished, Subject: &id, Publish: &types.PublishGrant{Names: ps}})
	}
	mc := types.PublishedName{Label: "mc", Port: 25565, Public: 25565}
	h := newHarness(t, 1, 1)
	nas, vps, pi := h.addNode("nas"), h.addNode("vps"), h.addNode("pi")
	h.apply(h.auth.Builder().SetDomain("pub.example.org"))
	h.apply(h.auth.Builder().SetPublished(nas.Identity, []types.PublishedName{mc}))
	if got := publishedOf(t, h.fork().State(), nas.Identity); !slices.Equal(got, []types.PublishedName{mc}) {
		t.Fatalf("reopened, nas publishes %+v", got)
	}
	h.mustReject("a public port another member publishes on", RuleState,
		tcp(h, pi.Identity, types.PublishedName{Label: "mc2", Port: 25566, Public: 25565}))
	for _, port := range []uint16{80, 443, 41643} {
		h.mustReject("a public port an ingress holds", RuleMalformed,
			tcp(h, pi.Identity, types.PublishedName{Label: "x", Port: 1, Public: port}))
	}
	h.apply(h.auth.Builder().SetNodeRoutes(vps.Identity, []types.Role{types.RoleIngress}, nil))
	h.mustReject("an ingress's own name on a public port", RuleState,
		tcp(h, vps.Identity, types.PublishedName{Label: "web", Port: 25565}))
	h.apply(h.auth.Builder().SetPublished(vps.Identity, []types.PublishedName{{Label: "web", Port: 8443}}))
	h.mustReject("a public port an ingress's own name goes to", RuleState,
		tcp(h, pi.Identity, types.PublishedName{Label: "alt", Port: 1, Public: 8443}))
	h.apply(h.auth.Builder().SetPublished(pi.Identity, []types.PublishedName{{Label: "alt", Port: 8443, Public: 8444}}))
	box := h.addNode("box")
	h.apply(h.auth.Builder().SetPublished(box.Identity, []types.PublishedName{{Label: "box", Port: 25565}}))
	h.mustReject("the ingress role for a device whose name goes to a public port", RuleState,
		h.signed(types.AUM{Kind: types.KindSetNodeRoutes, Subject: &box.Identity,
			Grant: &types.RouteGrant{Roles: []types.Role{types.RoleIngress}}}))
}

// A name for members alone is published, and a policy names it.
func TestNamesForMembers(t *testing.T) {
	h := newHarness(t, 1, 1)
	nas, laptop := h.addNode("nas"), h.addNode("laptop")
	h.apply(h.auth.Builder().SetDomain("pub.example.org"))
	photos := types.PublishedName{Label: "photos", Port: 443, Members: true}
	h.apply(h.auth.Builder().SetPublished(nas.Identity, []types.PublishedName{photos}))
	h.apply(h.auth.Builder().SetPolicy(&types.Policy{Rules: []types.PolicyRule{{
		From: types.PolicyRefs{Nodes: []types.Identity{laptop.Identity}}, To: types.PolicyRefs{Names: []string{"photos"}}}}}))
	if got := publishedOf(t, h.fork().State(), nas.Identity); !slices.Equal(got, []types.PublishedName{photos}) {
		t.Fatalf("reopened, nas publishes %+v", got)
	}
}
