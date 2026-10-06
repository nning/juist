package types

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// MaxPublishedPerNode caps the names one member publishes.
const MaxPublishedPerNode = 16

// A PublishedName is a service a member publishes through the network's
// ingresses: LABEL.DOMAIN, or DOMAIN itself for the empty label, reached on
// Port of the member, with the client's address in a PROXY protocol v2
// header where Proxy is set. Where Public is set, every ingress passes TCP
// on that port to it, from [SchemaTCP] on; otherwise TLS on 443, by name.
type PublishedName struct {
	Label  string `cbor:"1,keyasint"`
	Port   uint16 `cbor:"2,keyasint"`
	Proxy  bool   `cbor:"3,keyasint,omitempty"`
	Public uint16 `cbor:"4,keyasint,omitempty"`
}

// juist's own ports, every instance's: none is a public port.
const (
	FirstJuistPort = 41640
	LastJuistPort  = 41739
)

// ValidatePublicPort checks a port a name may be published on by TCP: not
// 80 or 443, which an ingress holds for every name, nor juist's own.
func ValidatePublicPort(port uint16) error {
	switch {
	case port == 0:
		return errors.New("port 0")
	case port == 80 || port == 443:
		return fmt.Errorf("port %d, which every ingress holds for names published by TLS", port)
	case port >= FirstJuistPort && port <= LastJuistPort:
		return fmt.Errorf("port %d, one of juist's own (%d to %d)", port, FirstJuistPort, LastJuistPort)
	}
	return nil
}

// ValidateLabel checks one DNS label as a published name takes it.
func ValidateLabel(l string) error { return validateLabel(l) }

// Under is the name p is published as under domain: the domain itself for
// the empty label. Every published name is made here.
func (p PublishedName) Under(domain string) string {
	if p.Label == "" {
		return domain
	}
	return p.Label + "." + domain
}

// shown is p's label as a message names it.
func (p PublishedName) shown() string {
	if p.Label == "" {
		return "the domain itself"
	}
	return p.Label
}

// validatePublished checks a member's published names: each one DNS label,
// or the empty one for the domain itself, on a port, sorted by label, no
// label twice, within [MaxPublishedPerNode]. A name published by TCP has a
// public port of its own and a port no other name of the member has.
func validatePublished(ps []PublishedName) error {
	if len(ps) > MaxPublishedPerNode {
		return fmt.Errorf("%d published names, over the %d limit", len(ps), MaxPublishedPerNode)
	}
	for i, p := range ps {
		if p.Label != "" {
			if err := validateLabel(p.Label); err != nil {
				return fmt.Errorf("published name: %w", err)
			}
		}
		if p.Port == 0 {
			return fmt.Errorf("published name %s has no port", p.shown())
		}
		if i > 0 && ps[i-1].Label >= p.Label {
			return fmt.Errorf("published names are not sorted and unique at %s", p.shown())
		}
		if p.Public == 0 {
			continue
		}
		if err := ValidatePublicPort(p.Public); err != nil {
			return fmt.Errorf("published name %s is published on %w", p.shown(), err)
		}
		for _, q := range ps[:i] {
			switch {
			case q.Public == p.Public:
				return fmt.Errorf("published names %s and %s are both published on port %d", q.shown(), p.shown(), p.Public)
			case q.Port == p.Port:
				return fmt.Errorf("published names %s and %s both go to port %d, which a name published by TCP has alone",
					q.shown(), p.shown(), p.Port)
			}
		}
		for _, q := range ps[i+1:] {
			if q.Public == 0 && q.Port == p.Port {
				return fmt.Errorf("published names %s and %s both go to port %d, which a name published by TCP has alone",
					p.shown(), q.shown(), p.Port)
			}
		}
	}
	return nil
}

// ShareLabel is the label n's name gives, under which the publish role has
// it publish: the name lowercased, where that is a DNS label.
func (n *NodeRecord) ShareLabel() (string, bool) {
	l := strings.ToLower(n.Name)
	return l, validateLabel(l) == nil
}

// ValidatePublishing refuses a member the publish role whose name gives no
// label, or a name by TCP on 443, where it shares; and an ingress
// publishing on 80, 443 or a public port of its own, which it holds itself.
func (n *NodeRecord) ValidatePublishing() error {
	if _, ok := n.ShareLabel(); n.HasRole(RolePublish) && !ok {
		return fmt.Errorf("node %v is named %q, which gives no DNS label to publish under", n.Identity.ShortString(), n.Name)
	}
	if n.HasRole(RolePublish) {
		if i := slices.IndexFunc(n.Published, func(p PublishedName) bool { return p.Public != 0 && p.Port == 443 }); i >= 0 {
			return fmt.Errorf("node %v shares on port 443, and publishes %s by TCP to it",
				n.Identity.ShortString(), n.Published[i].shown())
		}
	}
	if !n.HasRole(RoleIngress) {
		return nil
	}
	for _, p := range n.Published {
		if p.Port == 80 || p.Port == 443 || slices.ContainsFunc(n.Published, func(q PublishedName) bool { return q.Public == p.Port }) {
			return fmt.Errorf("node %v is an ingress, which holds port %d, and publishes %s on it",
				n.Identity.ShortString(), p.Port, p.shown())
		}
	}
	return nil
}

// publishedLabel is the label name is published under in domain, if it is one
// label of it, or the empty one where it is the domain itself.
func publishedLabel(name, domain string) (string, bool) {
	if domain != "" && name == domain {
		return "", true
	}
	label, ok := strings.CutSuffix(name, "."+domain)
	return label, ok && domain != "" && label != "" && !strings.Contains(label, ".")
}
