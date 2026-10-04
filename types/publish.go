package types

import (
	"fmt"
	"strings"
)

// MaxPublishedPerNode caps the names one member publishes.
const MaxPublishedPerNode = 16

// A PublishedName is a service a member publishes through the network's
// ingresses: LABEL.DOMAIN, or DOMAIN itself for the empty label, reached on
// Port of the member, with the client's address in a PROXY protocol v2
// header where Proxy is set.
type PublishedName struct {
	Label string `cbor:"1,keyasint"`
	Port  uint16 `cbor:"2,keyasint"`
	Proxy bool   `cbor:"3,keyasint,omitempty"`
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
// label twice, within [MaxPublishedPerNode].
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
// label, and an ingress publishing on 80 or 443, which it holds itself for
// every name it passes on.
func (n *NodeRecord) ValidatePublishing() error {
	if _, ok := n.ShareLabel(); n.HasRole(RolePublish) && !ok {
		return fmt.Errorf("node %v is named %q, which gives no DNS label to publish under", n.Identity.ShortString(), n.Name)
	}
	if !n.HasRole(RoleIngress) {
		return nil
	}
	for _, p := range n.Published {
		if p.Port == 80 || p.Port == 443 {
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
