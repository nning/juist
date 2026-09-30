package types

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Limits on a member's name overrides.
const (
	// MaxNamesPerNode caps the public names one member answers for.
	MaxNamesPerNode = 32

	// MaxHostNameLen is a DNS name's limit in its presentation form.
	MaxHostNameLen = 253
)

// NamesTLD is juist's own top-level domain: a network's members are named
// DEVICE.NETWORK.juist, which no override may claim.
const NamesTLD = "juist"

// reservedTLDs are top-level domains no override may name: juist's own, and
// those that mean something to the host itself or are never delegated.
var reservedTLDs = []string{NamesTLD, "arpa", "invalid", "local", "localhost", "onion"}

// ValidateHostName checks a public DNS name an override points at a member:
// lowercase ASCII, a Unicode name in its xn-- form, of two labels or more,
// letters, digits and inner hyphens alone, and neither an address nor a name
// of a reserved domain. A name of one form alone, so that two spellings
// cannot be two overrides.
func ValidateHostName(name string) error {
	switch {
	case name == "":
		return errors.New("an empty name")
	case len(name) > MaxHostNameLen:
		return fmt.Errorf("a name of %d bytes, over the %d limit", len(name), MaxHostNameLen)
	case strings.HasSuffix(name, "."):
		return fmt.Errorf("name %q ends in a dot", name)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return fmt.Errorf("name %q is a top-level domain", name)
	}
	for _, l := range labels {
		if err := validateLabel(l); err != nil {
			return fmt.Errorf("name %q: %w", name, err)
		}
	}
	tld := labels[len(labels)-1]
	if strings.Trim(tld, "0123456789") == "" {
		return fmt.Errorf("name %q ends in a number, as an address does", name)
	}
	if slices.Contains(reservedTLDs, tld) {
		return fmt.Errorf("name %q is in .%s, which no override may name", name, tld)
	}
	return nil
}

func validateLabel(l string) error {
	switch {
	case l == "":
		return errors.New("an empty label")
	case len(l) > 63:
		return fmt.Errorf("label %q is over 63 bytes", l)
	case l[0] == '-' || l[len(l)-1] == '-':
		return fmt.Errorf("label %q begins or ends with a hyphen", l)
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return fmt.Errorf("label %q holds %q; only lowercase letters, digits and hyphens", l, c)
		}
	}
	return nil
}

// validateNames checks a member's override set: each a valid name, sorted,
// no name twice, within [MaxNamesPerNode].
func validateNames(names []string) error {
	if len(names) > MaxNamesPerNode {
		return fmt.Errorf("%d names, over the %d limit", len(names), MaxNamesPerNode)
	}
	for i, n := range names {
		if err := ValidateHostName(n); err != nil {
			return err
		}
		if i > 0 && names[i-1] >= n {
			return fmt.Errorf("names are not sorted and unique at %q", n)
		}
	}
	return nil
}
