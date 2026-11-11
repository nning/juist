package types

import (
	"strings"
	"testing"
)

// A state names its public DERP servers one way: a setting naming none is
// absent, and one below schema 24 is refused.
func TestASnapshotNamesItsPublicDERPOneWay(t *testing.T) {
	for _, c := range []struct {
		schema SchemaVersion
		derp   *PublicDERP
		ok     bool
	}{
		{SchemaPublicDERP, &PublicDERP{Tailscale: true}, true},
		{SchemaPublicDERP, &PublicDERP{}, false},
		{SchemaPublicDERP - 1, &PublicDERP{Tailscale: true}, false},
	} {
		s := Snapshot{Schema: c.schema, PublicDERP: c.derp}
		err := s.StaticValidate(true)
		if refusedForDERP := err != nil && strings.Contains(err.Error(), "public DERP"); refusedForDERP == c.ok {
			t.Errorf("schema %d, %+v: %v", c.schema, c.derp, err)
		}
	}
}
