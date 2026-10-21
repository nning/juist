package conn

import (
	"testing"

	"github.com/nning/juist/internal/plumber"
)

// egressPlumber records the egress it is told; it is told nothing else.
type egressPlumber struct {
	Plumber
	dev   string
	specs []plumber.EgressSpec
}

func (p *egressPlumber) SetEgress(dev string, e plumber.EgressSpec) error {
	p.dev = dev
	p.specs = append(p.specs, e)
	return nil
}

// Where a plumber plumbs the device, egress is held by it alone.
func TestHostControlHoldsEgressByThePlumber(t *testing.T) {
	p := &egressPlumber{}
	h := HostControl{Instance: 3, Plumber: p, Dev: "juist3"}
	if err := h.RefuseEgress(true); err != nil {
		t.Fatal(err)
	}
	if err := h.ClearEgress(); err != nil {
		t.Fatal(err)
	}
	if p.dev != "juist3" || len(p.specs) != 2 || p.specs[0].Mode != plumber.EgressRefused || !p.specs[0].Isolate ||
		p.specs[1].Mode != plumber.EgressDirect {
		t.Fatalf("told %q: %+v", p.dev, p.specs)
	}
}
