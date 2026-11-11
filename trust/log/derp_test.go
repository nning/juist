package log

import (
	"testing"

	"github.com/nning/juist/types"
)

// The public DERP setting needs schema 24, whose upgrade allows it; setting
// it again changes nothing, and a checkpoint carries it.
func TestThePublicDERPSettingNeedsSchema24(t *testing.T) {
	h := newHarnessWith(t, 1, 1, func(s *types.Snapshot) { s.Schema = 23 })
	tailscale := types.PublicDERP{Tailscale: true}
	h.mustReject("a public DERP setting at schema 23", RuleState,
		h.signed(types.AUM{Kind: types.KindSetPublicDERP, PublicDERP: &tailscale}))
	h.apply(h.auth.Builder().SchemaUpgrade(types.SchemaPublicDERP))
	h.apply(h.auth.Builder().SetPublicDERP(tailscale))
	if got := h.auth.State().PublicDERP(); got != tailscale {
		t.Fatalf("the state names %+v", got)
	}
	if _, err := h.auth.Builder().SetPublicDERP(tailscale); err == nil {
		t.Error("the setting in effect was set again")
	}
	snap := h.auth.State().Snapshot()
	if snap.PublicDERP == nil || *snap.PublicDERP != tailscale {
		t.Errorf("the snapshot carries %+v", snap.PublicDERP)
	}
	h.apply(h.auth.Builder().SetPublicDERP(types.PublicDERP{}))
	if snap := h.auth.State().Snapshot(); snap.PublicDERP != nil {
		t.Errorf("a setting naming none is written as %+v", snap.PublicDERP)
	}
}
