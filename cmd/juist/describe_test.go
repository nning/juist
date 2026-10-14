package main

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/nning/juist/types"
)

// Every kind types defines is named, says what it does, and is decided on
// whether it needs the log to be approved: a kind added without them would be
// signed by admins shown only "a kind record".
func TestEveryKindIsDescribed(t *testing.T) {
	id := types.Identity{1}
	q, v := uint32(1), uint32(2)
	schema := types.CurrentSchema
	name := "home"
	v4 := netip.MustParseAddr("198.18.0.9")
	prefix := netip.MustParsePrefix("198.18.4.0/22")
	samples := map[types.Kind]types.AUM{
		types.KindGenesis:           {State: &types.Snapshot{Network: "home", Quorum: 1}},
		types.KindAddNode:           {Node: &types.NodeRecord{Name: "laptop", Identity: id}},
		types.KindRemoveNode:        {Subject: &id},
		types.KindSetNodeRoutes:     {Subject: &id, Grant: &types.RouteGrant{Roles: []types.Role{types.RoleExit}}},
		types.KindRotateNodeKey:     {Subject: &id, Keys: &types.NodeKeys{}},
		types.KindRotateIdentity:    {Subject: &id, NewIdentity: &types.Identity{2}},
		types.KindAddAdminKey:       {Admin: &types.AdminKey{Public: id, Votes: 1}},
		types.KindRemoveAdminKey:    {Subject: &id},
		types.KindSetQuorum:         {Quorum: &q},
		types.KindCheckpoint:        {State: &types.Snapshot{Network: "home", Quorum: 1}},
		types.KindEpochBump:         {},
		types.KindSchemaUpgrade:     {Schema: &schema},
		types.KindSetVouchers:       {Vouchers: &v},
		types.KindSetHolder:         {Holder: &types.HolderPolicy{Name: "alice", Votes: 1, Needed: 2}},
		types.KindRenumberNetwork:   {Renumber: &types.Renumbering{Prefix: &prefix}},
		types.KindRenumberNode:      {Subject: &id, Renumber: &types.Renumbering{V4: &v4}},
		types.KindRetireAddresses:   {},
		types.KindRenameNetwork:     {Network: &name},
		types.KindSetAdminRecipient: {Subject: &id, Recipient: &types.RecipientKey{}},
		types.KindSetNodeNames:      {Subject: &id, Names: &types.NameGrant{Names: []string{"mx.example.org"}}},
		types.KindSetDomain:         {Domain: &name},
		types.KindSetPublished: {Subject: &id, Publish: &types.PublishGrant{
			Names: []types.PublishedName{{Label: "immich", Port: 443}}}},
		types.KindRenameNode: {Subject: &id, NodeName: &name},
		types.KindDisable:    {Secret: &types.DisablementSecret{1}},
		types.KindSetPolicy:  {Policy: &types.Policy{}},
	}
	if !changesAuthority(&types.AUM{Kind: types.Kind(255)}) {
		t.Error("a kind not decided on is approved without the log")
	}
	for k := types.Kind(1); k != 0; k++ {
		if strings.HasPrefix(k.String(), "kind?") {
			continue
		}
		if _, ok := kindChangesAuthority[k]; !ok && k != types.KindAddNode {
			t.Errorf("%v is not decided on whether it changes who may approve", k)
		}
		aum, ok := samples[k]
		if !ok {
			t.Errorf("%v has no sample here", k)
			continue
		}
		aum.Kind = k
		lines := effect(&aum, nil, 0)
		if len(lines) == 0 || lines[0] == fmt.Sprintf("a %s record", k) {
			t.Errorf("%v says nothing of what it does: %q", k, lines)
		}
	}
}
