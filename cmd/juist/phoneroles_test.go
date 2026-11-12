package main

import (
	"strings"
	"testing"

	"github.com/nning/juist/ipc"
	"github.com/nning/juist/types"
)

// A phone gets no role but voucher; one it holds stays; a member not known to
// be a phone, as one on an older juist, gets any.
func TestAPhoneCanOnlyBeAVoucher(t *testing.T) {
	phone := types.NodeRecord{Identity: types.Identity{1}, Name: "iophon"}
	laptop := types.NodeRecord{Identity: types.Identity{2}, Name: "laptop"}
	st := &ipc.Status{Derived: ipc.Derived{Devices: []ipc.Device{{Identity: phone.Identity, Phone: true}, {Identity: laptop.Identity}}}}
	for _, r := range []types.Role{types.RoleRelayCapable, types.RoleExit, types.RoleIngress, types.RolePublish} {
		if err := phoneRoles(st, phone, []types.Role{r}); err == nil || !strings.Contains(err.Error(), "iophon is a phone and can only be a voucher") {
			t.Errorf("%v for a phone: %v", r, err)
		}
	}
	if err := phoneRoles(st, phone, []types.Role{types.RoleAdmin}); err != nil {
		t.Errorf("voucher for a phone: %v", err)
	}
	held := phone
	held.Roles = []types.Role{types.RoleRelayCapable}
	if err := phoneRoles(st, held, []types.Role{types.RoleAdmin, types.RoleRelayCapable}); err != nil {
		t.Errorf("a role the phone holds already: %v", err)
	}
	if err := phoneRoles(st, laptop, []types.Role{types.RoleRelayCapable, types.RoleExit}); err != nil {
		t.Errorf("roles for a laptop: %v", err)
	}
	if err := phoneRoles(nil, phone, []types.Role{types.RoleRelayCapable}); err != nil {
		t.Errorf("without a status: %v", err)
	}
}
