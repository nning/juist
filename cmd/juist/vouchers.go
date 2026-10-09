package main

import (
	"slices"
	"strings"

	"github.com/nning/juist/types"
)

// warnVouchers says what a voucher set and its threshold leave exposed: no
// spare, so one voucher offline for the TTL limits every device to vouchers;
// or, at a threshold of one, a voucher that relays too, which alone can both
// cut a device off and keep it fresh.
func (a *app) warnVouchers(all []types.NodeRecord, needed int) {
	now := a.now().Unix()
	var vouchers []types.NodeRecord
	for i := range all {
		if !all[i].Expired(now) {
			vouchers = append(vouchers, all[i])
		}
	}
	if len(vouchers) == 0 {
		return
	}
	if len(vouchers) == needed {
		a.warn("no spare voucher: one offline for 48 hours limits every device to vouchers")
		a.hint("juist grant DEVICE voucher, on a device that is always on")
	}
	if needed != 1 {
		return
	}
	var relays []string
	for i := range vouchers {
		if vouchers[i].HasRole(types.RoleRelayCapable) {
			relays = append(relays, displayMember(vouchers[i]))
		}
	}
	if len(relays) > 0 {
		a.warn("%s relays too: with 1 voucher needed, it alone can keep a device it cuts off fresh",
			strings.Join(relays, ", "))
		a.hint("juist admins vouchers 2, with vouchers on hosts that fail apart")
	}
}

// hintVoucherCarries says where nothing would carry a change waiting for
// votes: such changes travel between vouchers alone.
func (a *app) hintVoucherCarries(quorum uint32, vouchers []types.NodeRecord) {
	now := a.now().Unix()
	if quorum > 1 && !slices.ContainsFunc(vouchers, func(n types.NodeRecord) bool { return !n.Expired(now) }) {
		a.hint(voucherCarriesHint)
	}
}

const voucherCarriesHint = "changes waiting for votes travel through vouchers: juist grant DEVICE voucher"

// vouchersWith is the network's vouchers once target holds roles.
func vouchersWith(all []types.NodeRecord, target types.NodeRecord, roles []types.Role) []types.NodeRecord {
	var out []types.NodeRecord
	for _, n := range all {
		if n.Identity != target.Identity && n.HasRole(types.RoleAdmin) {
			out = append(out, n)
		}
	}
	t := target
	t.Roles = roles
	if t.HasRole(types.RoleAdmin) {
		out = append(out, t)
	}
	return out
}
