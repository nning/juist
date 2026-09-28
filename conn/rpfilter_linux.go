//go:build linux && !android

package conn

import (
	"encoding/binary"
	"fmt"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// StrictRP6 reports whether firewalld's IPv6 reverse-path filter is strict,
// which drops an exit node's answers, as its ruleset says: reading it needs
// CAP_NET_ADMIN, and firewalld's configuration is root's alone.
func StrictRP6() (bool, error) {
	c, err := nftables.New()
	if err != nil {
		return false, fmt.Errorf("conn: nftables: %w", err)
	}
	defer c.CloseLasting()
	chains, err := c.ListChains()
	if err != nil {
		return false, fmt.Errorf("conn: listing chains: %w", err)
	}
	for _, ch := range chains {
		if ch.Table.Name != "firewalld" || ch.Hooknum == nil || *ch.Hooknum != *nftables.ChainHookPrerouting {
			continue
		}
		rules, err := ruleMessages(ch.Table, ch.Name)
		if err != nil {
			return false, fmt.Errorf("conn: listing %s: %w", ch.Name, err)
		}
		for _, r := range rules {
			if strictRPRule(r) {
				return true, nil
			}
		}
	}
	return false, nil
}

// ruleMessages are the rules of table's chain as the kernel encodes them.
// Read here rather than through nftables, which drops fib expressions.
func ruleMessages(table *nftables.Table, chain string) ([][]byte, error) {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(table.Name + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(chain + "\x00")},
	})
	if err != nil {
		return nil, err
	}
	msgs, err := c.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETRULE),
			Flags: netlink.Request | netlink.Dump,
		},
		// nfgenmsg: family, version, resource id.
		Data: append([]byte{byte(table.Family), unix.NFNETLINK_V0, 0, 0}, attrs...),
	})
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, m := range msgs {
		if len(m.Data) > 4 {
			out = append(out, m.Data[4:])
		}
	}
	return out, nil
}

// strictRPRule reports whether rule, a rule's attributes, looks a packet's
// source up by its incoming device, as a strict reverse-path check does; a
// loose one leaves the device out.
func strictRPRule(rule []byte) bool {
	for _, e := range ruleExprs(rule) {
		if e.name != "fib" {
			continue
		}
		ad, err := netlink.NewAttributeDecoder(e.data)
		if err != nil {
			continue
		}
		ad.ByteOrder = binary.BigEndian
		var flags, result uint32
		for ad.Next() {
			switch ad.Type() {
			case unix.NFTA_FIB_FLAGS:
				flags = ad.Uint32()
			case unix.NFTA_FIB_RESULT:
				result = ad.Uint32()
			}
		}
		if flags&unix.NFTA_FIB_F_SADDR != 0 && flags&unix.NFTA_FIB_F_IIF != 0 && result == unix.NFT_FIB_RESULT_OIF {
			return true
		}
	}
	return false
}

// A ruleExpr is one expression of a rule: its name, and its data undecoded.
type ruleExpr struct {
	name string
	data []byte
}

func ruleExprs(rule []byte) []ruleExpr {
	var out []ruleExpr
	ad, err := netlink.NewAttributeDecoder(rule)
	if err != nil {
		return nil
	}
	for ad.Next() {
		if ad.Type() != unix.NFTA_RULE_EXPRESSIONS {
			continue
		}
		ad.Nested(func(list *netlink.AttributeDecoder) error {
			for list.Next() {
				list.Nested(func(e *netlink.AttributeDecoder) error {
					var x ruleExpr
					for e.Next() {
						switch e.Type() {
						case unix.NFTA_EXPR_NAME:
							x.name = e.String()
						case unix.NFTA_EXPR_DATA:
							x.data = e.Bytes()
						}
					}
					out = append(out, x)
					return nil
				})
			}
			return nil
		})
	}
	return out
}
