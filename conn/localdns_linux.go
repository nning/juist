//go:build linux && !android

package conn

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// localDNSTable is the table that takes the host's own DNS to juistd's
// resolver, in each family.
func localDNSTable(family nftables.TableFamily) *nftables.Table {
	return &nftables.Table{Family: family, Name: "juist0dns"}
}

// RedirectLocalDNS takes what the host's own programs ask on port 53 of each
// of to's addresses to its port, which a resolv.conf cannot name; none
// removes the table.
func RedirectLocalDNS(to []netip.AddrPort) error {
	c, err := replacingTables(localDNSTable)
	if err != nil {
		return err
	}
	defer c.CloseLasting()
	if len(to) > 0 {
		accept := nftables.ChainPolicyAccept
		for _, fam := range families {
			t := c.AddTable(localDNSTable(fam))
			out := c.AddChain(&nftables.Chain{Table: t, Name: "output", Type: nftables.ChainTypeNAT,
				Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityNATDest, Policy: &accept})
			for _, ap := range to {
				if ap.Addr().Is4() != (fam == nftables.TableFamilyIPv4) || ap.Port() == 53 {
					continue
				}
				for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
					c.AddRule(&nftables.Rule{Table: t, Chain: out, Exprs: localDNSRule(ap, proto)})
				}
			}
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("conn: taking the host's DNS to juistd: %w", err)
	}
	return nil
}

// localDNSRule is "daddr a l4proto proto th dport 53 dnat to a:port".
func localDNSRule(to netip.AddrPort, proto byte) []expr.Any {
	a := to.Addr()
	fam := uint32(unix.NFPROTO_IPV4)
	if a.Is6() {
		fam = unix.NFPROTO_IPV6
	}
	return slices.Concat(
		addrIn(netip.PrefixFrom(a, a.BitLen()), false),
		[]expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 53}},
			&expr.Immediate{Register: 1, Data: a.AsSlice()},
			&expr.Immediate{Register: 2, Data: []byte{byte(to.Port() >> 8), byte(to.Port())}},
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: fam, RegAddrMin: 1, RegProtoMin: 2, Specified: true},
		})
}
