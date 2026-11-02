//go:build linux && !android

package conn

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"tailscale.com/tsconst"
	"tailscale.com/types/ipproto"
)

type discoveryRoute struct{ src, via netip.Addr }

func (r *linuxRouter) copyDiscovery(on bool, groups []netip.Addr, auto bool) {
	r.discoveryOn, r.discoveryGroups, r.discoveryAuto = on, slices.Clone(groups), auto
}

func discoveryTable(fam nftables.TableFamily, inst int) *nftables.Table {
	return &nftables.Table{Family: fam, Name: "juist" + strconv.Itoa(inst) + "discovery"}
}

func (r *linuxRouter) discoveryPeers(peers []Peer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("conn: discovery router is closed")
	}
	r.discoveryVia = netip.Addr{}
	for _, p := range peers {
		if p.Rests || p.Access != nil && (p.Access.Nothing || !slices.ContainsFunc(p.Access.GroupsTo, func(port Ports) bool { return port.Proto == 0 || port.Proto == ipproto.UDP })) {
			continue
		}
		for _, a := range p.Addrs {
			if a.IsSingleIP() && a.Addr().Is4() && (!r.discoveryVia.IsValid() || a.Addr().Less(r.discoveryVia)) {
				r.discoveryVia = a.Addr()
			}
		}
	}
	return r.copyDiscoveryLocked()
}

func (r *linuxRouter) copyDiscoveryLocked() error {
	var next discoveryRoute
	if r.discoveryOn && r.src4.IsValid() && r.discoveryVia.IsValid() && r.routes[netip.PrefixFrom(r.discoveryVia, 32)] {
		next = discoveryRoute{r.src4, r.discoveryVia}
	}
	if r.discoverySet && next == r.discoveryRoute {
		return nil
	}
	if err := setDiscovery(r.inst, r.link.Attrs().Index, r.link.Attrs().Name, next, r.discoveryGroups, r.discoveryAuto); err != nil {
		return err
	}
	r.discoveryRoute, r.discoverySet = next, true
	return nil
}

func setDiscovery(inst, index int, dev string, route discoveryRoute, groups []netip.Addr, auto bool) error {
	c, err := replacingTables(func(fam nftables.TableFamily) *nftables.Table { return discoveryTable(fam, inst) })
	if err != nil {
		return err
	}
	defer c.CloseLasting()
	if route.src.IsValid() && route.via.IsValid() {
		t := c.AddTable(discoveryTable(nftables.TableFamilyIPv4, inst))
		accept := nftables.ChainPolicyAccept
		out := c.AddChain(&nftables.Chain{Table: t, Name: "output", Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityRef(10), Policy: &accept})
		post := c.AddChain(&nftables.Chain{Table: t, Name: "postrouting", Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityMangle, Policy: &accept})
		var group *nftables.Set
		if len(groups) > 0 {
			group = &nftables.Set{Table: t, Name: "groups", KeyType: nftables.TypeIPAddr}
			elems := make([]nftables.SetElement, 0, len(groups))
			for _, a := range groups {
				elems = append(elems, nftables.SetElement{Key: a.AsSlice()})
			}
			if err := c.AddSet(group, elems); err != nil {
				return fmt.Errorf("conn: copying discovery groups: %w", err)
			}
		}
		for _, broadcast := range []bool{true, false} {
			if !broadcast && group == nil && !auto {
				continue
			}
			match := discoveryMatch(group, broadcast)
			original := []expr.Any{
				&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte("juist")},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname(dev)},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname("lo")},
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binary.NativeEndian.AppendUint32(nil, tsconst.LinuxFwmarkMaskNum), Xor: []byte{0, 0, 0, 0}},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binary.NativeEndian.AppendUint32(nil, tsconst.LinuxBypassMarkNum)},
			}
			mark := binary.NativeEndian.AppendUint32(nil, 0x6a750000+uint32(inst))
			duplicate := []expr.Any{
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 3},
				&expr.Immediate{Register: 4, Data: mark},
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 4, SourceRegister: true},
				&expr.Immediate{Register: 1, Data: route.via.AsSlice()},
				&expr.Immediate{Register: 2, Data: binary.NativeEndian.AppendUint32(nil, uint32(index))},
				&expr.Counter{}, &expr.Dup{RegAddr: 1, RegDev: 2, IsRegDevSet: true},
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 3, SourceRegister: true},
			}
			c.AddRule(&nftables.Rule{Table: t, Chain: out, Exprs: slices.Concat(original, match, duplicate)})
			// Only dup's marked copy may have its addresses rewritten.
			copyOnly := []expr.Any{
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: mark},
				&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(dev)},
			}
			rewrite := []expr.Any{&expr.Counter{}}
			if broadcast {
				rewrite = append(rewrite, rewriteDiscoveryAddress(16, netip.MustParseAddr("255.255.255.255"))...)
			}
			rewrite = append(rewrite, rewriteDiscoveryAddress(12, route.src)...)
			rewrite = append(rewrite, &expr.Immediate{Register: 1, Data: []byte{0, 0, 0, 0}}, &expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true})
			c.AddRule(&nftables.Rule{Table: t, Chain: post, Exprs: slices.Concat(copyOnly, match, rewrite)})
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("conn: copying discovery into %s: %w", dev, err)
	}
	return nil
}

// discoveryMatch selects local, unfragmented UDP that fits the tunnel.
func discoveryMatch(group *nftables.Set, broadcast bool) []expr.Any {
	rules := []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 0, Len: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x45}},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Fib{Register: 1, ResultADDRTYPE: true, FlagSADDR: true},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.NativeEndian.AppendUint32(nil, unix.RTN_LOCAL)},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 6, Len: 2},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 2, Mask: []byte{0x3f, 0xff}, Xor: []byte{0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 0}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: []byte{5, 0}},
	}
	if broadcast {
		rules = append(rules, &expr.Fib{Register: 1, ResultADDRTYPE: true, FlagDADDR: true}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.NativeEndian.AppendUint32(nil, unix.RTN_BROADCAST)})
		for _, offset := range []uint32{0, 2} {
			rules = append(rules, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2})
			for _, port := range broadcastBlockedPorts {
				rules = append(rules, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, port)})
			}
		}
	} else if group != nil {
		rules = append(rules, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}, &expr.Lookup{SourceRegister: 1, SetName: group.Name, SetID: group.ID})
	} else {
		rules = append(rules, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0xf0}, Xor: []byte{0}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0xe0}})
	}
	return rules
}

func rewriteDiscoveryAddress(offset uint32, a netip.Addr) []expr.Any {
	return []expr.Any{&expr.Immediate{Register: 1, Data: a.AsSlice()}, &expr.Payload{OperationType: expr.PayloadWrite, SourceRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4, CsumType: expr.CsumTypeInet, CsumOffset: 10, CsumFlags: unix.NFT_PAYLOAD_L4CSUM_PSEUDOHDR}}
}
