//go:build linux && !android

package conn

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/tailscale/netlink/nl"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"tailscale.com/tsconst"
)

// natTable is instance inst's nftables table for serving as an exit node,
// and guardTable its table keeping a client's traffic in the tunnel, in each
// family.
func natTable(family nftables.TableFamily, inst int) *nftables.Table {
	return &nftables.Table{Family: family, Name: "juist" + strconv.Itoa(inst)}
}

func guardTable(family nftables.TableFamily, inst int) *nftables.Table {
	return &nftables.Table{Family: family, Name: "juist" + strconv.Itoa(inst) + "guard"}
}

var families = []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6}

// replacingTables opens a transaction that begins by deleting the table that
// table names in each of [families], for the caller to add again whole and
// flush. The caller closes it.
func replacingTables(table func(nftables.TableFamily) *nftables.Table) (*nftables.Conn, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("conn: nftables: %w", err)
	}
	for _, fam := range families {
		t := table(fam)
		c.AddTable(t) // so that the delete below cannot fail for a missing table
		c.DelTable(t)
	}
	return c, nil
}

// setGuard, on, drops what would leave outside the tunnel dev: every packet
// sent or forwarded out of another device, but for bypass-marked ones
// (magicsock's and tailscaled's), juistd's own by uid, DHCP, and those to
// what no exit node carries. Routing sends nothing there; the guard holds
// where routing does not, as for a socket bound to a device, or routes
// someone deleted. What goes into dev for the internet it rejects in a family
// through does not carry, and with refuse in both; through's subnets pass.
// dev may be "" where there is no tunnel; off removes the guard.
// Tables are replaced whole, in one transaction.
func setGuard(inst int, on bool, dev string, through tunnelled, refuse bool, uid uint32) error {
	c, err := replacingTables(func(fam nftables.TableFamily) *nftables.Table { return guardTable(fam, inst) })
	if err != nil {
		return err
	}
	defer c.CloseLasting()
	if on {
		for _, fam := range families {
			t := c.AddTable(guardTable(fam, inst))
			if !through.answers {
				// Marked where a connection comes in, before routing, and
				// on its answers, forwarded ones there and the host's own
				// in a route chain, which routes them again.
				accept := nftables.ChainPolicyAccept
				pre := c.AddChain(&nftables.Chain{Table: t, Name: "answers-in", Type: nftables.ChainTypeFilter,
					Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityMangle, Policy: &accept})
				c.AddRule(&nftables.Rule{Table: t, Chain: pre, Exprs: markIncoming(dev)})
				c.AddRule(&nftables.Rule{Table: t, Chain: pre, Exprs: clearAnswerMark()})
				c.AddRule(&nftables.Rule{Table: t, Chain: pre, Exprs: markAnswer()})
				out := c.AddChain(&nftables.Chain{Table: t, Name: "answers-out", Type: nftables.ChainTypeRoute,
					Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityMangle, Policy: &accept})
				c.AddRule(&nftables.Rule{Table: t, Chain: out, Exprs: markAnswer()})
			}
			for _, hook := range []*nftables.ChainHook{nftables.ChainHookOutput, nftables.ChainHookForward} {
				accept := nftables.ChainPolicyAccept
				ch := c.AddChain(&nftables.Chain{Table: t, Name: map[bool]string{true: "output", false: "forward"}[hook == nftables.ChainHookOutput],
					Type: nftables.ChainTypeFilter, Hooknum: hook, Priority: nftables.ChainPriorityFilter, Policy: &accept})
				for _, rule := range guardRules(fam, hook == nftables.ChainHookOutput, dev, through, refuse, uid) {
					c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: rule})
				}
			}
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("conn: guarding the tunnel: %w", err)
	}
	return nil
}

// guardRules are one guard chain's rules, in order, the last dropping.
func guardRules(fam nftables.TableFamily, output bool, dev string, through tunnelled, refuse bool, uid uint32) [][]expr.Any {
	refuse = refuse || !through.carries(fam)
	accept := &expr.Verdict{Kind: expr.VerdictAccept}
	otherFam := func(p netip.Prefix) bool { return p.Addr().Is4() != (fam == nftables.TableFamilyIPv4) }
	allowed := slices.DeleteFunc(offTunnel(), otherFam)
	oif := func(d string) []expr.Any {
		return []expr.Any{&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(d)}}
	}
	var rules [][]expr.Any
	if dev != "" && refuse {
		for _, p := range slices.Concat(allowed, slices.DeleteFunc(slices.Clone(through.subnets), otherFam)) {
			rules = append(rules, slices.Concat(oif(dev), addrIn(p, false), []expr.Any{accept}))
		}
		rules = append(rules, append(oif(dev), &expr.Reject{Type: unix.NFT_REJECT_ICMP_UNREACH, Code: 0}))
	} else if dev != "" {
		rules = append(rules, append(oif(dev), accept))
	}
	if !through.answers {
		rules = append(rules, append(isAnswer(), accept))
	}
	rules = append(rules, append(oif("lo"), accept))
	rules = append(rules, [][]expr.Any{
		{&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(tsconst.LinuxFwmarkMaskNum), Xor: u32(0)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: u32(tsconst.LinuxBypassMarkNum)}, accept},
	}...)
	if output && uid != 0 {
		rules = append(rules, []expr.Any{&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: u32(uid)}, accept})
	}
	// The host's own DHCP, to a server that may be off the link and in
	// public space, from the client's port, which only root may bind; and
	// its neighbour discovery, which answers from global addresses too, and
	// never leaves the link (hop limit 255). Neither is forwarded.
	if output {
		rules = append(rules, dhcpRule(fam, accept))
		if fam == nftables.TableFamilyIPv6 {
			rules = append(rules, []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 7, Len: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{255}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
				&expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: []byte{133}, ToData: []byte{137}}, accept})
		}
	}
	for _, p := range allowed {
		rules = append(rules, append(addrIn(p, false), accept))
	}
	return append(rules, []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}})
}

// markIncoming marks a connection coming in by another device, from its
// first packet or, for one older than the guard, its next: "ct direction
// original ct mark & answerMark == 0 iifname != { juist*, dev, lo } fib
// daddr . iif type local meta mark set meta mark | answerMark fib saddr .
// mark . iif oif != 0 ct mark set ct mark | answerMark". It must be sent to
// an address of that device, and the host's routes, as answers take them,
// must lead back by it: what a LAN sends to the overlay's addresses, or what
// comes in by a device whose routes are not the host's, as another VPN's, is
// no connection to answer that way.
func markIncoming(dev string) []expr.Any {
	e := []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}}, // IP_CT_DIR_ORIGINAL
		&expr.Ct{Register: 1, Key: expr.CtKeyMARK},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(answerMark), Xor: u32(0)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: u32(0)},
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte("juist")}, // a prefix: every instance's
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname("lo")},
	}
	if dev != "" {
		e = append(e, &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname(dev)})
	}
	return append(e,
		&expr.Fib{Register: 1, FlagDADDR: true, FlagIIF: true, ResultADDRTYPE: true},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: u32(unix.RTN_LOCAL)},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(^uint32(answerMark)), Xor: u32(answerMark)},
		&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
		&expr.Fib{Register: 1, FlagSADDR: true, FlagMARK: true, FlagIIF: true, ResultOIF: true},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: u32(0)},
		&expr.Ct{Register: 1, Key: expr.CtKeyMARK},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(^uint32(answerMark)), Xor: u32(answerMark)},
		&expr.Ct{Register: 1, Key: expr.CtKeyMARK, SourceRegister: true},
	)
}

// clearAnswerMark takes the mark [markIncoming] looked the way back up with
// off the packet that came in: "ct direction original meta mark set meta
// mark & ~answerMark".
func clearAnswerMark() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(^uint32(answerMark)), Xor: u32(0)},
		&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
	}
}

// isAnswer is "ct direction reply ct mark & answerMark != 0".
func isAnswer() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}}, // IP_CT_DIR_REPLY
		&expr.Ct{Register: 1, Key: expr.CtKeyMARK},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(answerMark), Xor: u32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: u32(0)},
	}
}

// markAnswer is [isAnswer] "meta mark set meta mark | answerMark".
func markAnswer() []expr.Any {
	return append(isAnswer(),
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(^uint32(answerMark)), Xor: u32(answerMark)},
		&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1})
}

// dhcpRule is "udp sport client dport server", of DHCP in fam.
func dhcpRule(fam nftables.TableFamily, verdict expr.Any) []expr.Any {
	client, server := uint16(68), uint16(67)
	if fam == nftables.TableFamilyIPv6 {
		client, server = 546, 547
	}
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1,
			Data: []byte{byte(client >> 8), byte(client), byte(server >> 8), byte(server)}}, verdict}
}

// ifname is dev as an interface name compares in nftables.
func ifname(dev string) []byte { return []byte(dev + "\x00") }

func u32(v uint32) []byte {
	b := make([]byte, 4)
	nl.NativeEndian().PutUint32(b, v)
	return b
}

// addrIn is "saddr in p", or "daddr in p" where dst.
func addrIn(p netip.Prefix, src bool) []expr.Any {
	field := addrField(p.Addr().Is6(), src)
	return []expr.Any{
		field,
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: field.Len, Mask: netipx.PrefixIPNet(p).Mask, Xor: make([]byte, field.Len)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: p.Masked().Addr().AsSlice()},
	}
}

// addrField loads a packet's source address, or its destination, into
// register 1.
func addrField(v6, src bool) *expr.Payload {
	off, n := uint32(16), uint32(4)
	if v6 {
		off, n = 24, 16
	}
	if src {
		off -= n
	}
	return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: n}
}

// carries reports whether an exit node's routes carry fam.
func (t tunnelled) carries(fam nftables.TableFamily) bool {
	if fam == nftables.TableFamilyIPv6 {
		return t.v6
	}
	return t.v4
}
