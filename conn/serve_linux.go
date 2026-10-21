//go:build linux && !android

package conn

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/safchain/ethtool"
	"golang.org/x/sys/unix"
)

func (r *linuxRouter) setServe(s Serve) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed && s.serving() {
		return errors.New("conn: router is closed")
	}
	return r.setServeLocked(s)
}

// setServeLocked serves s from a table of this instance's own, which it
// replaces whole; with no routes it removes the table. It masquerades what
// peers send from s.Sources out of any device but this node's, and drops
// what arrives from elsewhere with an overlay source, or comes new into the
// overlay from a public one: forwarding is on for the whole host, and neither
// is a peer's.
func (r *linuxRouter) setServeLocked(s Serve) error {
	if !s.serving() {
		// Before anything below can fail.
		r.restoreUplink()
	}
	if s.serving() {
		// Any other instance's egress, higher ones' too: its table would take
		// what this one's peers send out. Refused, nothing is served.
		refuse := forwardingOff(os.ReadFile, slices.Concat(s.Routes, s.Subnets))
		if refuse == nil {
			if other, err := r.otherEgressLocked(false); err != nil {
				refuse = err
			} else if other >= 0 {
				refuse = ErrEgressTaken
			}
		}
		if refuse != nil {
			return errors.Join(refuse, r.setServeLocked(Serve{}))
		}
	}
	c, err := replacingTables(func(fam nftables.TableFamily) *nftables.Table { return natTable(fam, r.inst) })
	if err != nil {
		return err
	}
	defer c.CloseLasting()
	if s.serving() {
		dev := ifname(r.link.Attrs().Name)
		for _, fam := range families {
			t := c.AddTable(natTable(fam, r.inst))
			accept := nftables.ChainPolicyAccept
			nat := c.AddChain(&nftables.Chain{Table: t, Name: "postrouting", Type: nftables.ChainTypeNAT,
				Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource, Policy: &accept})
			fwd := c.AddChain(&nftables.Chain{Table: t, Name: "forward", Type: nftables.ChainTypeFilter,
				Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &accept})
			for _, rule := range serveRules(fam, dev, s.Sources) {
				c.AddRule(&nftables.Rule{Table: t, Chain: fwd, Exprs: rule})
			}
			for _, src := range s.Sources {
				if src.Addr().Is4() == (fam == nftables.TableFamilyIPv4) {
					c.AddRule(&nftables.Rule{Table: t, Chain: nat, Exprs: masquerade(src, dev)})
				}
			}
			if s.DNS == 0 {
				continue
			}
			dnat := c.AddChain(&nftables.Chain{Table: t, Name: "prerouting", Type: nftables.ChainTypeNAT,
				Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest, Policy: &accept})
			for a := range r.addrs {
				if a.Addr().Is4() != (fam == nftables.TableFamilyIPv4) {
					continue
				}
				for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
					c.AddRule(&nftables.Rule{Table: t, Chain: dnat, Exprs: dnsRedirect(dev, a.Addr(), proto, s.DNS)})
				}
			}
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("conn: setting up masquerade: %w", err)
	}
	r.serving = s.serving()
	if r.serving {
		r.forwardUDPInBatches()
	}
	return nil
}

// The features UDP GRO forwarding is: the uplink's to set, and the
// device's without which it gains nothing.
const (
	rxUDPGROForwarding = "rx-udp-gro-forwarding"
	rxGROList          = "rx-gro-list"
	txUDPSegmentation  = "tx-udp-segmentation"
)

// nicFeatures reads and changes a device's offload features, as ethtool -k
// and -K do.
type nicFeatures interface {
	Features(dev string) (map[string]bool, error)
	Change(dev string, features map[string]bool) error
	Close()
}

var openNICFeatures = func() (nicFeatures, error) { return ethtool.NewEthtool() }

// forwardUDPInBatches has the uplink coalesce the UDP it forwards into the
// device, as tailscaled advises a node that serves: without it every datagram
// passes alone. What it changes is kept, for restoreUplink. The caller holds
// r.mu.
func (r *linuxRouter) forwardUDPInBatches() {
	if r.mon != nil {
		r.forwardUDPInBatchesOn(r.mon.InterfaceState().DefaultRouteInterface)
	}
}

// forwardUDPInBatchesOn is forwardUDPInBatches with up the uplink.
func (r *linuxRouter) forwardUDPInBatchesOn(up string) {
	if up == "" || up == r.groFor {
		return
	}
	r.restoreUplink()
	r.groFor = up
	e, err := openNICFeatures()
	if err != nil {
		r.logf("UDP GRO forwarding on %s: %v", up, err)
		return
	}
	defer e.Close()
	dev, err := e.Features(r.link.Attrs().Name)
	if err != nil || !dev[txUDPSegmentation] {
		return
	}
	had, err := e.Features(up)
	if _, ok := had[rxUDPGROForwarding]; err != nil || !ok || had[rxUDPGROForwarding] && !had[rxGROList] {
		return
	}
	if err := e.Change(up, map[string]bool{rxUDPGROForwarding: true, rxGROList: false}); err != nil {
		r.logf("UDP GRO forwarding on %s: %v; UDP passes through more slowly", up, err)
		return
	}
	r.groWas = map[string]bool{rxUDPGROForwarding: had[rxUDPGROForwarding], rxGROList: had[rxGROList]}
	r.logf("set UDP GRO forwarding on %s while serving", up)
}

// restoreUplink gives the uplink back the features forwardUDPInBatches
// changed. The caller holds r.mu.
func (r *linuxRouter) restoreUplink() {
	up, was := r.groFor, r.groWas
	r.groFor, r.groWas = "", nil
	if was == nil {
		return
	}
	e, err := openNICFeatures()
	if err == nil {
		defer e.Close()
		err = e.Change(up, was)
	}
	if err != nil {
		r.logf("restoring %s's UDP GRO forwarding: %v", up, err)
		return
	}
	r.logf("gave %s its UDP GRO forwarding back", up)
}

// serveRules are the serving table's forward chain: "iifname != juist*
// saddr in sources drop", then for what goes out of dev from elsewhere, new,
// "saddr in local space accept" and "drop". Every juist device of the host
// is let through the first, since networks on one host may share overlay
// space.
func serveRules(fam nftables.TableFamily, dev []byte, sources []netip.Prefix) [][]expr.Any {
	family := []byte(strings.TrimRight(strings.TrimSuffix(string(dev), "\x00"), "0123456789"))
	notFromDev := []expr.Any{&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: dev}}
	notFromJuist := []expr.Any{&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: family}}
	intoDevNew := slices.Concat(notFromDev, []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dev},
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(expr.CtStateBitNEW), Xor: u32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: u32(0)},
	})
	drop := &expr.Verdict{Kind: expr.VerdictDrop}
	var rules [][]expr.Any
	for _, src := range sources {
		if src.Addr().Is4() == (fam == nftables.TableFamilyIPv4) {
			rules = append(rules, slices.Concat(notFromJuist, addrIn(src, true), []expr.Any{drop}))
		}
	}
	for _, p := range localSpace {
		if p.Addr().Is4() == (fam == nftables.TableFamilyIPv4) {
			rules = append(rules, slices.Concat(intoDevNew, addrIn(p, true), []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}))
		}
	}
	return append(rules, slices.Concat(intoDevNew, []expr.Any{drop}))
}

// forwardingOff checks the host forwards every family routes hold, reading
// sysctls through read.
func forwardingOff(read func(string) ([]byte, error), routes []netip.Prefix) error {
	for _, fam := range []struct {
		v6   bool
		path string
	}{{false, "/proc/sys/net/ipv4/conf/all/forwarding"}, {true, "/proc/sys/net/ipv6/conf/all/forwarding"}} {
		if !slices.ContainsFunc(routes, func(p netip.Prefix) bool { return p.Addr().Is6() == fam.v6 }) {
			continue
		}
		b, err := read(fam.path)
		if fam.v6 && errors.Is(err, os.ErrNotExist) {
			continue // no IPv6 here; peers' IPv6 is dropped, as it would be refused
		}
		if err != nil || strings.TrimSpace(string(b)) != "1" {
			return ErrForwardingOff
		}
	}
	return nil
}

// dnsRedirect is "iifname dev daddr addr l4proto proto th dport 53 redirect
// to :port": peers' DNS to this node's address, and to no other server.
func dnsRedirect(dev []byte, addr netip.Addr, proto byte, port uint16) []expr.Any {
	return slices.Concat(
		[]expr.Any{&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dev}},
		addrIn(netip.PrefixFrom(addr, addr.BitLen()), false),
		[]expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 53}},
			&expr.Immediate{Register: 1, Data: []byte{byte(port >> 8), byte(port)}},
			&expr.Redir{RegisterProtoMin: 1},
		})
}

// masquerade is "saddr src oifname != dev masquerade".
func masquerade(src netip.Prefix, dev []byte) []expr.Any {
	return slices.Concat(addrIn(src, true), []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: dev},
		&expr.Masq{},
	})
}
