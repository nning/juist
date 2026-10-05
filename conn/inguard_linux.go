//go:build linux && !android

package conn

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// inTable is instance inst's table keeping the overlay's addresses to its
// device, in each family.
func inTable(family nftables.TableFamily, inst int) *nftables.Table {
	return &nftables.Table{Family: family, Name: "juist" + strconv.Itoa(inst) + "in"}
}

// guardOverlay drops what comes in by another device than the tunnel or
// loopback for one of own, and, but by a juist device, from one of own or
// peers: Linux delivers to an address on any device (the weak host model).
// It replaces the table whole, and only where own or peers changed.
func (r *linuxRouter) guardOverlay(own, peers []netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	if r.inInstalled && slices.Equal(own, r.inOwn) && slices.Equal(peers, r.inPeers) {
		return nil
	}
	r.inInstalled = false
	if err := setInGuard(r.inst, r.link.Attrs().Name, own, peers); err != nil {
		return err
	}
	r.inOwn, r.inPeers, r.inInstalled = slices.Clone(own), slices.Clone(peers), true
	return nil
}

// setInGuard installs instance inst's [inTable] for dev, or removes it where
// own and peers are both empty, in one transaction.
func setInGuard(inst int, dev string, own, peers []netip.Addr) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("conn: nftables: %w", err)
	}
	defer c.CloseLasting()
	for _, fam := range families {
		t := inTable(fam, inst)
		c.AddTable(t) // so that the delete below cannot fail for a missing table
		c.DelTable(t)
	}
	for _, fam := range families {
		key, ownFam, srcFam := nftables.TypeIPAddr, ofFamily(own, fam), ofFamily(peers, fam)
		if fam == nftables.TableFamilyIPv6 {
			key = nftables.TypeIP6Addr
		}
		srcFam = append(srcFam, ownFam...)
		slices.SortFunc(srcFam, netip.Addr.Compare)
		srcFam = slices.Compact(srcFam)
		if len(srcFam) == 0 {
			continue
		}
		t := c.AddTable(inTable(fam, inst))
		accept := nftables.ChainPolicyAccept
		ch := c.AddChain(&nftables.Chain{Table: t, Name: "prerouting", Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRaw, Policy: &accept})
		var dst, src *nftables.Set
		for _, s := range []struct {
			set   **nftables.Set
			name  string
			addrs []netip.Addr
		}{{&dst, "own", ownFam}, {&src, "overlay", srcFam}} {
			if len(s.addrs) == 0 {
				continue
			}
			*s.set = &nftables.Set{Table: t, Name: s.name, KeyType: key}
			elems := make([]nftables.SetElement, 0, len(s.addrs))
			for _, a := range s.addrs {
				elems = append(elems, nftables.SetElement{Key: a.AsSlice()})
			}
			if err := c.AddSet(*s.set, elems); err != nil {
				return fmt.Errorf("conn: guarding the overlay's addresses: %w", err)
			}
		}
		for _, rule := range inRules(fam, dev, dst, src) {
			c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: rule})
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("conn: guarding the overlay's addresses: %w", err)
	}
	return nil
}

// inRules are the in table's rules: "iifname != { dev, lo } daddr @own
// drop" and "iifname != { juist*, dev, lo } saddr @overlay drop", each
// counting, either left out where its set is nil. Every juist device may bring
// overlay sources in, since networks on one host may share overlay space.
func inRules(fam nftables.TableFamily, dev string, own, overlay *nftables.Set) [][]expr.Any {
	notFrom := func(name []byte) []expr.Any {
		return []expr.Any{&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: name}}
	}
	notLocal := slices.Concat(notFrom(ifname(dev)), notFrom(ifname("lo")))
	drop := []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}
	var rules [][]expr.Any
	for _, s := range []struct {
		set  *nftables.Set
		src  bool
		from []expr.Any
	}{{own, false, notLocal}, {overlay, true, slices.Concat(notFrom([]byte("juist")), notLocal)}} {
		if s.set == nil {
			continue
		}
		rules = append(rules, slices.Concat(s.from,
			[]expr.Any{addrField(fam == nftables.TableFamilyIPv6, s.src),
				&expr.Lookup{SourceRegister: 1, SetName: s.set.Name, SetID: s.set.ID}}, drop))
	}
	return rules
}

// ofFamily is the addresses of addrs in fam.
func ofFamily(addrs []netip.Addr, fam nftables.TableFamily) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if a.Is4() == (fam == nftables.TableFamilyIPv4) {
			out = append(out, a)
		}
	}
	return out
}
