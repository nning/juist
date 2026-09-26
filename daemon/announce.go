package daemon

import (
	"net/netip"
	"slices"
	"time"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/internal/underlay"
	"github.com/nning/juist/types"
)

// announcement returns this node's signed endpoint record, rebuilding it when
// the underlay addresses or the data-plane port change, and signing it again
// every [announceRenewal] though they do not. The sequence number is the
// wall clock, so a restart does not reissue numbers peers would dismiss as
// replays, and a peer reads from it when the record was signed.
func (d *Daemon) announcement() (gossip.Endpoint, bool) { return d.announce(announceRenewal) }

// publishedAnnouncement is [Daemon.announcement] for the DHT, freshly signed
// unless it just was: an item there is read long after it is put.
func (d *Daemon) publishedAnnouncement() (gossip.Endpoint, bool) { return d.announce(time.Minute) }

func (d *Daemon) announce(renew time.Duration) (gossip.Endpoint, bool) {
	// The interface scan is what makes a LAN with no internet work; the
	// addresses the data plane learned are what makes an off-LAN peer
	// reachable. Reflexive addresses are added to the scan, never substituted
	// for it.
	scanned, internal := d.underlayEndpoints()
	addrs := mergeEndpoints(gossip.SortAddrs(scanned), d.reachableLearned(d.manager.LocalEndpoints(), internal))
	relayInfo := d.relayInfo()
	home := uint16(d.manager.HomeRelay())

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.status.NotMember {
		// A removed device goes quiet on the LAN too: no beacons, no answers
		// to queries, no Self in a gossip hello. Re-enrollment arrives over
		// IPC, so it loses nothing it needs. A fork alarm does not gate this
		// — staying discoverable is how the resolving records arrive.
		return gossip.Endpoint{}, false
	}
	e := gossip.Endpoint{
		Identity:   d.self,
		Disco:      d.discoPublic,
		Addrs:      addrs,
		GossipPort: d.gossipPort,
		Relay:      relayInfo,
		HomeRelay:  home,
	}
	now := d.now()
	renewal := d.signed != nil && d.signed.SameAs(&e)
	if d.announced != nil && renewal && now.Sub(d.announcedAt) < renew {
		return *d.announced.Clone(), true
	}
	if !renewal && d.seq != 0 && d.dht != nil {
		// Changed since the last one: a peer whose tunnel it breaks finds
		// the new one in the DHT, so it goes there at once.
		d.dht.Kick()
	}
	e.Seq = d.nextSeq()
	if err := e.Sign(d.identity); err != nil {
		d.logf("daemon: signing this node's announcement: %v", err)
		return gossip.Endpoint{}, false
	}
	d.announced, d.signed, d.announcedAt = &e, &e, now
	return *e.Clone(), true
}

// nextSeq returns a strictly increasing sequence number, seeded from the
// clock. The caller holds d.mu.
func (d *Daemon) nextSeq() uint64 {
	next := uint64(d.now().Unix())
	if next <= d.seq {
		next = d.seq + 1
	}
	d.seq = next
	return next
}

// underlayEndpoints reports where this node's data plane can be reached from
// the local network, and the addresses of this host's that cannot be. The
// host's interfaces are read directly, since magicsock reports no endpoints
// without a STUN result or a DERP map and we want no third party. Down,
// loopback, link-local and overlay addresses are filtered out — the last would
// ask peers to reach the tunnel through the tunnel.
func (d *Daemon) underlayEndpoints() (eps []netip.AddrPort, internal []netip.Addr) {
	port := d.manager.LocalPort()
	if port == 0 {
		return nil, nil
	}
	// Cached briefly: this runs on every gossip session and discovery tick,
	// and enumerating interfaces is a syscall walk over every host address.
	now := d.now()
	d.mu.Lock()
	if d.addrsPort == port && now.Before(d.addrsUntil) {
		eps, internal = slices.Clone(d.addrs), slices.Clone(d.internal)
		d.mu.Unlock()
		return eps, internal
	}
	d.mu.Unlock()

	addrs, internal := underlay.Scan()
	for _, ip := range addrs {
		if d.usableUnderlay(ip) {
			eps = append(eps, netip.AddrPortFrom(ip, port))
		} else {
			internal = append(internal, ip)
		}
	}
	if len(eps) > gossip.MaxEndpointAddrs {
		eps = eps[:gossip.MaxEndpointAddrs]
	}
	d.mu.Lock()
	d.addrs, d.internal = slices.Clone(eps), slices.Clone(internal)
	d.addrsPort, d.addrsUntil = port, now.Add(underlayCacheFor)
	d.mu.Unlock()
	return eps, internal
}

// reachableLearned drops what the data plane reports that the interface scan
// refused: magicsock reads the same interfaces, but only knows to leave out
// Tailscale's ranges, not this network's overlay or a container bridge.
func (d *Daemon) reachableLearned(learned []netip.AddrPort, internal []netip.Addr) []netip.AddrPort {
	return slices.DeleteFunc(slices.Clone(learned), func(ap netip.AddrPort) bool {
		ip := ap.Addr().Unmap()
		return !d.usableUnderlay(ip) || slices.Contains(internal, ip)
	})
}

// underlayCacheFor is how long an interface scan is reused. Short enough that
// a laptop moving between networks re-announces within one discovery interval
// of arriving.
const underlayCacheFor = 2 * time.Second

func (d *Daemon) usableUnderlay(ip netip.Addr) bool {
	switch {
	case !ip.IsValid(), ip.IsLoopback(), ip.IsLinkLocalUnicast(),
		ip.IsLinkLocalMulticast(), ip.IsMulticast(), ip.IsUnspecified():
		return false
	case types.IsOverlayV4(ip):
		// An overlay v4 range, this network's or Tailscale's. A host
		// legitimately using one on its LAN cannot also be reached there by
		// members, so excluding it is right either way.
		return false
	case d.ula.IsValid() && d.ula.Contains(ip):
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return !slices.ContainsFunc(d.v4, func(r netip.Prefix) bool { return r.Contains(ip) })
}

// mergeEndpoints adds the addresses the data plane learned, such as reflexive
// ones, to the interface scan; neither is a superset of the other. Past what
// one announcement carries the learned ones are kept: truncating the sorted
// union would drop the reflexive address, usually the highest there is.
func mergeEndpoints(scanned, learned []netip.AddrPort) []netip.AddrPort {
	if len(learned) == 0 {
		return scanned
	}
	keep := gossip.SortAddrs(learned)
	if len(keep) > gossip.MaxEndpointAddrs {
		keep = keep[:gossip.MaxEndpointAddrs]
	}
	for _, ap := range scanned {
		if len(keep) >= gossip.MaxEndpointAddrs {
			break
		}
		if !slices.Contains(keep, ap) {
			keep = append(keep, ap)
		}
	}
	return gossip.SortAddrs(keep)
}

// onConnectivityChange is called by the data plane when the relay region it
// chose, or the set of addresses it believes it is reachable at, has moved.
// Both are in this node's announcement, so it is rebuilt and pushed.
func (d *Daemon) onConnectivityChange() {
	d.mu.Lock()
	d.announced = nil
	d.mu.Unlock()
	d.MarkDirty()
}
