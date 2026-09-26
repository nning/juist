package daemon

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"slices"
	"time"

	"github.com/nning/juist/internal/statedir"

	"github.com/nning/juist/gossip"
	"github.com/nning/juist/types"
)

// The endpoint cache is what a restarted node knows before it hears anything.
// Without it, a device that comes back with no member on its LAN has only the
// rendezvous path, which costs a DHT round trip per peer and does not work at
// all where the DHT is off.
//
// What is written is exactly what was received: signed announcements, so the
// file is not trusted. A record that was edited fails its signature and is
// dropped, and one that is merely stale loses to the first fresher one a peer
// sends, because [gossip.Endpoint.Seq] orders them.

// loadEndpointCache reads announcements a previous run persisted. A missing
// file is not an error — it is what a first run looks like — and neither is an
// unreadable one: the cache is a hint, and refusing to start over it would
// turn a corrupt hint into an outage.
func (d *Daemon) loadEndpointCache(path string) {
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		d.logf("daemon: reading the endpoint cache: %v", err)
		return
	}
	var held []gossip.Endpoint
	if err := gossip.DecodeCachedEndpoints(b, &held); err != nil {
		d.logf("daemon: the endpoint cache did not decode and was ignored: %v", err)
		return
	}
	n := 0
	for i := range held {
		e := held[i]
		if e.Identity == d.self {
			// This node is the authority on its own announcement; a stale
			// copy of it must not shadow the one this run builds.
			continue
		}
		if err := e.Verify(); err != nil {
			continue
		}
		if d.endpoints.Add(e) {
			n++
		}
	}
	if n > 0 {
		d.logf("daemon: recovered %d cached peer address(es) from %s", n, path)
	}
}

// saveEndpointCache writes the announcements this node holds for members. Only
// members: a subject the log does not carry is an announcement this node was
// handed and has not acted on, and persisting those would let anyone holding
// an epoch secret grow the file without bound.
func (d *Daemon) saveEndpointCache(path string) {
	if path == "" {
		return
	}
	all := d.endpoints.All()
	keep := make([]gossip.Endpoint, 0, len(all))
	for i := range all {
		if all[i].Identity == d.self || !d.endpoints.IsMember(all[i].Identity) {
			continue
		}
		keep = append(keep, all[i])
		if len(keep) >= types.MaxNodes {
			break
		}
	}
	b, err := gossip.EncodeCachedEndpoints(keep)
	if err != nil {
		d.logf("daemon: encoding the endpoint cache: %v", err)
		return
	}

	// Renewed signatures alone do not rewrite it more than hourly: what the
	// file is for — where to reach a peer after a restart — has not moved.
	d.mu.Lock()
	unchanged := bytes.Equal(d.cachedEndpoints, b) ||
		slices.EqualFunc(d.cachedList, keep, func(x, y gossip.Endpoint) bool { return x.SameAs(&y) }) &&
			d.now().Sub(d.cachedAt) < cacheRenewal
	if !unchanged {
		d.cachedEndpoints, d.cachedList, d.cachedAt = b, keep, d.now()
	}
	d.mu.Unlock()
	if unchanged {
		return
	}
	if err := statedir.WriteFilePrivate(path, b); err != nil {
		d.logf("daemon: writing the endpoint cache: %v", err)
	}
}

// cacheRenewal is how often the endpoint cache is rewritten for renewed
// signatures alone.
const cacheRenewal = time.Hour
