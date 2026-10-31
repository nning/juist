package daemon

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/nning/juist/relay"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// IngressRelayName is the name the relay of the network's ingress takes on
// 443 where none is set, relay.DOMAIN, and that ingress: of those that relay
// too and have not expired at unix time now, the one of the lowest identity.
// "" where there is none.
func IngressRelayName(state *log.State, now int64) (string, types.Identity) {
	if state.Domain() == "" {
		return "", types.Identity{}
	}
	for _, n := range state.NodesWithRole(types.RoleIngress) {
		if n.HasRole(types.RoleRelayCapable) && !n.Expired(now) {
			return "relay." + state.Domain(), n.Identity
		}
	}
	return "", types.Identity{}
}

// A relay's public name is its member's word, and whoever holds a
// certificate for the name serves it: another member could claim it. A name
// is taken as a relay's once the server at it says it is that relay.
type relayNameProofs struct {
	mu     sync.Mutex
	by     map[nameClaim]*nameProof
	newAt  map[types.Identity]time.Time // when each relay last got a name asked about
	over   map[types.Identity]string    // the ingress's announced name its role's name was taken over
	wanted chan struct{}
}

// passOver notes whether the ingress id is taken by its role's name over
// announced, the name it announces; done is false where it is not.
func (p *relayNameProofs) passOver(id types.Identity, announced string, done bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case done:
		if p.over == nil {
			p.over = map[types.Identity]string{}
		}
		p.over[id] = announced
	case p.over[id] != announced:
		delete(p.over, id)
	}
}

// passedOver is the announced name the ingress id was last taken over by its
// role's name, held until it announces another; ok is false for none.
func (p *relayNameProofs) passedOver(id types.Identity) (announced string, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	announced, ok = p.over[id]
	return announced, ok
}

// nameClaim is a name as one relay claims it.
type nameClaim struct {
	name string
	by   types.Identity
}

type nameProof struct {
	asked    time.Time // when it was last claimed
	answered bool
	is       types.Identity // whom the server at the name said it was
	due      time.Time
	gap      time.Duration
}

// Bounds on asking relays' names whose they are. A relay's names past its
// own bound, or anyone's past the bound in all, push out the one longest
// unclaimed, so a relay cycling names spends its own slots alone; one past
// its own bound is taken once every nameProofNewEvery, so the names it has
// every member ask stay few.
const (
	maxNameProofs     = 64
	maxNamesPerRelay  = 4
	nameProofNewEvery = 10 * time.Minute
	nameProofHeld     = 6 * time.Hour
	nameProofFirst    = time.Minute
	nameProofMost     = time.Hour
	nameProofForget   = 24 * time.Hour
	nameProofWait     = 15 * time.Second
)

// relayNameProven reports whether the server at name said it is id's relay,
// asking it otherwise. This device's own name needs no asking.
func (d *Daemon) relayNameProven(name string, id types.Identity) bool {
	if id == d.self {
		return name == d.relayName
	}
	p := &d.nameProofs
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.by == nil {
		p.by, p.newAt = map[nameClaim]*nameProof{}, map[types.Identity]time.Time{}
	}
	now := d.now()
	k := nameClaim{name, id}
	e := p.by[k]
	if e == nil {
		if p.claimsBy(id) >= maxNamesPerRelay {
			if now.Sub(p.newAt[id]) < nameProofNewEvery {
				return false
			}
			p.forgetLongestUnclaimed(func(c nameClaim) bool { return c.by == id })
		}
		if len(p.by) >= maxNameProofs {
			p.forgetLongestUnclaimed(func(nameClaim) bool { return true })
		}
		e = &nameProof{}
		p.by[k], p.newAt[id] = e, now
	}
	e.asked = now
	if !e.answered {
		select {
		case p.wanted <- struct{}{}:
		default:
		}
	} else if e.is != id {
		d.logOnce("daemon: " + name + " is announced by a relay its server says it is not")
	}
	return e.answered && e.is == id
}

// claimsBy counts the names id claims, with p.mu held.
func (p *relayNameProofs) claimsBy(id types.Identity) int {
	n := 0
	for c := range p.by {
		if c.by == id {
			n++
		}
	}
	return n
}

// forgetLongestUnclaimed forgets the claim of those which was last claimed
// longest ago, with p.mu held.
func (p *relayNameProofs) forgetLongestUnclaimed(of func(nameClaim) bool) {
	var oldest *nameClaim
	for c, e := range p.by {
		if of(c) && (oldest == nil || e.asked.Before(p.by[*oldest].asked)) {
			oldest = &c
		}
	}
	if oldest != nil {
		delete(p.by, *oldest)
	}
}

// proveRelayNames asks the relays' names whose they are, as they are
// claimed and again now and then, and reconciles where an answer changed.
func (d *Daemon) proveRelayNames(ctx context.Context) {
	tick := time.NewTicker(nameProofWait)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-d.nameProofs.wanted:
		}
		if d.proveDue(ctx) {
			d.MarkDirty()
		}
	}
}

// proveDue asks each name whose answer is due, reporting whether any
// answer changed.
func (d *Daemon) proveDue(ctx context.Context) bool {
	now := d.now()
	p := &d.nameProofs
	p.mu.Lock()
	var due []nameClaim
	for c, e := range p.by {
		switch {
		case now.Sub(e.asked) > nameProofForget:
			delete(p.by, c)
		case !now.Before(e.due):
			due = append(due, c)
		}
	}
	for id, at := range p.newAt {
		if now.Sub(at) > nameProofNewEvery && p.claimsBy(id) == 0 {
			delete(p.newAt, id)
		}
	}
	p.mu.Unlock()
	changed := false
	for _, c := range due {
		actx, cancel := context.WithTimeout(ctx, nameProofWait)
		is, err := d.askWhoami(actx, c.name)
		cancel()
		if ctx.Err() != nil {
			return changed
		}
		p.mu.Lock()
		e := p.by[c]
		if e == nil {
			p.mu.Unlock()
			continue
		}
		before, was := e.answered, e.is
		if err != nil {
			// What was answered stands until the server says otherwise.
			e.gap = min(max(2*e.gap, nameProofFirst), nameProofMost)
			e.due = d.now().Add(e.gap)
		} else {
			e.answered, e.is, e.gap, e.due = true, types.Identity(is), 0, d.now().Add(nameProofHeld)
		}
		changed = changed || before != e.answered || was != e.is
		p.mu.Unlock()
	}
	return changed
}

// whoamiClient is how this device asks a relay's name whose it is: as it
// reaches relays, through the proxy on HTTPS alone.
func (d *Daemon) whoamiClient() *http.Client {
	hc := d.httpsClient()
	if !d.httpsOnly {
		hc.Transport.(*http.Transport).Proxy = nil
	}
	return hc
}

func (d *Daemon) defaultAskWhoami(ctx context.Context, name string) ([32]byte, error) {
	return relay.Whoami(ctx, d.whoamiHTTP, name)
}
