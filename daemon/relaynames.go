package daemon

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/nning/juist/relay"
	"github.com/nning/juist/types"
)

// A relay's public name is its member's word, and whoever holds a
// certificate for the name serves it: another member could claim it. A name
// is taken as a relay's once the server at it says it is that relay.
type relayNameProofs struct {
	mu     sync.Mutex
	by     map[string]*nameProof
	wanted chan struct{}
}

type nameProof struct {
	asked    time.Time // when it was last claimed
	answered bool
	is       types.Identity // whom the server at the name said it was
	due      time.Time
	gap      time.Duration
}

// Bounds on asking relays' names whose they are.
const (
	maxNameProofs   = 64
	nameProofHeld   = 6 * time.Hour
	nameProofFirst  = time.Minute
	nameProofMost   = time.Hour
	nameProofForget = 24 * time.Hour
	nameProofWait   = 15 * time.Second
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
		p.by = map[string]*nameProof{}
	}
	e := p.by[name]
	if e == nil {
		if len(p.by) >= maxNameProofs {
			return false
		}
		e = &nameProof{}
		p.by[name] = e
	}
	e.asked = d.now()
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

// proveRelayNames asks the relays' names whose they are, as they are
// claimed and again now and then, and reconciles where an answer changed.
func (d *Daemon) proveRelayNames(ctx context.Context) {
	tick := time.NewTicker(nameProofWait)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.closed:
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
	var due []string
	for name, e := range p.by {
		switch {
		case now.Sub(e.asked) > nameProofForget:
			delete(p.by, name)
		case !now.Before(e.due):
			due = append(due, name)
		}
	}
	p.mu.Unlock()
	changed := false
	for _, name := range due {
		actx, cancel := context.WithTimeout(ctx, nameProofWait)
		is, err := d.askWhoami(actx, name)
		cancel()
		if ctx.Err() != nil {
			return changed
		}
		p.mu.Lock()
		e := p.by[name]
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
