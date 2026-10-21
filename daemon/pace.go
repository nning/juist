package daemon

import (
	"sync"
	"sync/atomic"
	"time"
)

// While saving battery, the tunnels are checked every savingReachEvery, an
// answer stands for savingProbeStands, the log is synced with a random member
// every savingSyncEvery, and it is reconciled, and the service looks for what
// moved, with neither an event nor a deadline every savingReconcileEvery and
// savingWatchEvery. Pushes, new announcements, deadlines and the data
// plane's traffic keep their pace.
const (
	savingReachEvery     = 5 * time.Minute
	savingProbeStands    = 30 * time.Minute
	savingSyncEvery      = 30 * time.Minute
	savingReconcileEvery = 10 * time.Minute
	savingWatchEvery     = 10 * time.Minute
)

// A Pace says whether the mesh saves the device's battery, as a phone's does
// while its screen is off. Safe for concurrent use; a nil Pace never saves.
type Pace struct {
	saving  atomic.Bool
	mu      sync.Mutex
	changed chan struct{}
}

// NewPace returns a Pace that does not save.
func NewPace() *Pace { return &Pace{changed: make(chan struct{})} }

// SetSaving sets whether the mesh saves battery.
func (p *Pace) SetSaving(saving bool) {
	if p.saving.Swap(saving) == saving {
		return
	}
	p.mu.Lock()
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
}

// Saving reports whether the mesh saves battery.
func (p *Pace) Saving() bool { return p != nil && p.saving.Load() }

// Changed is closed at the next change; nil for a nil Pace.
func (p *Pace) Changed() <-chan struct{} {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.changed
}

// every is normal, or saving while p saves.
func (p *Pace) every(normal, saving time.Duration) time.Duration {
	if p.Saving() {
		return saving
	}
	return normal
}

// savingPace is how often what slows down runs while saving.
type savingPace struct{ reach, sync, reconcile time.Duration }

// due reports whether a tick of what last ran at last runs: always at the
// normal pace, and once saving long after it. Pacing measures real time, as
// the timers it runs by do; d.now is the clock times in the log are read by.
func (d *Daemon) due(last time.Time, saving time.Duration) bool {
	return time.Since(last) >= d.pace.every(0, saving)
}

// followPace tells the data plane whether to save battery, and has LAN
// discovery, quiet while saving, announce this device once it no longer is.
func (d *Daemon) followPace() {
	saving := d.pace.Saving()
	d.manager.SetSaving(saving)
	if !saving && d.beacon != nil {
		d.beacon.Wake()
	}
}
