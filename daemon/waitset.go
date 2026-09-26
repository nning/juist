package daemon

import "sync"

// A waitSet is a WaitGroup that stops admitting once stopped, so an Add that
// takes the counter off zero cannot race the Wait.
type waitSet struct {
	mu      sync.Mutex
	stopped bool
	wg      sync.WaitGroup
}

// track admits a goroutine, which calls done when it ends, or reports that the
// set is stopped and it must not start.
func (w *waitSet) track() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return false
	}
	w.wg.Add(1)
	return true
}

func (w *waitSet) done() { w.wg.Done() }

// stop admits nobody further.
func (w *waitSet) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopped = true
}

// wait waits for every goroutine admitted.
func (w *waitSet) wait() { w.wg.Wait() }
