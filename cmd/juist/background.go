package main

import (
	"io"
	"strings"

	"github.com/nning/juist/ipc"
)

// backgroundEnv marks the run of a background share, whose descriptor 3
// says once the share is up.
const backgroundEnv = "JUIST_BACKGROUND"

// shareInBackground runs this invocation again in a session of its own,
// which says the share as a foreground one would and then shares on; this
// one ends once the share is up, or with the run's error, which it said.
func (a *app) shareInBackground(st *ipc.Status) error {
	// Started here, where sudo can ask, and not where nobody answers.
	if terminatorDown(st) && !a.terminatorStarts() && (a.host.terminatorOn == nil || !a.host.terminatorOn(a.ctx)) {
		if err := a.packageScript(a.host.serveScript, "on", "the terminator's service"); err != nil {
			return err
		}
	}
	ready, wait, kill, err := a.spawn(a.argv)
	if err != nil {
		return err
	}
	up := make(chan bool, 1)
	go func() {
		b, _ := io.ReadAll(ready)
		ready.Close()
		up <- strings.TrimSpace(string(b)) == "ok"
	}()
	select {
	case ok := <-up:
		if ok {
			return nil
		}
	case <-a.ctx.Done():
		kill()
		<-up
		_ = wait()
		return nil
	}
	if err := wait(); err != nil {
		return errSilent
	}
	return nil
}

// detachShare says the background share is up, and stops writing to the
// terminal it was started from.
func (a *app) detachShare() {
	a.out, a.errOut = io.Discard, io.Discard
	if a.detach != nil {
		a.detach()
	}
	_, _ = io.WriteString(a.ready, "ok\n")
	a.ready.Close()
}
