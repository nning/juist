package main

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// A question is given up on when the operator interrupts, as with Ctrl-C,
// rather than waiting for a line nobody is going to type.
func TestAnInterruptEndsAQuestion(t *testing.T) {
	t.Parallel()
	in, w := io.Pipe()
	defer w.Close()
	var out syncBuffer
	a := newApp(in, &out, &out)
	a.interactive = true
	ctx, cancel := context.WithCancel(context.Background())
	a.ctx = ctx
	done := make(chan error, 1)
	go func() {
		_, err := a.confirm("remove phone?")
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, errAborted) {
			t.Fatalf("interrupted question: %v, want %v", err, errAborted)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the question outlived the interrupt")
	}
}
