// Package tray is juist tray: juist's state in a Linux desktop's status bar,
// as a StatusNotifierItem, and a menu that switches the exit node. It asks
// juistd over the control socket and leaves every judgement and change to
// juist itself, run as the person.
package tray

import (
	"context"
	"errors"
	"io"
)

// Config is what the tray watches and how it runs juist.
type Config struct {
	// SocketOf is instance n's control socket, and Home its state
	// directory, which juist removes with the instance. Only says the
	// default instance is the one network to watch.
	SocketOf func(n int) string
	Home     func(n int) string
	Only     bool

	// Juist runs juist with args as the person would, and returns its
	// output; calls come one at a time.
	Juist func(ctx context.Context, args []string) (stdout, stderr string, err error)

	// Stderr takes warnings where no notification can be shown.
	Stderr io.Writer

	// Replaced, where set, reports whether juist's program was replaced,
	// as by an update, whose juistd this process's juist may not read.
	Replaced func() bool
}

// ErrReplaced ends Run when juist's program was replaced: the caller starts
// the new one in its place.
var ErrReplaced = errors.New("juist was replaced")

// Run shows the tray until the person quits it from its menu, ctx ends, or
// Replaced says so.
func Run(ctx context.Context, c Config) error { return run(ctx, newWatcher(c), c) }
