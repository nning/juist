//go:build !((linux && !android) || freebsd)

package tray

import (
	"context"
	"errors"
)

// Supported says whether the tray runs here.
const Supported = false

func run(context.Context, *watcher, Config) error {
	return errors.New("juist tray runs on Linux desktops")
}
