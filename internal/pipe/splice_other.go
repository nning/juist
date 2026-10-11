//go:build !linux

package pipe

import (
	"net"
	"sync/atomic"
)

// splice copies nothing: the caller does.
func splice(_, _ net.Conn, _ *atomic.Bool) (rerr, werr error, ok bool) { return nil, nil, false }
