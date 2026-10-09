package relay

import (
	"bytes"
	"fmt"
	"log"
	"sync"
	"time"

	"tailscale.com/types/logger"
)

// handshakeLogEvery is how often a refused TLS handshake is logged: a member
// pinned to an old certificate retries several times a second.
const handshakeLogEvery = time.Minute

// handshakeLog passes the HTTP server's errors on, all but one refused TLS
// handshake per handshakeLogEvery, which says how many it stands for.
type handshakeLog struct {
	logf logger.Logf
	now  func() time.Time

	mu         sync.Mutex
	last       time.Time
	suppressed int
}

func newServerErrorLog(logf logger.Logf, now func() time.Time) *log.Logger {
	return log.New(&handshakeLog{logf: logf, now: now}, "", 0)
}

func (h *handshakeLog) Write(p []byte) (int, error) {
	line := string(bytes.TrimSpace(p))
	if !bytes.Contains(p, []byte("TLS handshake error")) {
		h.logf("relay: %s", line)
		return len(p), nil
	}
	h.mu.Lock()
	now := h.now()
	if !h.last.IsZero() && now.Sub(h.last) < handshakeLogEvery {
		h.suppressed++
		h.mu.Unlock()
		return len(p), nil
	}
	more := ""
	if h.suppressed > 0 {
		more = fmt.Sprintf(" (%d more since %s)", h.suppressed, h.last.UTC().Format(time.TimeOnly))
	}
	h.last, h.suppressed = now, 0
	h.mu.Unlock()
	h.logf("relay: %s%s", line, more)
	return len(p), nil
}
