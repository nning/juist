package relay

import (
	"bytes"
	"fmt"
	"log"
	"time"

	"github.com/nning/juist/internal/lograte"
	"tailscale.com/types/logger"
)

// handshakeLogEvery is how often a refused TLS handshake is logged: a member
// pinned to an old certificate retries several times a second.
const handshakeLogEvery = time.Minute

// handshakeLog passes the HTTP server's errors on, all but one refused TLS
// handshake per handshakeLogEvery, which says how many it stands for.
type handshakeLog struct {
	logf  logger.Logf
	now   func() time.Time
	every lograte.Every
}

func newServerErrorLog(logf logger.Logf, now func() time.Time) *log.Logger {
	return log.New(&handshakeLog{logf: logf, now: now, every: lograte.Every{Interval: handshakeLogEvery}}, "", 0)
}

func (h *handshakeLog) Write(p []byte) (int, error) {
	line := string(bytes.TrimSpace(p))
	if !bytes.Contains(p, []byte("TLS handshake error")) {
		h.logf("relay: %s", line)
		return len(p), nil
	}
	left, last, ok := h.every.Allow(h.now())
	if !ok {
		return len(p), nil
	}
	more := ""
	if left > 0 {
		more = fmt.Sprintf(" (%d more since %s)", left, last.UTC().Format(time.TimeOnly))
	}
	h.logf("relay: %s%s", line, more)
	return len(p), nil
}
