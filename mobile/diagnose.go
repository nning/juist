package mobile

import (
	"cmp"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// slowLookup is how long a lookup may take before it counts as slow.
const slowLookup = time.Second

// recentLookups is how many failed lookups a diagnosis keeps, and apart
// from them how many slow ones, so that slow ones crowd out no failure.
const recentLookups = 12

// dnsStats counts what the resolver asked upstream, and keeps the latest
// lookups that failed or were slow, in memory alone.
type dnsStats struct {
	logf func(format string, args ...any)

	mu             sync.Mutex
	d              dnsDiagnosis
	failed, slowed []dnsLookup
	lastLog        time.Time
	unlogged       int
}

type dnsDiagnosis struct {
	Queries   int         `json:"queries"`
	Failed    int         `json:"failed"`
	Slow      int         `json:"slow"`
	MaxMillis int64       `json:"maxMillis"`
	Recent    []dnsLookup `json:"recent,omitempty"`
}

// A dnsLookup is one that failed or was slow: Why is the RCode's name or the
// error, "" where it was only slow.
type dnsLookup struct {
	At     int64  `json:"at"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Why    string `json:"why,omitempty"`
	Millis int64  `json:"millis"`
}

func newDNSStats(logf func(format string, args ...any)) *dnsStats { return &dnsStats{logf: logf} }

// logEvery spaces the log lines failed lookups write.
const logEvery = 10 * time.Second

func (s *dnsStats) observe(q []byte, rcode int, err error, took time.Duration) {
	why := ""
	switch {
	case err != nil:
		why = err.Error()
	case rcode == 2:
		why = "SERVFAIL"
	case rcode == 5:
		why = "REFUSED"
	}
	ms := took.Milliseconds()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.Queries++
	s.d.MaxMillis = max(s.d.MaxMillis, ms)
	if why == "" && took < slowLookup {
		return
	}
	if why != "" {
		s.d.Failed++
	} else {
		s.d.Slow++
	}
	name, typ := question(q)
	l := dnsLookup{At: time.Now().Unix(), Name: name, Type: typ, Why: why, Millis: ms}
	if why == "" {
		s.slowed = keepLast(append(s.slowed, l), recentLookups)
		return
	}
	s.failed = keepLast(append(s.failed, l), recentLookups)
	if now := time.Now(); now.Sub(s.lastLog) >= logEvery {
		more := ""
		if s.unlogged > 0 {
			more = ", and " + strconv.Itoa(s.unlogged) + " more since"
		}
		s.logf("resolver: %s %s failed after %dms: %s%s", name, typ, ms, why, more)
		s.lastLog, s.unlogged = now, 0
	} else {
		s.unlogged++
	}
}

func (s *dnsStats) snapshot() dnsDiagnosis {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.d
	d.Recent = append(slices.Clone(s.failed), s.slowed...)
	slices.SortStableFunc(d.Recent, func(a, b dnsLookup) int { return cmp.Compare(a.At, b.At) })
	return d
}

func keepLast(ls []dnsLookup, n int) []dnsLookup {
	if len(ls) > n {
		return slices.Delete(ls, 0, len(ls)-n)
	}
	return ls
}

// question is q's name and type, "?" for what does not parse.
func question(q []byte) (string, string) {
	var p dnsmessage.Parser
	if _, err := p.Start(q); err != nil {
		return "?", "?"
	}
	qs, err := p.Question()
	if err != nil {
		return "?", "?"
	}
	return strings.TrimSuffix(qs.Name.String(), "."), strings.TrimPrefix(qs.Type.String(), "Type")
}

// A diagnosis is what the core can say of how the phone's traffic fares
// beside the tunnel, for a person to copy with the log.
type diagnosis struct {
	Established     int          `json:"established"`
	LastEstablished int64        `json:"lastEstablished,omitempty"`
	Saving          bool         `json:"saving"`
	DNS             dnsDiagnosis `json:"dns"`
}

// Diagnose is what the core can say of how the phone's traffic fares, a
// JSON diagnosis: how often the VPN was established, whether the core saves
// battery, and how the resolver's lookups went.
func (c *Core) Diagnose() string {
	n, last := c.hub.Established()
	d := diagnosis{Established: n, Saving: c.pace.Saving(), DNS: c.dns.snapshot()}
	if !last.IsZero() {
		d.LastEstablished = last.Unix()
	}
	b, _ := json.Marshal(d)
	return string(b)
}
