package ipc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/nning/juist/types"
)

// Visibility is what a status page shows a client who is no member; members
// see all of it.
type Visibility uint8

const (
	ShowNone     Visibility = iota // nothing: the page answers members alone
	ShowServices                   // the published names and shares, and whether they are up
	ShowNetwork                    // the devices, their reach and the alarms too
	ShowAll                        // the log's changes too
)

var visibilityNames = []string{"none", "services", "network", "all"}

func (v Visibility) String() string {
	if int(v) < len(visibilityNames) {
		return visibilityNames[v]
	}
	return fmt.Sprintf("visibility?<%d>", uint8(v))
}

// ParseVisibility reads one of none, services, network and all.
func ParseVisibility(s string) (Visibility, error) {
	if i := slices.Index(visibilityNames, s); i >= 0 {
		return Visibility(i), nil
	}
	return 0, fmt.Errorf("%q is none, services, network or all", s)
}

// statusPageTo is the [ServeTo.To] of a status page, which no HOST:PORT is.
const statusPageTo = "status-page"

// StatusPageTo is the [ServeTo.To] of a name that serves the status page,
// showing v to the public.
func StatusPageTo(v Visibility) string {
	if v == ShowServices {
		return statusPageTo
	}
	return statusPageTo + ":" + v.String()
}

// StatusPageOf reports whether to names the status page, and what it shows
// the public.
func StatusPageOf(to string) (Visibility, bool) {
	rest, ok := strings.CutPrefix(to, statusPageTo)
	switch {
	case !ok:
		return 0, false
	case rest == "":
		return ShowServices, true
	case !strings.HasPrefix(rest, ":"):
		return 0, false
	}
	v, err := ParseVisibility(rest[1:])
	return v, err == nil
}

// MaxPageChanges caps the changes a [StatusPage] carries, the newest.
const MaxPageChanges = 50

// A StatusPage is what the terminator renders a status page from: this
// device's status, as an operator reads it, and the log's newest changes.
type StatusPage struct {
	Status Status `cbor:"1,keyasint"`

	// Changes are the newest of the log's Total changes, newest first.
	Changes []Change `cbor:"2,keyasint,omitempty"`
	Total   int      `cbor:"3,keyasint,omitempty"`

	// Members are the overlay addresses whose connections are a member's:
	// every member's but an ingress's, which brings the public.
	Members []netip.Addr `cbor:"4,keyasint,omitempty"`

	// Shares are the names members share under now, this device's too.
	Shares []string `cbor:"5,keyasint,omitempty"`
}

// A Change is one record of the log as juist log lists it.
type Change struct {
	Index   int        `cbor:"1,keyasint"`
	What    string     `cbor:"2,keyasint"`
	Signers []string   `cbor:"3,keyasint,omitempty"`
	Hash    types.Hash `cbor:"4,keyasint"`
}

// Member reports whether a connection from a is a member's.
func (p *StatusPage) Member(a netip.Addr) bool {
	return a.IsValid() && slices.Contains(p.Members, a.Unmap())
}

// statusPageFrame is a [Response] as the terminator reads a status page.
type statusPageFrame struct {
	Err        string      `cbor:"1,keyasint,omitempty"`
	StatusPage *StatusPage `cbor:"13,keyasint,omitempty"`
}

// CallStatusPage asks the daemon at path what its status page shows,
// ignoring fields it does not know.
func CallStatusPage(ctx context.Context, path string) (*StatusPage, error) {
	b, err := callRaw(ctx, path, Request{Command: CmdStatusPage})
	if err != nil {
		return nil, err
	}
	var f statusPageFrame
	if err := publishedDec.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("ipc: decoding the status page: %w", err)
	}
	makePrintable(&f)
	switch {
	case f.Err != "":
		return nil, errors.New(f.Err)
	case f.StatusPage == nil:
		return nil, errors.New("ipc: juistd sent no status page")
	}
	return f.StatusPage, nil
}
