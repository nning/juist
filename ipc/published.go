package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"

	"github.com/fxamacker/cbor/v2"
)

// TerminatorWanted is the file juistd keeps on Linux while this device needs
// its terminator, which juist-serve.path starts it by.
const TerminatorWanted = "/run/juist/serve-wanted"

// IngressPorts is the file juistd keeps on Linux listing the public TCP
// ports its ingress takes, which juist-ingress-ports.path has the firewall
// follow.
const IngressPorts = "/run/juist/ingress-ports"

// Published is what an ingress serves: every name published in the network,
// nothing while this device is no ingress or its view is stale. Names go by
// TLS on 443 and TCP by their public port, a list of its own, so that a
// helper too old to know it passes none of them by name.
//
// Answering [CmdServing], Ingresses are the ingresses' overlay addresses,
// the only sources whose PROXY protocol header a terminator believes, and
// Idle says that nothing here needs the terminator, which may then stop.
type Published struct {
	Names     []PublishedTarget `cbor:"1,keyasint,omitempty"`
	Ingresses []netip.Addr      `cbor:"2,keyasint,omitempty"`
	Idle      bool              `cbor:"3,keyasint,omitempty"`
	TCP       []PublishedTarget `cbor:"4,keyasint,omitempty"`
}

// A PublishedTarget is one published name and where it goes: the target's
// overlay addresses and port, and whether the client's address goes first in
// a PROXY protocol v2 header; Public is the port of a name passed by TCP.
//
// Answering [CmdServing], Addrs are this device's own, to listen on, and To
// is where the name's plain connections go.
type PublishedTarget struct {
	Name   string       `cbor:"1,keyasint"`
	Addrs  []netip.Addr `cbor:"2,keyasint,omitempty"`
	Port   uint16       `cbor:"3,keyasint"`
	Proxy  bool         `cbor:"4,keyasint,omitempty"`
	To     string       `cbor:"5,keyasint,omitempty"`
	Public uint16       `cbor:"6,keyasint,omitempty"`
}

// An IngressReport is what an ingress tells juistd as it asks: the public
// ports it listens on, those another program holds, and whether QUIC's is.
type IngressReport struct {
	Listening, Unbound []uint16
	NoQUIC             bool // 443/udp held by another program
}

// quicUnbound is how a report's NoQUIC travels, among the ports unbound.
const quicUnbound = "443/udp"

// publishedFrame is a [Response] as an ingress reads it: the two fields it
// needs, so that a juistd upgraded before it, whose replies carry more,
// does not silence it.
type publishedFrame struct {
	Err       string     `cbor:"1,keyasint,omitempty"`
	Published *Published `cbor:"11,keyasint,omitempty"`
	Serving   *Published `cbor:"12,keyasint,omitempty"`
}

var publishedDec = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		UTF8:             cbor.UTF8RejectInvalid,
		MaxNestedLevels:  maxNestedLevels,
		MaxArrayElements: 1 << 16,
		MaxMapPairs:      maxMapPairs,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("ipc: building the ingress's decoder: %v", err))
	}
	return m
}()

// DecodePublished reads a reply to [CmdPublished] or [CmdServing], ignoring
// fields it does not know.
func DecodePublished(b []byte) (*Published, error) {
	if len(b) == 0 || len(b) > MaxResponse {
		return nil, fmt.Errorf("ipc: a reply of %d bytes", len(b))
	}
	var f publishedFrame
	if err := publishedDec.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("ipc: decoding what is published: %w", err)
	}
	if f.Err != "" {
		return nil, errors.New(printable(f.Err))
	}
	switch {
	case f.Published != nil:
		return f.Published, nil
	case f.Serving != nil:
		return f.Serving, nil
	}
	return &Published{}, nil
}

// CallPublished asks the daemon at path what its ingress serves, telling it
// the ingress's report, if any.
func CallPublished(ctx context.Context, path string, r *IngressReport) (*Published, error) {
	req := Request{Command: CmdPublished}
	if r != nil {
		req.Listening, req.Unbound = portStrings(r.Listening), portStrings(r.Unbound)
		if r.NoQUIC && len(req.Unbound) < MaxIngressPorts {
			req.Unbound = append(req.Unbound, quicUnbound)
		}
	}
	return callHelper(ctx, path, req)
}

// portStrings is ports in the terminator's report's fields, as many as a
// request carries.
func portStrings(ports []uint16) []string {
	var out []string
	for _, p := range ports[:min(len(ports), MaxIngressPorts)] {
		out = append(out, strconv.Itoa(int(p)))
	}
	return out
}

// IngressReportOf reads the report an ingress's request carries, dropping
// what is no port.
func IngressReportOf(req Request) IngressReport {
	ports := func(ss []string) []uint16 {
		var out []uint16
		for _, s := range ss {
			if p, err := strconv.ParseUint(s, 10, 16); err == nil && p != 0 {
				out = append(out, uint16(p))
			}
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	return IngressReport{Listening: ports(req.Listening), Unbound: ports(req.Unbound),
		NoQUIC: slices.Contains(req.Unbound, quicUnbound)}
}

// CallServing asks the daemon at path what its terminator ends TLS for,
// telling it the terminator's report.
func CallServing(ctx context.Context, path string, r *TerminatorReport) (*Published, error) {
	req := Request{Command: CmdServing}
	if r != nil {
		req.Account, req.Listening, req.Unbound, req.NoCert, req.Stopping = r.Account, r.Listening, r.Unbound, r.NoCert, r.Stopping
	}
	return callHelper(ctx, path, req)
}

func callHelper(ctx context.Context, path string, req Request) (*Published, error) {
	b, err := callRaw(ctx, path, req)
	if err != nil {
		return nil, err
	}
	return DecodePublished(b)
}

// callRaw sends a helper's req to the daemon at path and returns its reply
// undecoded.
func callRaw(ctx context.Context, path string, req Request) ([]byte, error) {
	var d net.Dialer
	ctx, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	_ = c.SetDeadline(deadline)
	if err := WriteMessage(c, &req, MaxRequest); err != nil {
		return nil, err
	}
	b, err := ReadMessage(c, MaxResponse)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || len(b) > MaxResponse {
		return nil, fmt.Errorf("ipc: a reply of %d bytes", len(b))
	}
	return b, nil
}
