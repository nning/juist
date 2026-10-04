package ipc

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
)

func TestAStatusPageTargetSaysWhatThePublicSees(t *testing.T) {
	for v := ShowNone; v <= ShowAll; v++ {
		got, ok := StatusPageOf(StatusPageTo(v))
		if !ok || got != v {
			t.Errorf("%v: read back as %v, %v", v, got, ok)
		}
		if p, err := ParseVisibility(v.String()); err != nil || p != v {
			t.Errorf("%v: parsed as %v, %v", v, p, err)
		}
	}
	if StatusPageTo(ShowServices) != "status-page" {
		t.Error("the default is spelled out")
	}
	for _, to := range []string{"127.0.0.1:80", "status-page:443", "status-page-x", ""} {
		if _, ok := StatusPageOf(to); ok {
			t.Errorf("%q read as a status page", to)
		}
	}
}

// A member is known by its address, IPv4-mapped or not, and nothing is a
// member's that the page does not list.
func TestAStatusPageKnowsItsMembers(t *testing.T) {
	p := &StatusPage{Members: []netip.Addr{netip.MustParseAddr("100.80.0.3"), netip.MustParseAddr("fd7a::3")}}
	for a, want := range map[string]bool{"100.80.0.3": true, "::ffff:100.80.0.3": true, "fd7a::3": true,
		"100.80.0.4": false, "203.0.113.1": false} {
		if got := p.Member(netip.MustParseAddr(a)); got != want {
			t.Errorf("%s: %v", a, got)
		}
	}
	if p.Member(netip.Addr{}) {
		t.Error("no address is a member's")
	}
}

// The terminator reads a status page from a reply carrying more than it
// knows, and juistd's refusal as an error.
func TestTheTerminatorReadsAStatusPage(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type newer struct {
		Response
		Later string `cbor:"99,keyasint"`
	}
	replies := []any{
		newer{Response: Response{StatusPage: &StatusPage{Total: 7, Status: Status{Derived: Derived{NetworkName: "home"}}}}, Later: "x"},
		Response{Err: "this device serves no status page"},
	}
	go func() {
		for _, r := range replies {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if b, err := ReadMessage(c, MaxRequest); err != nil {
				return
			} else if req, err := DecodeRequest(b); err != nil || req.Command != CmdStatusPage {
				return
			}
			_ = WriteMessage(c, r, MaxResponse)
			c.Close()
		}
	}()
	p, err := CallStatusPage(context.Background(), sock)
	if err != nil || p.Total != 7 || p.Status.NetworkName != "home" {
		t.Fatalf("read %+v, %v", p, err)
	}
	if _, err := CallStatusPage(context.Background(), sock); err == nil || err.Error() != "this device serves no status page" {
		t.Errorf("a refusal read as %v", err)
	}
}
