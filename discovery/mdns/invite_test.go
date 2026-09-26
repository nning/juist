package mdns

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestInviteIsFoundByItsNameplate(t *testing.T) {
	h := &hub{}
	r, err := AnswerInvite(42, 41642, InviteOptions{Conn: h.join()})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	other, err := AnswerInvite(43, 41643, InviteOptions{Conn: h.join()})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	hosts, err := FindInvite(context.Background(), 42, 5*time.Second, InviteOptions{Conn: h.join()})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || len(hosts[0].Addrs) != 1 || hosts[0].Addrs[0].Port() != 41642 {
		t.Fatalf("found %+v, want one host on port 41642", hosts)
	}
}

// Two hosts answering for one nameplate must both be reported, so the guest
// can refuse to guess between them rather than spend one of their invites.
func TestTwoHostsForOneNameplateAreBothReported(t *testing.T) {
	h := &hub{}
	for _, port := range []uint16{41642, 41643} {
		r, err := AnswerInvite(7, port, InviteOptions{Conn: h.join()})
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
	}
	hosts, err := FindInvite(context.Background(), 7, 5*time.Second, InviteOptions{Conn: h.join()})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Fatalf("found %+v, want two hosts", hosts)
	}
}

func TestNoAnswerReturnsNothing(t *testing.T) {
	h := &hub{}
	hosts, err := FindInvite(context.Background(), 9, 700*time.Millisecond, InviteOptions{Conn: h.join()})
	if err != nil || len(hosts) != 0 {
		t.Fatalf("got %v, %v", hosts, err)
	}
}

// farConn is a hub member whose datagrams arrive from an address on no
// subnet of this host's.
type farConn struct{ *hubConn }

func (c farConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := c.hubConn.ReadFrom(b)
	return n, &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9)}, err
}

// An answer from off the link is no answer: it would steer the guest to a
// host of someone else's choosing.
func TestAnswersFromOffTheLinkAreIgnored(t *testing.T) {
	h := &hub{}
	r, err := AnswerInvite(42, 41642, InviteOptions{Conn: h.join()})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	hosts, err := FindInvite(context.Background(), 42, 700*time.Millisecond, InviteOptions{Conn: farConn{h.join()}})
	if err != nil || len(hosts) != 0 {
		t.Fatalf("an off-link answer was taken: %v, %v", hosts, err)
	}
}
