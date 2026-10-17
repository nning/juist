package conn

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/nning/juist/internal/netstack"
)

// netstackNode is a node whose overlay is a network stack in this process.
func netstackNode(t *testing.T, id uint64, v4, v6 string) (*node, *netstack.Net) {
	t.Helper()
	dev, stack, err := netstack.New([]netip.Addr{netip.MustParsePrefix(v4).Addr(), netip.MustParsePrefix(v6).Addr()}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	n := startNode(t, id, v4, v6, func(o *Options) { o.Tun, o.RespondToPing = dev, false })
	return n, stack
}

// echoOn answers each connection at ap on stack with a line naming the
// caller.
func echoOn(t *testing.T, stack *netstack.Net, ap netip.AddrPort) {
	t.Helper()
	ln, err := stack.ListenTCPAddrPort(ap)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			fmt.Fprintf(c, "from %v\n", c.RemoteAddr())
			c.Close()
		}
	}()
}

func askOn(stack *netstack.Net, ap netip.AddrPort, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := stack.DialContextTCPAddrPort(ctx, ap)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	return bufio.NewReader(c).ReadString('\n')
}

// Over two network stacks a member opens a connection to a service member
// and is answered; the service member opens none to the member.
func TestAServiceMemberAnswersAndOpensNothing(t *testing.T) {
	t.Parallel()
	member, memberNet := netstackNode(t, 1, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	service, serviceNet := netstackNode(t, 2, "100.64.0.2/32", "fd7a:115c:a1e0::2/128")
	confined := service.peer()
	confined.Access = serviceAccess()
	if err := member.mgr.SetPeers([]Peer{confined}); err != nil {
		t.Fatal(err)
	}
	if err := service.mgr.SetPeers([]Peer{member.peer()}); err != nil {
		t.Fatal(err)
	}
	echoOn(t, serviceNet, netip.MustParseAddrPort("100.64.0.2:443"))
	echoOn(t, memberNet, netip.MustParseAddrPort("100.64.0.1:41644"))

	var got string
	var err error
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
		if got, err = askOn(memberNet, netip.MustParseAddrPort("100.64.0.2:443"), 2*time.Second); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("the member reached no service member: %v", err)
	}
	if want := "from 100.64.0.1:"; len(got) < len(want) || got[:len(want)] != want {
		t.Errorf("the service member answered %q", got)
	}
	if got, err := askOn(serviceNet, netip.MustParseAddrPort("100.64.0.1:41644"), 3*time.Second); err == nil {
		t.Errorf("the service member reached the member: %q", got)
	}
}
